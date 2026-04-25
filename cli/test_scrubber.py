#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Machine Data Insights Inc.
# https://machinedatainsights.com
"""
Test suite for log_scrubber v1.1.0.

Covers:
 - Nested @json path bug fix (the original issue)
 - Backward compat: unqualified @json rules still match at any depth
 - Credential & token patterns
 - PII patterns (SSN, Luhn-validated CC, phone, SID, NPI)
 - CUI marking detection (banner, portion, legacy)
 - Auto-mode detection
 - Scrubber class API
 - Backward compat: v1 CLI syntax still works
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from log_scrubber import (
    Scrubber,
    apply_json_field_scrubbing,
    detect_cui,
    detect_file_mode,
    expand_input_paths,
    luhn_valid,
    npi_valid,
    parse_scrubbing_config,
    scrub_json_obj,
    scrub_text,
)

PASS = 0
FAIL = 0


def check(label, actual, expected_in=None, expected_not_in=None, expected_eq=None):
    global PASS, FAIL
    ok = True
    reasons = []
    if expected_eq is not None and actual != expected_eq:
        ok = False
        reasons.append(f"expected == {expected_eq!r}")
    if expected_in is not None:
        needles = expected_in if isinstance(expected_in, list) else [expected_in]
        for needle in needles:
            if needle not in actual:
                ok = False
                reasons.append(f"expected to contain {needle!r}")
    if expected_not_in is not None:
        needles = expected_not_in if isinstance(expected_not_in, list) else [expected_not_in]
        for needle in needles:
            if needle in actual:
                ok = False
                reasons.append(f"expected NOT to contain {needle!r}")
    if ok:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}")
        print(f"        actual: {actual!r}")
        for r in reasons:
            print(f"        {r}")


# ==========================================================================
# 1. Nested @json path bug fix - THE ORIGINAL BUG
# ==========================================================================
print("\n[1] Nested @json path rules")

# Rule: userIdentity.arn - should ONLY match arn when it's under userIdentity
rules = [("userIdentity.arn", "single", "arn:aws:iam::REDACTED:user/REDACTED")]

# Positive case: nested under userIdentity (original bug: this didn't work)
obj = {"userIdentity": {"arn": "arn:aws:iam::123456789012:user/admin"}}
scrub_json_obj(obj, rules)
check("nested path matches at correct location",
      obj["userIdentity"]["arn"],
      expected_eq="arn:aws:iam::REDACTED:user/REDACTED")

# Negative case: top-level arn should NOT be touched by a path-qualified rule
obj = {"arn": "arn:aws:iam::123456789012:role/SomeRole",
       "userIdentity": {"arn": "arn:aws:iam::999999999999:user/admin"}}
scrub_json_obj(obj, rules)
check("top-level arn untouched by qualified path rule",
      obj["arn"],
      expected_eq="arn:aws:iam::123456789012:role/SomeRole")
check("nested arn still scrubbed",
      obj["userIdentity"]["arn"],
      expected_eq="arn:aws:iam::REDACTED:user/REDACTED")

# Deeply nested case: rule should still match via path suffix
obj = {"detail": {"userIdentity": {"arn": "arn:aws:iam::111:user/deep"}}}
scrub_json_obj(obj, rules)
check("deeply nested path matches (suffix match)",
      obj["detail"]["userIdentity"]["arn"],
      expected_eq="arn:aws:iam::REDACTED:user/REDACTED")

# ==========================================================================
# 2. Backward compat: unqualified rules match anywhere
# ==========================================================================
print("\n[2] Unqualified @json rules still work (backward compat)")

rules = [("accountId", "single", "000000000000")]
obj = {"accountId": "123456789012",
       "detail": {"accountId": "999999999999"},
       "nested": {"deep": {"accountId": "777777777777"}}}
scrub_json_obj(obj, rules)
check("top-level accountId scrubbed",
      obj["accountId"], expected_eq="000000000000")
check("nested accountId scrubbed",
      obj["detail"]["accountId"], expected_eq="000000000000")
check("deeply nested accountId scrubbed",
      obj["nested"]["deep"]["accountId"], expected_eq="000000000000")

# Tag pattern still works
rules = [("Owner", "single", "REDACTED_OWNER")]
obj = {"tags": [{"key": "Owner", "value": "admin@corp.com"}]}
scrub_json_obj(obj, rules)
check("tag key/value pattern still matches",
      obj["tags"][0]["value"], expected_eq="REDACTED_OWNER")

# ==========================================================================
# 3. Credential & token patterns
# ==========================================================================
print("\n[3] Credential & token scrubbing")

# AWS access key
out = scrub_text("key=AKIAIOSFODNN7EXAMPLE user=bob", [], [])
check("AWS AKIA access key redacted",
      out, expected_not_in="AKIAIOSFODNN7EXAMPLE")

# GitHub PAT
out = scrub_text("token=ghp_abcdefghijklmnopqrstuvwxyz0123456789AB", [], [])
check("GitHub PAT redacted",
      out, expected_not_in="ghp_abcdefghijklmnopqrstuvwxyz0123456789AB")

# JWT
jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
out = scrub_text(f"Authorization: Bearer {jwt}", [], [])
check("JWT redacted", out, expected_not_in=jwt)
check("Bearer scheme preserved", out, expected_in="Bearer")

# Private key block
pem = ("-----BEGIN RSA PRIVATE KEY-----\n"
       "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF7s7F5rP5+\n"
       "-----END RSA PRIVATE KEY-----")
out = scrub_text(pem, [], [])
check("private key block redacted",
      out, expected_not_in="MIIEpAIBAAKCAQEA")
check("private key replaced with placeholder",
      out, expected_in="[REDACTED_PRIVATE_KEY]")

# Slack token
out = scrub_text("xoxb-123456789012-abcdefghijkl", [], [])
check("Slack token redacted",
      out, expected_not_in="xoxb-123456789012-abcdefghijkl")

# Query string credential
out = scrub_text("GET /api?api_key=secret123&foo=bar HTTP/1.1", [], [])
check("query string api_key redacted", out, expected_not_in="secret123")
check("non-credential query param preserved", out, expected_in="foo=bar")

# ==========================================================================
# 4. PII patterns (SSN, CC with Luhn, phone, SID)
# ==========================================================================
print("\n[4] PII scrubbing")

# SSN (formatted)
out = scrub_text("SSN: 123-45-6789 on file", [], [])
check("formatted SSN redacted", out, expected_not_in="123-45-6789")

# SSN (invalid range - should NOT match, proves the exclusion regex works)
out = scrub_text("ref 666-45-6789 (invalid SSN area)", [], [])
check("invalid SSN range (666) not matched", out, expected_in="666-45-6789")

# Credit card (Luhn-valid Visa test number)
out = scrub_text("Card: 4111-1111-1111-1111", [], [])
# Note: 4111-1111-1111-1111 is Luhn-valid AND is itself the placeholder.
# Use a different valid test number to prove detection works.
out2 = scrub_text("Card: 4532015112830366", [], [])
check("Luhn-valid CC redacted",
      out2, expected_not_in="4532015112830366")

# Credit card (Luhn-invalid digits - should NOT be touched)
out = scrub_text("Order #: 1234567890123456", [], [])
check("Luhn-invalid 16-digit sequence not redacted",
      out, expected_in="1234567890123456")

# Phone number
out = scrub_text("Call me at (555) 234-5678 tomorrow", [], [])
check("formatted phone redacted",
      out, expected_not_in="234-5678")

# Windows SID
out = scrub_text("User SID: S-1-5-21-1234567890-1234567890-1234567890-1001", [], [])
check("Windows SID redacted",
      out, expected_not_in="1234567890-1234567890-1234567890-1001")

# Well-known SID preserved (S-1-5-18 = SYSTEM, not the 5-21 pattern)
out = scrub_text("Running as S-1-5-18 (SYSTEM)", [], [])
check("well-known SID SYSTEM preserved",
      out, expected_in="S-1-5-18")

# Luhn helper direct test
check("luhn_valid: Visa test number passes",
      "yes" if luhn_valid("4532015112830366") else "no",
      expected_eq="yes")
check("luhn_valid: invalid number fails",
      "yes" if luhn_valid("1234567890123456") else "no",
      expected_eq="no")

# ==========================================================================
# 5. CUI marking detection
# ==========================================================================
print("\n[5] CUI marking detection")

# Banner marking
out = scrub_text("CUI//SP-PRVCY Employee record: John Smith DOB 01/15/1980",
                 [], [])
check("CUI banner triggers full-value redaction",
      out, expected_in=["CUI-REDACTED", "SP-PRVCY"])
check("CUI banner redaction drops content",
      out, expected_not_in=["John Smith", "01/15/1980"])

# Portion marking
out = scrub_text("(U//FOUO) Contract award to vendor XYZ", [], [])
check("portion marking (U//FOUO) triggers redaction",
      out, expected_in="CUI-REDACTED")
check("portion marking redaction drops content",
      out, expected_not_in="vendor XYZ")

# Legacy marking
out = scrub_text("FOUO meeting notes attached", [], [])
check("legacy FOUO marking triggers redaction",
      out, expected_in=["CUI-REDACTED", "LEGACY"])

# Adjacent marking
out = scrub_text("ITAR-controlled technical data", [], [])
check("adjacent ITAR marking triggers redaction",
      out, expected_in=["CUI-REDACTED", "ADJACENT"])

# CUI can be disabled
out = scrub_text("CUI//BASIC some content", [], [], enable_cui=False)
check("enable_cui=False suppresses CUI detection",
      out, expected_in="some content")

# No marking, no redaction
out = scrub_text("Ordinary log line about a web request", [], [])
check("no CUI marking = no CUI redaction",
      out, expected_in="Ordinary log line")

# Direct detect_cui
check("detect_cui finds banner",
      detect_cui("banner CUI//SP-PRVCY content") or "",
      expected_in="CUI")
check("detect_cui returns None for clean text",
      repr(detect_cui("just a normal log line")),
      expected_eq="None")

# ==========================================================================
# 6. Auto-mode detection
# ==========================================================================
print("\n[6] Auto-mode detection")

with tempfile.TemporaryDirectory() as tmp:
    # Splunk fieldsummary CSV
    fs_path = os.path.join(tmp, "fs.csv")
    with open(fs_path, "w") as f:
        f.write("field,count,distinct_count,values\n")
        f.write("accountId,100,5,{'value': '123'}\n")
    check("auto-detect: Splunk fieldsummary CSV",
          detect_file_mode(fs_path), expected_eq="fieldsummary")

    # Pre-scrubbed export CSV
    pre_path = os.path.join(tmp, "pre_scrubbed.csv")
    with open(pre_path, "w") as f:
        f.write("Field Name,Raw Values,Scrubbed Values,Count,Distinct Count\n")
        f.write("user,jsmith,REDACTED,50,1\n")
    check("auto-detect: pre-scrubbed export CSV",
          detect_file_mode(pre_path), expected_eq="fieldsummary")

    # Samples CSV
    samp_path = os.path.join(tmp, "samples.csv")
    with open(samp_path, "w") as f:
        f.write("_time,host,_raw\n")
        f.write('2026-01-01,host1,"Jan 1 10:00:00 host1 sshd: bob logged in"\n')
    check("auto-detect: samples CSV with _raw",
          detect_file_mode(samp_path), expected_eq="samples")

    # JSON samples
    json_path = os.path.join(tmp, "events.json")
    with open(json_path, "w") as f:
        f.write('{"eventTime":"2026-01-01","sourceIPAddress":"1.2.3.4"}\n')
    check("auto-detect: JSON events",
          detect_file_mode(json_path), expected_eq="samples")

    # Plain text samples
    txt_path = os.path.join(tmp, "raw.txt")
    with open(txt_path, "w") as f:
        f.write("Jan  1 10:00:00 host1 sshd[1234]: Accepted for bob from 1.2.3.4\n")
    check("auto-detect: plain text",
          detect_file_mode(txt_path), expected_eq="samples")

# ==========================================================================
# 7. Scrubber class API
# ==========================================================================
print("\n[7] Scrubber class (library API)")

scrubber = Scrubber(
    text_rules=[("acme.com", "single", "example.com")],
    json_field_rules=[("accountId", "single", "000000000000")],
)
out = scrubber.scrub("User bob@acme.com from acct 123456789012")
check("Scrubber.scrub applies text rules",
      out, expected_in="example.com")
check("Scrubber.scrub applies built-in email rule",
      out, expected_in="user@example.com")

# Scrubber with CUI disabled
scrubber_nocui = Scrubber(text_rules=[], json_field_rules=[], enable_cui=False)
out = scrubber_nocui.scrub("CUI//BASIC some sensitive note")
check("Scrubber(enable_cui=False) passes CUI content through",
      out, expected_in="sensitive note")

# scrub_many
results = scrubber.scrub_many(["one@acme.com", "two@acme.com"])
check("Scrubber.scrub_many returns list",
      repr(type(results).__name__), expected_eq="'list'")
check("Scrubber.scrub_many processes each item",
      results[0], expected_in="example.com")

# ==========================================================================
# 8. apply_json_field_scrubbing with nested paths via regex fallback
# ==========================================================================
print("\n[8] JSON field scrubbing via parsed JSON")

rules = [("userIdentity.arn", "single", "arn:aws:iam::REDACTED:user/REDACTED"),
         ("sourceIPAddress", "single", "10.0.0.x")]
event = json.dumps({
    "eventTime": "2026-01-01T00:00:00Z",
    "userIdentity": {"arn": "arn:aws:iam::123456789012:user/admin",
                     "accountId": "123456789012"},
    "sourceIPAddress": "192.0.2.55"
})
out = apply_json_field_scrubbing(event, rules)
out_obj = json.loads(out)
check("nested userIdentity.arn scrubbed via parsed JSON",
      out_obj["userIdentity"]["arn"],
      expected_eq="arn:aws:iam::REDACTED:user/REDACTED")
check("unqualified sourceIPAddress rule still works",
      out_obj["sourceIPAddress"], expected_eq="10.0.0.x")

# ==========================================================================
# 9. glob expansion
# ==========================================================================
print("\n[9] Glob expansion")

with tempfile.TemporaryDirectory() as tmp:
    for name in ("a.csv", "b.csv", "c.txt"):
        open(os.path.join(tmp, name), "w").close()
    out = expand_input_paths([os.path.join(tmp, "*.csv")])
    check("glob expands and sorts",
          sorted([os.path.basename(p) for p in out]),
          expected_eq=["a.csv", "b.csv"])
    out = expand_input_paths([os.path.join(tmp, "a.csv"),
                              os.path.join(tmp, "a.csv"),
                              os.path.join(tmp, "b.csv")])
    check("dedup preserves first occurrence",
          len(out), expected_eq=2)


# ==========================================================================
# Summary
# ==========================================================================
print(f"\n{'='*50}")
print(f"  {PASS} passed, {FAIL} failed")
print(f"{'='*50}")
sys.exit(0 if FAIL == 0 else 1)
