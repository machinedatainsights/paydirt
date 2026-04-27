#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Machine Data Insights Inc.
# https://machinedatainsights.com
"""
Log Scrubber - Standalone CLI Utility + Importable Module
Machine Data Insights Inc. | machinedatainsights.com

Scrubs CUI, PII, PHI, credentials, and other sensitive data from Splunk
field-value exports and log samples. Can be run as a CLI tool or imported
as a library.

Compliance coverage: CMMC (CUI markings + NIST SP 800-171), HIPAA (PHI
identifiers), GDPR (personal data including IPs and device identifiers).

Usage (CLI):
    # Auto-detect mode from file contents (easiest)
    python log_scrubber.py my_fields.csv

    # Batch multiple files / glob
    python log_scrubber.py ~/Downloads/*.csv

    # Explicit mode (backward compatible)
    python log_scrubber.py fieldsummary splunk_web_access_fields.csv
    python log_scrubber.py samples splunk_web_access_samples.csv

    # Specify a custom scrubbing config
    python log_scrubber.py fields.csv --config my_scrubbing_config.csv

    # Specify output path
    python log_scrubber.py events.csv --output scrubbed_events.csv

    # Disable specific scrubbing layers
    python log_scrubber.py events.csv --no-cui      # skip CUI marking redaction
    python log_scrubber.py events.csv --no-builtin  # skip all built-in regex

Usage (as a library):
    from log_scrubber import Scrubber

    scrubber = Scrubber(config_path='log_scrubbing_config.csv')
    clean_text = scrubber.scrub(raw_log_line)

    # Or the functional API (backward compatible):
    from log_scrubber import parse_scrubbing_config, scrub_text
    text_rules, json_rules = parse_scrubbing_config('config.csv')
    clean = scrub_text(raw, text_rules, json_rules)

Splunk SPL for exporting field values (run in Splunk Web → export as CSV):
    index=<idx> sourcetype="<st>" earliest=-7d@d latest=now
    | fieldsummary maxvals=5
    | search field!="_*" AND field!="date_*" AND field!="linecount"
      AND field!="punct" AND field!="timestartpos" AND field!="timeendpos"
      AND field!="splunk_server_group"

Splunk SPL for exporting log samples (run in Splunk Web → export as CSV):
    index=<idx> sourcetype="<st>" earliest=-1d@d latest=now
    | dedup punct | head 20

Version: 1.2.0
Copyright (c) 2026 Machine Data Insights Inc.
https://machinedatainsights.com
"""

import argparse
import csv
import glob
import json
import os
import random
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

__version__ = "1.2.0"


# ============================================================================
# CUI Marking Detection (CMMC / NIST SP 800-171)
# ============================================================================
#
# CUI is identified by banner markings and portion markings, not by content
# patterns. When a line contains a CUI marking, the entire payload is treated
# as sensitive - we replace it with a placeholder that preserves shape/size
# metadata for downstream LLM consumers while leaking no content.
#
# References:
# - 32 CFR Part 2002 (CUI program)
# - NIST SP 800-171 (protection of CUI in nonfederal systems)
# - DoD CUI Registry categories (SP-PRVCY, SP-PROPIN, SP-EXPT, SP-CTI, etc.)

# Banner markings: "CUI", "CUI//SP-PRVCY", "CONTROLLED//SP-PROPIN", etc.
# Intentionally bounded - must appear as a standalone token, not a substring.
CUI_BANNER_RE = re.compile(
    r"\b(CUI|CONTROLLED)(?://(SP-[A-Z]+|BASIC|NOFORN|FEDCON|FED ONLY|DL ONLY|"
    r"REL TO [A-Z, ]+))*\b"
)

# Portion markings inside text: "(CUI)", "(U//FOUO)", "(CUI//SP-PRVCY)", etc.
CUI_PORTION_RE = re.compile(
    r"\((CUI|U//FOUO|U//SBU|U//LES|C|U|FOUO|SBU|LES)(?://[A-Z-]+)?\)"
)

# Legacy markings still widely found in pre-2010 documents and tickets.
# These predate the CUI program but are treated as CUI-equivalent for
# scrubbing purposes.
CUI_LEGACY_RE = re.compile(
    r"\b(FOUO|SBU|LES|OUO|LIMDIS|NOFORN|FEDCON|ORCON)\b"
)

# Export-control and contract markings that are CUI-adjacent. Matching these
# is conservative - they often appear in filenames and document titles that
# show up in log entries (downloaded filename, email subject, ticket title).
CUI_ADJACENT_RE = re.compile(
    r"\b(ITAR|EAR99|ECCN\s*[0-9A-Z]+|DD\s*254|FCI)\b"
)


def detect_cui(text: str) -> Optional[str]:
    """
    Scan text for CUI markings. Returns the CUI category string if found,
    else None.

    Detection order: banner > portion > legacy > adjacent. The first match
    wins because banners are the most authoritative.
    """
    if not text:
        return None

    m = CUI_BANNER_RE.search(text)
    if m:
        return m.group(0)

    m = CUI_PORTION_RE.search(text)
    if m:
        return m.group(0).strip("()")

    m = CUI_LEGACY_RE.search(text)
    if m:
        return f"LEGACY:{m.group(0)}"

    m = CUI_ADJACENT_RE.search(text)
    if m:
        return f"ADJACENT:{m.group(0)}"

    return None


def redact_cui(text: str, category: str) -> str:
    """
    Replace CUI-tainted content with a metadata-only placeholder.
    Preserves byte count so downstream consumers (LLMs, dashboards) know
    roughly how much content was redacted.

    Leading and trailing whitespace (including newlines) are preserved so
    that line-oriented processors - samples mode in particular - don't lose
    line boundaries when an entire log line is CUI-redacted. Byte count
    reported reflects the stripped content only.
    """
    leading_ws = text[:len(text) - len(text.lstrip())]
    trailing_ws = text[len(text.rstrip()):]
    core = text.strip()
    return f"{leading_ws}[CUI-REDACTED: {category}, {len(core)} bytes]{trailing_ws}"


# ============================================================================
# Credential & Token Detection
# ============================================================================
#
# These patterns target high-entropy secrets that frequently leak into logs:
# cloud provider keys, OAuth/JWT tokens, vendor API keys, and HTTP auth
# headers. Each pattern has a known prefix or structure to minimize false
# positives. Run these BEFORE the generic IP/email/FQDN patterns so we don't
# chop a token in half.

CREDENTIAL_PATTERNS = [
    # Private key blocks - match the whole PEM block, newlines included.
    (re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
        r"[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
    ), "[REDACTED_PRIVATE_KEY]"),

    # AWS access key IDs (20 chars, AKIA prefix for long-term, ASIA for STS).
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "AKIAREDACTEDREDACTED"),

    # GitHub personal access tokens (classic ghp_, OAuth gho_, etc.)
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "ghp_REDACTED"),

    # Slack tokens (bot, user, workspace, app, refresh, legacy).
    (re.compile(r"\bxox[baprs]-[0-9a-zA-Z-]{10,}\b"), "xoxb-REDACTED"),

    # Stripe secret keys (live and test).
    (re.compile(r"\bsk_(?:live|test)_[0-9a-zA-Z]{24,}\b"), "sk_test_REDACTED"),

    # JSON Web Tokens - three base64url segments, 'eyJ' is the only stable anchor.
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
     "eyJREDACTED.REDACTED.REDACTED"),

    # Google API keys (AIza prefix, 35 char alphanumeric).
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "AIzaREDACTED"),

    # HTTP Authorization header values - redact the credential, keep the scheme.
    (re.compile(r"(Authorization\s*:\s*(?:Bearer|Basic|Digest|Token))\s+\S+",
                re.IGNORECASE),
     r"\1 REDACTED"),

    # URL query-string credentials: ?password=..., &api_key=..., etc.
    (re.compile(
        r"([?&](?:password|passwd|pwd|token|api_key|apikey|access_token|"
        r"refresh_token|auth|authorization|secret|session|sessionid|sid)"
        r"=)[^&\s\"']+",
        re.IGNORECASE),
     r"\1REDACTED"),
]


# ============================================================================
# Additional PII Detection (SSN, Credit Card with Luhn, Phone, Windows SID)
# ============================================================================

# SSN requires formatting (XXX-XX-XXXX) - unformatted 9-digit numbers have
# catastrophic false-positive rates. We also exclude known-invalid SSN ranges
# per SSA rules (000, 666, 900-999 area; 00 group; 0000 serial).
SSN_RE = re.compile(
    r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
)

# Candidate credit-card patterns - 13 to 19 digits, optional separators
# between digits (but never trailing). Results are Luhn-validated before
# redaction.
CC_CANDIDATE_RE = re.compile(
    r"\b\d(?:[ -]?\d){12,18}\b"
)

# Phone numbers - require at least one separator or parens to reduce FP.
# Matches (555) 123-4567, 555-123-4567, 555.123.4567, +1 555 123 4567.
# The opening paren is handled via lookbehind so it's consumed by the match
# cleanly when present (avoids leaving an orphan '(' behind on replacement).
PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?!\d)"
)

# Windows Security Identifier (SID) - distinctive S-1-5-21- prefix for
# domain/local user SIDs. We don't scrub well-known SIDs (S-1-5-18 = SYSTEM,
# S-1-5-19 = LocalService, S-1-5-20 = NetworkService).
SID_RE = re.compile(r"\bS-1-5-21-\d+-\d+-\d+-\d+\b")

# National Provider Identifier (NPI) - 10 digits, Luhn-like check using the
# Rabin-Karp variant defined in 45 CFR 162.406. Use a candidate matcher plus
# validator to keep false positives low.
NPI_CANDIDATE_RE = re.compile(r"\b\d{10}\b")


def luhn_valid(num_str: str) -> bool:
    """Validate a digit string using the Luhn algorithm (ISO/IEC 7812-1)."""
    digits = [int(c) for c in num_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def npi_valid(num_str: str) -> bool:
    """
    Validate a 10-digit NPI using the Luhn variant from 45 CFR 162.406.
    The NPI prefix '80840' is prepended before running Luhn.
    """
    if len(num_str) != 10 or not num_str.isdigit():
        return False
    return luhn_valid("80840" + num_str)


def _redact_ccs(text: str) -> str:
    """Find candidate credit-card numbers and redact only the Luhn-valid ones."""
    def _replace(m):
        candidate = m.group(0)
        digits = "".join(c for c in candidate if c.isdigit())
        if luhn_valid(digits):
            return "4111-1111-1111-1111"  # the canonical test-card placeholder
        return candidate
    return CC_CANDIDATE_RE.sub(_replace, text)


def _redact_npis(text: str) -> str:
    """Find candidate 10-digit numbers and redact only valid NPIs."""
    def _replace(m):
        candidate = m.group(0)
        if npi_valid(candidate):
            return "1234567893"  # canonical NPI test value
        return candidate
    return NPI_CANDIDATE_RE.sub(_replace, text)


# ============================================================================
# Config Parser
# ============================================================================

def parse_scrubbing_config(config_path: str) -> Tuple[list, list]:
    """
    Parse scrubbing config CSV into text rules and JSON field rules.

    Returns:
        (text_rules, json_field_rules)
        text_rules:       [(search_term, mode, replacement_values), ...]
        json_field_rules: [(field_name, mode, replacement_values), ...]

    Config formats:
        # Text substitution
        search_term,single,replacement
        search_term,random,"val1,val2,val3"

        # JSON field scrubbing
        @json,field_name,replacement                    (implicit single)
        @json,field_name,single,replacement
        @json,field_name,random,"val1,val2,val3"
    """
    text_rules = []
    json_field_rules = []

    if not config_path or not os.path.exists(config_path):
        return text_rules, json_field_rules

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or not row[0].strip() or row[0].strip().startswith("#"):
                    continue
                if len(row) < 3:
                    continue

                first = row[0].strip()

                if first.lower() == "@json":
                    field_name = row[1].strip()
                    if not field_name:
                        continue
                    if len(row) >= 4 and row[2].strip().lower() in ("single", "random"):
                        mode = row[2].strip().lower()
                        replacement_values = row[3].strip()
                        json_field_rules.append((field_name, mode, replacement_values))
                    else:
                        replacement = row[2].strip()
                        json_field_rules.append((field_name, "single", replacement))
                else:
                    # Text rule: 2-col (search,replacement) or 3-col (search,mode,replacement)
                    if len(row) == 2:
                        text_rules.append((first, "single", row[1].strip()))
                    else:
                        mode = row[1].strip().lower()
                        if mode not in ("single", "random"):
                            # Treat as 2-col: search_term,replacement
                            text_rules.append((first, "single", row[1].strip()))
                        else:
                            text_rules.append((first, mode, row[2].strip()))
    except Exception as e:
        print(f"  [!] Warning: Could not parse config '{config_path}': {e}", file=sys.stderr)

    return text_rules, json_field_rules


# ============================================================================
# Replacement Resolver
# ============================================================================

def resolve_replacement(mode: str, replacement_values: str) -> str:
    """Resolve a replacement value based on mode (single or random)."""
    if mode == "random":
        choices = [v.strip() for v in replacement_values.split(",") if v.strip()]
        return random.choice(choices) if choices else replacement_values
    return replacement_values


# ============================================================================
# JSON Scrubbing
# ============================================================================

def _rule_matches_path(rule_field: str, current_path: str, current_key: str) -> bool:
    """
    Match a rule's field specifier against the current position in a JSON tree.

    Unqualified rules (no dots, e.g. 'accountId'): match any field with that
    exact name at any nesting depth - this is the v1.0 behavior and is
    preserved for backward compatibility.

    Qualified rules (contain dots, e.g. 'userIdentity.arn'): match as a path
    suffix anchored at a dotted boundary. So 'userIdentity.arn' matches the
    paths 'userIdentity.arn' and 'detail.userIdentity.arn' but not the path
    'foo.userIdentity.arn.extra'.
    """
    if "." in rule_field:
        return current_path == rule_field or current_path.endswith("." + rule_field)
    return current_key == rule_field


def scrub_json_obj(obj, field_rules: list, current_path: str = ""):
    """
    Recursively walk a parsed JSON object and replace values for matching
    field names at any nesting depth.

    Handles two patterns:
      1. Direct field match:  {"accountId": "123"} - replaces "123"
      2. Key-value pair:      {"key": "Owner", "value": "admin"} - replaces "admin"
         Common in AWS tags, Azure tags, GCP labels, CloudTrail requestParameters.

    Nested paths (v1.1.0+): a rule like 'userIdentity.arn' matches the arn
    field only when it appears under userIdentity (at any depth), not any
    top-level arn.
    """
    if isinstance(obj, dict):
        # Pattern 2: Key-value pair detection
        kv_key_field = None
        kv_val_field = None

        keys_lower_map = {k.lower(): k for k in obj}

        for candidate in ("key", "name"):
            if candidate in keys_lower_map:
                kv_key_field = keys_lower_map[candidate]
                break

        for candidate in ("value",):
            if candidate in keys_lower_map:
                kv_val_field = keys_lower_map[candidate]
                break

        if (kv_key_field is not None and kv_val_field is not None
                and isinstance(obj[kv_key_field], str)):
            tag_name = obj[kv_key_field]
            for rule in field_rules:
                fn = rule[0]
                # Tag matching only applies to unqualified rules - qualified
                # paths don't meaningfully address tag keys.
                if "." in fn:
                    continue
                if tag_name == fn:
                    mode = rule[1] if len(rule) > 2 else "single"
                    repl_vals = rule[2] if len(rule) > 2 else rule[1]
                    obj[kv_val_field] = resolve_replacement(mode, repl_vals)
                    for k in obj:
                        if k != kv_val_field:
                            new_path = f"{current_path}.{k}" if current_path else k
                            obj[k] = scrub_json_obj(obj[k], field_rules, new_path)
                    return obj

        # Pattern 1: Direct field match (supports both unqualified name match
        # and qualified dotted-path match)
        for key in obj:
            new_path = f"{current_path}.{key}" if current_path else key
            matched = False
            for rule in field_rules:
                fn = rule[0]
                if _rule_matches_path(fn, new_path, key):
                    mode = rule[1] if len(rule) > 2 else "single"
                    repl_vals = rule[2] if len(rule) > 2 else rule[1]
                    obj[key] = resolve_replacement(mode, repl_vals)
                    matched = True
                    break
            if not matched:
                obj[key] = scrub_json_obj(obj[key], field_rules, new_path)
        return obj
    elif isinstance(obj, list):
        return [scrub_json_obj(item, field_rules, current_path) for item in obj]
    else:
        return obj


def apply_json_field_scrubbing(text: str, field_rules: list) -> str:
    """
    Apply JSON field scrubbing to a text string.

    Handles:
      1. Entire string is a JSON object/array
      2. JSON embedded after a syslog-style prefix
      3. Key-value pair regex fallback
      4. Direct field regex fallback
    """
    if not field_rules or not text:
        return text

    stripped = text.strip()

    def _try_json_parse_and_scrub(json_str):
        try:
            obj = json.loads(json_str)
            scrub_json_obj(obj, field_rules)
            compact = "\n" not in json_str
            return json.dumps(obj, separators=(",", ":") if compact
                              else (",", ": "), ensure_ascii=False)
        except (json.JSONDecodeError, ValueError):
            pass

        for trim in [",", "},", "}],", "]},", "\n", " "]:
            if json_str.rstrip().endswith(trim.rstrip()):
                candidate = json_str.rstrip()
                while candidate and not candidate.endswith("}") and not candidate.endswith("]"):
                    candidate = candidate[:-1]
                if candidate:
                    try:
                        obj = json.loads(candidate)
                        scrub_json_obj(obj, field_rules)
                        compact = "\n" not in json_str
                        suffix = json_str[len(candidate):]
                        return json.dumps(obj, separators=(",", ":") if compact
                                          else (",", ": "), ensure_ascii=False) + suffix
                    except (json.JSONDecodeError, ValueError):
                        pass
        return None

    # Case 1: Entire string is JSON
    if stripped.startswith("{") or stripped.startswith("["):
        result = _try_json_parse_and_scrub(stripped)
        if result is not None:
            return result

    # Case 2: JSON embedded after prefix
    brace_idx = text.find("{")
    if brace_idx > 0:
        prefix = text[:brace_idx]
        json_part = text[brace_idx:]
        result = _try_json_parse_and_scrub(json_part)
        if result is not None:
            return prefix + result

    # Regex fallback
    rule_map = {}
    for rule in field_rules:
        fn = rule[0]
        mode = rule[1] if len(rule) > 2 else "single"
        repl_vals = rule[2] if len(rule) > 2 else rule[1]
        rule_map[fn] = (mode, repl_vals)

    # Case 3: Key-value pair patterns
    def _kv_replacer_dq(m):
        tag_name = m.group(1)
        if tag_name in rule_map:
            mode, repl_vals = rule_map[tag_name]
            replacement = resolve_replacement(mode, repl_vals)
            return m.group(0).replace(m.group(2), replacement)
        return m.group(0)

    text = re.sub(
        r'"(?:key|Key|name|Name)"\s*:\s*"([^"]*)"\s*,\s*"(?:value|Value)"\s*:\s*"([^"]*)"',
        _kv_replacer_dq, text
    )

    def _kv_replacer_sq(m):
        tag_name = m.group(1)
        if tag_name in rule_map:
            mode, repl_vals = rule_map[tag_name]
            replacement = resolve_replacement(mode, repl_vals)
            return m.group(0).replace(m.group(2), replacement)
        return m.group(0)

    text = re.sub(
        r"'(?:key|Key|name|Name)'\s*:\s*'([^']*)'\s*,\s*'(?:value|Value)'\s*:\s*'([^']*)'",
        _kv_replacer_sq, text
    )

    # Case 4: Direct field patterns
    for fn, (mode, repl_vals) in rule_map.items():
        replacement = resolve_replacement(mode, repl_vals)
        pattern = r'("' + re.escape(fn) + r'")\s*:\s*"[^"]*"'
        repl = r'\1: "' + replacement.replace("\\", "\\\\") + '"'
        text = re.sub(pattern, repl, text)
        pattern_sq = r"('" + re.escape(fn) + r"')\s*:\s*'[^']*'"
        repl_sq = r"\1: '" + replacement.replace("\\", "\\\\") + "'"
        text = re.sub(pattern_sq, repl_sq, text)

    return text


# ============================================================================
# Fieldsummary-aware Value Replacement
# ============================================================================

def scrub_fieldsummary_values(raw_values: str, replacement: str) -> str:
    """
    Replace the 'value' entries in Splunk fieldsummary format while
    preserving structure and counts.

    Input:  {'value': '736350333106', 'count': 446}, {'value': '113968', 'count': 6}
    Output: {'value': 'REDACTED', 'count': 446}, {'value': 'REDACTED', 'count': 6}
    """
    result = raw_values
    result = re.sub(
        r"('value':\s*')([^']*?)(')",
        lambda m: m.group(1) + replacement + m.group(3),
        result,
    )
    result = re.sub(
        r'("value":\s*")([^"]*?)(")',
        lambda m: m.group(1) + replacement + m.group(3),
        result,
    )
    return result


# ============================================================================
# Core Scrubbing Functions
# ============================================================================

# Well-known public hostnames that should NEVER be scrubbed by the FQDN
# regex. These are industry-standard public schema/namespace/documentation
# URLs that routinely appear in XML, JSON, and log data without being PII.
# The FQDN regex excludes these via negative lookahead.
WELL_KNOWN_PUBLIC_HOSTS = (
    r"schemas\.microsoft\.com"
    r"|schemas\.xmlsoap\.org"
    r"|schemas\.openxmlformats\.org"
    r"|www\.w3\.org"
    r"|www\.iana\.org"
    r"|xmlns\.com"
    r"|tools\.ietf\.org"
    r"|docs\.oasis-open\.org"
    r"|purl\.org"
    r"|ns\.adobe\.com"
)


def scrub_text(text: str, text_rules: list, json_field_rules: list,
               field_name: str = None,
               enable_builtins: bool = True,
               enable_cui: bool = True) -> str:
    """
    Scrub a single text value using the full scrubbing pipeline.

    Order of operations (each step is skippable via flag):

      1. @json field-name shortcut - for fieldsummary rows whose field name
         directly matches an unqualified @json rule, rewrite just the 'value'
         entries and return early.
      2. CUI detection (enable_cui) - if a CUI banner/portion/legacy marking
         is present, replace the entire value with a metadata-only placeholder
         and return early. This is intentionally aggressive: per NIST SP
         800-171, CUI content must be protected at rest and in transit.
      3. Credential & token patterns (enable_builtins) - AWS keys, GitHub
         PATs, Slack tokens, JWTs, PEM private keys, HTTP Authorization
         headers, URL query-string credentials.
      4. Original built-in patterns (enable_builtins) - IP, AWS ip- host,
         email, FQDN, UNC path, DOMAIN\\user, MAC.
      5. Additional PII (enable_builtins) - SSN, Luhn-validated credit
         cards, phone numbers, Windows SIDs, validated NPIs.
      6. Custom text substitution rules from config.
      7. JSON field-level scrubbing (parsed JSON or regex fallback).

    The backward-compatible default (all flags True) preserves v1.0 behavior
    plus adds the v1.1 layers. Callers that want strict v1.0-only behavior
    can pass enable_cui=False.
    """
    if not text or not text.strip():
        return text

    scrubbed = text

    # Step 1: @json field-name shortcut (fieldsummary data).
    # Only unqualified rules can match - dotted paths don't address a bare
    # Splunk field name.
    json_field_map = {fn: (mode, repl) for fn, mode, repl
                      in json_field_rules if "." not in fn}
    if field_name and field_name in json_field_map:
        mode, repl_vals = json_field_map[field_name]
        replacement = resolve_replacement(mode, repl_vals)
        return scrub_fieldsummary_values(scrubbed, replacement)

    # Step 2: CUI marking detection. If present, redact the whole value.
    if enable_cui:
        category = detect_cui(scrubbed)
        if category is not None:
            return redact_cui(scrubbed, category)

    if enable_builtins:
        # Step 3: Credentials & tokens (BEFORE generic patterns so tokens
        # containing IP-shaped or email-shaped substrings stay intact).
        for pattern, replacement in CREDENTIAL_PATTERNS:
            scrubbed = pattern.sub(replacement, scrubbed)

        # Step 4: Original built-in regex patterns (v1.0.0).
        scrubbed = re.sub(
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "10.0.0.x", scrubbed
        )
        scrubbed = re.sub(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "user@example.com", scrubbed,
        )
        # AWS-style ip- hostnames (e.g., ip-10-50-26-117.us-gov-west-1.compute.internal)
        scrubbed = re.sub(
            r"\bip-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\b",
            "ip-10-0-0-x", scrubbed,
        )
        scrubbed = re.sub(
            r"\b(?!(?:" + WELL_KNOWN_PUBLIC_HOSTS + r")\b)"
            r"[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.(com|net|org|io|local|internal)\b",
            "host.example.com", scrubbed,
        )
        scrubbed = re.sub(
            r"\\\\[a-zA-Z0-9._-]+\\[a-zA-Z0-9._$-]+",
            r"\\\\SERVER\\SHARE", scrubbed,
        )
        scrubbed = re.sub(
            r"\b[A-Z][A-Z0-9_-]+\\[a-zA-Z0-9._-]+\b",
            r"DOMAIN\\user", scrubbed,
        )
        scrubbed = re.sub(
            r"\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
            "00:00:00:00:00:00", scrubbed,
        )

        # Step 5: Additional PII (v1.1.0).
        scrubbed = SSN_RE.sub("000-00-0000", scrubbed)
        scrubbed = _redact_ccs(scrubbed)
        scrubbed = PHONE_RE.sub("555-555-5555", scrubbed)
        scrubbed = SID_RE.sub("S-1-5-21-0-0-0-0", scrubbed)
        scrubbed = _redact_npis(scrubbed)

    # Step 6: Custom text substitution rules.
    for search_term, mode, replacement_values in text_rules:
        if search_term in scrubbed:
            if mode == "random":
                choices = [v.strip() for v in replacement_values.split(",") if v.strip()]
                replacement = random.choice(choices) if choices else replacement_values
            else:
                replacement = replacement_values
            scrubbed = scrubbed.replace(search_term, replacement)

    # Step 7: JSON field scrubbing (parsed JSON walk + regex fallback).
    if json_field_rules:
        scrubbed = apply_json_field_scrubbing(scrubbed, json_field_rules)

    return scrubbed


# ============================================================================
# Scrubber Class (Library API)
# ============================================================================

class Scrubber:
    """
    High-level facade over the scrubbing pipeline. Bundles loaded rules with
    toggle flags so consuming applications can hold a single object and call
    .scrub(text) repeatedly without re-parsing the config.

    Typical usage when embedding this module into another application
    (e.g. pre-prompt sanitization for an LLM, request-handler middleware,
    batch ETL jobs):

        scrubber = Scrubber(config_path='log_scrubbing_config.csv')
        safe_text = scrubber.scrub(raw_user_input)

    Rules and flags can also be supplied directly for programmatic use:

        scrubber = Scrubber(
            text_rules=[('acme.com', 'single', 'example.com')],
            json_field_rules=[('accountId', 'single', '000000000000')],
            enable_cui=True,
        )

    The class holds no mutable per-call state, so a single Scrubber instance
    is safe to share across threads as long as the rule lists are not
    mutated after construction.
    """

    def __init__(self,
                 config_path: Optional[str] = None,
                 text_rules: Optional[list] = None,
                 json_field_rules: Optional[list] = None,
                 enable_builtins: bool = True,
                 enable_cui: bool = True):
        if config_path:
            file_text, file_json = parse_scrubbing_config(config_path)
            self.text_rules = list(file_text) + list(text_rules or [])
            self.json_field_rules = list(file_json) + list(json_field_rules or [])
        else:
            self.text_rules = list(text_rules or [])
            self.json_field_rules = list(json_field_rules or [])
        self.enable_builtins = enable_builtins
        self.enable_cui = enable_cui

    def scrub(self, text: str, field_name: Optional[str] = None) -> str:
        """Scrub a single string using the bundled rules and flags."""
        return scrub_text(text, self.text_rules, self.json_field_rules,
                          field_name=field_name,
                          enable_builtins=self.enable_builtins,
                          enable_cui=self.enable_cui)

    def scrub_many(self, texts, field_name: Optional[str] = None) -> list:
        """Scrub an iterable of strings. Convenience for batch pipelines."""
        return [self.scrub(t, field_name=field_name) for t in texts]


# ============================================================================
# File Processors
# ============================================================================


def scrub_fieldsummary_csv(input_path: str, output_path: str,
                           text_rules: list, json_field_rules: list,
                           include_raw: bool = False) -> dict:
    """
    Scrub a Splunk fieldsummary CSV export.

    Supports two input formats:
      1. Splunk fieldsummary: columns include "field" and "values"
      2. Pre-scrubbed export:  columns include "Field Name", "Raw Values", "Scrubbed Values"

    By default, outputs only the scrubbed values (no raw column).
    Use include_raw=True to keep the original raw values column.
    """
    stats = {"rows": 0, "scrubbed": 0, "skipped": 0}

    # Increase CSV field size limit for large JSON events
    csv.field_size_limit(10 * 1024 * 1024)

    with open(input_path, "r", encoding="utf-8", errors="replace") as fin:
        reader = csv.DictReader(fin)
        if not reader.fieldnames:
            print(f"  [!] Empty or invalid CSV: {input_path}", file=sys.stderr)
            return stats

        # Determine the values column name
        # Supports Splunk fieldsummary format ("values") and pre-scrubbed export format ("Raw Values")
        values_col = None
        for candidate in ("values", "Values", "VALUES", "Raw Values", "raw_values"):
            if candidate in reader.fieldnames:
                values_col = candidate
                break

        # Determine the field name column
        field_col = None
        for candidate in ("field", "Field", "FIELD", "field_name", "Field Name", "Field_Name"):
            if candidate in reader.fieldnames:
                field_col = candidate
                break

        # Determine if there's an existing scrubbed column (pre-scrubbed export format)
        existing_scrubbed_col = None
        for candidate in ("Scrubbed Values", "scrubbed_values", "Scrubbed_Values"):
            if candidate in reader.fieldnames:
                existing_scrubbed_col = candidate
                break

        # Build output fieldnames
        out_fields = list(reader.fieldnames)
        if existing_scrubbed_col:
            scrubbed_output_col = existing_scrubbed_col
        elif values_col and "scrubbed_values" not in out_fields:
            idx = out_fields.index(values_col) + 1
            out_fields.insert(idx, "scrubbed_values")
            scrubbed_output_col = "scrubbed_values"
        else:
            scrubbed_output_col = "scrubbed_values"

        # Remove raw values column from output unless --include-raw
        if not include_raw and values_col and values_col in out_fields:
            out_fields.remove(values_col)

        # Rename scrubbed column to clean name for output
        # (e.g., "scrubbed_values" → "Scrubbed Values" for readability)
        col_rename = {}
        if scrubbed_output_col == "scrubbed_values" and "scrubbed_values" in out_fields:
            idx = out_fields.index("scrubbed_values")
            out_fields[idx] = "Scrubbed Values"
            col_rename["scrubbed_values"] = "Scrubbed Values"
            scrubbed_output_col_out = "Scrubbed Values"
        else:
            scrubbed_output_col_out = scrubbed_output_col

        # Normalize field name column header for clean output
        field_col_out = field_col
        if field_col and field_col in ("field", "Field", "FIELD") and field_col in out_fields:
            idx = out_fields.index(field_col)
            out_fields[idx] = "Field Name"
            col_rename[field_col] = "Field Name"
            field_col_out = "Field Name"

        with open(output_path, "w", encoding="utf-8", newline="") as fout:
            writer = csv.DictWriter(fout, fieldnames=out_fields, extrasaction="ignore")
            writer.writeheader()

            for row in reader:
                stats["rows"] += 1
                raw_values = row.get(values_col, "") if values_col else ""
                field_name = row.get(field_col, "") if field_col else None

                if raw_values.strip():
                    scrubbed = scrub_text(raw_values, text_rules, json_field_rules,
                                          field_name=field_name)
                    row[scrubbed_output_col] = scrubbed
                    stats["scrubbed"] += 1
                else:
                    if not existing_scrubbed_col:
                        row[scrubbed_output_col] = ""
                    stats["skipped"] += 1

                # Apply column renames for output
                out_row = {}
                for col in out_fields:
                    # Find source column (check rename map)
                    src_col = next((k for k, v in col_rename.items() if v == col), col)
                    out_row[col] = row.get(src_col, row.get(col, ""))
                writer.writerow(out_row)

    return stats


def scrub_samples_csv(input_path: str, output_path: str,
                      text_rules: list, json_field_rules: list) -> dict:
    """
    Scrub a log samples CSV export from Splunk.

    Handles two formats:
      1. CSV with _raw column (from Splunk CSV export)
      2. Plain text file (one event per line or multi-line JSON)
    """
    stats = {"events": 0, "scrubbed": 0}

    csv.field_size_limit(10 * 1024 * 1024)

    # Detect format: try CSV first
    is_csv = False
    try:
        with open(input_path, "r", encoding="utf-8", errors="replace") as f:
            sample = f.read(4096)
            sniffer = csv.Sniffer()
            try:
                sniffer.sniff(sample)
                # Check if it has a _raw header
                f.seek(0)
                reader = csv.DictReader(f)
                if reader.fieldnames and "_raw" in reader.fieldnames:
                    is_csv = True
            except csv.Error:
                pass
    except Exception:
        pass

    if is_csv:
        return _scrub_samples_csv_format(input_path, output_path,
                                          text_rules, json_field_rules)
    else:
        return _scrub_samples_text_format(input_path, output_path,
                                           text_rules, json_field_rules)


def _scrub_samples_csv_format(input_path: str, output_path: str,
                               text_rules: list, json_field_rules: list) -> dict:
    """
    Scrub CSV-format log samples.

    Splunk CSV exports routinely contain the same sensitive data in many
    columns: _raw carries the full event, but columns like host, Computer,
    dvc, SubjectUserSid, and dozens of extracted fields each carry pieces
    of the same data. Scrubbing only _raw would leave all the other columns
    exposed, producing output that looks scrubbed but isn't.

    This function scrubs EVERY cell of EVERY row through the full scrubbing
    pipeline. The column header row is preserved verbatim (headers are not
    data). Each cell is passed to scrub_text with the column name as
    field_name, so @json-field-name shortcuts still apply when a column
    matches a rule's field.

    stats:
      events:   total number of data rows processed
      cells:    total number of cells that had content and were scrubbed
      scrubbed: same as events, retained for API compatibility with the
                previous version of this function
    """
    stats = {"events": 0, "cells": 0, "scrubbed": 0}

    with open(input_path, "r", encoding="utf-8", errors="replace") as fin:
        reader = csv.DictReader(fin)
        fieldnames = list(reader.fieldnames) if reader.fieldnames else []

        with open(output_path, "w", encoding="utf-8", newline="") as fout:
            writer = csv.DictWriter(fout, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()

            for row in reader:
                stats["events"] += 1
                # Scrub every non-empty cell in this row
                for col in fieldnames:
                    value = row.get(col, "")
                    if value and value.strip():
                        row[col] = scrub_text(value, text_rules, json_field_rules,
                                              field_name=col)
                        stats["cells"] += 1
                stats["scrubbed"] += 1
                writer.writerow(row)

    return stats


def _scrub_samples_text_format(input_path: str, output_path: str,
                                text_rules: list, json_field_rules: list) -> dict:
    """
    Scrub plain-text log samples (one event per line, or multi-line JSON).

    Handles:
 - Single-line events (syslog, key=value, etc.)
 - Multi-line JSON events (detects { on one line, accumulates until matching })
 - JSONL (one JSON object per line)
    """
    stats = {"events": 0, "scrubbed": 0}

    with open(input_path, "r", encoding="utf-8", errors="replace") as fin:
        content = fin.read()

    # Try to detect JSONL or multi-line JSON
    lines = content.splitlines(keepends=True)
    events = []
    json_buffer = []
    brace_depth = 0

    for line in lines:
        stripped = line.strip()

        # Track JSON brace depth for multi-line events
        if json_buffer or (stripped.startswith("{") and brace_depth == 0):
            json_buffer.append(line)
            brace_depth += stripped.count("{") - stripped.count("}")
            if brace_depth <= 0:
                events.append("".join(json_buffer))
                json_buffer = []
                brace_depth = 0
        elif stripped:
            events.append(line)

    # Flush any remaining buffer
    if json_buffer:
        events.append("".join(json_buffer))

    scrubbed_events = []
    for event in events:
        stats["events"] += 1
        scrubbed = scrub_text(event, text_rules, json_field_rules)
        scrubbed_events.append(scrubbed)
        stats["scrubbed"] += 1

    with open(output_path, "w", encoding="utf-8") as fout:
        fout.write("".join(scrubbed_events))

    return stats


# ============================================================================
# Format Auto-Detection & Input Expansion
# ============================================================================

def detect_file_mode(input_path: str) -> str:
    """
    Inspect a file and guess whether it's a fieldsummary export or a samples
    export. Returns 'fieldsummary' or 'samples'.

    Heuristics, in order:
      1. If the first line is a CSV header containing '_raw' → samples.
      2. If the first line contains 'Field Name', 'field,' 'Raw Values',
         or 'values,' → fieldsummary.
      3. If the file starts with '{' or '[' → samples (JSON/JSONL).
      4. Otherwise → samples (plain text, one event per line).

    When in doubt we default to 'samples' because it's the more forgiving
    mode - samples passes content through as text, while fieldsummary
    expects a specific column layout.
    """
    try:
        with open(input_path, "r", encoding="utf-8", errors="replace") as f:
            first_chunk = f.read(4096)
    except Exception:
        return "samples"

    if not first_chunk.strip():
        return "samples"

    # Check first non-empty line
    first_line = ""
    for line in first_chunk.splitlines():
        if line.strip():
            first_line = line
            break

    # JSON / JSONL
    stripped = first_line.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return "samples"

    first_line_lower = first_line.lower()

    # Samples CSV (has _raw column)
    if "_raw" in first_line_lower:
        return "samples"

    # Fieldsummary CSV (pre-scrubbed export format)
    pre_scrubbed_signals = ("field name", "raw values", "scrubbed values", "distinct count")
    if any(s in first_line_lower for s in pre_scrubbed_signals):
        return "fieldsummary"

    # Fieldsummary CSV (Splunk native export format)
    # Signature: comma-separated header that includes both 'field' and 'values'
    # (plus usually 'count', 'distinct_count', etc).
    if "," in first_line_lower:
        tokens = [t.strip().strip('"') for t in first_line_lower.split(",")]
        if "field" in tokens and "values" in tokens:
            return "fieldsummary"
        if "field" in tokens and "distinct_count" in tokens:
            return "fieldsummary"

    return "samples"


def expand_input_paths(inputs: List[str]) -> List[str]:
    """
    Expand shell-style globs in a list of input paths. Shells on Unix
    typically expand globs before argv reaches Python, but Windows cmd.exe
    doesn't - so we handle it ourselves for cross-platform consistency.

    Duplicates are removed while preserving order. Non-existent literal
    paths are returned as-is so the caller can report a clean error.
    """
    expanded = []
    seen = set()
    for item in inputs:
        if any(ch in item for ch in "*?[]"):
            matches = sorted(glob.glob(item, recursive=True))
            if not matches:
                # No matches - pass through so caller reports "not found"
                if item not in seen:
                    expanded.append(item)
                    seen.add(item)
                continue
            for m in matches:
                if m not in seen:
                    expanded.append(m)
                    seen.add(m)
        else:
            if item not in seen:
                expanded.append(item)
                seen.add(item)
    return expanded


# ============================================================================
# Output Path Builder
# ============================================================================

def build_output_path(input_path: str, explicit_output: str = None) -> str:
    """Build output path: explicit path, or input_scrubbed_<timestamp>.ext"""
    if explicit_output:
        return explicit_output

    p = Path(input_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return str(p.parent / f"{p.stem}_scrubbed_{timestamp}{p.suffix}")


# ============================================================================
# CLI
# ============================================================================

def find_default_config() -> str:
    """Look for log_scrubbing_config.csv in common locations."""
    candidates = [
        Path("log_scrubbing_config.csv"),
        Path("data/log_scrubbing_config.csv"),
        Path(__file__).parent / "log_scrubbing_config.csv",
        Path(__file__).parent / "data" / "log_scrubbing_config.csv",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return None


def _process_one_file(input_path: str, args, text_rules: list,
                      json_field_rules: list) -> int:
    """
    Scrub a single file. Returns 0 on success, non-zero on error.
    Factored out of main() so batch mode can iterate cleanly.
    """
    if not os.path.exists(input_path):
        print(f"  [!] Not found: {input_path}", file=sys.stderr)
        return 1

    # Resolve mode: explicit flag wins, otherwise auto-detect per file.
    if args.mode == "auto":
        mode = detect_file_mode(input_path)
        mode_note = f"{mode} (auto-detected)"
    else:
        mode = args.mode
        mode_note = mode

    # Output path: if --output given AND there's only one input, honor it.
    # Otherwise always use the auto-timestamped pattern to avoid collisions.
    if args.output and len(args.inputs_resolved) == 1:
        output_path = args.output
    else:
        output_path = build_output_path(input_path)

    if not args.quiet:
        print(f"  [>] {input_path}")
        print(f"      Mode:   {mode_note}")
        print(f"      Output: {output_path}")

    if args.dry_run:
        if not args.quiet:
            print(f"      [DRY RUN] No output written.")
        return 0

    # File processors call scrub_text() by name. To respect --no-builtin /
    # --no-cui without rewriting every processor signature, we locally swap
    # the module-level scrub_text for a closure that forwards the flags,
    # then restore it when done. Simple, reversible, keeps change surface
    # small.
    global scrub_text
    original_scrub_text = scrub_text

    def scrub_text_with_flags(text, tr, jr, field_name=None):
        return original_scrub_text(
            text, tr, jr,
            field_name=field_name,
            enable_builtins=not args.no_builtin,
            enable_cui=not args.no_cui,
        )

    scrub_text = scrub_text_with_flags
    try:
        if mode == "fieldsummary":
            stats = scrub_fieldsummary_csv(input_path, output_path,
                                           text_rules, json_field_rules,
                                           include_raw=args.include_raw)
            if not args.quiet:
                print(f"      [OK] Scrubbed {stats['scrubbed']}/{stats['rows']} fields"
                      f" (skipped {stats['skipped']} empty)")
        else:
            stats = scrub_samples_csv(input_path, output_path,
                                      text_rules, json_field_rules)
            if not args.quiet:
                print(f"      [OK] Scrubbed {stats['scrubbed']}/{stats['events']} events")
    finally:
        scrub_text = original_scrub_text

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Log Scrubber - Scrub CUI, PII, PHI, and credentials from "
                    "Splunk field-value exports and log samples",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s my_fields.csv                              (auto-detects mode)
  %(prog)s ~/Downloads/*.csv                          (batch, auto-detects each)
  %(prog)s fieldsummary my_fields.csv                 (explicit mode, v1 syntax)
  %(prog)s samples my_events.csv --output clean.csv
  %(prog)s *.csv --config custom_rules.csv
  %(prog)s events.csv --no-cui                        (disable CUI redaction)

Export SPL for fieldsummary (Splunk Web -> Export -> CSV):
  index=<idx> sourcetype="<st>" earliest=-7d@d latest=now
  | fieldsummary maxvals=5
  | search field!="_*" AND field!="date_*" AND field!="linecount"
    AND field!="punct" AND field!="timestartpos" AND field!="timeendpos"
    AND field!="splunk_server_group"

Export SPL for log samples (Splunk Web -> Export -> CSV):
  index=<idx> sourcetype="<st>" earliest=-1d@d latest=now
  | dedup punct | head 20
        """,
    )

    # The first positional may be a mode keyword ('fieldsummary'/'samples')
    # or a file path. We accept everything as 'args' and disambiguate below
    # so both the v1 syntax and the new auto-detect syntax work.
    parser.add_argument(
        "args",
        nargs="+",
        help="Either [mode] input [input ...] where mode is 'fieldsummary' "
             "or 'samples', or just input [input ...] to auto-detect.",
    )
    parser.add_argument(
        "--config", "-c",
        help="Path to log_scrubbing_config.csv (auto-detected if not specified)",
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file path (single input only; ignored for batch). "
             "Default: <input>_scrubbed_<timestamp>.<ext>",
    )
    parser.add_argument(
        "--no-builtin",
        action="store_true",
        help="Disable built-in regex patterns (IP, email, tokens, SSN, etc.)",
    )
    parser.add_argument(
        "--no-cui",
        action="store_true",
        help="Disable CUI marking detection (CMMC/NIST SP 800-171 redaction)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without writing output",
    )
    parser.add_argument(
        "--include-raw",
        action="store_true",
        help="Include the original raw values column in fieldsummary output "
             "(default: scrubbed only)",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress informational output",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"log_scrubber {__version__}",
    )

    args = parser.parse_args()

    # Disambiguate positional args: if the first token is a mode keyword,
    # strip it off and treat the rest as inputs. Otherwise all tokens are
    # inputs and mode is 'auto'.
    raw_args = args.args
    if raw_args and raw_args[0] in ("fieldsummary", "samples"):
        args.mode = raw_args[0]
        inputs = raw_args[1:]
    else:
        args.mode = "auto"
        inputs = raw_args

    if not inputs:
        print("Error: no input files specified", file=sys.stderr)
        sys.exit(1)

    # Expand globs (for Windows cmd.exe users and for consistent semantics).
    args.inputs_resolved = expand_input_paths(inputs)

    # Find config
    config_path = args.config or find_default_config()

    # Parse config
    text_rules, json_field_rules = [], []
    if config_path and os.path.exists(config_path):
        text_rules, json_field_rules = parse_scrubbing_config(config_path)
        if not args.quiet:
            print(f"  Config: {config_path}")
            print(f"    Text rules:   {len(text_rules)}")
            print(f"    @json rules:  {len(json_field_rules)}")
            print(f"    CUI scrub:    {'disabled' if args.no_cui else 'enabled'}")
            print(f"    Built-ins:    {'disabled' if args.no_builtin else 'enabled'}")
    else:
        if not args.quiet:
            print("  Config: None found (using built-in patterns only)")
            print(f"    CUI scrub: {'disabled' if args.no_cui else 'enabled'}")
            print(f"    Built-ins: {'disabled' if args.no_builtin else 'enabled'}")

    if not args.quiet:
        print(f"  Files:  {len(args.inputs_resolved)} to process")
        print()

    # Process each file
    failures = 0
    for input_path in args.inputs_resolved:
        rc = _process_one_file(input_path, args, text_rules, json_field_rules)
        if rc != 0:
            failures += 1

    if failures:
        sys.exit(2)


if __name__ == "__main__":
    print()
    print("===================================================")
    print(f"  Log Scrubber v{__version__}")
    print("  Machine Data Insights")
    print("  machinedatainsights.com")
    print("===================================================")
    print()
    main()
    print()
