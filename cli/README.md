# CLI Tests

This directory contains the test suite for `log_scrubber.py`.

The CLI itself lives in the project root, not here - that way users who
download the single-file Python CLI can find it immediately. This directory
is a home for developer-facing test code.

## Running the tests

From the project root:

```bash
python3 cli/test_scrubber.py
```

The test suite has 50 tests covering:

- Config parsing (text rules, @json rules, nested paths, random mode, comments)
- CUI marking detection (banner, portion, legacy, adjacent styles)
- Credential and token patterns (AWS keys, JWTs, GitHub tokens, etc.)
- PII patterns (SSN with invalid-range exclusions, Luhn-validated credit
  cards, phone numbers, Windows SIDs with well-known SID preservation,
  NPIs with 45 CFR 162.406 Luhn validation)
- JSON path traversal and tag structure matching
- The `Scrubber` class library API

## Related test suites

- `paydirt/tests/` - JavaScript unit tests and browser smoke tests for
  the Paydirt browser tool
- `shared-tests/` - Parity tests that run identical inputs through both
  the Python CLI and the JavaScript implementation and verify byte-for-byte
  matching output
