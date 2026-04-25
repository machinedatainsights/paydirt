# Shared tests (Python ↔ JavaScript parity)

This directory contains test infrastructure that verifies the Python CLI
(`log_scrubber.py`) and the JavaScript implementation (`paydirt/src/scrubber.js`)
produce identical output on identical input.

Parity matters because Paydirt and the CLI must be interchangeable: a user
who scrubs a file with one and then re-scrubs it with the other should see
the same result. If the two implementations drift, users could end up
trusting one tool and being surprised by the other.

## Layout

```
shared-tests/
├── run_parity.py       the test harness
└── input/              fixtures fed through both implementations
    ├── 01_plain_events.txt      plain-text syslog / key=value events
    ├── 02_cloudtrail.json       CloudTrail-style nested JSON event
    ├── 03_cui_samples.txt       CUI markings of various styles
    └── 04_windows_xml_event.csv XmlWinEventLog CSV with many columns
```

## Running

```bash
python3 shared-tests/run_parity.py
```

For each fixture, the script runs it through the Python CLI and through
the JavaScript implementation (via Node), then compares the outputs
byte-for-byte. Prints MATCH or DIFF per fixture with a failure summary.

## Known differences

The CSV fixture produces cosmetically different but semantically equivalent
output between Python's `csv` module and the JavaScript CSV writer - Python
strips unnecessary field quoting, while the JS writer is more conservative.
Both outputs are valid CSV representing the same data. The difference is
flagged as a DIFF in the report but is not a parity violation.

## Adding a fixture

Drop a new file in `input/`. The harness auto-discovers all files in
that directory and runs them through both implementations.

Note: random-mode config rules (where the scrubber picks a replacement
at random from a list) are non-deterministic without seeded RNGs on both
sides. The parity config uses only `single`-mode rules to enable strict
equality. If you're testing a random-mode rule, verify it manually rather
than expecting parity.
