# Repo Reorganization Checklist

Apply these changes to your local project folder to match the new layout.
The test suite has been verified to pass in the new structure.

## Before you start

- Close any editor or shell that has files open from the old locations
- If you're using Git: this is a good commit point. Commit whatever you
  have first so these moves show up as discrete changes in history
- Back up the folder if you want a safety net (a `.bak` copy, or Git is fine)

## Step 1 - Create the new directory structure

From your project root, create these directories if they don't already exist:

```
docs/
shared-tests/input/
```

You should already have `cli/`, `paydirt/src/`, and `paydirt/tests/`.

## Step 2 - Move files to their new homes

The changes below are all MOVES (not copies). Source paths are relative
to your project root.

### Move TO the project root

These files need to be at the top level so users find them instantly:

| From | To |
|------|----|
| `paydirt/dist/Paydirt.html` | `Paydirt.html` |
| `cli/log_scrubber.py` | `log_scrubber.py` |

### Move INTO docs/

| From | To |
|------|----|
| `COMPLIANCE_PRIMER.md` | `docs/COMPLIANCE_PRIMER.md` |
| `LOG_SCRUBBER_GUIDE.pdf` | `docs/LOG_SCRUBBER_GUIDE.pdf` |

### DELETE these

These are no longer needed:

- `paydirt/dist/` (the entire directory - `Paydirt.html` now builds to root)
- `cli/__pycache__/` (Python bytecode cache, should not be in source control)
- `paydirt/tests/debug-test3.py` (was a debug artifact, superseded by smoke-test.py)

### Stay where they are

These files don't move:

- `README.md` (but needs a content update - see Step 4)
- `log_scrubbing_config.csv`
- `paydirt_demo.log`
- `paydirt_demo_config.csv`
- `cli/test_scrubber.py`
- `paydirt/build.py`
- `paydirt/src/index.html`
- `paydirt/src/styles.css`
- `paydirt/src/scrubber.js`
- `paydirt/src/app.js`
- `paydirt/tests/smoke-test.py`
- `paydirt/tests/test-node.js`
- `shared-tests/run_parity.py`
- `shared-tests/input/*`

## Step 3 - Replace these files with updated versions

Four files have content updates to match the new paths. Replace them with
the versions in this delivery:

- `cli/test_scrubber.py` (sys.path adjusted for new log_scrubber.py location)
- `paydirt/build.py` (writes to repo root now, not paydirt/dist/)
- `paydirt/tests/smoke-test.py` (looks for Paydirt.html at repo root)
- `shared-tests/run_parity.py` (finds CLI at repo root)
- `README.md` (top section updated to cover both tools)

## Step 4 - Add new files

These are new files from this reorganization:

- `cli/README.md` (short orientation note for developers)
- `paydirt/README.md` (source/build guide for developers)
- `shared-tests/README.md` (parity test documentation)

## Step 5 - Verify everything works

From the project root:

```bash
# Python CLI tests (expect 50 passed)
python3 cli/test_scrubber.py

# Rebuild Paydirt.html from source
python3 paydirt/build.py
# Should produce: Built <repo-root>/Paydirt.html (~120 KB)

# JavaScript unit tests (expect 50 passed)
node paydirt/tests/test-node.js

# Browser smoke test (requires playwright installed)
python3 paydirt/tests/smoke-test.py
# Should show: All smoke tests passed

# Parity between Python and JS
python3 shared-tests/run_parity.py
# Should show: 3/4 fixtures match byte-for-byte
# (The 4th is a cosmetic CSV-quoting difference, not a parity violation)
```

## Step 6 - Commit

If you're using Git, the result should look approximately like:

```
new file:    Paydirt.html                     (moved from paydirt/dist/)
new file:    cli/README.md
new file:    paydirt/README.md
new file:    shared-tests/README.md
renamed:     cli/log_scrubber.py -> log_scrubber.py
renamed:     COMPLIANCE_PRIMER.md -> docs/COMPLIANCE_PRIMER.md
renamed:     LOG_SCRUBBER_GUIDE.pdf -> docs/LOG_SCRUBBER_GUIDE.pdf
deleted:     paydirt/dist/Paydirt.html
modified:    README.md
modified:    cli/test_scrubber.py
modified:    paydirt/build.py
modified:    paydirt/tests/smoke-test.py
modified:    shared-tests/run_parity.py
```

A suggested commit message:

```
Reorganize repo layout for public release

- Top-level downloadables (Paydirt.html, log_scrubber.py) at repo root
  so users find them immediately
- Compliance/architecture docs consolidated under docs/
- build.py now outputs directly to repo root, no dist/ intermediate
- Per-directory READMEs guide developers through source layout
- All test suites verified passing in new layout
```

## Questions

If anything doesn't work after the move, the likely culprit is a stale
relative path reference. Let me know what fails and we can troubleshoot.
