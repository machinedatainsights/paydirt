# CLAUDE.md — Paydirt session handoff

Orientation for a fresh Claude Code session. Read this first; it captures how this
repo is laid out, how to build/test it, and the gotchas that waste time if rediscovered.

## What this project is

**Paydirt** is a log scrubber for Splunk exports — it strips sensitive data (PII, CUI
markings, credentials, tokens, etc.) so logs can be shared/analyzed safely. Two engines
that must stay in lockstep:

- **Browser tool** — a single self-contained file, `Paydirt.html`, that runs entirely
  in-browser (no network, CSP-strict). This is what end users download.
- **Python CLI** — `log_scrubber.py` at the repo root (stdlib only, Python 3.9+).

By Machine Data Insights. Apache-2.0.

## Critical: `Paydirt.html` is a BUILD ARTIFACT — never edit it directly

`Paydirt.html` (~290 KB, repo root) is **generated** by `paydirt/build.py`, which inlines
the modular source. Edit the source, then rebuild. Hand-edits to `Paydirt.html` get
overwritten on the next build.

### Source of truth (`paydirt/src/`)
| File | Role |
|------|------|
| `paydirt/src/index.html` | Markup, incl. the `#result-card-template` cloned per scrubbed file |
| `paydirt/src/styles.css` | All styling |
| `paydirt/src/scrubber.js` | Core scrubbing engine (mirrors `log_scrubber.py`) |
| `paydirt/src/app.js` | UI layer: drag/drop, config, result cards, download/copy/report buttons |
| `log_scrubbing_config.csv` | Default config (repo root); inlined into the build |

### Build
```
python paydirt/build.py
```
Inlines CSS + both JS files + the default config into `Paydirt.html`, and stamps a
`yyyymmddxx` build number (auto-incrementing same-day counter stored in
`paydirt/.last_build`). No dependencies beyond the stdlib.

## Tests

```
python cli/test_scrubber.py        # CLI unit tests (should report "N passed, 0 failed")
python shared-tests/run_parity.py  # byte-for-byte parity: Python CLI vs JS engine
node   paydirt/tests/test-node.js  # JS engine tests (only if Node is installed)
```

**Known pre-existing parity diff:** `run_parity.py` reports a `DIFF` on
`04_windows_xml_event.csv` (Python emits some CSV fields unquoted where the JS engine
quotes them — a cosmetic CSV-dialect difference, not a scrubbing-correctness bug). The
other fixtures match byte-for-byte. Don't be alarmed by `PARITY_EXIT=1` from this alone;
confirm it's *only* that fixture and the quoting difference.

## Releasing / bumping the version

The semantic version lives in several places that must move together. Last done for
v1.3.2 (see git log). When bumping `X.Y.Z`, update:

1. `paydirt/src/scrubber.js` — `const PAYDIRT_VERSION = '...'`
2. `paydirt/src/app.js` — two fallback strings: the `versionPill` line in `init()` and
   the `version:` field in the report generator
3. `log_scrubber.py` — both the `Version:` line in the module docstring and `__version__`
4. `cli/test_scrubber.py` — the "Test suite for log_scrubber vX.Y.Z" header line
5. `README.md` — download-link label (top), "Latest release" line, a new `### vX.Y.Z`
   entry under **Version History**, and the `*Version X.Y.Z - <date>*` footer
6. `docs/LOG_SCRUBBER_GUIDE.md` — the `*Version X.Y.Z - <date>*` footer
7. Then **rebuild** (`python paydirt/build.py`) so `Paydirt.html` picks up the new version

Quick audit before committing:
```
git grep -n "<OLD_VERSION>"
```
Expect remaining hits only for legitimate historical references (e.g. the
`@names directive (v1.3.1+)` comment documents when a feature was *introduced*, and
`Paydirt.html` will contain that same comment via the inlined config). Version *stamps*
should all be the new number.

## Result-card buttons (where the per-file actions live)

Each scrubbed file renders a card from the `#result-card-template` in `index.html`. The
action buttons (`data-action="download" | "copy" | "download-report" | "remove"`) are
wired up in `buildResultCard()` in `app.js`. The error path (`buildErrorCard()`) strips
the data-producing buttons. The `copyTextToClipboard()` helper in `app.js` (Clipboard API
+ textarea fallback for `file://`) is shared by the card Copy button and the SPL copy
buttons.

## Environment & tooling gotchas (Windows)

- **Shell is Windows PowerShell 5.1.** Use PS syntax. See the PowerShell tool notes —
  `$null` not `/dev/null`, no `&&` chaining, etc.
- **Never `throw` in a PowerShell tool call to "flush" output** — a thrown/erroring call
  **cancels every other tool call in the same batch**, including file Edits. This silently
  reverted real work earlier in this project's history. If a batch member errors, assume
  the whole batch was discarded and re-verify state.
- **Prefer the `Edit`/`Write`/`Read` tools over PowerShell scripts** for file changes.
  They preserve encoding (UTF-8 no-BOM) and line endings and are far less error-prone than
  hand-rolled `[IO.File]` scripts.
- **`Grep` does not satisfy `Edit`'s "must Read first" requirement** — you must call `Read`
  on a file before `Edit` will touch it, even if you've already `Grep`'d it.
- Tool output can **lag** — results sometimes surface a turn late. Don't retry a command
  just because its output hasn't appeared; check state with a fresh read instead of
  re-running mutations.
- Don't leave scratch files (`_*.txt`, `*.bak`, `*.ps1`) in the repo root — clean them up;
  `git status` should stay tidy. (`__pycache__/log_scrubber.cpython-*.pyc` showing as
  modified is normal noise.)

## Repo map (top level)

```
Paydirt.html              generated browser tool (do not edit by hand)
log_scrubber.py           Python CLI engine
log_scrubbing_config.csv  default scrub config (inlined into the build)
paydirt/
  build.py                build script (src -> Paydirt.html)
  src/                     index.html, styles.css, scrubber.js, app.js
  tests/                   test-node.js, smoke-test.py
cli/                       test_scrubber.py, README.md
shared-tests/              run_parity.py + input/ fixtures (CLI vs JS parity)
docs/                      LOG_SCRUBBER_GUIDE.md, COMPLIANCE_PRIMER.md, *.pdf, images/
assets/branding/           icons, wordmarks
archive/                   superseded docs/fixtures
```
