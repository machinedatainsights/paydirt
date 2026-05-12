# Paydirt (browser tool) - source

This directory contains the source code and build system for `Paydirt.html`.
The built single-file distributable lives in the project root. If you're a
user who just wants to use Paydirt, grab `Paydirt.html` from the root - you
don't need anything in this directory.

If you're modifying Paydirt, read on.

## Layout

```
paydirt/
├── README.md          (this file)
├── build.py           concatenates src/ files into the top-level Paydirt.html
├── src/
│   ├── index.html     page structure, CSP meta tag, result-card template
│   ├── styles.css     design tokens, layout, highlight colors
│   ├── scrubber.js    JS port of log_scrubber.py - zero dependencies
│   └── app.js         UI layer: event handlers, file I/O, comparison view
└── tests/
    ├── test-node.js   unit tests for scrubber.js (50 tests, runs in Node)
    └── smoke-test.py  headless browser test using Playwright
```

## Building

```bash
python3 paydirt/build.py
```

Produces `Paydirt.html` at the project root. Inlines all CSS, JavaScript,
and the bundled default config into a single self-contained HTML file
(~120 KB). No external dependencies at build time beyond the Python
standard library.

### Build numbers

Each build is stamped with a `yyyymmddxx` build number where `xx`
increments for same-day rebuilds (`2026051201`, `2026051202`, ...). The
number is shown in the header next to the version pill, embedded as a
comment near the top of `Paydirt.html`, and printed at the end of the
build output.

The same-day counter is persisted in `paydirt/.last_build` (gitignored).
If the file is missing or unreadable the counter resets to `01` for the
current day; nothing depends on a continuous sequence across machines.

## Testing

```bash
# Unit tests (Node - no browser required)
node paydirt/tests/test-node.js

# Browser smoke test (requires Playwright installed)
pip install playwright
playwright install chromium
python3 paydirt/tests/smoke-test.py
```

## Design principles

- **No external resources** - strict CSP, no CDN loads, no external fonts.
  Everything loads from within the single HTML file.
- **No build-time dependencies beyond the Python standard library** -
  no npm, no webpack, no bundler. The build is plain string concatenation.
- **Scrubbing parity with log_scrubber.py** - scrubber.js mirrors the
  Python implementation function-for-function so both tools produce
  identical output on identical input (verified by shared-tests/run_parity.py).
- **CSP-strict** - no inline event handlers, no eval, no template string
  interpolation with user input. All DOM events bound in app.js.

## Related

- `../log_scrubber.py` - Python CLI counterpart
- `../log_scrubbing_config.csv` - default config, inlined by build.py
- `../shared-tests/` - parity tests between Python and JS implementations
