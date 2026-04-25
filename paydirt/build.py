#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Machine Data Insights Inc.
# https://machinedatainsights.com
"""
Build script for Paydirt.

Reads src/index.html, src/styles.css, src/scrubber.js, src/app.js and the
project-level log_scrubbing_config.csv, and produces dist/Paydirt.html with
everything inlined. The result is a single-file distribution that can be
saved locally, emailed around, or hosted on any static web server.

No dependencies beyond the Python standard library.
"""
import re
from pathlib import Path
from datetime import datetime

SRC = Path(__file__).parent / 'src'
REPO_ROOT = Path(__file__).parent.parent

INDEX_HTML = SRC / 'index.html'
STYLES_CSS = SRC / 'styles.css'
SCRUBBER_JS = SRC / 'scrubber.js'
APP_JS = SRC / 'app.js'
DEFAULT_CONFIG = REPO_ROOT / 'log_scrubbing_config.csv'
OUTPUT = REPO_ROOT / 'Paydirt.html'


def js_string_literal(text: str) -> str:
    """Escape a string for embedding as a JS string literal between backticks.
    We use template literals so newlines don't need to be escaped."""
    # Escape backticks, backslashes, and ${ to avoid breaking the template
    text = text.replace('\\', '\\\\')
    text = text.replace('`', '\\`')
    text = text.replace('${', '\\${')
    return text


def main():
    html = INDEX_HTML.read_text(encoding='utf-8')
    css = STYLES_CSS.read_text(encoding='utf-8')
    scrubber_js = SCRUBBER_JS.read_text(encoding='utf-8')
    app_js = APP_JS.read_text(encoding='utf-8')
    default_config = DEFAULT_CONFIG.read_text(encoding='utf-8')

    # Inline the CSS (using str.replace to avoid regex-escape issues in content)
    link_tag = '<link rel="stylesheet" href="styles.css">'
    if link_tag not in html:
        raise RuntimeError(f'Could not find stylesheet link tag in index.html')
    html = html.replace(link_tag, f'<style>\n{css}\n</style>', 1)

    # Inject the default config as a global before scrubber.js loads.
    config_literal = js_string_literal(default_config)
    config_script = (
        '<script>\n'
        f'window.__PAYDIRT_DEFAULT_CONFIG__ = `{config_literal}`;\n'
        '</script>'
    )

    # Inline scrubber.js
    scrubber_tag = '<script src="scrubber.js"></script>'
    if scrubber_tag not in html:
        raise RuntimeError(f'Could not find scrubber.js script tag in index.html')
    html = html.replace(
        scrubber_tag,
        f'{config_script}\n<script>\n{scrubber_js}\n</script>',
        1,
    )

    # Inline app.js
    app_tag = '<script src="app.js"></script>'
    if app_tag not in html:
        raise RuntimeError(f'Could not find app.js script tag in index.html')
    html = html.replace(app_tag, f'<script>\n{app_js}\n</script>', 1)

    # Add a build banner at the top of the HTML so anyone inspecting the
    # file knows when it was built and from what version.
    build_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    banner = (
        f'\n<!--\n'
        f'  Paydirt - Log Scrubber\n'
        f'  Built: {build_time}\n'
        f'  Machine Data Insights - machinedatainsights.com\n'
        f'\n'
        f'  This file runs entirely in your browser.\n'
        f'  Your data never leaves your device.\n'
        f'-->\n'
    )
    html = html.replace('<!DOCTYPE html>', '<!DOCTYPE html>' + banner, 1)

    OUTPUT.write_text(html, encoding='utf-8')
    size_kb = OUTPUT.stat().st_size / 1024
    print(f'Built {OUTPUT} ({size_kb:.1f} KB)')


if __name__ == '__main__':
    main()
