#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Machine Data Insights Inc.
# https://machinedatainsights.com
"""
Smoke test for Paydirt.html using Playwright. Loads the built file, simulates
a file drop, verifies the scrubbed output appears, clicks through the tabs,
and confirms core UI interactions work.

This is not a full UI test suite - it's a "does the damn thing load and
roughly work" sanity check, meant to catch obvious regressions during
Stage 2 development.
"""
import sys
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

HTML_PATH = Path(__file__).parent.parent.parent / 'Paydirt.html'


SAMPLE_LOG = """Jan 1 10:00:00 host1.acme.com sshd: Accepted password for bob from 192.168.1.50
Jan 1 10:00:05 authd: API key AKIAIOSFODNN7EXAMPLE used by admin@acme.com
Jan 1 10:00:10 FOUO - internal memo about contract
Jan 1 10:00:15 host1 app: card=4532015112830366 ssn=123-45-6789
Jan 1 10:00:20 host1 auth: user logged in from 203.0.113.42 with MAC 00:1A:2B:3C:4D:5E
"""


def main():
    if not HTML_PATH.exists():
        print(f'Paydirt.html not found at {HTML_PATH}. Run build.py first.', file=sys.stderr)
        sys.exit(1)

    failures = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        # Capture any JS console errors - these are failures
        console_errors = []
        page.on('console', lambda msg: console_errors.append(msg.text) if msg.type == 'error' else None)
        page.on('pageerror', lambda err: console_errors.append('pageerror: ' + str(err)))

        # Capture network activity - there should be ZERO outbound calls
        network_requests = []
        page.on('request', lambda req: network_requests.append(req.url))

        # Load the file
        url = 'file://' + str(HTML_PATH.resolve())
        page.goto(url)
        page.wait_for_load_state('domcontentloaded')

        print(f'Loaded: {url}')

        # --- Test 1: Page structure renders
        try:
            expect(page.locator('.brand-name')).to_have_text('Paydirt')
            expect(page.locator('#drop-zone')).to_be_visible()
            expect(page.locator('#config-source')).to_have_text('Built-in defaults')
            print('  PASS  Page structure renders')
        except Exception as e:
            failures.append(('Page structure', str(e)))
            print('  FAIL  Page structure renders:', e)

        # --- Test 2: Config loads with non-zero rule counts
        try:
            counts_text = page.locator('#config-counts').text_content()
            if ' text, ' not in counts_text or ' @json' not in counts_text:
                raise AssertionError(f'Unexpected counts text: {counts_text}')
            # Extract numbers and verify they're non-zero
            import re as regex
            m = regex.match(r'(\d+) text, (\d+) @json', counts_text)
            if not m:
                raise AssertionError(f'Counts format wrong: {counts_text}')
            text_count, json_count = int(m.group(1)), int(m.group(2))
            if text_count == 0 and json_count == 0:
                raise AssertionError('No rules loaded')
            print(f'  PASS  Config loaded: {text_count} text, {json_count} @json')
        except Exception as e:
            failures.append(('Config counts', str(e)))
            print('  FAIL  Config counts:', e)

        # --- Test 3: Paste -> scrub -> result card appears
        try:
            page.locator('.paste-details summary').click()
            page.locator('#paste-input').fill(SAMPLE_LOG)
            page.locator('#paste-scrub-btn').click()
            # Wait for a result card to appear
            page.wait_for_selector('.result-card', timeout=3000)
            expect(page.locator('.result-card')).to_have_count(1)
            print('  PASS  Paste + scrub produces a result card')
        except Exception as e:
            failures.append(('Paste + scrub', str(e)))
            print('  FAIL  Paste + scrub:', e)

        # --- Test 4: Scrubbed tab shows redacted content
        try:
            scrubbed_text = page.locator('.scrubbed-pre').first.text_content()
            expected_absent = ['AKIAIOSFODNN7EXAMPLE', '192.168.1.50', 'admin@acme.com',
                              '4532015112830366', '123-45-6789']
            missing = [s for s in expected_absent if s in scrubbed_text]
            if missing:
                raise AssertionError(f'Expected these to be redacted, but found: {missing}')
            if 'CUI-REDACTED' not in scrubbed_text:
                raise AssertionError('Expected CUI-REDACTED placeholder for FOUO line')
            print('  PASS  Scrubbed output contains expected redactions')
        except Exception as e:
            failures.append(('Scrubbed output', str(e)))
            print('  FAIL  Scrubbed output:', e)

        # --- Test 5: Comparison tab switches and shows two panes
        try:
            page.locator('.result-tab[data-tab="comparison"]').click()
            expect(page.locator('.result-tab[data-tab="comparison"]')).to_have_attribute('aria-selected', 'true')
            expect(page.locator('.original-pane .comparison-line').first).to_be_visible()
            expect(page.locator('.scrubbed-pane .comparison-line').first).to_be_visible()
            # At least one line should be marked as modified
            modified_count = page.locator('.comparison-line.line-modified, .comparison-line.line-cui').count()
            if modified_count == 0:
                raise AssertionError('No lines marked as modified or CUI-redacted')
            print(f'  PASS  Comparison tab shows {modified_count} highlighted lines')
        except Exception as e:
            failures.append(('Comparison tab', str(e)))
            print('  FAIL  Comparison tab:', e)

        # --- Test 6: CUI redaction uses its own highlight class
        try:
            cui_count = page.locator('.comparison-line.line-cui').count()
            if cui_count == 0:
                raise AssertionError('Expected at least 1 line-cui class (FOUO line)')
            print(f'  PASS  CUI-specific highlighting present ({cui_count} lines)')
        except Exception as e:
            failures.append(('CUI highlight', str(e)))
            print('  FAIL  CUI highlight:', e)

        # --- Test 7: Summary tab shows counts
        try:
            page.locator('.result-tab[data-tab="summary"]').click()
            expect(page.locator('.result-tab[data-tab="summary"]')).to_have_attribute('aria-selected', 'true')
            summary_text = page.locator('.summary-content').text_content()
            # Should contain at least IP addresses, emails, SSN, etc.
            expected_labels = ['IP addresses', 'Email addresses', 'CUI markings']
            missing = [l for l in expected_labels if l not in summary_text]
            if missing:
                raise AssertionError(f'Summary missing labels: {missing}')
            print('  PASS  Summary tab contains expected category labels')
        except Exception as e:
            failures.append(('Summary tab', str(e)))
            print('  FAIL  Summary tab:', e)

        # --- Test 8: No console errors
        if console_errors:
            failures.append(('Console errors', str(console_errors)))
            print('  FAIL  Console errors present:')
            for err in console_errors:
                print('         ', err)
        else:
            print('  PASS  No JS console errors')

        # --- Test 9: No outbound network requests (CSP + offline-by-default)
        # We expect only the initial file:// load itself, nothing else.
        external_requests = [r for r in network_requests
                            if not r.startswith('file://') and not r.startswith('data:')]
        if external_requests:
            failures.append(('Network', f'Unexpected requests: {external_requests}'))
            print('  FAIL  Unexpected network requests:', external_requests)
        else:
            print('  PASS  Zero outbound network requests')

        browser.close()

    print()
    print('=' * 50)
    if failures:
        print(f'  {len(failures)} FAILURE(S):')
        for name, msg in failures:
            print(f'    - {name}: {msg}')
        print('=' * 50)
        sys.exit(1)
    else:
        print('  All smoke tests passed')
        print('=' * 50)
        sys.exit(0)


if __name__ == '__main__':
    main()
