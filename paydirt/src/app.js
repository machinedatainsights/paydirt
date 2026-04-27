// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Machine Data Insights Inc.
// https://machinedatainsights.com
//
// ============================================================================
// Paydirt UI layer (app.js)
//
// Thin layer on top of scrubber.js. Handles:
// - Drag/drop, file picker, paste input
// - Config loading (bundled default, user upload, LocalStorage remember)
// - Running files through the scrubber and building result cards
// - Tabbed view: Scrubbed (plain), Comparison (side-by-side), Summary
// - Line-level diff highlighting and synchronized scrolling
// - Download of scrubbed output
//
// Everything runs in-browser. No network calls. No inline event handlers
// (CSP-strict). All event binding happens here programmatically.
// ============================================================================

(function () {
    'use strict';

    // ----------------------------------------------------------------------
    // Constants
    // ----------------------------------------------------------------------

    const COMPARISON_MAX_LINES = 1000;
    const COMPARISON_MAX_BYTES = 500 * 1024;
    const LARGE_FILE_SPINNER_THRESHOLD = 500 * 1024;  // show spinner over 500KB

    const LOCAL_STORAGE_KEY = 'paydirt.customConfig.v1';
    const REMEMBER_KEY = 'paydirt.rememberConfig.v1';

    // Pipeline pattern categories for summary reporting. Each pattern in
    // scrubber.js gets categorized here so we can count redactions per type.
    // The implementation scans pre and post strings and counts what changed.
    // We derive counts by re-running specific patterns against the original
    // and the scrubbed text; this is a reporting mechanism, not a scrub.
    const SUMMARY_CATEGORIES = [
        { key: 'cui', label: 'CUI markings', matcher: 'cuiMarker' },
        { key: 'ip', label: 'IP addresses', pattern: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, ignoreReplacement: '10.0.0.x' },
        { key: 'email', label: 'Email addresses', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, ignoreReplacement: 'user@example.com' },
        { key: 'fqdn', label: 'Hostnames / FQDNs', pattern: /\b[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.(com|net|org|io|local|internal)\b/g, ignoreReplacement: 'host.example.com' },
        { key: 'aws_host', label: 'AWS ip- hostnames', pattern: /\bip-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\b/g, ignoreReplacement: 'ip-10-0-0-x' },
        { key: 'domain_user', label: 'Domain usernames', pattern: /\b[A-Z][A-Z0-9_-]+\\[a-zA-Z0-9._-]+\b/g, ignoreReplacement: 'DOMAIN\\user' },
        { key: 'unc_path', label: 'UNC paths', pattern: /\\\\[a-zA-Z0-9._-]+\\[a-zA-Z0-9._$-]+/g, ignoreReplacement: '\\\\SERVER\\SHARE' },
        { key: 'mac', label: 'MAC addresses', pattern: /\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g, ignoreReplacement: '00:00:00:00:00:00' },
        { key: 'ssn', label: 'SSN', pattern: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g, ignoreReplacement: '000-00-0000' },
        { key: 'cc', label: 'Credit cards', matcher: 'luhnCc' },
        { key: 'phone', label: 'Phone numbers', pattern: /(?<!\d)(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?!\d)/g, ignoreReplacement: '555-555-5555' },
        { key: 'sid', label: 'Windows SIDs', pattern: /\bS-1-5-21-\d+-\d+-\d+-\d+\b/g, ignoreReplacement: 'S-1-5-21-0-0-0-0' },
        { key: 'aws_key', label: 'AWS access keys', pattern: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, ignoreReplacement: 'AKIAREDACTEDREDACTED' },
        { key: 'jwt', label: 'JWTs', pattern: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g },
        { key: 'gh_pat', label: 'GitHub tokens', pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
        { key: 'slack', label: 'Slack tokens', pattern: /\bxox[baprs]-[0-9a-zA-Z-]{10,}\b/g },
        { key: 'stripe', label: 'Stripe keys', pattern: /\bsk_(?:live|test)_[0-9a-zA-Z]{24,}\b/g },
        { key: 'google_api', label: 'Google API keys', pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
        { key: 'pem_key', label: 'PEM private keys', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g },
        { key: 'auth_header', label: 'Authorization headers', pattern: /Authorization\s*:\s*(?:Bearer|Basic|Digest|Token)\s+\S+/gi },
    ];

    // ----------------------------------------------------------------------
    // State
    // ----------------------------------------------------------------------

    let activeConfig = null;  // {source, text, textRules, jsonFieldRules}
    let builtInConfig = null;
    let resultCards = [];     // array of {id, filename, element}

    // ----------------------------------------------------------------------
    // Default config (bundled). Embedded as a template string at build time.
    // For development we fetch from default-config.csv; the build script
    // substitutes the string inline for the distributed single-file HTML.
    // ----------------------------------------------------------------------

    // The build system replaces this with the inlined config CSV content.
    // During development, if this is the empty placeholder, the init code
    // falls back to a minimal inlined default so the app is always usable.
    const DEFAULT_CONFIG_CSV = window.__PAYDIRT_DEFAULT_CONFIG__ || getFallbackConfig();

    function getFallbackConfig() {
        // Minimal fallback so development works even without the build step.
        // The real default lives in log_scrubbing_config.csv at the repo root.
        return [
            '# Paydirt default scrubbing config (minimal fallback)',
            '# Built-in regex patterns handle IP, email, tokens, SSN, CC, CUI',
            '# markings, etc. automatically. Rules below add AWS, Azure, Okta',
            '# specifics that need explicit targeting.',
            '',
            '@json,sourceIPAddress,10.0.0.x',
            '@json,accountId,000000000000',
            '@json,userIdentity.arn,arn:aws:iam::000000000000:user/REDACTED',
            '@json,userIdentity.principalId,REDACTED_PRINCIPAL',
            '@json,tenantId,00000000-0000-0000-0000-000000000000',
            '@json,callerIpAddress,10.0.0.x',
            '@json,upn,user@example.com',
            '@json,client.ipAddress,10.0.0.x',
            '@json,actor.alternateId,user@example.com',
            '@json,Owner,REDACTED_OWNER',
            '@json,Environment,REDACTED_ENV',
        ].join('\n');
    }

    // ----------------------------------------------------------------------
    // DOM references
    // ----------------------------------------------------------------------

    const $ = (id) => document.getElementById(id);

    const dom = {
        dropZone: $('drop-zone'),
        fileInput: $('file-input'),
        filePickerTrigger: $('file-picker-trigger'),
        pasteInput: $('paste-input'),
        pasteScrubBtn: $('paste-scrub-btn'),
        configFileInput: $('config-file-input'),
        configSource: $('config-source'),
        configCounts: $('config-counts'),
        configResetBtn: $('config-reset-btn'),
        configTemplateBtn: $('config-template-btn'),
        configExportBtn: $('config-export-btn'),
        rememberConfig: $('remember-config'),
        resultsContainer: $('results-container'),
        resultsEmpty: $('results-empty'),
        clearResultsBtn: $('clear-results-btn'),
        resultCardTemplate: $('result-card-template'),
        processingOverlay: $('processing-overlay'),
        processingText: $('processing-text'),
        versionPill: $('version-pill'),
    };

    // ----------------------------------------------------------------------
    // Init
    // ----------------------------------------------------------------------

    function init() {
        dom.versionPill.textContent = 'v' + (window.Paydirt && window.Paydirt.version || '1.2.0');

        // Parse built-in default config once
        builtInConfig = buildConfigFromText(DEFAULT_CONFIG_CSV, 'Built-in defaults');

        // If the user has opted in to "remember config," restore it
        const remembered = loadRememberedConfig();
        if (remembered) {
            activeConfig = remembered;
            dom.rememberConfig.checked = true;
        } else {
            activeConfig = builtInConfig;
            dom.rememberConfig.checked = false;
        }
        updateConfigDisplay();

        bindEventHandlers();
    }

    function buildConfigFromText(text, source) {
        const parsed = window.Paydirt.parseScrubbingConfig(text);
        return {
            source,
            text,
            textRules: parsed.textRules,
            jsonFieldRules: parsed.jsonFieldRules,
        };
    }

    function updateConfigDisplay() {
        dom.configSource.textContent = activeConfig.source;
        dom.configCounts.textContent =
            activeConfig.textRules.length + ' text, ' +
            activeConfig.jsonFieldRules.length + ' @json';
        const isCustom = (activeConfig !== builtInConfig);
        dom.configResetBtn.hidden = !isCustom;
        dom.configExportBtn.hidden = !isCustom;
    }

    // ----------------------------------------------------------------------
    // Config: LocalStorage (remember)
    // ----------------------------------------------------------------------

    function loadRememberedConfig() {
        try {
            const remember = localStorage.getItem(REMEMBER_KEY);
            if (remember !== 'true') return null;
            const text = localStorage.getItem(LOCAL_STORAGE_KEY);
            if (!text) return null;
            return buildConfigFromText(text, 'Remembered custom config');
        } catch (e) {
            // LocalStorage may be disabled; fall back silently
            return null;
        }
    }

    function saveRememberedConfig(text) {
        try {
            localStorage.setItem(REMEMBER_KEY, 'true');
            localStorage.setItem(LOCAL_STORAGE_KEY, text);
        } catch (e) {
            // Fail silently; checkbox stays checked but nothing is persisted
        }
    }

    function clearRememberedConfig() {
        try {
            localStorage.removeItem(REMEMBER_KEY);
            localStorage.removeItem(LOCAL_STORAGE_KEY);
        } catch (e) {
            // noop
        }
    }

    // ----------------------------------------------------------------------
    // Event binding
    // ----------------------------------------------------------------------

    function bindEventHandlers() {
        // Drop zone
        dom.dropZone.addEventListener('click', (e) => {
            // Clicks on the inner link-button shouldn't trigger the file input
            if (e.target.closest('.link-button')) return;
            dom.fileInput.click();
        });
        dom.dropZone.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                dom.fileInput.click();
            }
        });
        dom.dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dom.dropZone.classList.add('drag-active');
        });
        dom.dropZone.addEventListener('dragleave', (e) => {
            // Only clear when leaving the drop zone, not moving between children
            if (!dom.dropZone.contains(e.relatedTarget)) {
                dom.dropZone.classList.remove('drag-active');
            }
        });
        dom.dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dom.dropZone.classList.remove('drag-active');
            handleFiles(Array.from(e.dataTransfer.files));
        });

        dom.filePickerTrigger.addEventListener('click', (e) => {
            e.stopPropagation();
            dom.fileInput.click();
        });
        dom.fileInput.addEventListener('change', (e) => {
            handleFiles(Array.from(e.target.files));
            e.target.value = '';  // allow re-selecting the same file
        });

        // Paste area
        dom.pasteScrubBtn.addEventListener('click', () => {
            const text = dom.pasteInput.value;
            if (!text.trim()) return;
            processText(text, 'pasted-text-' + Date.now() + '.txt');
            dom.pasteInput.value = '';
        });

        // Config
        dom.configFileInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (!file) return;
            loadCustomConfig(file);
            e.target.value = '';
        });
        dom.configResetBtn.addEventListener('click', () => {
            activeConfig = builtInConfig;
            if (dom.rememberConfig.checked) {
                clearRememberedConfig();
                dom.rememberConfig.checked = false;
            }
            updateConfigDisplay();
        });

        dom.configTemplateBtn.addEventListener('click', () => {
            // Download the bundled default config as a starter for the user
            // to edit in their preferred text editor, then load back in.
            downloadText(builtInConfig.text, 'log_scrubbing_config.csv');
        });

        dom.configExportBtn.addEventListener('click', () => {
            // Export the currently-loaded custom config so the user can save
            // it after editing via load-and-modify cycles.
            downloadText(activeConfig.text, 'log_scrubbing_config.csv');
        });
        dom.rememberConfig.addEventListener('change', () => {
            if (dom.rememberConfig.checked) {
                if (activeConfig && activeConfig !== builtInConfig) {
                    saveRememberedConfig(activeConfig.text);
                }
            } else {
                clearRememberedConfig();
            }
        });

        // SPL copy-to-clipboard buttons. Each .spl-copy-btn sits next to a
        // <pre><code> block; clicking copies that block's text content to the
        // clipboard. Clipboard API isn't available on file:// origins in some
        // browsers, so we have a textarea-based fallback.
        document.querySelectorAll('.spl-copy-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const block = btn.closest('.spl-block');
                if (!block) return;
                const codeEl = block.querySelector('code');
                if (!codeEl) return;
                const text = codeEl.textContent;
                copyTextToClipboard(text).then(ok => {
                    const original = btn.textContent;
                    btn.textContent = ok ? 'Copied' : 'Copy failed';
                    btn.classList.add('copied');
                    setTimeout(() => {
                        btn.textContent = original;
                        btn.classList.remove('copied');
                    }, 1500);
                });
            });
        });

        // Results
        dom.clearResultsBtn.addEventListener('click', () => {
            resultCards.forEach(card => card.element.remove());
            resultCards = [];
            updateResultsVisibility();
        });
    }

    // ----------------------------------------------------------------------
    // Config upload
    // ----------------------------------------------------------------------

    function loadCustomConfig(file) {
        const reader = new FileReader();
        reader.onload = (e) => {
            const text = e.target.result;
            try {
                activeConfig = buildConfigFromText(text, 'Custom: ' + file.name);
                updateConfigDisplay();
                if (dom.rememberConfig.checked) {
                    saveRememberedConfig(text);
                }
            } catch (err) {
                alert('Failed to parse config file: ' + err.message);
            }
        };
        reader.readAsText(file);
    }

    // ----------------------------------------------------------------------
    // File handling
    // ----------------------------------------------------------------------

    function handleFiles(files) {
        if (!files || files.length === 0) return;
        // Process sequentially so the UI stays responsive and cards appear in order
        let index = 0;
        function next() {
            if (index >= files.length) return;
            const file = files[index++];
            processFile(file, next);
        }
        next();
    }

    function processFile(file, onComplete) {
        const reader = new FileReader();
        reader.onload = (e) => {
            processText(e.target.result, file.name);
            if (onComplete) setTimeout(onComplete, 0);
        };
        reader.onerror = () => {
            buildErrorCard(file.name, 'Failed to read file');
            if (onComplete) setTimeout(onComplete, 0);
        };
        reader.readAsText(file);
    }

    function processText(text, filename) {
        const largeFile = text.length > LARGE_FILE_SPINNER_THRESHOLD;
        if (largeFile) showProcessing('Scrubbing ' + filename + '...');

        // Yield to the event loop so the spinner renders before heavy work
        setTimeout(() => {
            try {
                const scrubbed = looksLikeCsv(text, filename)
                    ? scrubCsvInput(text)
                    : scrubMultiLineInput(text);
                buildResultCard(filename, text, scrubbed);
            } catch (err) {
                buildErrorCard(filename, err.message || String(err));
            } finally {
                if (largeFile) hideProcessing();
            }
        }, largeFile ? 10 : 0);
    }

    // ----------------------------------------------------------------------
    // Format detection
    // ----------------------------------------------------------------------

    function looksLikeCsv(text, filename) {
        // Dispatch to CSV-aware scrubbing when the input is clearly tabular.
        // Heuristics (any one suffices):
        //   1. Filename ends in .csv
        //   2. First line contains '_raw' as a column header
        //   3. First line is a multi-column header (>= 3 comma-separated
        //      identifiers, no embedded JSON braces)
        if (filename && filename.toLowerCase().endsWith('.csv')) return true;

        const firstNewline = text.indexOf('\n');
        const firstLine = firstNewline === -1 ? text : text.substring(0, firstNewline);
        if (!firstLine) return false;

        // Splunk exports always have _raw when samples CSV
        if (firstLine.indexOf('_raw') !== -1 && firstLine.indexOf(',') !== -1) {
            return true;
        }

        // Look like a header row? Many comma-separated tokens that are plain
        // identifiers/quoted-identifiers, no braces, no protocol schemes.
        if (firstLine.indexOf('{') !== -1 || firstLine.indexOf('://') !== -1) {
            return false;
        }
        const commaCount = (firstLine.match(/,/g) || []).length;
        if (commaCount >= 2) {
            // Check tokens look like identifiers (header-ish), not arbitrary text
            const tokens = firstLine.split(',').map(t => t.trim().replace(/^"|"$/g, ''));
            const identifierish = tokens.filter(t => /^[A-Za-z_][A-Za-z0-9_.:-]*$/.test(t)).length;
            // If most tokens look like column names, it's a CSV header
            if (identifierish / tokens.length >= 0.7) return true;
        }

        return false;
    }

    // ----------------------------------------------------------------------
    // CSV-aware scrubbing
    //
    // Splunk CSV exports contain the same sensitive data redundantly across
    // many columns (_raw plus hundreds of extracted fields). Scrubbing only
    // _raw would leave the other columns exposed. This function parses the
    // CSV, scrubs every cell through the scrubber (with the column name
    // passed as fieldName so @json-field-name shortcuts still apply), and
    // re-emits a valid CSV.
    // ----------------------------------------------------------------------

    function scrubCsvInput(text) {
        const rows = parseCsv(text);
        if (rows.length === 0) return text;

        const header = rows[0];
        const out = [formatCsvRow(header)];

        for (let r = 1; r < rows.length; r++) {
            const row = rows[r];
            const scrubbedRow = [];
            for (let c = 0; c < row.length; c++) {
                const cellValue = row[c];
                const columnName = c < header.length ? header[c] : null;
                if (cellValue && cellValue.trim()) {
                    scrubbedRow.push(window.Paydirt.scrubText(
                        cellValue,
                        activeConfig.textRules,
                        activeConfig.jsonFieldRules,
                        { fieldName: columnName }
                    ));
                } else {
                    scrubbedRow.push(cellValue);
                }
            }
            out.push(formatCsvRow(scrubbedRow));
        }

        return out.join('\r\n') + '\r\n';
    }

    // RFC 4180-ish CSV parser. Handles quoted fields with embedded commas,
    // newlines, and escaped quotes ("" -> "). Tolerates both \n and \r\n
    // line endings and unterminated final rows.
    function parseCsv(text) {
        const rows = [];
        let row = [];
        let field = '';
        let inQuotes = false;
        let i = 0;
        while (i < text.length) {
            const c = text[i];
            if (inQuotes) {
                if (c === '"') {
                    if (text[i + 1] === '"') {
                        field += '"';
                        i += 2;
                        continue;
                    }
                    inQuotes = false;
                    i++;
                    continue;
                }
                field += c;
                i++;
            } else {
                if (c === '"') {
                    inQuotes = true;
                    i++;
                } else if (c === ',') {
                    row.push(field);
                    field = '';
                    i++;
                } else if (c === '\n' || c === '\r') {
                    row.push(field);
                    rows.push(row);
                    row = [];
                    field = '';
                    if (c === '\r' && text[i + 1] === '\n') i += 2;
                    else i++;
                } else {
                    field += c;
                    i++;
                }
            }
        }
        if (field.length > 0 || row.length > 0) {
            row.push(field);
            rows.push(row);
        }
        return rows;
    }

    // Format a row back to CSV. Quotes any field that contains comma, quote,
    // newline, or carriage-return, and doubles embedded quotes. Matches
    // Python's csv module default dialect.
    function formatCsvRow(row) {
        return row.map(formatCsvField).join(',');
    }

    function formatCsvField(value) {
        if (value === null || value === undefined) return '';
        const s = String(value);
        if (s.indexOf(',') !== -1 || s.indexOf('"') !== -1 ||
            s.indexOf('\n') !== -1 || s.indexOf('\r') !== -1) {
            return '"' + s.replace(/"/g, '""') + '"';
        }
        return s;
    }

    // ----------------------------------------------------------------------
    // Scrubbing: run the full input through scrubber.js event-by-event
    // This mirrors the Python _scrub_samples_text_format logic so we behave
    // the same way for multi-line JSON, JSONL, and plain-text log inputs.
    // ----------------------------------------------------------------------

    function scrubMultiLineInput(content) {
        const lines = content.split(/(?<=\n)/);  // keep newline terminators
        const events = [];
        let jsonBuffer = [];
        let braceDepth = 0;

        for (const line of lines) {
            const stripped = line.trim();
            if (jsonBuffer.length > 0 || (stripped.startsWith('{') && braceDepth === 0)) {
                jsonBuffer.push(line);
                // Count braces outside strings. Simple approximation.
                for (const ch of stripped) {
                    if (ch === '{') braceDepth++;
                    if (ch === '}') braceDepth--;
                }
                if (braceDepth <= 0) {
                    events.push(jsonBuffer.join(''));
                    jsonBuffer = [];
                    braceDepth = 0;
                }
            } else if (stripped) {
                events.push(line);
            } else {
                // Preserve blank lines in the output
                events.push(line);
            }
        }
        if (jsonBuffer.length > 0) events.push(jsonBuffer.join(''));

        const scrubbed = events.map(ev => {
            if (!ev.trim()) return ev;
            return window.Paydirt.scrubText(ev, activeConfig.textRules, activeConfig.jsonFieldRules);
        });
        return scrubbed.join('');
    }

    // ----------------------------------------------------------------------
    // Result card building
    // ----------------------------------------------------------------------

    function buildResultCard(filename, original, scrubbed) {
        const card = dom.resultCardTemplate.content.firstElementChild.cloneNode(true);
        const cardId = 'card-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8);
        card.dataset.cardId = cardId;

        // Populate header
        card.querySelector('.result-filename').textContent = filename;
        card.querySelector('.result-size').textContent = formatBytes(original.length) + ' -> ' + formatBytes(scrubbed.length);

        // Populate Scrubbed tab
        const scrubbedPre = card.querySelector('.scrubbed-pre');
        scrubbedPre.textContent = scrubbed;

        // Populate Comparison tab (with line-level diff and synced scroll)
        populateComparison(card, original, scrubbed);

        // Populate Summary tab
        populateSummary(card, original, scrubbed);

        // Wire up tab switching
        wireUpTabs(card);

        // Wire up download + remove
        card.querySelector('[data-action="download"]').addEventListener('click', () => {
            downloadText(scrubbed, buildScrubbedFilename(filename));
        });
        card.querySelector('[data-action="remove"]').addEventListener('click', () => {
            card.remove();
            resultCards = resultCards.filter(c => c.id !== cardId);
            updateResultsVisibility();
        });

        // Insert at top of results (most recent first)
        dom.resultsContainer.insertBefore(card, dom.resultsContainer.firstChild);
        resultCards.push({id: cardId, filename, element: card});
        updateResultsVisibility();
    }

    function buildErrorCard(filename, message) {
        const card = dom.resultCardTemplate.content.firstElementChild.cloneNode(true);
        card.classList.add('has-error');
        card.querySelector('.result-filename').textContent = filename;
        card.querySelector('.result-size').textContent = 'error';
        // Replace tab panels with an error message
        const panelsContainer = card.querySelector('.result-tab-panels');
        panelsContainer.innerHTML = '';
        const errDiv = document.createElement('div');
        errDiv.className = 'error-content';
        errDiv.textContent = 'Could not scrub this file: ' + message;
        panelsContainer.appendChild(errDiv);
        card.querySelector('.result-tabs').remove();
        card.querySelector('[data-action="download"]').remove();
        card.querySelector('[data-action="remove"]').addEventListener('click', () => {
            card.remove();
            updateResultsVisibility();
        });
        dom.resultsContainer.insertBefore(card, dom.resultsContainer.firstChild);
        updateResultsVisibility();
    }

    function updateResultsVisibility() {
        const hasAny = dom.resultsContainer.querySelector('.result-card') !== null;
        dom.resultsEmpty.hidden = hasAny;
        dom.clearResultsBtn.hidden = !hasAny;
    }

    function buildScrubbedFilename(filename) {
        const ts = new Date().toISOString().slice(0, 19).replace(/[-:T]/g, '').replace(/^(\d{8})(\d{6})/, '$1_$2');
        const dotIdx = filename.lastIndexOf('.');
        if (dotIdx > 0) {
            return filename.slice(0, dotIdx) + '_scrubbed_' + ts + filename.slice(dotIdx);
        }
        return filename + '_scrubbed_' + ts;
    }

    // ----------------------------------------------------------------------
    // Tab wiring
    // ----------------------------------------------------------------------

    function wireUpTabs(card) {
        const tabs = Array.from(card.querySelectorAll('.result-tab'));
        const panels = Array.from(card.querySelectorAll('.result-tab-panel'));
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const target = tab.dataset.tab;
                tabs.forEach(t => t.setAttribute('aria-selected', t.dataset.tab === target ? 'true' : 'false'));
                panels.forEach(p => {
                    p.hidden = (p.dataset.panel !== target);
                });
            });
        });
    }

    // ----------------------------------------------------------------------
    // Comparison view
    // ----------------------------------------------------------------------

    function populateComparison(card, original, scrubbed) {
        const originalPane = card.querySelector('.original-pane');
        const scrubbedPane = card.querySelector('.scrubbed-pane');
        const notice = card.querySelector('[data-panel="comparison"] .truncation-notice');

        // Split into lines, keeping them aligned
        const origLines = original.split('\n');
        const scrubLines = scrubbed.split('\n');
        const lineCount = Math.max(origLines.length, scrubLines.length);

        // Determine truncation
        let truncated = false;
        let maxLines = lineCount;
        if (lineCount > COMPARISON_MAX_LINES) {
            maxLines = COMPARISON_MAX_LINES;
            truncated = true;
        }
        // Also cap by byte budget - use original as the reference
        let byteBudget = COMPARISON_MAX_BYTES;
        let byteCappedAt = null;
        for (let i = 0; i < maxLines; i++) {
            byteBudget -= (origLines[i] ? origLines[i].length + 1 : 1);
            if (byteBudget <= 0) {
                byteCappedAt = i + 1;
                break;
            }
        }
        if (byteCappedAt !== null && byteCappedAt < maxLines) {
            maxLines = byteCappedAt;
            truncated = true;
        }

        // Precompute the replacement values for config rules so the scrubbed-
        // side highlighter knows what to look for beyond the built-in tokens.
        const configReplacements = gatherConfigReplacements();

        // Build line elements. For alignment, when one side has fewer lines,
        // we pad with empty lines on that side.
        const origFragment = document.createDocumentFragment();
        const scrubFragment = document.createDocumentFragment();

        for (let i = 0; i < maxLines; i++) {
            const origLine = origLines[i] !== undefined ? origLines[i] : '';
            const scrubLine = scrubLines[i] !== undefined ? scrubLines[i] : '';

            const lineChanged = origLine !== scrubLine;
            const isCuiLine = lineChanged && scrubLine.indexOf('[CUI-REDACTED:') !== -1;

            // Original-side highlighting: mark the ranges that WOULD be
            // scrubbed (built-in patterns + config search-terms + CUI markings).
            const origSpan = makeHighlightedLineSpan(origLine, highlightRangesForOriginal(origLine, configReplacements));

            // Scrubbed-side highlighting: mark the replacement tokens present
            // in the output (built-in replacements + config replacement values
            // + CUI placeholders).
            const scrubSpan = makeHighlightedLineSpan(scrubLine, highlightRangesForScrubbed(scrubLine, configReplacements));

            // Soft row background for any changed line, so quick scroll-by-
            // scan still shows which rows changed even when a span is small.
            if (lineChanged) {
                const rowClass = isCuiLine ? 'line-cui' : 'line-modified';
                origSpan.classList.add(rowClass);
                scrubSpan.classList.add(rowClass);
            }

            origFragment.appendChild(origSpan);
            scrubFragment.appendChild(scrubSpan);
        }

        originalPane.appendChild(origFragment);
        scrubbedPane.appendChild(scrubFragment);

        if (truncated) {
            notice.hidden = false;
            notice.textContent =
                'Showing first ' + maxLines + ' lines of ' + lineCount +
                '. The full scrubbed file is downloadable above.';
        }

        // Synchronized scrolling
        setupSyncedScroll(originalPane, scrubbedPane);
    }

    // ----------------------------------------------------------------------
    // Per-field highlighting (Option B: replacement-aware)
    //
    // Rather than running a general-purpose text diff, we exploit the fact
    // that we OWN the scrubber: we know every pattern it looks for, and
    // every replacement token it writes. So we can highlight precisely the
    // things the scrubber cares about, categorized by type, on both the
    // original and scrubbed sides.
    //
    // Each highlighter returns a list of {start, end, kind} ranges which
    // are then merged (overlaps resolved, first-wins) and rendered as
    // <span class="hl-<kind>"> wrappers.
    //
    // Categories:
    //   'pii' - PII / credential / token redactions (yellow)
    //   'cui' - CUI marking redactions (orange)
    //   'custom' - config-rule replacements (soft red)
    // ----------------------------------------------------------------------

    function gatherConfigReplacements() {
        // Extract unique literal replacement tokens from the active config so
        // we can find them in the scrubbed output. Random-mode rules contribute
        // all their choices. Duplicates are deduplicated. The search-term side
        // (used for original-side highlighting) is a separate list.
        const replacementTokens = new Set();
        const searchTerms = new Set();

        for (const [term, mode, values] of activeConfig.textRules) {
            searchTerms.add(term);
            if (mode === 'random') {
                values.split(',').map(v => v.trim()).filter(Boolean)
                      .forEach(v => replacementTokens.add(v));
            } else {
                if (values) replacementTokens.add(values);
            }
        }
        for (const [field, mode, values] of activeConfig.jsonFieldRules) {
            if (mode === 'random') {
                values.split(',').map(v => v.trim()).filter(Boolean)
                      .forEach(v => replacementTokens.add(v));
            } else {
                if (values) replacementTokens.add(values);
            }
        }

        // Drop empty strings and very short tokens (< 2 chars) to avoid
        // matching incidental characters like a literal '-' or ','.
        const filterSet = (s) => Array.from(s).filter(t => t && t.length >= 2);
        return {
            replacementTokens: filterSet(replacementTokens),
            searchTerms: filterSet(searchTerms),
        };
    }

    // Built-in PII/token patterns used to locate sensitive content in the
    // ORIGINAL text. Mirrors the SUMMARY_CATEGORIES patterns. We also include
    // a pattern for the whole CUI-marking category so we can tag original-side
    // spans as 'cui' vs 'pii'.
    const ORIGINAL_PII_PATTERNS = [
        /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,                               // IP
        /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,                  // email
        /\bip-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\b/g,                               // AWS ip-host
        /\b[A-Z][A-Z0-9_-]+\\[a-zA-Z0-9._-]+\b/g,                                // DOMAIN\user
        /\\\\[a-zA-Z0-9._-]+\\[a-zA-Z0-9._$-]+/g,                                // UNC
        /\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g,                            // MAC
        /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,                // SSN
        /(?<!\d)(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?!\d)/g,          // phone
        /\bS-1-5-21-\d+-\d+-\d+-\d+\b/g,                                         // Windows SID
        /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g,                                          // AWS key
        /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,                // JWT
        /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g,                                       // GitHub PAT
        /\bxox[baprs]-[0-9a-zA-Z-]{10,}\b/g,                                     // Slack
        /\bsk_(?:live|test)_[0-9a-zA-Z]{24,}\b/g,                                // Stripe
        /\bAIza[0-9A-Za-z\-_]{35}\b/g,                                           // Google API
        /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g,
        /Authorization\s*:\s*(?:Bearer|Basic|Digest|Token)\s+\S+/gi,             // auth header
        // FQDNs excluding well-known-public (mirrors scrubber logic)
        new RegExp(
            '\\b(?!(?:schemas\\.microsoft\\.com|schemas\\.xmlsoap\\.org|' +
            'schemas\\.openxmlformats\\.org|www\\.w3\\.org|www\\.iana\\.org|' +
            'xmlns\\.com|tools\\.ietf\\.org|docs\\.oasis-open\\.org|' +
            'purl\\.org|ns\\.adobe\\.com)\\b)' +
            '[a-zA-Z0-9-]+\\.[a-zA-Z0-9-]+\\.(?:com|net|org|io|local|internal)\\b',
            'g'
        ),
    ];

    // CUI markings - these redact an entire line; highlight the marking
    // itself so the user sees what triggered the whole-line redaction.
    const ORIGINAL_CUI_PATTERNS = [
        /\b(CUI|CONTROLLED)(?:\/\/(?:SP-[A-Z]+|BASIC|NOFORN|FEDCON|FED ONLY|DL ONLY|REL TO [A-Z, ]+))*\b/g,
        /\((CUI|U\/\/FOUO|U\/\/SBU|U\/\/LES|C|U|FOUO|SBU|LES)(?:\/\/[A-Z-]+)?\)/g,
        /\b(FOUO|SBU|LES|OUO|LIMDIS|NOFORN|FEDCON|ORCON)\b/g,
        /\b(ITAR|EAR99|ECCN\s*[0-9A-Z]+|DD\s*254|FCI)\b/g,
    ];

    function highlightRangesForOriginal(line, configReplacements) {
        if (!line) return [];
        const ranges = [];

        for (const re of ORIGINAL_PII_PATTERNS) {
            re.lastIndex = 0;
            let m;
            while ((m = re.exec(line)) !== null) {
                // Credit-card pattern is handled separately because Luhn-validation
                // is required (not done here - we only highlight candidates).
                ranges.push({ start: m.index, end: m.index + m[0].length, kind: 'pii' });
                if (m[0].length === 0) re.lastIndex++;
            }
        }

        // CC candidate + Luhn validation
        const ccRe = /\b\d(?:[ -]?\d){12,18}\b/g;
        let cm;
        while ((cm = ccRe.exec(line)) !== null) {
            const digits = cm[0].replace(/\D/g, '');
            if (window.Paydirt.luhnValid(digits)) {
                ranges.push({ start: cm.index, end: cm.index + cm[0].length, kind: 'pii' });
            }
            if (cm[0].length === 0) ccRe.lastIndex++;
        }

        for (const re of ORIGINAL_CUI_PATTERNS) {
            re.lastIndex = 0;
            let m;
            while ((m = re.exec(line)) !== null) {
                ranges.push({ start: m.index, end: m.index + m[0].length, kind: 'cui' });
                if (m[0].length === 0) re.lastIndex++;
            }
        }

        // Config search-term literal matches. Apply a word-boundary check to
        // avoid highlighting a substring that happens to appear inside a
        // longer token (e.g., '000000000000' inside hex '0x8020000000000000'
        // would otherwise be flagged as a custom-rule match).
        for (const term of configReplacements.searchTerms) {
            let idx = 0;
            while ((idx = line.indexOf(term, idx)) !== -1) {
                if (isWordBoundaryMatch(line, idx, term.length)) {
                    ranges.push({ start: idx, end: idx + term.length, kind: 'custom' });
                }
                idx += term.length;
            }
        }

        return resolveOverlaps(ranges);
    }

    // Returns true if the substring at [start, start+length) is bordered on
    // both sides by non-word characters (or string boundary). Mirrors the
    // behavior of a regex \b on either side of a plain indexOf match. Used
    // to avoid false-positive highlighting when a short replacement token
    // happens to appear as a substring of a longer identifier.
    //
    // Word character = [A-Za-z0-9_]. If the token's first or last character
    // is already non-word (e.g. '@acme.com' starts with '@'), that side is
    // treated as a boundary because a word-boundary requires a word-to-
    // non-word transition and we don't have one to violate there.
    function isWordBoundaryMatch(text, start, length) {
        const end = start + length;
        const WORD_CHAR = /[A-Za-z0-9_]/;
        const firstChar = text[start];
        const lastChar = text[end - 1];
        if (WORD_CHAR.test(firstChar)) {
            // Left side must be start-of-line or a non-word char
            if (start > 0 && WORD_CHAR.test(text[start - 1])) return false;
        }
        if (WORD_CHAR.test(lastChar)) {
            // Right side must be end-of-line or a non-word char
            if (end < text.length && WORD_CHAR.test(text[end])) return false;
        }
        return true;
    }

    // Replacement tokens the scrubber writes into the output. Mirrors the
    // Python+JS replacement values exactly.
    const SCRUBBED_REPLACEMENT_TOKENS = [
        { pattern: /10\.0\.0\.x/g, kind: 'pii' },
        { pattern: /user@example\.com/g, kind: 'pii' },
        { pattern: /ip-10-0-0-x/g, kind: 'pii' },
        { pattern: /host\.example\.com/g, kind: 'pii' },
        { pattern: /\\\\SERVER\\SHARE/g, kind: 'pii' },
        { pattern: /\bDOMAIN\\user\b/g, kind: 'pii' },
        { pattern: /00:00:00:00:00:00/g, kind: 'pii' },
        { pattern: /000-00-0000/g, kind: 'pii' },
        { pattern: /4111-1111-1111-1111/g, kind: 'pii' },
        { pattern: /555-555-5555/g, kind: 'pii' },
        { pattern: /S-1-5-21-0-0-0-0/g, kind: 'pii' },
        { pattern: /\bAKIAREDACTEDREDACTED\b/g, kind: 'pii' },
        { pattern: /\beyJREDACTED\.REDACTED\.REDACTED\b/g, kind: 'pii' },
        { pattern: /\bghp_REDACTED\b/g, kind: 'pii' },
        { pattern: /\bxoxb-REDACTED\b/g, kind: 'pii' },
        { pattern: /\bsk_test_REDACTED\b/g, kind: 'pii' },
        { pattern: /\bAIzaREDACTED\b/g, kind: 'pii' },
        { pattern: /\[REDACTED_PRIVATE_KEY\]/g, kind: 'pii' },
        { pattern: /1234567893/g, kind: 'pii' },  // NPI replacement
        { pattern: /(Authorization\s*:\s*(?:Bearer|Basic|Digest|Token))\s+REDACTED\b/gi, kind: 'pii' },
        { pattern: /([?&](?:password|passwd|pwd|token|api_key|apikey|access_token|refresh_token|auth|authorization|secret|session|sessionid|sid)=)REDACTED\b/gi, kind: 'pii' },
        // CUI placeholder
        { pattern: /\[CUI-REDACTED: [^\]]+\]/g, kind: 'cui' },
    ];

    function highlightRangesForScrubbed(line, configReplacements) {
        if (!line) return [];
        const ranges = [];

        for (const { pattern, kind } of SCRUBBED_REPLACEMENT_TOKENS) {
            pattern.lastIndex = 0;
            let m;
            while ((m = pattern.exec(line)) !== null) {
                ranges.push({ start: m.index, end: m.index + m[0].length, kind });
                if (m[0].length === 0) pattern.lastIndex++;
            }
        }

        // Config replacement tokens: literal-match each unique replacement,
        // with word-boundary checks so zero-padded hex or longer identifiers
        // that happen to contain a replacement token as a substring are not
        // incorrectly highlighted.
        for (const token of configReplacements.replacementTokens) {
            let idx = 0;
            while ((idx = line.indexOf(token, idx)) !== -1) {
                if (isWordBoundaryMatch(line, idx, token.length)) {
                    ranges.push({ start: idx, end: idx + token.length, kind: 'custom' });
                }
                idx += token.length;
            }
        }

        return resolveOverlaps(ranges);
    }

    function resolveOverlaps(ranges) {
        // Sort by start, then by earlier-end-first so we get a stable order.
        // Then walk the list and drop any range that starts before the previous
        // one ended. First-wins so PII patterns take precedence over FQDN,
        // and so on. Good enough for visual highlighting.
        if (ranges.length <= 1) return ranges;
        const sorted = ranges.slice().sort((a, b) =>
            a.start - b.start || a.end - b.end);
        const out = [sorted[0]];
        for (let i = 1; i < sorted.length; i++) {
            const r = sorted[i];
            const last = out[out.length - 1];
            if (r.start >= last.end) {
                out.push(r);
            }
            // else: skip (overlap, first-wins)
        }
        return out;
    }

    function makeHighlightedLineSpan(line, ranges) {
        // Build a line element that mixes plain text with highlighted spans.
        // textContent is used for each piece to preserve XSS-safety (no HTML
        // injection from user data).
        const lineSpan = document.createElement('span');
        lineSpan.className = 'comparison-line';
        if (line.length === 0) {
            lineSpan.textContent = '\u200B';  // zero-width space so row is visible
            return lineSpan;
        }

        if (ranges.length === 0) {
            lineSpan.textContent = line;
            return lineSpan;
        }

        let cursor = 0;
        for (const r of ranges) {
            // Text before this range
            if (r.start > cursor) {
                lineSpan.appendChild(document.createTextNode(line.substring(cursor, r.start)));
            }
            // Highlighted range
            const hl = document.createElement('span');
            hl.className = 'hl hl-' + r.kind;
            hl.textContent = line.substring(r.start, r.end);
            lineSpan.appendChild(hl);
            cursor = r.end;
        }
        // Trailing text
        if (cursor < line.length) {
            lineSpan.appendChild(document.createTextNode(line.substring(cursor)));
        }
        return lineSpan;
    }

    function setupSyncedScroll(paneA, paneB) {
        // Bidirectional synced scrolling. A flag prevents feedback loops when
        // one pane's programmatic scroll triggers the other's scroll handler.
        let syncing = false;
        function sync(source, target) {
            if (syncing) return;
            syncing = true;
            // Percentage-based sync so different content heights still track
            const sMax = source.scrollHeight - source.clientHeight;
            const tMax = target.scrollHeight - target.clientHeight;
            if (sMax > 0 && tMax > 0) {
                target.scrollTop = (source.scrollTop / sMax) * tMax;
            } else {
                target.scrollTop = source.scrollTop;
            }
            target.scrollLeft = source.scrollLeft;
            // Release the lock after the scroll event has been processed
            requestAnimationFrame(() => { syncing = false; });
        }
        paneA.addEventListener('scroll', () => sync(paneA, paneB));
        paneB.addEventListener('scroll', () => sync(paneB, paneA));
    }

    // ----------------------------------------------------------------------
    // Summary tab
    // ----------------------------------------------------------------------

    function populateSummary(card, original, scrubbed) {
        const container = card.querySelector('.summary-content');
        const counts = computeRedactionCounts(original, scrubbed);
        const totalRedactions = counts.reduce((sum, c) => sum + c.count, 0);
        const usingDefaults = (activeConfig === builtInConfig);

        if (totalRedactions === 0) {
            const clean = document.createElement('div');
            clean.className = 'summary-clean-notice';
            clean.textContent = 'No sensitive data was detected or redacted. Review the original manually to confirm.';
            container.appendChild(clean);

            // Extra nudge when nothing matched AND the user hasn't customized.
            if (usingDefaults) {
                container.appendChild(makeConfigNudge(
                    "Most real-world logs contain environment-specific identifiers " +
                    "(internal hostnames, usernames, project codenames) that Paydirt " +
                    "can't recognize without your help. Click 'Download template' in " +
                    "the Configuration section above to get a starter config you can " +
                    "edit with your own rules."
                ));
            }
        } else {
            const group = document.createElement('div');
            group.className = 'summary-group';
            const title = document.createElement('h3');
            title.className = 'summary-group-title';
            title.textContent = 'Redactions';
            group.appendChild(title);

            const countsEl = document.createElement('div');
            countsEl.className = 'summary-counts';
            counts.forEach(c => {
                if (c.count === 0) return;
                const row = document.createElement('div');
                row.className = 'summary-count';
                const label = document.createElement('span');
                label.className = 'summary-count-label';
                label.textContent = c.label;
                const value = document.createElement('span');
                value.className = 'summary-count-value';
                value.textContent = c.count.toString();
                row.appendChild(label);
                row.appendChild(value);
                countsEl.appendChild(row);
            });
            group.appendChild(countsEl);
            container.appendChild(group);

            // Low-redaction nudge: user got SOMETHING but using defaults and
            // the count seems light for a real log file.
            const looksLight = totalRedactions < 3 || (totalRedactions / Math.max(1, original.length / 1024) < 0.5);
            if (usingDefaults && looksLight) {
                container.appendChild(makeConfigNudge(
                    "Only " + totalRedactions + " redaction" + (totalRedactions === 1 ? '' : 's') +
                    " with the built-in defaults. Real log data usually contains " +
                    "environment-specific identifiers (hostnames, usernames, custom IDs) " +
                    "that need explicit rules. Click 'Download template' in the " +
                    "Configuration section above to start customizing."
                ));
            }
        }

        // Metadata footer: config source, input/output bytes, timestamp
        const meta = document.createElement('div');
        meta.className = 'summary-meta';
        const metaItems = [
            { label: 'Config', value: activeConfig.source },
            { label: 'Original', value: formatBytes(original.length) },
            { label: 'Scrubbed', value: formatBytes(scrubbed.length) },
            { label: 'Scrubbed at', value: new Date().toLocaleString() },
        ];
        metaItems.forEach(item => {
            const row = document.createElement('span');
            row.className = 'summary-meta-item';
            const l = document.createElement('span');
            l.className = 'summary-meta-item-label';
            l.textContent = item.label + ':';
            const v = document.createElement('span');
            v.className = 'summary-meta-item-value';
            v.textContent = item.value;
            row.appendChild(l);
            row.appendChild(v);
            meta.appendChild(row);
        });
        container.appendChild(meta);
    }

    function makeConfigNudge(message) {
        // Build a styled info panel for guiding users toward custom configs.
        // Used in the Summary tab when zero or very few redactions occurred
        // while the user is still on the built-in defaults.
        const nudge = document.createElement('div');
        nudge.className = 'summary-nudge';
        const icon = document.createElement('span');
        icon.className = 'summary-nudge-icon';
        icon.setAttribute('aria-hidden', 'true');
        icon.textContent = 'i';
        const text = document.createElement('span');
        text.className = 'summary-nudge-text';
        text.textContent = message;
        nudge.appendChild(icon);
        nudge.appendChild(text);
        return nudge;
    }

    function computeRedactionCounts(original, scrubbed) {
        // For each category, count how many matches appear in the original
        // that do NOT survive into the scrubbed output. This gives a
        // reasonable "things we redacted" count per category.
        const results = [];

        for (const cat of SUMMARY_CATEGORIES) {
            let count = 0;

            if (cat.matcher === 'cuiMarker') {
                // CUI redaction is whole-line: count the [CUI-REDACTED ...]
                // placeholders in the scrubbed text.
                const matches = scrubbed.match(/\[CUI-REDACTED:[^\]]+\]/g);
                count = matches ? matches.length : 0;
            } else if (cat.matcher === 'luhnCc') {
                // Luhn-valid credit card numbers in original that are not in scrubbed
                const candidateRe = /\b\d(?:[ -]?\d){12,18}\b/g;
                const origMatches = original.match(candidateRe) || [];
                for (const m of origMatches) {
                    const digits = m.replace(/\D/g, '');
                    if (window.Paydirt.luhnValid(digits) && scrubbed.indexOf(m) === -1) {
                        count++;
                    }
                }
            } else if (cat.pattern) {
                const origMatches = original.match(cat.pattern) || [];
                for (const m of origMatches) {
                    // A match was redacted if it doesn't appear in the scrubbed output,
                    // OR if it's equal to the replacement token (already scrubbed input).
                    if (cat.ignoreReplacement && m === cat.ignoreReplacement) continue;
                    if (scrubbed.indexOf(m) === -1) count++;
                }
            }

            results.push({ label: cat.label, count });
        }

        // Custom rule counts: for each text rule and each @json rule, count
        // how many times the rule's search term appears in the original that
        // was replaced (i.e., doesn't appear in scrubbed output with the same
        // literal text). We keep these as individual per-rule counts with a
        // label like "Custom: MDI-LEGION" so users can see exactly which
        // rules fired and how often.
        for (const [term, mode, replValues] of activeConfig.textRules) {
            if (!term) continue;
            // Count literal occurrences in original, subtract occurrences still
            // in scrubbed (in case the rule didn't fire on all of them).
            const origCount = countSubstring(original, term);
            const scrubCount = countSubstring(scrubbed, term);
            const redacted = Math.max(0, origCount - scrubCount);
            if (redacted > 0) {
                results.push({
                    label: 'Custom: ' + truncateLabel(term),
                    count: redacted,
                    isCustom: true,
                });
            }
        }

        return results;
    }

    // Count non-overlapping literal occurrences of needle in haystack.
    function countSubstring(haystack, needle) {
        if (!needle) return 0;
        let count = 0;
        let idx = 0;
        while ((idx = haystack.indexOf(needle, idx)) !== -1) {
            count++;
            idx += needle.length;
        }
        return count;
    }

    function truncateLabel(s) {
        return s.length > 40 ? s.substring(0, 37) + '...' : s;
    }

    // ----------------------------------------------------------------------
    // Download
    // ----------------------------------------------------------------------

    function downloadText(text, filename) {
        // Build a Blob and trigger a download via a temporary anchor tag.
        // No network round-trip, no third-party services.
        const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        // Revoke URL after a short delay so the download has time to start
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    function copyTextToClipboard(text) {
        // Modern Clipboard API path. Returns a Promise that resolves to true
        // on success, false on failure. The Clipboard API requires a secure
        // context, which file:// is treated as in modern browsers; if it's
        // not available for any reason, fall back to the legacy textarea
        // selection approach.
        if (navigator.clipboard && navigator.clipboard.writeText) {
            return navigator.clipboard.writeText(text)
                .then(() => true)
                .catch(() => copyTextToClipboardFallback(text));
        }
        return Promise.resolve(copyTextToClipboardFallback(text));
    }

    function copyTextToClipboardFallback(text) {
        // Legacy fallback: temporary off-screen textarea + execCommand.
        // Works in older browsers and on origins where Clipboard API is
        // restricted. Returns boolean (synchronous).
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.top = '-9999px';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        let ok = false;
        try {
            ok = document.execCommand('copy');
        } catch (_) {
            ok = false;
        }
        document.body.removeChild(ta);
        return ok;
    }

    // ----------------------------------------------------------------------
    // Processing overlay
    // ----------------------------------------------------------------------

    function showProcessing(text) {
        dom.processingText.textContent = text || 'Scrubbing...';
        dom.processingOverlay.hidden = false;
    }

    function hideProcessing() {
        dom.processingOverlay.hidden = true;
    }

    // ----------------------------------------------------------------------
    // Utilities
    // ----------------------------------------------------------------------

    function formatBytes(n) {
        if (n < 1024) return n + ' B';
        if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
        return (n / (1024 * 1024)).toFixed(2) + ' MB';
    }

    // ----------------------------------------------------------------------
    // Go
    // ----------------------------------------------------------------------

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
