// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Machine Data Insights Inc.
// https://machinedatainsights.com
//
// ============================================================================
// Paydirt - Log Scrubber (JavaScript Port)
//
// Scrubs CUI, PII, PHI, credentials, and other sensitive data from Splunk
// field-value exports and log samples. Ports the exact behavior of the Python
// log_scrubber.py so both tools produce identical output for identical input.
//
// Pipeline, in order:
//   1. @json field-name shortcut (for fieldsummary data)
//   2. CUI marking detection (full-value redaction when triggered)
//   3. Credential & token patterns (AWS keys, JWTs, PEM blocks, etc.)
//   4. Original built-in patterns (IP, email, FQDN, UNC, DOMAIN\user, MAC)
//   5. Additional PII (SSN, Luhn-valid CCs, phone, Windows SIDs, NPIs)
//   6. Custom text substitution rules from config
//   7. JSON field-level scrubbing (parsed walk + regex fallback)
//
// Human-readable by design. Function names, comments, and structure mirror
// log_scrubber.py so a reader can cross-reference the two.
// ============================================================================

const PAYDIRT_VERSION = '1.2.0';

// ============================================================================
// CUI Marking Detection (CMMC / NIST SP 800-171)
// ============================================================================
//
// CUI is identified by banner/portion/legacy markings, not by content patterns.
// When a marking is present, the entire value is redacted with a metadata-only
// placeholder that preserves category and byte count for downstream LLM use.

const CUI_BANNER_RE = /\b(CUI|CONTROLLED)(?:\/\/(?:SP-[A-Z]+|BASIC|NOFORN|FEDCON|FED ONLY|DL ONLY|REL TO [A-Z, ]+))*\b/;

const CUI_PORTION_RE = /\((CUI|U\/\/FOUO|U\/\/SBU|U\/\/LES|C|U|FOUO|SBU|LES)(?:\/\/[A-Z-]+)?\)/;

const CUI_LEGACY_RE = /\b(FOUO|SBU|LES|OUO|LIMDIS|NOFORN|FEDCON|ORCON)\b/;

const CUI_ADJACENT_RE = /\b(ITAR|EAR99|ECCN\s*[0-9A-Z]+|DD\s*254|FCI)\b/;


function detectCui(text) {
    // Scan text for CUI markings. Returns the CUI category string if found,
    // else null. Detection order: banner > portion > legacy > adjacent.
    if (!text) return null;

    let m = text.match(CUI_BANNER_RE);
    if (m) return m[0];

    m = text.match(CUI_PORTION_RE);
    if (m) return m[0].replace(/[()]/g, '');

    m = text.match(CUI_LEGACY_RE);
    if (m) return 'LEGACY:' + m[0];

    m = text.match(CUI_ADJACENT_RE);
    if (m) return 'ADJACENT:' + m[0];

    return null;
}


function redactCui(text, category) {
    // Replace CUI-tainted content with a metadata-only placeholder.
    // Preserve leading/trailing whitespace so line boundaries survive when
    // an entire log line is redacted in samples mode.
    const leadingMatch = text.match(/^\s*/);
    const trailingMatch = text.match(/\s*$/);
    const leadingWs = leadingMatch ? leadingMatch[0] : '';
    const trailingWs = trailingMatch ? trailingMatch[0] : '';
    const core = text.trim();
    return leadingWs + '[CUI-REDACTED: ' + category + ', ' + core.length + ' bytes]' + trailingWs;
}


// ============================================================================
// Credential & Token Patterns
// ============================================================================
//
// Run BEFORE the generic IP/email/FQDN patterns so tokens containing IP-shaped
// or email-shaped substrings aren't corrupted. Each pattern has a known prefix
// or structural anchor to minimize false positives.

const CREDENTIAL_PATTERNS = [
    // PEM private key blocks - match the whole block including newlines.
    [/-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g,
     '[REDACTED_PRIVATE_KEY]'],

    // AWS access key IDs (AKIA = long-term, ASIA = STS)
    [/\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, 'AKIAREDACTEDREDACTED'],

    // GitHub personal access tokens (classic ghp_, OAuth gho_, etc.)
    [/\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, 'ghp_REDACTED'],

    // Slack tokens (bot, user, workspace, app, refresh, legacy)
    [/\bxox[baprs]-[0-9a-zA-Z-]{10,}\b/g, 'xoxb-REDACTED'],

    // Stripe secret keys (live and test)
    [/\bsk_(?:live|test)_[0-9a-zA-Z]{24,}\b/g, 'sk_test_REDACTED'],

    // JWTs - three base64url segments, eyJ is the stable anchor
    [/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
     'eyJREDACTED.REDACTED.REDACTED'],

    // Google API keys (AIza prefix, 35 char alphanumeric)
    [/\bAIza[0-9A-Za-z\-_]{35}\b/g, 'AIzaREDACTED'],

    // HTTP Authorization header values - redact credential, keep scheme
    [/(Authorization\s*:\s*(?:Bearer|Basic|Digest|Token))\s+\S+/gi,
     '$1 REDACTED'],

    // URL query-string credentials
    [/([?&](?:password|passwd|pwd|token|api_key|apikey|access_token|refresh_token|auth|authorization|secret|session|sessionid|sid)=)[^&\s"']+/gi,
     '$1REDACTED'],
];


// ============================================================================
// Additional PII Patterns
// ============================================================================

// SSN requires formatting (XXX-XX-XXXX). Also excludes invalid SSN ranges
// per SSA rules (000/666/9xx area, 00 group, 0000 serial).
const SSN_RE = /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g;

// Candidate CC matcher. Results are Luhn-validated before redaction.
const CC_CANDIDATE_RE = /\b\d(?:[ -]?\d){12,18}\b/g;

// Phone numbers. Require at least one separator/paren to reduce FP.
const PHONE_RE = /(?<!\d)(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?!\d)/g;

// Windows SIDs - S-1-5-21- prefix is distinctive for domain/local user SIDs.
// Well-known SIDs (S-1-5-18 SYSTEM, etc.) do not match this pattern.
const SID_RE = /\bS-1-5-21-\d+-\d+-\d+-\d+\b/g;

// NPI candidates - 10-digit sequences. Validated via Luhn variant before redaction.
const NPI_CANDIDATE_RE = /\b\d{10}\b/g;


function luhnValid(numStr) {
    // Validate a digit string using the Luhn algorithm (ISO/IEC 7812-1).
    const digits = numStr.split('').filter(c => /\d/.test(c)).map(Number);
    if (digits.length < 13 || digits.length > 19) return false;

    let checksum = 0;
    for (let i = 0; i < digits.length; i++) {
        // i counts from the right (reversed iteration)
        const revIdx = digits.length - 1 - i;
        let d = digits[revIdx];
        if (i % 2 === 1) {
            d *= 2;
            if (d > 9) d -= 9;
        }
        checksum += d;
    }
    return checksum % 10 === 0;
}


function npiValid(numStr) {
    // Validate a 10-digit NPI using the Luhn variant from 45 CFR 162.406.
    // The NPI prefix '80840' is prepended before running Luhn.
    if (numStr.length !== 10 || !/^\d{10}$/.test(numStr)) return false;
    return luhnValid('80840' + numStr);
}


function redactCcs(text) {
    // Find candidate credit-card numbers and redact only the Luhn-valid ones.
    return text.replace(CC_CANDIDATE_RE, (match) => {
        const digits = match.replace(/\D/g, '');
        return luhnValid(digits) ? '4111-1111-1111-1111' : match;
    });
}


function redactNpis(text) {
    // Find candidate 10-digit numbers and redact only valid NPIs.
    return text.replace(NPI_CANDIDATE_RE, (match) => {
        return npiValid(match) ? '1234567893' : match;
    });
}


// ============================================================================
// Config Parsing
// ============================================================================
//
// Parses log_scrubbing_config.csv. Returns { textRules, jsonFieldRules }.
// Rule formats:
//   search_term,single,replacement              (text, explicit single mode)
//   search_term,random,"val1,val2,val3"         (text, random mode)
//   search_term,replacement                      (text, implicit single mode)
//   @json,field_name,replacement                 (json, implicit single)
//   @json,field_name,single,replacement          (json, explicit single)
//   @json,field_name,random,"val1,val2,val3"     (json, random mode)

function parseScrubbingConfig(csvText) {
    const textRules = [];
    const jsonFieldRules = [];

    if (!csvText) return { textRules, jsonFieldRules };

    const rows = parseCsv(csvText);

    for (const row of rows) {
        if (!row || row.length === 0) continue;
        const first = (row[0] || '').trim();
        if (!first || first.startsWith('#')) continue;
        if (row.length < 3) continue;

        if (first.toLowerCase() === '@json') {
            const fieldName = (row[1] || '').trim();
            if (!fieldName) continue;
            const thirdVal = (row[2] || '').trim().toLowerCase();
            if (row.length >= 4 && (thirdVal === 'single' || thirdVal === 'random')) {
                const mode = thirdVal;
                const replacementValues = (row[3] || '').trim();
                jsonFieldRules.push([fieldName, mode, replacementValues]);
            } else {
                const replacement = (row[2] || '').trim();
                jsonFieldRules.push([fieldName, 'single', replacement]);
            }
        } else {
            // Text rule: 2-col (search,replacement) or 3-col (search,mode,replacement)
            if (row.length === 2) {
                textRules.push([first, 'single', (row[1] || '').trim()]);
            } else {
                const mode = (row[1] || '').trim().toLowerCase();
                if (mode !== 'single' && mode !== 'random') {
                    // Treat as 2-col: search_term,replacement
                    textRules.push([first, 'single', (row[1] || '').trim()]);
                } else {
                    textRules.push([first, mode, (row[2] || '').trim()]);
                }
            }
        }
    }

    return { textRules, jsonFieldRules };
}


function parseCsv(text) {
    // Minimal RFC 4180-ish CSV parser. Handles quoted fields with embedded
    // commas and escaped quotes. Good enough for config files; not a general-
    // purpose CSV parser (the scrubber uses the browser File API + user-provided
    // input for samples, so this parser is only applied to configs).
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
                // Swallow \r\n pair as one line ending
                if (c === '\r' && text[i + 1] === '\n') i += 2;
                else i++;
            } else {
                field += c;
                i++;
            }
        }
    }
    // Handle trailing field/row (file without final newline)
    if (field.length > 0 || row.length > 0) {
        row.push(field);
        rows.push(row);
    }
    return rows;
}


// ============================================================================
// Replacement Resolver
// ============================================================================

// A deterministic PRNG would be nice for reproducible scrubbing. For now,
// random-mode rules use Math.random() just like the Python version uses
// random.choice() without seeding.
function resolveReplacement(mode, replacementValues) {
    if (mode === 'random') {
        const choices = replacementValues.split(',').map(v => v.trim()).filter(Boolean);
        return choices.length ? choices[Math.floor(Math.random() * choices.length)]
                              : replacementValues;
    }
    return replacementValues;
}


// ============================================================================
// JSON Path Matching (v1.1.0+)
// ============================================================================
//
// Unqualified rules (no dots): match any field with that exact name at any
// depth. This is the v1.0 behavior, preserved for backward compatibility.
//
// Qualified rules (contain dots): match as a path suffix anchored at a dotted
// boundary. So 'userIdentity.arn' matches 'userIdentity.arn' and
// 'detail.userIdentity.arn' but not 'foo.userIdentity.arn.extra'.

function ruleMatchesPath(ruleField, currentPath, currentKey) {
    if (ruleField.indexOf('.') !== -1) {
        return currentPath === ruleField || currentPath.endsWith('.' + ruleField);
    }
    return currentKey === ruleField;
}


function scrubJsonObj(obj, fieldRules, currentPath) {
    // Recursively walk a parsed JSON object and replace values for matching
    // field names. Handles two patterns:
    //   1. Direct field match:   {"accountId": "123"}
    //   2. Key-value tag match:  {"key": "Owner", "value": "admin@corp.com"}
    currentPath = currentPath || '';

    if (obj === null || obj === undefined) return obj;

    if (Array.isArray(obj)) {
        return obj.map(item => scrubJsonObj(item, fieldRules, currentPath));
    }

    if (typeof obj === 'object') {
        // Pattern 2: key-value pair detection.
        // Build a case-insensitive map so we catch 'key'/'Key'/'name'/'Name' uniformly.
        const keysLowerMap = {};
        for (const k of Object.keys(obj)) {
            keysLowerMap[k.toLowerCase()] = k;
        }

        let kvKeyField = null;
        let kvValField = null;
        for (const candidate of ['key', 'name']) {
            if (keysLowerMap[candidate]) {
                kvKeyField = keysLowerMap[candidate];
                break;
            }
        }
        if (keysLowerMap['value']) {
            kvValField = keysLowerMap['value'];
        }

        if (kvKeyField !== null && kvValField !== null
                && typeof obj[kvKeyField] === 'string') {
            const tagName = obj[kvKeyField];
            for (const rule of fieldRules) {
                const fn = rule[0];
                // Tag matching only applies to unqualified rules.
                if (fn.indexOf('.') !== -1) continue;
                if (tagName === fn) {
                    const mode = rule.length > 2 ? rule[1] : 'single';
                    const replVals = rule.length > 2 ? rule[2] : rule[1];
                    obj[kvValField] = resolveReplacement(mode, replVals);
                    for (const k of Object.keys(obj)) {
                        if (k !== kvValField) {
                            const newPath = currentPath ? currentPath + '.' + k : k;
                            obj[k] = scrubJsonObj(obj[k], fieldRules, newPath);
                        }
                    }
                    return obj;
                }
            }
        }

        // Pattern 1: direct field match (supports unqualified and dotted-path)
        for (const key of Object.keys(obj)) {
            const newPath = currentPath ? currentPath + '.' + key : key;
            let matched = false;
            for (const rule of fieldRules) {
                const fn = rule[0];
                if (ruleMatchesPath(fn, newPath, key)) {
                    const mode = rule.length > 2 ? rule[1] : 'single';
                    const replVals = rule.length > 2 ? rule[2] : rule[1];
                    obj[key] = resolveReplacement(mode, replVals);
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                obj[key] = scrubJsonObj(obj[key], fieldRules, newPath);
            }
        }
        return obj;
    }

    return obj;
}


function applyJsonFieldScrubbing(text, fieldRules) {
    // Apply JSON field scrubbing to a text string.
    // Handles: entire-JSON, JSON-after-prefix, key-value regex fallback,
    // direct-field regex fallback.
    if (!fieldRules || fieldRules.length === 0 || !text) return text;

    const stripped = text.trim();

    function tryJsonParseAndScrub(jsonStr) {
        try {
            const obj = JSON.parse(jsonStr);
            scrubJsonObj(obj, fieldRules, '');
            const compact = jsonStr.indexOf('\n') === -1;
            return compact ? JSON.stringify(obj) : JSON.stringify(obj, null, 2);
        } catch (e) {
            // Not valid JSON or partial JSON - caller falls through to regex
            return null;
        }
    }

    // Case 1: entire string is JSON
    if (stripped.startsWith('{') || stripped.startsWith('[')) {
        const result = tryJsonParseAndScrub(stripped);
        if (result !== null) return result;
    }

    // Case 2: JSON embedded after prefix
    const braceIdx = text.indexOf('{');
    if (braceIdx > 0) {
        const prefix = text.substring(0, braceIdx);
        const jsonPart = text.substring(braceIdx);
        const result = tryJsonParseAndScrub(jsonPart);
        if (result !== null) return prefix + result;
    }

    // Build rule lookup map for regex fallback
    const ruleMap = {};
    for (const rule of fieldRules) {
        const fn = rule[0];
        const mode = rule.length > 2 ? rule[1] : 'single';
        const replVals = rule.length > 2 ? rule[2] : rule[1];
        ruleMap[fn] = [mode, replVals];
    }

    // Case 3: key-value pair regex fallback (double-quoted)
    text = text.replace(
        /"(?:key|Key|name|Name)"\s*:\s*"([^"]*)"\s*,\s*"(?:value|Value)"\s*:\s*"([^"]*)"/g,
        (match, tagName, tagValue) => {
            if (ruleMap[tagName]) {
                const [mode, replVals] = ruleMap[tagName];
                const replacement = resolveReplacement(mode, replVals);
                return match.replace(tagValue, replacement);
            }
            return match;
        }
    );

    // Case 3b: key-value pair regex fallback (single-quoted)
    text = text.replace(
        /'(?:key|Key|name|Name)'\s*:\s*'([^']*)'\s*,\s*'(?:value|Value)'\s*:\s*'([^']*)'/g,
        (match, tagName, tagValue) => {
            if (ruleMap[tagName]) {
                const [mode, replVals] = ruleMap[tagName];
                const replacement = resolveReplacement(mode, replVals);
                return match.replace(tagValue, replacement);
            }
            return match;
        }
    );

    // Case 4: direct field regex fallback
    for (const fn of Object.keys(ruleMap)) {
        const [mode, replVals] = ruleMap[fn];
        const replacement = resolveReplacement(mode, replVals);
        const escaped = fn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

        // Double-quoted: "fieldname": "value"
        const dqPattern = new RegExp('("' + escaped + '")\\s*:\\s*"[^"]*"', 'g');
        text = text.replace(dqPattern, '$1: "' + replacement.replace(/\\/g, '\\\\') + '"');

        // Single-quoted: 'fieldname': 'value'
        const sqPattern = new RegExp("('" + escaped + "')\\s*:\\s*'[^']*'", 'g');
        text = text.replace(sqPattern, "$1: '" + replacement.replace(/\\/g, '\\\\') + "'");
    }

    return text;
}


// ============================================================================
// Fieldsummary-aware Value Replacement
// ============================================================================

function scrubFieldsummaryValues(rawValues, replacement) {
    // Replace the 'value' entries in Splunk fieldsummary format while preserving
    // structure and counts.
    let result = rawValues;
    result = result.replace(/('value':\s*')([^']*?)(')/g,
        (m, p1, p2, p3) => p1 + replacement + p3);
    result = result.replace(/("value":\s*")([^"]*?)(")/g,
        (m, p1, p2, p3) => p1 + replacement + p3);
    return result;
}


// ============================================================================
// Well-known Public Hosts (FQDN exclusion list)
// ============================================================================
//
// These are industry-standard public schema/namespace/documentation URLs
// that routinely appear in XML, JSON, and log data without being PII. The
// FQDN regex excludes these via negative lookahead so they're left intact.
// Keep this list conservative - only hosts that are categorically NOT PII
// across any customer's data.

const WELL_KNOWN_PUBLIC_HOSTS_PATTERN =
    'schemas\\.microsoft\\.com' +
    '|schemas\\.xmlsoap\\.org' +
    '|schemas\\.openxmlformats\\.org' +
    '|www\\.w3\\.org' +
    '|www\\.iana\\.org' +
    '|xmlns\\.com' +
    '|tools\\.ietf\\.org' +
    '|docs\\.oasis-open\\.org' +
    '|purl\\.org' +
    '|ns\\.adobe\\.com';

// Built from the above at module load so we don't recompile it on every call.
const FQDN_RE = new RegExp(
    '\\b(?!(?:' + WELL_KNOWN_PUBLIC_HOSTS_PATTERN + ')\\b)' +
    '[a-zA-Z0-9-]+\\.[a-zA-Z0-9-]+\\.(com|net|org|io|local|internal)\\b',
    'g'
);


// ============================================================================
// Core Scrubbing Function
// ============================================================================

function scrubText(text, textRules, jsonFieldRules, options) {
    // Scrub a single text value using the full pipeline.
    // options: { fieldName, enableBuiltins, enableCui } - all optional.
    options = options || {};
    const fieldName = options.fieldName || null;
    const enableBuiltins = options.enableBuiltins !== false;  // default true
    const enableCui = options.enableCui !== false;             // default true

    if (!text || !text.trim()) return text;

    let scrubbed = text;

    // Step 1: @json field-name shortcut (fieldsummary data).
    // Only unqualified rules can match a bare field name.
    const jsonFieldMap = {};
    for (const rule of jsonFieldRules) {
        if (rule[0].indexOf('.') === -1) {
            jsonFieldMap[rule[0]] = [rule[1], rule[2]];
        }
    }
    if (fieldName && jsonFieldMap[fieldName]) {
        const [mode, replVals] = jsonFieldMap[fieldName];
        const replacement = resolveReplacement(mode, replVals);
        return scrubFieldsummaryValues(scrubbed, replacement);
    }

    // Step 2: CUI marking detection.
    if (enableCui) {
        const category = detectCui(scrubbed);
        if (category !== null) {
            return redactCui(scrubbed, category);
        }
    }

    if (enableBuiltins) {
        // Step 3: credentials & tokens (before generic patterns)
        for (const [pattern, replacement] of CREDENTIAL_PATTERNS) {
            scrubbed = scrubbed.replace(pattern, replacement);
        }

        // Step 4: original built-in patterns (v1.0.0)
        scrubbed = scrubbed.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, '10.0.0.x');
        scrubbed = scrubbed.replace(
            /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
            'user@example.com'
        );
        scrubbed = scrubbed.replace(
            /\bip-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\b/g,
            'ip-10-0-0-x'
        );
        scrubbed = scrubbed.replace(FQDN_RE, 'host.example.com');
        scrubbed = scrubbed.replace(
            /\\\\[a-zA-Z0-9._-]+\\[a-zA-Z0-9._$-]+/g,
            '\\\\SERVER\\SHARE'
        );
        scrubbed = scrubbed.replace(
            /\b[A-Z][A-Z0-9_-]+\\[a-zA-Z0-9._-]+\b/g,
            'DOMAIN\\user'
        );
        scrubbed = scrubbed.replace(
            /\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g,
            '00:00:00:00:00:00'
        );

        // Step 5: additional PII (v1.1.0)
        scrubbed = scrubbed.replace(SSN_RE, '000-00-0000');
        scrubbed = redactCcs(scrubbed);
        scrubbed = scrubbed.replace(PHONE_RE, '555-555-5555');
        scrubbed = scrubbed.replace(SID_RE, 'S-1-5-21-0-0-0-0');
        scrubbed = redactNpis(scrubbed);
    }

    // Step 6: custom text substitution rules
    for (const [searchTerm, mode, replacementValues] of textRules) {
        if (scrubbed.indexOf(searchTerm) !== -1) {
            let replacement;
            if (mode === 'random') {
                const choices = replacementValues.split(',').map(v => v.trim()).filter(Boolean);
                replacement = choices.length ? choices[Math.floor(Math.random() * choices.length)]
                                             : replacementValues;
            } else {
                replacement = replacementValues;
            }
            // Simple literal replacement, all occurrences
            scrubbed = scrubbed.split(searchTerm).join(replacement);
        }
    }

    // Step 7: JSON field scrubbing
    if (jsonFieldRules.length > 0) {
        scrubbed = applyJsonFieldScrubbing(scrubbed, jsonFieldRules);
    }

    return scrubbed;
}


// ============================================================================
// Scrubber Class (convenience wrapper, parallels Python's Scrubber class)
// ============================================================================

class Scrubber {
    constructor(options) {
        options = options || {};
        if (options.configText) {
            const parsed = parseScrubbingConfig(options.configText);
            this.textRules = parsed.textRules.concat(options.textRules || []);
            this.jsonFieldRules = parsed.jsonFieldRules.concat(options.jsonFieldRules || []);
        } else {
            this.textRules = (options.textRules || []).slice();
            this.jsonFieldRules = (options.jsonFieldRules || []).slice();
        }
        this.enableBuiltins = options.enableBuiltins !== false;
        this.enableCui = options.enableCui !== false;
    }

    scrub(text, fieldName) {
        return scrubText(text, this.textRules, this.jsonFieldRules, {
            fieldName: fieldName || null,
            enableBuiltins: this.enableBuiltins,
            enableCui: this.enableCui,
        });
    }

    scrubMany(texts, fieldName) {
        return texts.map(t => this.scrub(t, fieldName));
    }
}


// ============================================================================
// Browser / Module Exports
// ============================================================================

// In a browser (via <script src=...> or build-time inline), everything attaches
// to window.Paydirt. In a Node-style module context (tests), we export via
// CommonJS. The conditional lets the same file work in both contexts without
// preprocessing.

const PAYDIRT_API = {
    version: PAYDIRT_VERSION,
    Scrubber,
    scrubText,
    parseScrubbingConfig,
    detectCui,
    redactCui,
    luhnValid,
    npiValid,
    scrubJsonObj,
    applyJsonFieldScrubbing,
};

if (typeof window !== 'undefined') {
    window.Paydirt = PAYDIRT_API;
}
if (typeof module !== 'undefined' && module.exports) {
    module.exports = PAYDIRT_API;
}
