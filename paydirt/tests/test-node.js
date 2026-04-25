#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Machine Data Insights Inc.
// https://machinedatainsights.com
// Test suite for paydirt/src/scrubber.js
// Mirrors cli/test_scrubber.py to verify behavioral parity between the two.

const {
    Scrubber,
    scrubText,
    parseScrubbingConfig,
    detectCui,
    scrubJsonObj,
    applyJsonFieldScrubbing,
    luhnValid,
    npiValid,
    version,
} = require('../src/scrubber.js');

let PASS = 0;
let FAIL = 0;

function check(label, actual, expected) {
    let ok = true;
    const reasons = [];

    if (expected.eq !== undefined) {
        // Deep-ish equality via JSON (good enough for our test values)
        const actualStr = JSON.stringify(actual);
        const expectedStr = JSON.stringify(expected.eq);
        if (actualStr !== expectedStr) {
            ok = false;
            reasons.push('expected == ' + expectedStr + ', got ' + actualStr);
        }
    }
    if (expected.contains !== undefined) {
        const needles = Array.isArray(expected.contains) ? expected.contains : [expected.contains];
        for (const needle of needles) {
            if (typeof actual !== 'string' || actual.indexOf(needle) === -1) {
                ok = false;
                reasons.push('expected to contain ' + JSON.stringify(needle));
            }
        }
    }
    if (expected.notContains !== undefined) {
        const needles = Array.isArray(expected.notContains) ? expected.notContains : [expected.notContains];
        for (const needle of needles) {
            if (typeof actual === 'string' && actual.indexOf(needle) !== -1) {
                ok = false;
                reasons.push('expected NOT to contain ' + JSON.stringify(needle));
            }
        }
    }

    if (ok) {
        PASS++;
        console.log('  PASS  ' + label);
    } else {
        FAIL++;
        console.log('  FAIL  ' + label);
        console.log('        actual: ' + JSON.stringify(actual));
        for (const r of reasons) console.log('        ' + r);
    }
}

// ==========================================================================
// 1. Nested @json path rules (the original bug fix)
// ==========================================================================
console.log('\n[1] Nested @json path rules');

let rules = [['userIdentity.arn', 'single', 'arn:aws:iam::REDACTED:user/REDACTED']];

let obj = {userIdentity: {arn: 'arn:aws:iam::123456789012:user/admin'}};
scrubJsonObj(obj, rules);
check('nested path matches at correct location',
    obj.userIdentity.arn,
    {eq: 'arn:aws:iam::REDACTED:user/REDACTED'});

obj = {arn: 'arn:aws:iam::123456789012:role/SomeRole',
       userIdentity: {arn: 'arn:aws:iam::999999999999:user/admin'}};
scrubJsonObj(obj, rules);
check('top-level arn untouched by qualified path rule',
    obj.arn,
    {eq: 'arn:aws:iam::123456789012:role/SomeRole'});
check('nested arn still scrubbed',
    obj.userIdentity.arn,
    {eq: 'arn:aws:iam::REDACTED:user/REDACTED'});

obj = {detail: {userIdentity: {arn: 'arn:aws:iam::111:user/deep'}}};
scrubJsonObj(obj, rules);
check('deeply nested path matches (suffix match)',
    obj.detail.userIdentity.arn,
    {eq: 'arn:aws:iam::REDACTED:user/REDACTED'});

// ==========================================================================
// 2. Unqualified rules still work (backward compat)
// ==========================================================================
console.log('\n[2] Unqualified @json rules still work (backward compat)');

rules = [['accountId', 'single', '000000000000']];
obj = {accountId: '123456789012',
       detail: {accountId: '999999999999'},
       nested: {deep: {accountId: '777777777777'}}};
scrubJsonObj(obj, rules);
check('top-level accountId scrubbed', obj.accountId, {eq: '000000000000'});
check('nested accountId scrubbed', obj.detail.accountId, {eq: '000000000000'});
check('deeply nested accountId scrubbed', obj.nested.deep.accountId, {eq: '000000000000'});

rules = [['Owner', 'single', 'REDACTED_OWNER']];
obj = {tags: [{key: 'Owner', value: 'admin@corp.com'}]};
scrubJsonObj(obj, rules);
check('tag key/value pattern still matches',
    obj.tags[0].value,
    {eq: 'REDACTED_OWNER'});

// ==========================================================================
// 3. Credential & token patterns
// ==========================================================================
console.log('\n[3] Credential & token scrubbing');

let out = scrubText('key=AKIAIOSFODNN7EXAMPLE user=bob', [], []);
check('AWS AKIA access key redacted', out, {notContains: 'AKIAIOSFODNN7EXAMPLE'});

out = scrubText('token=ghp_abcdefghijklmnopqrstuvwxyz0123456789AB', [], []);
check('GitHub PAT redacted', out, {notContains: 'ghp_abcdefghijklmnopqrstuvwxyz0123456789AB'});

const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
out = scrubText('Authorization: Bearer ' + jwt, [], []);
check('JWT redacted', out, {notContains: jwt});
check('Bearer scheme preserved', out, {contains: 'Bearer'});

const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF7s7F5rP5+\n-----END RSA PRIVATE KEY-----';
out = scrubText(pem, [], []);
check('private key block redacted', out, {notContains: 'MIIEpAIBAAKCAQEA'});
check('private key placeholder present', out, {contains: '[REDACTED_PRIVATE_KEY]'});

out = scrubText('xoxb-123456789012-abcdefghijkl', [], []);
check('Slack token redacted', out, {notContains: 'xoxb-123456789012-abcdefghijkl'});

out = scrubText('GET /api?api_key=secret123&foo=bar HTTP/1.1', [], []);
check('query string api_key redacted', out, {notContains: 'secret123'});
check('non-credential query param preserved', out, {contains: 'foo=bar'});

// ==========================================================================
// 4. PII patterns
// ==========================================================================
console.log('\n[4] PII scrubbing');

out = scrubText('SSN: 123-45-6789 on file', [], []);
check('formatted SSN redacted', out, {notContains: '123-45-6789'});

out = scrubText('ref 666-45-6789 (invalid SSN area)', [], []);
check('invalid SSN range (666) not matched', out, {contains: '666-45-6789'});

out = scrubText('Card: 4532015112830366', [], []);
check('Luhn-valid CC redacted', out, {notContains: '4532015112830366'});

out = scrubText('Order #: 1234567890123456', [], []);
check('Luhn-invalid 16-digit sequence not redacted', out, {contains: '1234567890123456'});

out = scrubText('Call me at (555) 234-5678 tomorrow', [], []);
check('formatted phone redacted', out, {notContains: '234-5678'});

out = scrubText('User SID: S-1-5-21-1234567890-1234567890-1234567890-1001', [], []);
check('Windows SID redacted', out, {notContains: '1234567890-1234567890-1234567890-1001'});

out = scrubText('Running as S-1-5-18 (SYSTEM)', [], []);
check('well-known SID SYSTEM preserved', out, {contains: 'S-1-5-18'});

check('luhnValid: Visa test number passes',
    luhnValid('4532015112830366') ? 'yes' : 'no', {eq: 'yes'});
check('luhnValid: invalid number fails',
    luhnValid('1234567890123456') ? 'yes' : 'no', {eq: 'no'});

// ==========================================================================
// 5. CUI marking detection
// ==========================================================================
console.log('\n[5] CUI marking detection');

out = scrubText('CUI//SP-PRVCY Employee record: John Smith DOB 01/15/1980', [], []);
check('CUI banner triggers full-value redaction',
    out, {contains: ['CUI-REDACTED', 'SP-PRVCY']});
check('CUI banner redaction drops content',
    out, {notContains: ['John Smith', '01/15/1980']});

out = scrubText('(U//FOUO) Contract award to vendor XYZ', [], []);
check('portion marking (U//FOUO) triggers redaction',
    out, {contains: 'CUI-REDACTED'});
check('portion marking redaction drops content',
    out, {notContains: 'vendor XYZ'});

out = scrubText('FOUO meeting notes attached', [], []);
check('legacy FOUO marking triggers redaction',
    out, {contains: ['CUI-REDACTED', 'LEGACY']});

out = scrubText('ITAR-controlled technical data', [], []);
check('adjacent ITAR marking triggers redaction',
    out, {contains: ['CUI-REDACTED', 'ADJACENT']});

out = scrubText('CUI//BASIC some content', [], [], undefined);
// Actually need to pass options properly
out = scrubText('CUI//BASIC some content', [], [], {enableCui: false});
check('enableCui=false suppresses CUI detection',
    out, {contains: 'some content'});

out = scrubText('Ordinary log line about a web request', [], []);
check('no CUI marking = no CUI redaction',
    out, {contains: 'Ordinary log line'});

check('detectCui finds banner',
    detectCui('banner CUI//SP-PRVCY content') || '',
    {contains: 'CUI'});
check('detectCui returns null for clean text',
    detectCui('just a normal log line'), {eq: null});

// ==========================================================================
// 6. Scrubber class API
// ==========================================================================
console.log('\n[6] Scrubber class (library API)');

let scrubber = new Scrubber({
    textRules: [['acme.com', 'single', 'example.com']],
    jsonFieldRules: [['accountId', 'single', '000000000000']],
});
out = scrubber.scrub('User bob@acme.com from acct 123456789012');
check('Scrubber.scrub applies text rules', out, {contains: 'example.com'});
check('Scrubber.scrub applies built-in email rule', out, {contains: 'user@example.com'});

const scrubberNoCui = new Scrubber({textRules: [], jsonFieldRules: [], enableCui: false});
out = scrubberNoCui.scrub('CUI//BASIC some sensitive note');
check('Scrubber(enableCui=false) passes CUI content through',
    out, {contains: 'sensitive note'});

const results = scrubber.scrubMany(['one@acme.com', 'two@acme.com']);
check('Scrubber.scrubMany returns array',
    Array.isArray(results) ? 'yes' : 'no', {eq: 'yes'});
check('Scrubber.scrubMany processes each item',
    results[0], {contains: 'example.com'});

// ==========================================================================
// 7. JSON field scrubbing on realistic event
// ==========================================================================
console.log('\n[7] JSON field scrubbing via parsed JSON');

rules = [
    ['userIdentity.arn', 'single', 'arn:aws:iam::REDACTED:user/REDACTED'],
    ['sourceIPAddress', 'single', '10.0.0.x'],
];
const event = JSON.stringify({
    eventTime: '2026-01-01T00:00:00Z',
    userIdentity: {arn: 'arn:aws:iam::123456789012:user/admin',
                   accountId: '123456789012'},
    sourceIPAddress: '192.0.2.55',
});
out = applyJsonFieldScrubbing(event, rules);
const outObj = JSON.parse(out);
check('nested userIdentity.arn scrubbed via parsed JSON',
    outObj.userIdentity.arn,
    {eq: 'arn:aws:iam::REDACTED:user/REDACTED'});
check('unqualified sourceIPAddress rule still works',
    outObj.sourceIPAddress, {eq: '10.0.0.x'});

// ==========================================================================
// 8. Config parser
// ==========================================================================
console.log('\n[8] Config parser');

const cfg = `# comment line
ACME Corp,single,CompanyA
@acme.com,single,@company.com
john@test.com,random,"a@b.com,c@d.com"
@json,sourceIPAddress,10.0.0.x
@json,accountId,random,"000000000001,000000000002"
@json,userIdentity.arn,arn:aws:iam::REDACTED
`;
const parsed = parseScrubbingConfig(cfg);
check('config parser: 3 text rules', parsed.textRules.length, {eq: 3});
check('config parser: 3 json rules', parsed.jsonFieldRules.length, {eq: 3});
check('config parser: text rule format',
    parsed.textRules[0], {eq: ['ACME Corp', 'single', 'CompanyA']});
check('config parser: random mode with quoted list',
    parsed.textRules[2][2], {eq: 'a@b.com,c@d.com'});
check('config parser: implicit single @json rule',
    parsed.jsonFieldRules[0], {eq: ['sourceIPAddress', 'single', '10.0.0.x']});
check('config parser: random @json rule',
    parsed.jsonFieldRules[1], {eq: ['accountId', 'random', '000000000001,000000000002']});
check('config parser: dotted-path @json rule',
    parsed.jsonFieldRules[2][0], {eq: 'userIdentity.arn'});

// ==========================================================================
// Summary
// ==========================================================================
console.log('\n' + '='.repeat(50));
console.log('  ' + PASS + ' passed, ' + FAIL + ' failed');
console.log('='.repeat(50));
process.exit(FAIL === 0 ? 0 : 1);
