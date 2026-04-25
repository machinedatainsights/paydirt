#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Machine Data Insights Inc.
# https://machinedatainsights.com
"""
Parity test: runs each input fixture through both the Python CLI and the
JavaScript implementation and compares outputs byte-for-byte.

Important note on random-mode rules: any @json or text rule that uses
'random' mode produces non-deterministic output (Math.random on the JS
side, random.choice on the Python side). These tests use config rules
that are all 'single' mode (deterministic) so we can do strict equality
comparisons. Random-mode parity would need seeded RNGs on both sides,
which is a future enhancement.
"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
CLI = ROOT / 'log_scrubber.py'
JS_SCRUBBER = ROOT / 'paydirt' / 'src' / 'scrubber.js'
CONFIG = ROOT / 'log_scrubbing_config.csv'
INPUT_DIR = ROOT / 'shared-tests' / 'input'
EXPECTED_DIR = ROOT / 'shared-tests' / 'expected'

# Use a deterministic config - all 'single' mode rules - to enable strict
# equality comparison. The shared canonical config has some 'random' rules
# which we can't compare without seeded RNGs.
DETERMINISTIC_CONFIG = """# Deterministic test config - single mode only
ACME Corp,single,CompanyA
ACME,single,COMP
@acme.com,single,@company.com

@json,sourceIPAddress,10.0.0.x
@json,userIdentity.arn,arn:aws:iam::REDACTED:user/REDACTED
@json,userIdentity.principalId,REDACTED_PRINCIPAL
@json,accountId,000000000000
@json,bucketName,example-bucket
@json,Owner,REDACTED_OWNER
@json,Environment,REDACTED_ENV
@json,resource.accessKeyDetails.accessKeyId,AKIAIOSFODNN7REDACTED
@json,resource.accessKeyDetails.userName,aws-user-redacted
@json,resource.eksClusterDetails.arn,arn:aws:eks:us-gov-west-1:000000000000:cluster/REDACTED
"""

NODE_RUNNER = """
const fs = require('fs');
const { Scrubber, scrubText, parseScrubbingConfig } =
    require(process.argv[2]);

const configText = fs.readFileSync(process.argv[3], 'utf-8');
const inputText = fs.readFileSync(process.argv[4], 'utf-8');
const mode = process.argv[5];  // 'samples' or 'fieldsummary'

const { textRules, jsonFieldRules } = parseScrubbingConfig(configText);

if (mode === 'samples') {
    // Process as log samples: split into events (respecting multi-line JSON)
    // and scrub each event, matching the Python _scrub_samples_text_format logic.
    const content = inputText;
    const lines = content.split(/(?<=\\n)/);  // keep newlines
    const events = [];
    let jsonBuffer = [];
    let braceDepth = 0;

    for (const line of lines) {
        const stripped = line.trim();
        if (jsonBuffer.length > 0 || (stripped.startsWith('{') && braceDepth === 0)) {
            jsonBuffer.push(line);
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
        }
    }
    if (jsonBuffer.length > 0) events.push(jsonBuffer.join(''));

    const scrubbed = events.map(ev => scrubText(ev, textRules, jsonFieldRules));
    process.stdout.write(scrubbed.join(''));
} else {
    // Future: fieldsummary parity
    process.stdout.write(scrubText(inputText, textRules, jsonFieldRules));
}
"""


def run_python(input_path, config_path, output_path):
    """Run the Python CLI in samples mode."""
    result = subprocess.run(
        [sys.executable, str(CLI), 'samples', str(input_path),
         '--config', str(config_path),
         '--output', str(output_path),
         '--quiet'],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"Python CLI error: {result.stderr}", file=sys.stderr)
    return output_path.read_text() if output_path.exists() else ''


def run_node(input_path, config_path):
    """Run the JS implementation via Node."""
    runner_path = Path('/tmp/paydirt_parity_runner.js')
    runner_path.write_text(NODE_RUNNER)
    result = subprocess.run(
        ['node', str(runner_path), str(JS_SCRUBBER), str(config_path),
         str(input_path), 'samples'],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"Node runner error: {result.stderr}", file=sys.stderr)
    return result.stdout


def main():
    # Write deterministic config to a temp file
    det_config = Path('/tmp/paydirt_parity_config.csv')
    det_config.write_text(DETERMINISTIC_CONFIG)

    inputs = sorted(INPUT_DIR.glob('*'))
    if not inputs:
        print(f"No fixtures found in {INPUT_DIR}", file=sys.stderr)
        sys.exit(1)

    total = 0
    matching = 0
    for input_path in inputs:
        total += 1
        name = input_path.name
        py_out_path = Path('/tmp') / f'py_{name}.out'
        py_output = run_python(input_path, det_config, py_out_path)
        js_output = run_node(input_path, det_config)

        if py_output == js_output:
            matching += 1
            print(f"  MATCH  {name}  ({len(py_output)} bytes)")
        else:
            print(f"  DIFF   {name}")
            print(f"         Python ({len(py_output)} bytes):")
            for line in py_output.splitlines()[:5]:
                print(f"           {line!r}")
            print(f"         JavaScript ({len(js_output)} bytes):")
            for line in js_output.splitlines()[:5]:
                print(f"           {line!r}")
            # Show first differing position
            for i, (a, b) in enumerate(zip(py_output, js_output)):
                if a != b:
                    print(f"         First diff at byte {i}: py={a!r} js={b!r}")
                    print(f"         Context: py[{max(0,i-20)}:{i+20}] = {py_output[max(0,i-20):i+20]!r}")
                    print(f"                  js[{max(0,i-20)}:{i+20}] = {js_output[max(0,i-20):i+20]!r}")
                    break

    print()
    print("=" * 50)
    print(f"  {matching}/{total} fixtures match byte-for-byte")
    print("=" * 50)
    sys.exit(0 if matching == total else 1)


if __name__ == '__main__':
    main()
