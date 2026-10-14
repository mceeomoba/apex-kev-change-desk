#!/usr/bin/env python3
"""Run offline release checks against the checked-out tree. Does not fetch data."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FILES = ('kev_diff.py', 'markdown_report.py', 'tests/test_diff.py', 'examples/before.json',
         'examples/after.json', 'examples/review.json', 'examples/review.md', 'README.md', 'LICENSE',
         'scripts/verify_release.py', '.github/ISSUE_TEMPLATE/workflow-feedback.yml')

def run(args, cwd):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    return subprocess.run([sys.executable, '-B', *args], cwd=cwd, env=env,
                          capture_output=True, timeout=60)

def main():
    results = []
    try:
        with tempfile.TemporaryDirectory(prefix='apex-kev-check-') as temporary:
            test_command = (
                'import sys,unittest; '
                'suite=unittest.defaultTestLoader.discover(sys.argv[1]); '
                'count=suite.countTestCases(); '
                'result=unittest.TextTestRunner(verbosity=1).run(suite); '
                'sys.exit(0 if count>0 and result.wasSuccessful() else 1)'
            )
            tests = run(['-c', test_command, str(ROOT/'tests')], temporary)
            results.append({'check': 'synthetic_tests', 'pass': tests.returncode == 0,
                            'detail': tests.stderr.decode('utf-8', errors='replace').strip()})
            for format_name, filename in [('json', 'review.json'), ('markdown', 'review.md')]:
                result = run([str(ROOT/'kev_diff.py'), str(ROOT/'examples/before.json'),
                              str(ROOT/'examples/after.json'), '--format', format_name], temporary)
                expected = (ROOT/'examples'/filename).read_bytes()
                if format_name == 'json':
                    equal = result.returncode == 0 and json.loads(result.stdout) == json.loads(expected)
                else:
                    equal = result.returncode == 0 and result.stdout == expected
                results.append({'check': format_name + '_example', 'pass': equal,
                                'detail': 'Matches bundled expected output' if equal else 'CLI or expected-output mismatch'})
            bad = Path(temporary)/'invalid.json'
            bad.write_text('{"count": 1, "count": 2}', encoding='utf-8')
            result = run([str(ROOT/'kev_diff.py'), str(bad), str(bad)], temporary)
            results.append({'check': 'invalid_input_no_report',
                            'pass': result.returncode == 2 and not result.stdout,
                            'detail': 'Duplicate JSON keys must be rejected without stdout'})
        report = {'result': 'PASS' if all(check['pass'] for check in results) else 'FAIL',
                  'scope': 'Offline acceptance checks, not a security audit or proof of authenticity, exposure or demand.',
                  'checks': results, 'fileSHA256': {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in FILES}}
        print(json.dumps(report, indent=2))
        return 0 if report['result'] == 'PASS' else 1
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(json.dumps({'result': 'FAIL', 'error': str(error), 'checks': results}, indent=2))
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
