"""Run selected unittest suite and publish bounded failure details as a CI annotation."""
import os
import subprocess
import sys

args = sys.argv[1:]
if args == []:
    suite = 'Unit'
    command = [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-v']
elif args == ['--integration']:
    suite = 'Integration'
    command = [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_integration.py', '-v']
else:
    print('Usage: run_unit_tests.py [--integration]', file=sys.stderr)
    sys.exit(2)
result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, encoding='utf-8', errors='replace')
print(result.stdout, end='')
if result.returncode and os.environ.get('GITHUB_ACTIONS'):
    details = result.stdout[result.stdout.find('\n==='):] if '\n===' in result.stdout else result.stdout
    details = details[-12000:].replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
    print('::error title=' + suite + ' test failure::' + details)
sys.exit(result.returncode)
