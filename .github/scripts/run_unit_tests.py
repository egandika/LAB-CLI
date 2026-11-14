"""Run unittest and publish bounded failure details as a CI annotation."""
import os
import subprocess
import sys

result = subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-v'],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace')
print(result.stdout, end='')
if result.returncode and os.environ.get('GITHUB_ACTIONS'):
    details = result.stdout[result.stdout.find('\n==='):] if '\n===' in result.stdout else result.stdout
    details = details[-12000:].replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
    print('::error title=Unit test failure::' + details)
sys.exit(result.returncode)
