import re
import unittest
from pathlib import Path


class CiActionPinningTests(unittest.TestCase):
    def test_all_external_actions_use_full_commit_hash(self):
        workflows = Path(__file__).resolve().parents[1]/'.github'/'workflows'
        files = sorted(list(workflows.glob('*.yml')) + list(workflows.glob('*.yaml')))
        self.assertTrue(files)
        seen = []
        for path in files:
            for line in path.read_text(encoding='utf-8').splitlines():
                match = re.match(r'^\s*(?:-\s*)?uses:\s*([^\s#]+)', line)
                if not match: continue
                action = match.group(1); seen.append(action)
                if action.startswith('./'): continue
                self.assertRegex(action, r'^[^@\s]+@[0-9a-f]{40}$', (path, line))
        self.assertTrue(seen, 'Expected workflow actions')
        self.assertIn('actions/checkout@11d5960a326750d5838078e36cf38b85af677262', seen)
        self.assertIn('actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065', seen)
        self.assertIn('reactivecircus/android-emulator-runner@a421e43855164a8197daf9d8d40fe71c6996bb0d', seen)
