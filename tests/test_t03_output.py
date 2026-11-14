import sys
import unittest
from apklab.core import run

class BoundedOutputTests(unittest.TestCase):
    def test_large_stdout_and_stderr_are_drained_and_capped(self):
        script = "import sys; sys.stdout.write('x'*500000); sys.stderr.write('y'*100000)"
        result = run([sys.executable, '-c', script], timeout=10)
        self.assertEqual(result['returncode'], 0)
        self.assertEqual(len(result['stdout']), 200000); self.assertEqual(len(result['stderr']), 20000)
        self.assertTrue(result['stdout_truncated']); self.assertTrue(result['stderr_truncated'])
    def test_exact_cap_and_invalid_bytes(self):
        script = "import sys; sys.stdout.buffer.write(b'x'*199999+b'\\xff')"
        result = run([sys.executable, '-c', script], timeout=10)
        self.assertEqual(result['returncode'], 0); self.assertFalse(result['stdout_truncated'])
        self.assertTrue(result['stdout'].endswith('\ufffd'))
    def test_timeout_is_distinct(self):
        result = run([sys.executable, '-c', 'import time; time.sleep(5)'], timeout=0.2)
        self.assertIsNone(result['returncode']); self.assertIn('timed out', result['stderr'])
