import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from apklab.cli import main


class JadxDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.apk = self.root/'source.apk'; self.apk.write_bytes(b'fixture')
    def call(self, result):
        def fake(args, timeout, monitor):
            (Path(args[args.index('-d')+1])/'file.java').write_text('class A {}')
            monitor(); return result
        output = io.StringIO()
        with patch('apklab.jadx.find_tool', return_value='/fake/jadx'), patch('apklab.jadx.run', side_effect=fake), contextlib.redirect_stdout(output):
            code = main(['jadx', str(self.apk), str(self.root/'output')])
        return code, json.loads(output.getvalue())
    def test_success_preserves_warning_and_marks_cap(self):
        code, result = self.call({'returncode':0,'stdout':'','stderr':'warning '+('x'*10000),'stderr_truncated':False})
        self.assertEqual(code, 3, result); diag = result['jadx_diagnostics']
        self.assertEqual(len(diag['stderr']), 4000); self.assertTrue(diag['stderr'].startswith('warning ')); self.assertTrue(diag['stderr_truncated'])
    def test_runner_truncation_flag_is_not_lost(self):
        code, result = self.call({'returncode':0,'stdout':'','stderr':'warning','stderr_truncated':True})
        self.assertEqual(code, 3, result); self.assertEqual(result['jadx_diagnostics'], {'input_copy_bytes': 7, 'stderr':'warning','stderr_truncated':True})
    def test_failure_diagnostic_is_bounded_and_marked(self):
        code, result = self.call({'returncode':1,'stdout':'','stderr':'e'*10000,'stderr_truncated':False})
        self.assertEqual(code, 1, result); detail = result['failures'][0]['detail']
        self.assertLess(len(detail), 4100); self.assertIn('[diagnostic truncated]', detail)
        self.assertFalse((self.root/'output').exists()); self.assertEqual(self.apk.read_bytes(), b'fixture')
