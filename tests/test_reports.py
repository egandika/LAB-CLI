import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from apklab.cli import main
from apklab.core import report, add

class ReportTests(unittest.TestCase):
    def call(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out): code = main(list(args))
        return code, out.getvalue()
    def test_exit_codes_and_failure_precedence(self):
        cases = [([],0), ([('not_tested','unavailable')],3), ([('failures','bad'),('not_tested','unavailable')],1)]
        for entries, expected in cases:
            r = report()
            for category, text in entries: add(r, category, 'sample', text)
            with self.subTest(expected=expected), patch('apklab.cli.doctor', return_value=r):
                code, out = self.call('doctor')
                self.assertEqual(code,expected); self.assertEqual(json.loads(out),r)
    def test_summary_and_report_file_json(self):
        r = report(); add(r,'verified','crc','passed'); add(r,'not_tested','signature','missing tool')
        with tempfile.TemporaryDirectory() as tmp, patch('apklab.cli.doctor', return_value=r):
            path = Path(tmp)/'report.json'
            for args in [('--summary','doctor'), ('doctor','--summary')]:
                code, output = self.call(*args)
                self.assertEqual(code,3); self.assertIn('1 reported checks ran',output)
                self.assertIn('signature - missing tool',output); self.assertEqual(json.loads(output.split('JSON report:\n',1)[1]), r)
            code, output = self.call('doctor','--summary','--report',str(path))
            self.assertEqual(json.loads(path.read_text(encoding='utf-8')),r)
    def test_nested_summary(self):
        code, out = self.call('work','verify','--summary','does-not-exist')
        self.assertEqual(code,1); self.assertIn('JSON report:',out)
