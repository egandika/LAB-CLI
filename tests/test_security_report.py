import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from apklab.cli import main
from apklab.core import redact_report
from apklab.jadx import directory_size


class SecurityReportTests(unittest.TestCase):
    def test_nested_redaction_preserves_original(self):
        home = str(Path.home())
        value = {'data': [home + '/a https://example.com/private?token=abc', 'Bearer abc123', 'A'*40], 'api_key':'short', r'C:\Users\Alice\private': 'value'}
        result = redact_report(value); encoded = json.dumps(result)
        self.assertNotIn('example.com', encoded); self.assertNotIn('abc123', encoded); self.assertNotIn('A'*40, encoded)
        self.assertNotIn('Alice', encoded); self.assertEqual(result['api_key'], '[REDACTED]')
        self.assertIn(home, value['data'][0])
    def test_summary_file_and_nested_subcommand_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            outpath = Path(tmp)/'report.json'; out = io.StringIO()
            with patch('apklab.cli.find_tool', return_value=str(Path.home()/'secret-tool')), contextlib.redirect_stdout(out):
                code = main(['doctor','--redact','--summary','--report',str(outpath)])
            self.assertEqual(code,3); self.assertNotIn(str(Path.home()),out.getvalue()); self.assertNotIn(str(Path.home()),outpath.read_text())
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(['device','--serial','physical','--confirm-install','x.apk','--redact'])
            self.assertEqual(code,1)
            out = io.StringIO()
            with contextlib.redirect_stdout(out): main(['work','verify','missing', '--redact'])
            self.assertTrue(json.loads(out.getvalue())['warnings'])
    def test_device_warning_even_on_early_failure(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out): main(['device','--serial','physical','--confirm-install','x.apk'])
        self.assertIn('execute code', json.loads(out.getvalue())['warnings'][0])
    def test_early_directory_size_stops_after_threshold(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp); (p/'a').write_bytes(b'a'*20); (p/'b').write_bytes(b'b'*20)
            self.assertGreater(directory_size(p, 10), 10)
            self.assertEqual(directory_size(p),40)
