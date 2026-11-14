import contextlib
import io
import json
import unittest
from unittest.mock import patch
from apklab.cli import main
from apklab.core import _validate_windows_batch_args


class WindowsReviewTests(unittest.TestCase):
    def test_setup_install_without_geteuid_fails_without_spawning(self):
        out = io.StringIO()
        with patch('apklab.cli.find_executable', return_value='C:/apt-get.exe'), patch('apklab.cli.os.geteuid', None, create=True), patch('apklab.cli.run') as run, contextlib.redirect_stdout(out):
            code = main(['setup','--install'])
        self.assertEqual(code,1); self.assertIn('POSIX',json.loads(out.getvalue())['failures'][0]['detail']); run.assert_not_called()
    def test_case_insensitive_batch_extension_and_unsafe_arguments(self):
        for extension in ('.BAT','.CMD'):
            for value in ('a&b', 'a%b', 'a!b', 'a\nb'):
                with self.subTest(extension=extension, value=value), self.assertRaises(OSError):
                    _validate_windows_batch_args(['C:/tools/sign'+extension, value])
