import contextlib
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from apklab.cli import main
from apklab.io_utils import copy_file_bounded


class BoundedCopyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def call(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(list(args))
        return code, json.loads(output.getvalue())

    def test_per_file_and_aggregate_caps_leave_no_partial_copy(self):
        source = self.root / 'source.apk'
        source.write_bytes(b'1234567890')
        target = self.root / 'too-large.apk'
        with self.assertRaisesRegex(ValueError, '[Cc]opy size limit'):
            copy_file_bounded(source, target, 5)
        self.assertFalse(target.exists())
        self.assertEqual(source.read_bytes(), b'1234567890')

        first, second = self.root / 'first.apk', self.root / 'second.apk'
        source.write_bytes(b'1234')
        self.assertEqual(copy_file_bounded(source, first, 10, max_total_bytes=6), 4)
        source.write_bytes(b'123')
        with self.assertRaisesRegex(ValueError, '[Cc]opy size limit'):
            copy_file_bounded(source, second, 10, max_total_bytes=6, already_copied=4)
        self.assertFalse(second.exists())
        self.assertEqual(first.read_bytes(), b'1234')

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'POSIX FIFO required')
    def test_non_regular_source_is_rejected_without_blocking(self):
        source = self.root / 'input.apk'
        os.mkfifo(source)
        target = self.root / 'copy.apk'
        with self.assertRaisesRegex(ValueError, 'regular file'):
            copy_file_bounded(source, target, 1024)
        self.assertFalse(target.exists())

    def test_work_init_enforces_copy_limit_before_publishing_workspace(self):
        source = self.root / 'large.apk'
        source.write_bytes(b'x' * (1024 * 1024 + 1))
        workspace = self.root / 'workspace'
        code, result = self.call('work', 'init', '--max-copy-mib', '1', str(source), str(workspace))
        self.assertEqual(code, 1, result)
        self.assertFalse(workspace.exists())
        self.assertEqual(source.stat().st_size, 1024 * 1024 + 1)
        self.assertEqual(list(self.root.glob('.apklab-stage-*')), [])
        self.assertIn('copy size limit', result['failures'][0]['detail'].lower())

    def test_split_workspace_enforces_aggregate_copy_limit(self):
        first, second = self.root / 'base.apk', self.root / 'config.apk'
        first.write_bytes(b'a' * 600000)
        second.write_bytes(b'b' * 600000)
        workspace = self.root / 'split-workspace'
        code, result = self.call('splits', 'init', '--max-copy-total-mib', '1',
                                 str(workspace), str(first), str(second))
        self.assertEqual(code, 1, result)
        self.assertFalse(workspace.exists())
        self.assertEqual(list(self.root.glob('.apklab-stage-*')), [])
        self.assertIn('copy size limit', result['failures'][0]['detail'].lower())

    def test_physical_apk_archive_limit_blocks_zip_and_metadata_tools(self):
        source = self.root / 'large.apk'
        source.write_bytes(b'x' * (1024 * 1024 + 1))
        with patch('apklab.core.zipfile.ZipFile') as zip_open, patch('apklab.core.find_tool') as apk_tool, patch('apklab.split_metadata.find_tool') as split_tool:
            code, result = self.call('inspect', str(source), '--max-archive-mib', '1')
        self.assertEqual(code, 1, result)
        self.assertIn('size limit', result['failures'][0]['detail'].lower())
        zip_open.assert_not_called()
        apk_tool.assert_not_called()
        split_tool.assert_not_called()
        for command in ('inventory', 'dex'):
            code, report = self.call(command, str(source), '--max-archive-mib', '1')
            self.assertEqual(code, 1, report)
            self.assertIn('size limit', report['failures'][0]['detail'].lower())
        code, report = self.call('diff', str(source), str(source), '--max-archive-mib', '1')
        self.assertEqual(code, 1, report)
        self.assertIn('size limit', report['failures'][0]['detail'].lower())

    def test_xapk_and_apks_physical_archive_limits_preflight_before_zip_open(self):
        source = self.root / 'large-container.xapk'
        source.write_bytes(b'x' * (1024 * 1024 + 1))
        for args in (('xapk', 'inspect', str(source)), ('apks', 'inspect', str(source))):
            with self.subTest(args=args), patch('apklab.cli.examine_xapk') as examine:
                code, result = self.call(*args, '--max-archive-mib', '1')
            self.assertEqual(code, 1, result)
            self.assertIn('size limit', result['failures'][0]['detail'].lower())
            examine.assert_not_called()

    def test_preflight_copy_checks_all_declared_sizes_before_staging(self):
        from apklab.io_utils import preflight_copy_inputs
        first = self.root / 'first.apk'
        second = self.root / 'second.apk'
        first.write_bytes(b'a' * 4)
        second.write_bytes(b'b' * 7)
        self.assertEqual(preflight_copy_inputs([first, second], 8, 11), 11)
        with self.assertRaisesRegex(ValueError, 'aggregate limit'):
            preflight_copy_inputs([first, second], 8, 10)
        with self.assertRaisesRegex(ValueError, 'Copy size limit'):
            preflight_copy_inputs([first, second], 6, 11)

    def test_jadx_input_limit_blocks_tool_and_output(self):
        source = self.root / 'large.apk'
        source.write_bytes(b'x' * (1024 * 1024 + 1))
        destination = self.root / 'decompiled'
        with patch('apklab.jadx.find_tool', return_value='/fake/jadx') as find, patch('apklab.jadx.run') as run:
            code, result = self.call('jadx', str(source), str(destination), '--max-input-mib', '1')
        self.assertEqual(code, 1, result)
        self.assertFalse(destination.exists())
        find.assert_not_called()
        run.assert_not_called()
        self.assertIn('size limit', result['failures'][0]['detail'].lower())


if __name__ == '__main__':
    unittest.main()
