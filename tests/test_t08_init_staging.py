import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from apklab.splits import init_set
from apklab.workflow import init


class InitStagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.source = self.root/'source.apk'
        self.source.write_bytes(b'original')

    def test_partial_copy_never_publishes_and_original_error_is_preserved(self):
        for func, module in ((lambda p: init(self.source, p), 'apklab.workflow.shutil.copy2'),
                             (lambda p: init_set(p, [self.source]), 'apklab.splits.shutil.copyfile')):
            with self.subTest(module=module):
                destination = self.root/'work'
                def broken(source, target):
                    Path(target).write_bytes(b'partial')
                    raise OSError('original copy failure')
                with patch(module, side_effect=broken):
                    with self.assertRaisesRegex(OSError, 'original copy failure'): func(destination)
                self.assertFalse(destination.exists())
                self.assertEqual(list(self.root.glob('.apklab-stage-*')), [])
                self.assertEqual(self.source.read_bytes(), b'original')

    def test_cleanup_failure_reports_both_original_and_cleanup_error(self):
        def broken(source, target):
            Path(target).write_bytes(b'partial'); raise OSError('copy failure')
        with patch('apklab.workflow.shutil.copy2', side_effect=broken), patch('apklab.publish.shutil.rmtree', side_effect=OSError('cleanup failure')):
            with self.assertRaisesRegex(RuntimeError, 'copy failure.*cleanup failure'):
                init(self.source, self.root/'work')
        self.assertFalse((self.root/'work').exists())
        self.assertEqual(self.source.read_bytes(), b'original')

    def test_destination_created_during_copy_is_not_replaced(self):
        destination = self.root/'work'
        def racing(source, target):
            Path(target).write_bytes(b'copy')
            destination.mkdir(); (destination/'other').write_text('preserve')
        with patch('apklab.workflow.shutil.copy2', side_effect=racing):
            with self.assertRaises(OSError): init(self.source, destination)
        self.assertEqual((destination/'other').read_text(), 'preserve')
        self.assertEqual(list(self.root.glob('.apklab-stage-*')), [])
