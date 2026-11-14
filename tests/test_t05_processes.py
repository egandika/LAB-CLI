import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from apklab.core import run
import apklab.winjob

class ProcessTreeTests(unittest.TestCase):
    def child_script(self, target):
        return "import time,pathlib; time.sleep(1.2); pathlib.Path(%r).write_text('alive')" % str(target)
    def test_timeout_terminates_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)/'marker'
            script = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',%r]); time.sleep(8)" % self.child_script(target)
            result = run([sys.executable, '-c', script], timeout=0.5)
            self.assertIsNone(result['returncode']); self.assertIn('timed out', result['stderr'])
            time.sleep(1.5); self.assertFalse(target.exists(), 'child survived timeout')
    def test_parent_exit_cleans_up_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)/'marker'
            script = "import subprocess,sys; subprocess.Popen([sys.executable,'-c',%r])" % self.child_script(target)
            result = run([sys.executable, '-c', script], timeout=5)
            self.assertEqual(result['returncode'], 0, result)
            self.assertFalse(result['capture_incomplete'])
            time.sleep(1.5); self.assertFalse(target.exists(), 'child survived parent exit')
    def test_monitor_failure_terminates_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)/'marker'
            script = self.child_script(target)
            def monitor(): raise ValueError('monitor aborted')
            with self.assertRaisesRegex(ValueError, 'monitor aborted'):
                run([sys.executable, '-c', script], timeout=5, monitor=monitor)
            time.sleep(1.5); self.assertFalse(target.exists())

class WindowsContainmentTests(unittest.TestCase):
    def test_suspended_process_is_attached_before_monitor(self):
        import io
        from unittest.mock import patch
        events = []
        class Job:
            def attach_and_resume(self, process): events.append('attached')
            def close(self): events.append('closed')
        class Process:
            def __init__(self, args, **kwargs):
                self.stdout = io.BytesIO(b'ok'); self.stderr = io.BytesIO()
                self.returncode = 0
                self.assert_suspended(kwargs)
            def assert_suspended(self, kwargs):
                if kwargs.get('creationflags') != 4: raise AssertionError('not suspended')
            def poll(self): return 0
            def wait(self): return 0
        def monitor(): events.append('monitor')
        with patch('apklab.core.os.name', 'nt'), patch('apklab.winjob.WindowsJob', Job), patch('apklab.core.subprocess.Popen', Process):
            result = run(['fake'], timeout=1, monitor=monitor)
        self.assertEqual(result['returncode'], 0)
        self.assertLess(events.index('attached'), events.index('monitor'))
        self.assertIn('closed', events)

    def test_attach_failure_kills_suspended_process(self):
        import io
        from unittest.mock import patch
        events = []
        class Job:
            def attach_and_resume(self, process): raise OSError('job denied')
            def close(self): events.append('closed')
        class Process:
            def __init__(self, *args, **kwargs):
                self.stdout = io.BytesIO(); self.stderr = io.BytesIO(); self.returncode = None
            def poll(self): return self.returncode
            def kill(self): self.returncode = 1; events.append('killed')
            def wait(self): return self.returncode
        with patch('apklab.core.os.name', 'nt'), patch('apklab.winjob.WindowsJob', Job), patch('apklab.core.subprocess.Popen', Process):
            result = run(['fake'])
        self.assertIsNone(result['returncode']); self.assertIn('job denied', result['stderr'])
        self.assertEqual(events, ['killed', 'closed'])


class WorkspaceJadxLimitTests(unittest.TestCase):
    def test_workspace_jadx_uses_monitored_runner(self):
        import contextlib
        import io
        import json
        import zipfile
        from unittest.mock import patch
        from apklab.cli import main
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); apk = root/'input.apk'; work = root/'work'
            with zipfile.ZipFile(apk, 'w') as z: z.writestr('AndroidManifest.xml', 'test')
            with contextlib.redirect_stdout(io.StringIO()): main(['work','init',str(apk),str(work)])
            def fake_run(args, timeout, monitor):
                monitor()
                raise AssertionError('oversized output was not rejected')
            out = io.StringIO()
            with patch('apklab.workflow.find_tool', return_value='/fake/jadx'), \
                 patch('apklab.workflow.run', side_effect=fake_run), \
                 patch('apklab.jadx.directory_size', return_value=513 * 1024 * 1024), \
                 contextlib.redirect_stdout(out):
                code = main(['work','jadx',str(work)])
            self.assertEqual(code, 1)
            self.assertIn('128 MiB', json.loads(out.getvalue())['failures'][0]['detail'])
