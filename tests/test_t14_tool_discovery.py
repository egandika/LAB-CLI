import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from apklab.core import _build_tools_version, _validate_windows_batch_args, find_tool, run


class ToolDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sdk = self.root/'sdk'
    def make(self, name):
        path = self.sdk/name; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('fixture'); path.chmod(0o755)
        return path
    def find(self, name, windows):
        with patch.dict(os.environ, {'ANDROID_SDK_ROOT':str(self.sdk), 'ANDROID_HOME':'', 'GHIDRA_HOME':''}), \
             patch('apklab.core.shutil.which', return_value=None), patch('apklab.core._windows', return_value=windows), \
             patch('apklab.core.Path.home', return_value=self.root/'empty'):
            return find_tool(name)

    def test_windows_exe_batch_and_cmd_sdk_names(self):
        aapt = self.make('build-tools/35.0.0/aapt.exe')
        signer = self.make('build-tools/35.0.0/apksigner.bat')
        adb = self.make('platform-tools/adb.exe')
        analyzer = self.make('cmdline-tools/latest/bin/apkanalyzer.cmd')
        with patch('apklab.core.os.access', return_value=True):
            for name, path in [('aapt',aapt), ('apksigner',signer), ('adb',adb), ('apkanalyzer',analyzer)]:
                with self.subTest(name=name): self.assertEqual(self.find(name, True), str(path))

    def test_versions_are_numeric_and_stable_beats_same_version_preview(self):
        for version in ('9.0.0','34.0.0','35.0.0-rc2','35.0.0-rc10','35.0.0'):
            self.make('build-tools/'+version+'/zipalign')
        self.assertEqual(self.find('zipalign', False), str(self.sdk/'build-tools/35.0.0/zipalign'))
        versions = ['9.0.0','35.0.0-rc2','35.0.0-rc10','35.0.0','34.0.0']
        self.assertEqual([p.name for p in sorted(map(Path, versions), key=_build_tools_version)],
                         ['9.0.0','34.0.0','35.0.0-rc2','35.0.0-rc10','35.0.0'])

    def test_path_precedes_sdk_and_sdk_root_precedes_android_home(self):
        sdk_tool = self.make('build-tools/35.0.0/aapt')
        other = self.root/'other'/'build-tools'/'99.0.0'/'aapt'; other.parent.mkdir(parents=True); other.write_text('x'); other.chmod(0o755)
        with patch.dict(os.environ, {'ANDROID_SDK_ROOT':str(self.sdk), 'ANDROID_HOME':str(self.root/'other')}), \
             patch('apklab.core.shutil.which', return_value='/chosen/aapt'):
            self.assertEqual(find_tool('aapt'), '/chosen/aapt')
        with patch.dict(os.environ, {'ANDROID_SDK_ROOT':str(self.sdk), 'ANDROID_HOME':str(self.root/'other')}), \
             patch('apklab.core.shutil.which', return_value=None):
            self.assertEqual(find_tool('aapt'), str(sdk_tool))

    def test_windows_default_localappdata_sdk(self):
        tool = self.root/'local'/'Android'/'Sdk'/'platform-tools'/'adb.exe'
        tool.parent.mkdir(parents=True); tool.write_text('x')
        with patch.dict(os.environ, {'ANDROID_SDK_ROOT':'', 'ANDROID_HOME':'', 'LOCALAPPDATA':str(self.root/'local')}), \
             patch('apklab.core.shutil.which', return_value=None), patch('apklab.core._windows', return_value=True), \
             patch('apklab.core.os.access', return_value=True), patch('apklab.core.Path.home', return_value=self.root/'empty'):
            self.assertEqual(find_tool('adb'), str(tool))

    def test_windows_ghidra_batch(self):
        path = self.root/'ghidra'/'ghidraRun.bat'; path.parent.mkdir(); path.write_text('x')
        with patch.dict(os.environ, {'GHIDRA_HOME':str(path.parent), 'ANDROID_HOME':'', 'ANDROID_SDK_ROOT':''}), \
             patch('apklab.core.shutil.which', return_value=None), patch('apklab.core._windows', return_value=True), \
             patch('apklab.core.os.access', return_value=True), patch('apklab.core.Path.home', return_value=self.root/'empty'):
            self.assertEqual(find_tool('ghidra'), str(path))

    def test_batch_arguments_with_shell_syntax_are_refused(self):
        _validate_windows_batch_args(['C:\\sdk\\apksigner.bat', 'simple path.apk', '--verbose'])
        for char in '&|<>()^%!"\r\n':
            with self.subTest(char=char), self.assertRaisesRegex(OSError, 'Unsafe Windows batch argument'):
                _validate_windows_batch_args(['C:\\sdk\\apksigner.bat', 'file'+char+'name.apk'])
        _validate_windows_batch_args(['C:\\sdk\\aapt.exe', 'file&name.apk'])
        # Simulate Windows dispatch without launching cmd.exe or a process.
        with patch('apklab.core.os.name', 'nt'), patch('apklab.core.subprocess.Popen') as popen:
            result = run(['C:\\sdk\\apksigner.bat', 'file&name.apk'])
        self.assertIsNone(result['returncode']); self.assertIn('Unsafe Windows batch', result['stderr']); popen.assert_not_called()
