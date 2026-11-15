"""Regression coverage for fixture command construction, without Android tools."""
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import test_integration


class SplitFixtureCommandTests(unittest.TestCase):
    def test_emulator_uses_installed_sdk_build_tools(self):
        workflow = Path('.github/workflows/ci.yml').read_text(encoding='utf-8')
        emulator = workflow.split('  emulator:', 1)[1]
        self.assertIn('build-tools/35.0.0/aapt', emulator)
        self.assertIn('echo "$ANDROID_HOME/build-tools/35.0.0" >> "$GITHUB_PATH"', emulator)
        self.assertLess(emulator.index('Select installed Android build tools'), emulator.index('Install and launch test APK in disposable emulator'))

    def test_aapt_gets_distinct_canonical_manifest_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); sdk = root / 'sdk'
            platform = sdk / 'platforms' / 'android-35' / 'android.jar'
            platform.parent.mkdir(parents=True); platform.touch()
            work = root / 'work'; work.mkdir(); key = root / 'key.jks'
            manifests = []
            def fake_run(command, **kwargs):
                if command[1] == 'package':
                    manifest = Path(command[command.index('-M') + 1])
                    self.assertEqual(manifest.name, 'AndroidManifest.xml')
                    self.assertTrue(manifest.is_file())
                    manifests.append((manifest, manifest.read_text(encoding='utf-8')))
                    self.assertTrue(Path(command[command.index('-S') + 1]).is_dir())
                return SimpleNamespace(returncode=0, stdout='', stderr='')
            with patch.dict(os.environ, {'ANDROID_HOME': str(sdk)}), patch('test_integration.find_tool', side_effect=lambda name: name), patch('test_integration.subprocess.run', side_effect=fake_run):
                paths = test_integration.AndroidToolIntegration('test_round_trip').create_split_fixture(work, key)
            self.assertEqual(len(paths), 2)
            self.assertEqual(len(manifests), 2)
            self.assertNotEqual(manifests[0][0], manifests[1][0])
            self.assertNotIn('split="config.en"', manifests[0][1])
            self.assertIn('split="config.en"', manifests[1][1])


if __name__ == '__main__': unittest.main()
