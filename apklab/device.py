"""Opt-in, disposable-emulator-only installation test for copies of APKs."""

from __future__ import annotations
from typing import Any, Optional, Union
from os import PathLike
import re
import shutil
import tempfile
from pathlib import Path
from .core import add, find_tool, inspect_one, reported, run
from .split_metadata import assess_outputs, read_dependencies


@reported
def install_test(serial: str, apks: Any, confirm: bool=False, launch: bool=False, _report: Any=None) -> dict:
    r = _report
    if not re.fullmatch(r'emulator-[0-9]+', serial):
        raise ValueError('An explicit emulator-NNNN serial is required; physical devices are refused')
    if not confirm:
        raise ValueError('Installation changes emulator state; --confirm-install is required')
    tools = {name: find_tool(name) for name in ('adb', 'aapt', 'apksigner')}
    missing = [name for name, path in tools.items() if not path]
    if missing: raise ValueError('Required tools not found: ' + ', '.join(missing))
    if not apks: raise ValueError('At least one APK is required')
    inputs = [Path(p).resolve(strict=True) for p in apks]
    if any(not p.is_file() or p.suffix.lower() != '.apk' for p in inputs):
        raise ValueError('Inputs must be APK files')
    adb = tools['adb']
    def adb_command(*args):
        return run([adb, '-s', serial] + list(args), timeout=120)
    def complete(result):
        return result['returncode'] == 0 and not result.get('stdout_truncated') and not result.get('capture_incomplete')
    state = adb_command('get-state')
    if not complete(state) or state['stdout'].strip() != 'device':
        raise ValueError('Requested emulator is not online')
    identity = adb_command('emu', 'avd', 'name')
    qemu = adb_command('shell', 'getprop', 'ro.kernel.qemu')
    if not complete(identity) or 'OK' not in identity['stdout'] or not complete(qemu) or qemu['stdout'].strip() != '1':
        raise ValueError('Could not confirm Android emulator identity; refusing device operation')
    users = adb_command('shell', 'pm', 'list', 'users')
    found_users = re.findall(r'UserInfo\{(\d+):', users['stdout'])
    if not complete(users) or found_users != ['0']:
        raise ValueError('Expected a disposable single-user emulator; refusing installation')
    with tempfile.TemporaryDirectory(prefix='apklab-device-') as tmp:
        copies = []
        for i, src in enumerate(inputs):
            target = Path(tmp) / ('input-' + str(i) + '.apk')
            shutil.copyfile(src, target)
            copies.append(target)
        items = [inspect_one(p, r) for p in copies]
        if r['failures']:
            return r
        if any(not a['package'] or not a['version_code'] or not a['signer_sha256'] for a in items):
            raise ValueError('Metadata and verified signer digests are required for every APK')
        packages = {a['package'] for a in items}
        versions = {a['version_code'] for a in items}
        signers = {tuple(a['signer_sha256']) for a in items}
        if len(packages) != 1 or len(versions) != 1 or len(signers) != 1:
            raise ValueError('APK package, version, or signer sets differ')
        if sum(a.get('split') is None for a in items) != 1:
            raise ValueError('Exactly one base candidate without a split name is required')
        splits = [a['split'] for a in items if a.get('split')]
        if len(splits) != len(set(splits)): raise ValueError('Duplicate split names')
        observations = [{'id': str(i), 'source': str(inputs[i]), 'apk': item, 'dependencies': read_dependencies(copy)}
                        for i, (copy, item) in enumerate(zip(copies, items))]
        r['split_observations'] = observations
        r['split_analysis'] = analysis = assess_outputs(observations)
        if analysis['issues']:
            for issue in analysis['issues']: add(r, 'failures', 'split set', issue)
            add(r, 'not_tested', 'installation', 'Installation was blocked by split metadata checks')
            return r
        for unknown in analysis['unknown']:
            add(r, 'not_tested', 'split set', 'Unable to compare ' + unknown + ' for every input')
        package = next(iter(packages))
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+', package):
            raise ValueError('Unsupported package name')
        existing = adb_command('shell', 'pm', 'list', 'packages', '-u', package)
        lines = [line.strip() for line in existing['stdout'].splitlines() if line.strip()]
        if not complete(existing) or any(not line.startswith('package:') for line in lines):
            raise ValueError('Could not safely determine installed packages')
        if 'package:' + package in lines:
            raise ValueError('Package already exists on emulator; refusing to replace it')
        add(r, 'not_tested', 'runtime', 'Installation or a launcher event does not prove app functionality; device state may change even on failure')
        add(r, 'not_tested', 'split completeness', 'Split requirements, OBBs, and device compatibility are not fully validated')
        result = adb_command('install-multiple' if len(copies) > 1 else 'install', *copies)
        r['install'] = result
        if not complete(result) or not re.search(r'(?m)^Success\s*$', result['stdout']):
            add(r, 'failures', 'installation', 'ADB installation failed; see install result')
            return r
        add(r, 'verified', 'installation', 'ADB reported installation success on the selected emulator')
        r['package'] = package
        if launch:
            result = adb_command('shell', 'monkey', '-p', package, '-c', 'android.intent.category.LAUNCHER', '1')
            r['launch'] = result
            if not complete(result) or not re.search(r'Events injected:\s*1\b', result['stdout']):
                add(r, 'failures', 'launch', 'ADB did not confirm a launcher event; see launch result')
            else:
                add(r, 'verified', 'launch', 'ADB reported one launcher event; app functionality was not assessed')
        else:
            add(r, 'not_tested', 'launch', 'Launch not requested')
    return r
