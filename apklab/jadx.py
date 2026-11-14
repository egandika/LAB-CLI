"""Bounded best-effort JADX execution on an input copy."""
import os
import shutil
import tempfile
from pathlib import Path
from .core import find_tool, run
from .publish import publish_new, staging


def directory_size(root):
    size = 0
    for base, dirs, files in os.walk(root, followlinks=False):
        if any((Path(base) / d).is_symlink() for d in dirs):
            raise ValueError('JADX output contains a symlink')
        for name in files:
            path = Path(base) / name
            if path.is_symlink() or not path.is_file(): raise ValueError('JADX output contains a non-regular file')
            size += path.stat().st_size
    return size


def decompile(apk, destination, timeout, max_bytes):
    if timeout < 1 or max_bytes < 1: raise ValueError('Timeout and size limit must be positive')
    tool = find_tool('jadx')
    if not tool: raise ValueError('jadx not found; run apklab doctor')
    source = Path(apk).resolve(strict=True)
    if not source.is_file() or source.suffix.lower() != '.apk': raise ValueError('Input must be an APK file')
    dest = Path(destination)
    if os.path.lexists(dest): raise FileExistsError('Output already exists: ' + str(dest))
    with staging(dest) as staged:
        staged.mkdir()
        with tempfile.TemporaryDirectory(prefix='apklab-jadx-') as tmp:
            copied = Path(tmp) / 'input.apk'
            shutil.copyfile(source, copied)
            def monitor():
                if directory_size(staged) > max_bytes: raise RuntimeError('JADX output exceeded size limit')
            result = run([tool, '--no-res', '-d', str(staged.resolve()), str(copied)], timeout=timeout, monitor=monitor)
            if result['returncode'] != 0:
                raise RuntimeError('JADX failed: ' + (result['stderr'] or result['stdout'] or str(result['returncode']))[:4000])
            if staged.is_symlink() or not staged.is_dir():
                raise RuntimeError('JADX reported success without a regular output directory')
            size = directory_size(staged)
            if size > max_bytes: raise RuntimeError('JADX output exceeded size limit')
            publish_new(staged, dest, directory=True)
            return size
