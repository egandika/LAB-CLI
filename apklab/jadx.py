"""Bounded best-effort JADX execution on an input copy."""

from __future__ import annotations
from typing import Any, Optional, Union
from os import PathLike
import os
import shutil
import tempfile
from pathlib import Path
from .core import find_tool, run
from .publish import publish_new, staging


def directory_size(root: Union[str, PathLike], max_bytes: Optional[int]=None) -> int:
    size = 0
    count = 0
    for base, dirs, files in os.walk(root, followlinks=False):
        if any((Path(base) / d).is_symlink() for d in dirs):
            raise ValueError('JADX output contains a symlink')
        for name in files:
            count += 1
            if count > 100000: raise ValueError('JADX output file count exceeded limit')
            path = Path(base) / name
            if path.is_symlink() or not path.is_file(): raise ValueError('JADX output contains a non-regular file')
            size += path.stat().st_size
            if max_bytes is not None and size > max_bytes: return size
    return size


def decompile(apk: Union[str, PathLike], destination: Union[str, PathLike], timeout: int, max_bytes: int, *, include_diagnostics: bool=False) -> Any:
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
                if directory_size(staged, max_bytes) > max_bytes: raise RuntimeError('JADX output exceeded size limit')
            result = run([tool, '--no-res', '-d', str(staged.resolve()), str(copied)], timeout=timeout, monitor=monitor)
            if result['returncode'] != 0:
                using_stderr = bool(result['stderr'])
                detail = result['stderr'] or result['stdout'] or str(result['returncode'])
                truncated = len(detail) > 4000 or result.get('stderr_truncated' if using_stderr else 'stdout_truncated', False)
                raise RuntimeError('JADX failed: ' + detail[:4000] + (' [diagnostic truncated]' if truncated else ''))
            if staged.is_symlink() or not staged.is_dir():
                raise RuntimeError('JADX reported success without a regular output directory')
            size = directory_size(staged)
            if size > max_bytes: raise RuntimeError('JADX output exceeded size limit')
            publish_new(staged, dest, directory=True)
            diagnostic = result.get('stderr', '')
            details = {'stderr': diagnostic[:4000],
                       'stderr_truncated': len(diagnostic) > 4000 or bool(result.get('stderr_truncated'))}
            return (size, details) if include_diagnostics else size
