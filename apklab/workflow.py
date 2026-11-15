"""Workspace lifecycle; never overwrite input or existing outputs."""

from __future__ import annotations
from typing import Any, Optional, Union
from os import PathLike
import os
from pathlib import Path
from .core import find_tool, run
from .io_utils import (DEFAULT_MAX_COPY_BYTES, copy_file_bounded,
                       file_size_limited, preflight_copy_inputs)
from .publish import publish_new, staging


def init(source: Union[str, PathLike], workspace: Union[str, PathLike],
         max_copy_bytes: int=DEFAULT_MAX_COPY_BYTES) -> str:
    source = Path(source).resolve(strict=True)
    workspace = Path(workspace)
    if not source.is_file() or source.suffix.lower() != '.apk':
        raise ValueError('Source must be an APK file')
    if os.path.lexists(workspace): raise FileExistsError('Workspace already exists: ' + str(workspace))
    preflight_copy_inputs([source], max_copy_bytes, max_copy_bytes)
    workspace.parent.mkdir(parents=True, exist_ok=True)
    with staging(workspace) as staged:
        staged.mkdir()
        copy_file_bounded(source, staged / 'original.apk', max_copy_bytes)
        publish_new(staged, workspace, directory=True)
    return str(workspace.resolve())


def output_path(workspace: Union[str, PathLike], path: Union[str, PathLike]) -> tuple:
    root = Path(workspace).resolve(strict=True)
    if not root.is_dir() or not (root / 'original.apk').is_file():
        raise ValueError('Not an APKLab workspace (original.apk missing)')
    p = Path(path)
    p = root / p if not p.is_absolute() else p
    if os.path.lexists(p): raise ValueError('Output already exists: ' + str(p))
    p = p.resolve()
    if not p.is_relative_to(root) or p == root:
        raise ValueError('Output must be inside workspace')
    if p.exists(): raise ValueError('Output already exists: ' + str(p))
    return root, p


def workspace_input(workspace: Union[str, PathLike], source: Union[str, PathLike]) -> Path:
    root = Path(workspace).resolve(strict=True)
    if not root.is_dir() or not (root / 'original.apk').is_file():
        raise ValueError('Not an APKLab workspace (original.apk missing)')
    src = Path(source)
    src = (root / src).resolve() if not src.is_absolute() else src.resolve()
    if not src.is_relative_to(root) or not src.is_file():
        raise ValueError('Input must be an existing file inside workspace')
    return src


def supports_16k(tool: Any) -> bool:
    result = run([tool, '-h'], timeout=10)
    import re
    return bool(re.search(r'(?<!\w)-P(?:\s|,|<)', result['stdout'] + '\n' + result['stderr']))


def perform(stage: str, workspace: Union[str, PathLike], source: Optional[Union[str, PathLike]]=None, output: Optional[Union[str, PathLike]]=None, keystore: Optional[Union[str, PathLike]]=None, alias: Optional[str]=None, pass_env: Optional[str]=None, page_size: int=4, max_input_bytes: int=DEFAULT_MAX_COPY_BYTES) -> tuple:
    defaults = {'decode': 'decoded', 'jadx': 'jadx', 'build': 'rebuilt.apk', 'align': 'aligned.apk', 'sign': 'signed.apk'}
    root, dest = output_path(workspace, output or defaults[stage])
    toolname = {'decode': 'apktool', 'jadx': 'jadx', 'build': 'apktool', 'align': 'zipalign', 'sign': 'apksigner'}[stage]
    tool = find_tool(toolname)
    if not tool: raise ValueError(toolname + ' not found; run apklab doctor')
    defaults_in = {'decode': 'original.apk', 'jadx': 'original.apk', 'build': 'decoded', 'align': 'rebuilt.apk', 'sign': 'aligned.apk'}
    src = Path(source or defaults_in[stage])
    src = (root / src).resolve() if not src.is_absolute() else src.resolve()
    if not src.is_relative_to(root) or not src.exists():
        raise ValueError('Input must exist inside workspace')
    if stage in ('decode', 'jadx', 'align', 'sign'):
        file_size_limited(src, max_input_bytes, 'Workflow APK input')
    with staging(dest) as staged:
        if stage == 'decode': args = [tool, 'd', str(src), '-o', str(staged)]
        elif stage == 'jadx':
            if not src.is_file(): raise ValueError('JADX input must be a file')
            args = [tool, '--no-res', '-d', str(staged), str(src)]
        elif stage == 'build': args = [tool, 'b', str(src), '-o', str(staged)]
        elif stage == 'align':
            if page_size == 16 and not supports_16k(tool):
                raise ValueError('zipalign does not advertise -P; Android build tools with 16 KiB support are required')
            args = [tool] + (['-P', '16'] if page_size == 16 else ['-p']) + ['4', str(src), str(staged)]
        else:
            if not keystore or not alias or not pass_env:
                raise ValueError('sign requires --keystore, --alias and --pass-env (environment variable name)')
            import os
            if pass_env not in os.environ: raise ValueError('Signing password environment variable is not set')
            args = [tool, 'sign', '--ks', keystore, '--ks-key-alias', alias, '--ks-pass', 'env:' + pass_env,
                    '--out', str(staged), str(src)]
        if stage == 'jadx':
            from .jadx import directory_size
            def monitor():
                if directory_size(staged, 128 * 1024 * 1024) > 128 * 1024 * 1024:
                    raise RuntimeError('JADX output exceeded the 128 MiB monitored limit')
            result = run(args, timeout=600, monitor=monitor)
        else:
            result = run(args, timeout=600)
        if result['returncode'] != 0:
            detail = (result['stderr'] or result['stdout'] or 'No diagnostic output was returned')[:4000]
            if stage == 'build':
                raise RuntimeError('apktool build failed: ' + detail + '. Next: inspect apktool diagnostics and versions/frameworks, check decoded resource edits, and retry in a fresh workspace; some APKs cannot be rebuilt unchanged.')
            raise RuntimeError(toolname + ' failed: ' + detail)
        if staged.is_symlink() or (not staged.is_dir() if stage in ('decode', 'jadx') else not staged.is_file()):
            raise RuntimeError(toolname + ' reported success without the expected output type')
        publish_new(staged, dest, directory=stage in ('decode', 'jadx'))
        return str(dest), result
