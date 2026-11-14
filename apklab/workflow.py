"""Workspace lifecycle; never overwrite input or existing outputs."""
import shutil
from pathlib import Path
from .core import find_tool, run


def init(source, workspace):
    source = Path(source).resolve(strict=True)
    workspace = Path(workspace)
    if not source.is_file() or source.suffix.lower() != '.apk':
        raise ValueError('Source must be an APK file')
    workspace.mkdir(parents=True, exist_ok=False)
    try:
        shutil.copy2(source, workspace / 'original.apk')
    except Exception:
        workspace.rmdir()
        raise
    return str(workspace.resolve())


def output_path(workspace, path):
    root = Path(workspace).resolve(strict=True)
    if not root.is_dir() or not (root / 'original.apk').is_file():
        raise ValueError('Not an APKLab workspace (original.apk missing)')
    p = Path(path)
    p = (root / p).resolve() if not p.is_absolute() else p.resolve()
    if not p.is_relative_to(root) or p == root:
        raise ValueError('Output must be inside workspace')
    if p.exists(): raise ValueError('Output already exists: ' + str(p))
    return root, p


def workspace_input(workspace, source):
    root = Path(workspace).resolve(strict=True)
    if not root.is_dir() or not (root / 'original.apk').is_file():
        raise ValueError('Not an APKLab workspace (original.apk missing)')
    src = Path(source)
    src = (root / src).resolve() if not src.is_absolute() else src.resolve()
    if not src.is_relative_to(root) or not src.is_file():
        raise ValueError('Input must be an existing file inside workspace')
    return src


def perform(stage, workspace, source=None, output=None, keystore=None, alias=None, pass_env=None):
    defaults = {'decode': 'decoded', 'build': 'rebuilt.apk', 'align': 'aligned.apk', 'sign': 'signed.apk'}
    root, dest = output_path(workspace, output or defaults[stage])
    toolname = {'decode': 'apktool', 'build': 'apktool', 'align': 'zipalign', 'sign': 'apksigner'}[stage]
    tool = find_tool(toolname)
    if not tool: raise ValueError(toolname + ' not found; run apklab doctor')
    defaults_in = {'decode': 'original.apk', 'build': 'decoded', 'align': 'rebuilt.apk', 'sign': 'aligned.apk'}
    src = Path(source or defaults_in[stage])
    src = (root / src).resolve() if not src.is_absolute() else src.resolve()
    if not src.is_relative_to(root) or not src.exists():
        raise ValueError('Input must exist inside workspace')
    if stage == 'decode': args = [tool, 'd', str(src), '-o', str(dest)]
    elif stage == 'build': args = [tool, 'b', str(src), '-o', str(dest)]
    elif stage == 'align': args = [tool, '-p', '4', str(src), str(dest)]
    else:
        if not keystore or not alias or not pass_env:
            raise ValueError('sign requires --keystore, --alias and --pass-env (environment variable name)')
        import os
        if pass_env not in os.environ: raise ValueError('Signing password environment variable is not set')
        args = [tool, 'sign', '--ks', keystore, '--ks-key-alias', alias, '--ks-pass', 'env:' + pass_env,
                '--out', str(dest), str(src)]
    result = run(args, timeout=600)
    if result['returncode'] != 0:
        raise RuntimeError(toolname + ' failed: ' + (result['stderr'] or result['stdout'])[:4000])
    if not dest.exists(): raise RuntimeError(toolname + ' reported success without output')
    return str(dest), result
