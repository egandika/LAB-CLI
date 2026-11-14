"""Stage output beside its destination and publish without replacing an existing path."""
import contextlib
import ctypes
import errno
import os
import shutil
import sys
import tempfile
from pathlib import Path


def publish_new(source, destination, directory=False):
    source, destination = Path(source), Path(destination)
    if not directory:
        # A same-filesystem hard link creates the destination exclusively.
        os.link(str(source), str(destination), follow_symlinks=False)
        source.unlink()
        return
    if os.name == 'nt':
        os.rename(str(source), str(destination))  # Windows rename refuses existing targets.
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith('linux') and hasattr(libc, 'renameat2'):
        fn = libc.renameat2
        fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        fn.restype = ctypes.c_int
        result = fn(-100, os.fsencode(source), -100, os.fsencode(destination), 1)  # RENAME_NOREPLACE
    elif sys.platform == 'darwin' and hasattr(libc, 'renamex_np'):
        fn = libc.renamex_np
        fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        fn.restype = ctypes.c_int
        result = fn(os.fsencode(source), os.fsencode(destination), 4)  # RENAME_EXCL
    else:
        raise OSError(errno.ENOTSUP, 'Atomic no-replace directory publication is unavailable')
    if result:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(destination))


@contextlib.contextmanager
def staging(destination):
    """Yield a private sibling staging path and preserve errors if cleanup fails."""
    dest = Path(destination)
    tmp = Path(tempfile.mkdtemp(prefix='.apklab-stage-', dir=str(dest.parent)))
    try:
        yield tmp / 'output'
    except BaseException as original:
        try:
            shutil.rmtree(tmp)
        except OSError as cleanup:
            raise RuntimeError(str(original) + '; staging cleanup failed: ' + str(cleanup)) from original
        raise
    else:
        shutil.rmtree(tmp)
