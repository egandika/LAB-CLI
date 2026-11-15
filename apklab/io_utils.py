"""Bounded file-copy and size checks for untrusted APK inputs."""

from __future__ import annotations
import os
import stat
from pathlib import Path
from typing import Iterable, Optional, Union
from os import PathLike

COPY_CHUNK_BYTES = 1024 * 1024
DEFAULT_MAX_COPY_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_TOTAL_COPY_BYTES = 2048 * 1024 * 1024
DEFAULT_MAX_ARCHIVE_INPUT_BYTES = 1024 * 1024 * 1024
DEFAULT_MAX_CONTAINER_INPUT_BYTES = 9216 * 1024 * 1024


def _open_regular(source: Union[str, PathLike], purpose: str):
    """Open a regular file without blocking if a caller supplies a FIFO/device."""
    flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0)
    fd = os.open(source, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(purpose + ' must be a regular file')
        return fd, info
    except BaseException:
        os.close(fd)
        raise


def file_size_limited(source: Union[str, PathLike], max_bytes: int,
                      purpose: str = 'Input') -> int:
    """Validate a regular input's declared size and return its byte count.

    This is a preflight guard, not a hard resource quota: tools may allocate
    additional memory, temporary files, or output while processing the input.
    """
    if max_bytes < 1:
        raise ValueError('Input size limit must be positive')
    fd, info = _open_regular(source, purpose)
    try:
        if info.st_size > max_bytes:
            raise ValueError('{} size limit exceeded: {} bytes exceeds {} bytes'.format(
                purpose, info.st_size, max_bytes))
        return info.st_size
    finally:
        os.close(fd)


def preflight_copy_inputs(sources: Iterable[Union[str, PathLike]], max_bytes: int, max_total_bytes: int,
                          purpose: str = 'Copy') -> int:
    """Check per-file and aggregate declared sizes before allocating a workspace."""
    if max_bytes < 1:
        raise ValueError('Copy size limit must be positive')
    if max_total_bytes < 1:
        raise ValueError('Total copy size limit must be positive')
    total = 0
    for source in sources:
        size = file_size_limited(source, max_bytes, purpose)
        if total + size > max_total_bytes:
            raise ValueError('Copy size limit exceeded: declared total {} bytes exceeds aggregate limit {} bytes'.format(
                total + size, max_total_bytes))
        total += size
    return total


def copy_file_bounded(source: Union[str, PathLike], destination: Union[str, PathLike],
                      max_bytes: int, *, max_total_bytes: Optional[int] = None,
                      already_copied: int = 0) -> int:
    """Copy one regular file without exceeding per-file or aggregate byte caps.

    The destination must not already exist. If this call creates a partial copy
    and then fails, only that newly-created destination is removed. The caller
    remains responsible for placing it in a private staging or temporary folder.
    """
    if max_bytes < 1:
        raise ValueError('Copy size limit must be positive')
    if max_total_bytes is not None and max_total_bytes < 1:
        raise ValueError('Total copy size limit must be positive')
    if already_copied < 0:
        raise ValueError('Already-copied byte count cannot be negative')

    fd, info = _open_regular(source, 'Copy input')
    source_size = info.st_size
    if source_size > max_bytes:
        os.close(fd)
        raise ValueError('Copy size limit exceeded: declared file size {} bytes exceeds per-file limit {} bytes'.format(
            source_size, max_bytes))
    if max_total_bytes is not None and already_copied + source_size > max_total_bytes:
        os.close(fd)
        raise ValueError('Copy size limit exceeded: declared total {} bytes exceeds aggregate limit {} bytes'.format(
            already_copied + source_size, max_total_bytes))

    target = Path(destination)
    created = False
    copied = 0
    try:
        with os.fdopen(fd, 'rb') as src:
            fd = -1
            with target.open('xb') as dst:
                created = True
                while True:
                    remaining = max_bytes - copied
                    if max_total_bytes is not None:
                        remaining = min(remaining, max_total_bytes - already_copied - copied)
                    chunk = src.read(min(COPY_CHUNK_BYTES, remaining + 1))
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied > max_bytes or (max_total_bytes is not None and
                                              already_copied + copied > max_total_bytes):
                        raise ValueError('Copy size limit exceeded while reading input')
                    dst.write(chunk)
            final_info = os.fstat(src.fileno())
            if copied != source_size or final_info.st_size != source_size:
                raise ValueError('Copy input changed while it was being read')
        return copied
    except BaseException as original:
        if fd >= 0:
            os.close(fd)
        if created:
            try:
                target.unlink(missing_ok=True)
            except OSError as cleanup:
                raise RuntimeError(str(original) + '; partial-copy cleanup failed: ' + str(cleanup)) from original
        raise
