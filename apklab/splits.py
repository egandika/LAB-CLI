"""Copy-based split set workspaces; operations are deliberately non-destructive."""

from __future__ import annotations
from typing import Any, Optional, Union
from os import PathLike
import hashlib
import json
import os
import re
from pathlib import Path
from .io_utils import (DEFAULT_MAX_COPY_BYTES, DEFAULT_MAX_TOTAL_COPY_BYTES,
                       copy_file_bounded, preflight_copy_inputs)
from .publish import publish_new, staging

MAX_APKS = 1000


def sha256(path: Union[str, PathLike]) -> str:
    digest = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''): digest.update(chunk)
    return digest.hexdigest()


def init_set(destination: Union[str, PathLike], paths: Any,
             max_copy_bytes: int=DEFAULT_MAX_COPY_BYTES,
             max_total_copy_bytes: int=DEFAULT_MAX_TOTAL_COPY_BYTES) -> list:
    inputs = [Path(p).resolve(strict=True) for p in paths]
    if not inputs or len(inputs) > MAX_APKS: raise ValueError('Provide 1 to 1000 APK files')
    if len(inputs) != len(set(inputs)): raise ValueError('Duplicate APK paths')
    if any(not p.is_file() or p.suffix.lower() != '.apk' for p in inputs):
        raise ValueError('All inputs must be APK files')
    root = Path(destination)
    if os.path.lexists(root): raise FileExistsError('Workspace already exists: ' + str(root))
    preflight_copy_inputs(inputs, max_copy_bytes, max_total_copy_bytes)
    with staging(root) as staged:
        staged.mkdir()
        members = []
        copied_total = 0
        for i, source in enumerate(inputs):
            name = 'apk-' + str(i).zfill(4)
            folder = staged / name; folder.mkdir()
            dest = folder / 'original.apk'
            copied = copy_file_bounded(source, dest, max_copy_bytes,
                                       max_total_bytes=max_total_copy_bytes,
                                       already_copied=copied_total)
            copied_total += copied
            members.append({'id': name, 'source_name': source.name, 'sha256': sha256(dest)})
        with (staged / 'split-set.json').open('x', encoding='utf-8') as f:
            json.dump({'schema': 1, 'members': members}, f, indent=2)
        publish_new(staged, root, directory=True)
        return members



def read_set(destination: Union[str, PathLike]) -> tuple:
    root = Path(destination).resolve(strict=True)
    metadata = root / 'split-set.json'
    if not metadata.is_file() or metadata.stat().st_size > 1024 * 1024:
        raise ValueError('Missing or oversized split-set.json')
    data = json.loads(metadata.read_text(encoding='utf-8'))
    if not isinstance(data, dict) or data.get('schema') != 1 or not isinstance(data.get('members'), list) or not 1 <= len(data['members']) <= MAX_APKS:
        raise ValueError('Invalid split-set metadata')
    ids = set()
    for item in data['members']:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not re.fullmatch(r'apk-[0-9]{4}', item['id']):
            raise ValueError('Invalid split member ID')
        ident = item['id']
        if ident in ids: raise ValueError('Duplicate split member ID')
        ids.add(ident)
        folder = (root / ident).resolve(strict=True)
        original = (folder / 'original.apk').resolve(strict=True)
        if not folder.is_relative_to(root) or not original.is_relative_to(folder) or not original.is_file():
            raise ValueError('Split member must remain inside the set workspace')
        if not isinstance(item.get('sha256'), str) or sha256(original) != item['sha256']:
            raise ValueError('Workspace original copy changed: ' + ident)
    return root, data['members']
