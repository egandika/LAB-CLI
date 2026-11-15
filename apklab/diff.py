"""Read-only comparison of two validated APK ZIP archives."""
import hashlib
import zipfile
from os import PathLike
from typing import Any, Union
from .axml import read_manifest
from .core import validate_apk_archive


def snapshot(path: Union[str, PathLike], max_entry: int, max_total: int) -> dict:
    entries = {}
    with zipfile.ZipFile(path) as archive:
        infos = validate_apk_archive(path, archive, max_entry, max_total)
        for info in infos:
            if info.filename in entries: raise ValueError('Duplicate ZIP entry prevents unambiguous diff: ' + info.filename)
            digest = hashlib.sha256()
            if not info.is_dir():
                with archive.open(info) as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b''): digest.update(chunk)
            entries[info.filename] = {'size': info.file_size, 'compressed_size': info.compress_size,
                                      'sha256': digest.hexdigest(), 'directory': info.is_dir(), 'compression_method': info.compress_type}
    try:
        manifest = read_manifest(str(path))
        metadata = {'source': 'internal_axml', 'package': manifest['package'],
                    'version_code': manifest['version_code'], 'version_name': manifest['version_name']}
    except (ValueError, KeyError, OSError, RuntimeError, zipfile.BadZipFile, NotImplementedError):
        metadata = {'source': 'unavailable'}
    abis = sorted({parts[1] for name in entries for parts in [name.split('/')] if len(parts) >= 3 and parts[0] == 'lib' and parts[1] and name.endswith('.so')})
    return {'entries': entries, 'metadata': metadata, 'native_abi_directories': abis}


def compare(old: Any, new: Any) -> dict:
    left, right = old['entries'], new['entries']
    added = sorted(right.keys() - left.keys())
    removed = sorted(left.keys() - right.keys())
    changed = [{'path': name, 'old': left[name], 'new': right[name]} for name in sorted(left.keys() & right.keys()) if left[name] != right[name]]
    return {'added': [{'path': name, **right[name]} for name in added],
            'removed': [{'path': name, **left[name]} for name in removed], 'changed': changed,
            'native_abi_directories': {'old': old['native_abi_directories'], 'new': new['native_abi_directories']}}
