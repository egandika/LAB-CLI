"""Bounded inspection of copied APK members of an XAPK archive."""
import hashlib
import json
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Union
from os import PathLike

from .core import add, inspect_one
from .io_utils import DEFAULT_MAX_CONTAINER_INPUT_BYTES, file_size_limited
from .xapk import MIB, unique_json_object, validate

MAX_APK = 512 * MIB
MAX_TOTAL = 2048 * MIB
MAX_MEMBERS = 1000


def check_members(path: Union[str, PathLike], report: Any, max_entry: int, max_total: int,
                  max_archive_bytes: int=DEFAULT_MAX_CONTAINER_INPUT_BYTES) -> list:
    results = []
    file_size_limited(path, max_archive_bytes, 'Container archive input')
    with zipfile.ZipFile(path) as archive:
        infos = validate(archive, max_entry, max_total)
        members = [i for i in infos if not i.is_dir() and i.filename.lower().endswith('.apk')]
        if len(members) > MAX_MEMBERS or any(i.file_size > MAX_APK for i in members) or sum(i.file_size for i in members) > MAX_TOTAL:
            raise ValueError('Contained APK copy count or size exceeds safety limit')
        declared = {}
        package = None
        manifest = next((i for i in infos if i.filename == 'manifest.json'), None)
        if manifest and manifest.file_size <= MIB:
            try:
                data = json.loads(archive.read(manifest).decode('utf-8'), object_pairs_hook=unique_json_object)
                entries = data.get('split_apks') if isinstance(data, dict) else None
                package = data.get('package_name') if isinstance(data, dict) and isinstance(data.get('package_name'), str) else None
                if isinstance(entries, list) and all(isinstance(x, dict) and isinstance(x.get('file'), str) for x in entries):
                    for entry in entries: declared.setdefault(entry['file'], []).append(entry)
            except (ValueError, UnicodeError, RuntimeError, zipfile.BadZipFile):
                pass  # The outer manifest validation reports invalid or unsupported metadata.
        with tempfile.TemporaryDirectory(prefix='apklab-xapk-apks-') as tmp:
            for index, info in enumerate(members):
                target = Path(tmp) / ('input-%04d.apk' % index)
                digest = hashlib.sha256(); size = 0
                with archive.open(info) as src, target.open('xb') as dest:
                    while True:
                        chunk = src.read(MIB)
                        if not chunk: break
                        size += len(chunk)
                        if size > info.file_size or size > MAX_APK: raise ValueError('Contained APK exceeds size limit')
                        digest.update(chunk); dest.write(chunk)
                if size != info.file_size: raise ValueError('Contained APK size mismatch')
                item = {'entry': info.filename, 'size': size, 'sha256': digest.hexdigest()}
                results.append(item)
                add(report, 'verified', info.filename, 'Copied XAPK member with CRC and SHA-256; hash does not authenticate origin')
                refs = declared.get(info.filename, [])
                if len(refs) != 1:
                    add(report, 'not_tested', info.filename, 'No unique supported manifest declaration for size and SHA-256')
                else:
                    expected = refs[0]
                    for key, actual in (('size', size), ('sha256', digest.hexdigest())):
                        value = expected.get(key)
                        valid = (isinstance(value, int) and not isinstance(value, bool) and value >= 0) if key == 'size' else (isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdefABCDEF' for c in value))
                        if not valid: add(report, 'not_tested', info.filename, 'Manifest ' + key + ' is absent or unsupported')
                        elif (value.lower() if key == 'sha256' else value) != actual:
                            add(report, 'failures', info.filename, 'Manifest ' + key + ' differs from contained APK')
                        else: add(report, 'verified', info.filename, 'Manifest ' + key + ' matches contained APK')
                sub = {'verified': [], 'inferences': [], 'failures': [], 'not_tested': []}
                item['apk'] = inspect_one(target, sub, min(max_entry, MAX_APK), min(max_total, MAX_TOTAL))
                item['apk']['file'] = info.filename
                observed = item['apk'].get('package')
                if not package or not observed:
                    add(report, 'not_tested', info.filename, 'Cannot compare manifest package_name with APK package')
                else:
                    inference = item['apk'].get('metadata_source') == 'internal_axml'
                    category = ('inferences' if inference else ('verified' if package == observed else 'failures'))
                    add(report, category, info.filename, 'XAPK package_name ' + ('matches' if package == observed else 'differs from') + ' APK package' + (' (internal AXML)' if inference else ''))
                for category in ('verified', 'inferences', 'failures', 'not_tested'):
                    for entry in sub[category]:
                        add(report, category, info.filename, entry['detail'].replace(str(target), info.filename))
    add(report, 'not_tested', 'contained APKs', 'No split completeness, signer rotation, OBB compatibility or installation guarantee')
    return results
