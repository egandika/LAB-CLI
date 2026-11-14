"""Bounded XAPK archive inspection and extraction; never execute archive code."""
from collections import Counter
import hashlib
import json
import re
import shutil
import stat
import zipfile
from pathlib import Path

MIB = 1024 * 1024
MAX_FILES = 100000
CHUNK = 1024 * 1024


def validate(z, max_entry, max_total):
    if max_entry < 1 or max_total < 1:
        raise ValueError('Size limits must be positive')
    infos = z.infolist()
    if len(infos) > MAX_FILES:
        raise ValueError('Archive has more than 100000 entries')
    if sum(i.file_size for i in infos) > max_total:
        raise ValueError('Archive exceeds total uncompressed size limit')
    seen, files = set(), set()
    for info in infos:
        name = info.filename
        # Reject platform-specific aliases as well as traversal on any platform.
        if info.orig_filename != name or not name or len(name) > 4096 or '\\' in name or '\x00' in name or name.startswith('/'):
            raise ValueError('Unsafe archive path: ' + repr(name))
        parts = name.rstrip('/').split('/')
        if any(not p or p in ('.', '..') or ':' in p or p.endswith((' ', '.')) for p in parts):
            raise ValueError('Unsafe archive path: ' + repr(name))
        if any(re.fullmatch(r'(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?', p) for p in parts):
            raise ValueError('Reserved archive path: ' + repr(name))
        key = '/'.join(parts).casefold()
        if key in seen: raise ValueError('Duplicate archive path: ' + name)
        seen.add(key)
        if not info.is_dir(): files.add(key)
        mode = (info.external_attr >> 16) & 0xffff
        kind = stat.S_IFMT(mode) if info.create_system == 3 else 0
        if kind not in (0, stat.S_IFREG, stat.S_IFDIR) or (kind == stat.S_IFDIR and not info.is_dir()) or (kind == stat.S_IFREG and info.is_dir()):
            raise ValueError('Unsupported special archive entry: ' + name)
        if info.flag_bits & 1: raise ValueError('Encrypted archive entry is unsupported: ' + name)
        if info.is_dir() and info.file_size: raise ValueError('Directory entry has content: ' + name)
        if info.file_size > max_entry: raise ValueError('Archive entry exceeds size limit: ' + name)
    for key in seen:
        parts = key.split('/')
        if any('/'.join(parts[:i]) in files for i in range(1, len(parts))):
            raise ValueError('File/directory archive path collision: ' + key)
    return infos


def stream_entry(z, info, out=None):
    digest = hashlib.sha256()
    total = 0
    with z.open(info) as src:
        while True:
            chunk = src.read(CHUNK)
            if not chunk: break
            total += len(chunk)
            if total > info.file_size: raise ValueError('Entry exceeds declared size: ' + info.filename)
            digest.update(chunk)
            if out: out.write(chunk)
    if total != info.file_size: raise ValueError('Entry size mismatch: ' + info.filename)
    return digest.hexdigest()


def summarize(infos):
    return [{'path': i.filename, 'size': i.file_size,
             'kind': 'directory' if i.is_dir() else 'apk' if i.filename.lower().endswith('.apk') else 'obb' if i.filename.lower().endswith('.obb') else 'other'} for i in infos]


def examine(path, max_entry, max_total, verify=False):
    with zipfile.ZipFile(path) as z:
        infos = validate(z, max_entry, max_total)
        items = summarize(infos)
        if verify:
            for info, item in zip(infos, items):
                if not info.is_dir(): item['sha256'] = stream_entry(z, info)
        return items


def unpack(path, destination, max_entry, max_total):
    dest = Path(destination)
    # The archive is opened read-only; destination must not exist.
    with zipfile.ZipFile(path) as z:
        infos = validate(z, max_entry, max_total)
        if not any(not i.is_dir() and i.filename.lower().endswith('.apk') for i in infos):
            raise ValueError('No APK entries found in archive')
        dest.mkdir(exist_ok=False)
        try:
            items = summarize(infos)
            for info, item in zip(infos, items):
                target = dest.joinpath(*info.filename.rstrip('/').split('/'))
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open('xb') as out:
                        item['sha256'] = stream_entry(z, info, out)
            return items
        except BaseException:
            shutil.rmtree(dest)
            raise


def manifest_info(path, entries):
    """Compare the optional APKPure-style split_apks list, not trust it as truth."""
    item = next((i for i in entries if i['path'] == 'manifest.json' and i['kind'] == 'other'), None)
    if not item:
        return {'status': 'absent'}
    if item['size'] > MIB:
        return {'status': 'unsupported', 'reason': 'manifest.json exceeds 1 MiB'}
    try:
        with zipfile.ZipFile(path) as z:
            data = json.loads(z.read('manifest.json').decode('utf-8'))
    except (UnicodeError, ValueError, zipfile.BadZipFile, RuntimeError) as e:
        return {'status': 'invalid', 'reason': str(e)}
    if not isinstance(data, dict):
        return {'status': 'invalid', 'reason': 'manifest.json must be a JSON object'}
    declared = data.get('split_apks')
    if not isinstance(declared, list) or not declared:
        return {'status': 'unsupported', 'reason': 'no non-empty split_apks list'}
    if not all(isinstance(x, dict) and isinstance(x.get('file'), str) and x['file'] for x in declared):
        return {'status': 'unsupported', 'reason': 'split_apks entries need a file string'}
    filenames = [x['file'] for x in declared]
    apk_paths = {x['path'] for x in entries if x['kind'] == 'apk'}
    return {'status': 'parsed', 'declared_apks': filenames,
            'missing_apks': sorted(set(filenames) - apk_paths),
            'undeclared_apks': sorted(apk_paths - set(filenames)),
            'duplicate_references': sorted(x for x, count in Counter(filenames).items() if count > 1)}
