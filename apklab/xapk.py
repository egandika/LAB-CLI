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
        except BaseException as original:
            try: shutil.rmtree(dest)
            except OSError as cleanup:
                raise RuntimeError(str(original) + '; cleanup failed: ' + str(cleanup)) from original
            raise


def manifest_info(path, entries, directory=False):
    """Compare the optional APKPure-style split_apks list, not trust it as truth."""
    item = next((i for i in entries if i['path'] == 'manifest.json' and i['kind'] == 'other'), None)
    if not item:
        return {'status': 'absent'}
    if item['size'] > MIB:
        return {'status': 'unsupported', 'reason': 'manifest.json exceeds 1 MiB'}
    try:
        if directory:
            data = json.loads((Path(path) / 'manifest.json').read_bytes().decode('utf-8'))
        else:
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


def repack(path, destination, replacements, max_entry, max_total, *, update_manifest=False):
    """Copy a validated archive into a new XAPK, optionally replacing APK entries."""
    import copy
    from .core import validate_apk_archive
    dest = Path(destination)
    with zipfile.ZipFile(path) as source:
        infos = validate(source, max_entry, max_total)
        files = {i.filename: i for i in infos if not i.is_dir()}
        if not any(n.lower().endswith('.apk') for n in files):
            raise ValueError('No APK entries found in archive')
        for entry, replacement in replacements.items():
            p = Path(replacement)
            if entry not in files or not entry.lower().endswith('.apk'):
                raise ValueError('Replacement target must be an existing APK entry: ' + entry)
            if not p.is_file() or p.suffix.lower() != '.apk':
                raise ValueError('Replacement must be an APK file: ' + str(p))
            with zipfile.ZipFile(p) as apk:
                try:
                    validate_apk_archive(p, apk, max_entry, max_total)
                except ValueError as exc:
                    raise ValueError('Replacement APK: ' + str(exc)) from exc
        updated_manifest = None
        replacement_hashes = {}
        if update_manifest:
            if not replacements: raise ValueError('--update-manifest requires at least one replacement')
            manifest = files.get('manifest.json')
            if manifest is None or manifest.file_size > MIB: raise ValueError('A supported manifest.json within 1 MiB is required')
            def unique_object(pairs):
                obj = {}
                for key, value in pairs:
                    if key in obj: raise ValueError('Duplicate JSON key in manifest: ' + key)
                    obj[key] = value
                return obj
            try: data = json.loads(source.read(manifest).decode('utf-8'), object_pairs_hook=unique_object)
            except (UnicodeError, ValueError) as exc: raise ValueError('Invalid manifest.json: ' + str(exc)) from exc
            declarations = data.get('split_apks') if isinstance(data, dict) else None
            if not isinstance(declarations, list) or not all(isinstance(x, dict) and isinstance(x.get('file'), str) for x in declarations):
                raise ValueError('Unsupported manifest split_apks schema')
            for name, replacement in replacements.items():
                matches = [item for item in declarations if item['file'] == name]
                if len(matches) != 1: raise ValueError('Each replacement must have exactly one split_apks declaration: ' + name)
                item = matches[0]
                if any(key.lower() in ('checksum', 'md5', 'sha1', 'sha512', 'hash') for key in item):
                    raise ValueError('Unsupported additional checksum field in manifest: ' + name)
                digest = hashlib.sha256(); size = 0
                with open(replacement, 'rb') as source_apk:
                    for chunk in iter(lambda: source_apk.read(CHUNK), b''):
                        size += len(chunk)
                        if size > max_entry: raise ValueError('Replacement APK exceeds entry size limit')
                        digest.update(chunk)
                replacement_hashes[name] = (size, digest.hexdigest())
                item['size'] = size; item['sha256'] = digest.hexdigest()
            updated_manifest = (json.dumps(data, ensure_ascii=True, indent=2) + '\n').encode('utf-8')
            if len(updated_manifest) > MIB or len(updated_manifest) > max_entry: raise ValueError('Updated manifest exceeds size limit')
        total = sum(len(updated_manifest) if i.filename == 'manifest.json' and updated_manifest is not None else Path(replacements[i.filename]).stat().st_size if i.filename in replacements else i.file_size for i in infos)
        if total > max_total: raise ValueError('Repacked archive exceeds total size limit')
        if any(Path(p).stat().st_size > max_entry for p in replacements.values()):
            raise ValueError('Replacement APK exceeds entry size limit')
        with dest.open('xb') as out_file:
            try:
                with zipfile.ZipFile(out_file, 'w', allowZip64=True) as output:
                    items = summarize(infos)
                    for info, item in zip(infos, items):
                        new_info = copy.copy(info)
                        new_info.file_size = len(updated_manifest) if info.filename == 'manifest.json' and updated_manifest is not None else Path(replacements[info.filename]).stat().st_size if info.filename in replacements else info.file_size
                        if info.is_dir():
                            output.writestr(new_info, b'')
                        else:
                            with output.open(new_info, 'w') as target:
                                if info.filename == 'manifest.json' and updated_manifest is not None:
                                    target.write(updated_manifest)
                                    item.update(size=len(updated_manifest), sha256=hashlib.sha256(updated_manifest).hexdigest(), manifest_updated=True)
                                elif info.filename not in replacements:
                                    item['sha256'] = stream_entry(source, info, target)
                                else:
                                    digest = hashlib.sha256(); size = 0
                                    with open(replacements[info.filename], 'rb') as replacement:
                                        while True:
                                            chunk = replacement.read(CHUNK)
                                            if not chunk: break
                                            size += len(chunk)
                                            if size > new_info.file_size: raise ValueError('Replacement size changed during repack')
                                            digest.update(chunk); target.write(chunk)
                                    if size != new_info.file_size: raise ValueError('Replacement size changed during repack')
                                    if update_manifest and (size, digest.hexdigest()) != replacement_hashes[info.filename]:
                                        raise ValueError('Replacement changed during manifest update')
                                    item.update(size=size, sha256=digest.hexdigest(), replaced=True)
                return items
            except BaseException as original:
                # Only a file created exclusively by this operation can be removed.
                try:
                    out_file.close()
                    dest.unlink(missing_ok=True)
                except OSError as cleanup:
                    raise RuntimeError(str(original) + '; cleanup failed: ' + str(cleanup)) from original
                raise


def obb_layout(path, infos):
    """Validate the supported APKPure-style package_name/expansions layout."""
    names = {i.filename for i in infos if not i.is_dir()}
    obbs = {n for n in names if n.lower().endswith('.obb')}
    manifest = next((i for i in infos if i.filename == 'manifest.json' and not i.is_dir()), None)
    if not manifest or manifest.file_size > MIB:
        raise ValueError('A supported manifest.json is required for validated OBB placement')
    with zipfile.ZipFile(path) as z:
        data = json.loads(z.read(manifest).decode('utf-8'))
    if not isinstance(data, dict): raise ValueError('manifest.json must be an object')
    package = data.get('package_name')
    if not isinstance(package, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+', package):
        raise ValueError('Manifest package_name is missing or invalid')
    expansions = data.get('expansions')
    if not isinstance(expansions, list): raise ValueError('Manifest expansions must be a list')
    mapping = {}
    targets = set()
    for item in expansions:
        if not isinstance(item, dict) or not isinstance(item.get('file'), str) or not isinstance(item.get('install_location'), str):
            raise ValueError('Manifest expansion requires file and install_location strings')
        file, location = item['file'], item['install_location']
        expected_location = 'Android/obb/' + package
        if location.rstrip('/') != expected_location or not re.fullmatch(r'(?:main|patch)\.[0-9]+\.' + re.escape(package) + r'\.obb', file):
            raise ValueError('Manifest expansion has invalid OBB filename or placement')
        target = expected_location + '/' + file
        candidates = [name for name in (file, target) if name in obbs]
        if len(candidates) != 1 or target in targets: raise ValueError('Missing, ambiguous or duplicate OBB expansion: ' + file)
        mapping[candidates[0]] = target
        targets.add(target)
    if set(mapping) != obbs: raise ValueError('Archive contains OBB files not declared by supported manifest expansions')
    return mapping


def repack_directory(path, destination, replacements, max_entry, max_total, *, update_manifest=False):
    """Create a directory with new archive and strictly manifest-validated OBB layout."""
    with zipfile.ZipFile(path) as z:
        infos = validate(z, max_entry, max_total)
        mapping = obb_layout(path, infos)
    dest = Path(destination)
    dest.mkdir(exist_ok=False)
    try:
        items = repack(path, dest/'repacked.xapk', replacements, max_entry, max_total, update_manifest=update_manifest)
        with zipfile.ZipFile(path) as z:
            infos = validate(z, max_entry, max_total)
            by_name = {i.filename: i for i in infos}
            for source, target in mapping.items():
                output = dest.joinpath(*target.split('/'))
                output.parent.mkdir(parents=True, exist_ok=True)
                with output.open('xb') as out: stream_entry(z, by_name[source], out)
        return items
    except BaseException as original:
        try: shutil.rmtree(dest)
        except OSError as cleanup:
            raise RuntimeError(str(original) + '; cleanup failed: ' + str(cleanup)) from original
        raise
