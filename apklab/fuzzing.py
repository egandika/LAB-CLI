"""Bounded deterministic mutation smoke tests for synthetic APKLab parser inputs.

This is a real parser exercise, not coverage-guided fuzzing, a sandbox, or a
security certification. It never executes app code or uses user APK files.
"""
from __future__ import annotations
import hashlib
import io
import random
import struct
import zipfile
from zlib import error as ZlibError

from .analysis import parse_xmltree
from .axml import ANDROID, NONE, parse_manifest
from .core import validate_apk_archive
from .dex import read_dex
from .split_metadata import parse_dependencies, parse_split_types

MAX_CASES = 10000
MAX_INPUT_BYTES = 8 * 1024 * 1024


def _synthetic_axml_seed() -> bytes:
    """Build a small valid binary manifest without relying on test-only modules."""
    values = ['manifest', 'package', 'org.example', ANDROID, 'versionCode',
              'versionName', '1.2', 'uses-permission', 'name',
              'android.permission.INTERNET', 'application', 'activity', '.Main']
    index = {value: i for i, value in enumerate(values)}

    def chunk(kind, header, content):
        size = 8 + len(content)
        if size % 4:
            raise AssertionError('synthetic AXML chunk is not word-aligned')
        return struct.pack('<HHI', kind, header, size) + content

    blob = bytearray()
    offsets = []
    for value in values:
        encoded = value.encode('utf-8')
        offsets.append(len(blob))
        blob.extend(bytes((len(value), len(encoded))) + encoded + b'\0')
    blob.extend(b'\0' * (-len(blob) % 4))
    pool = chunk(1, 28, struct.pack('<IIIII', len(values), 0, 0x100,
                                    28 + 4 * len(values), 0)
                 + b''.join(struct.pack('<I', offset) for offset in offsets) + blob)

    def start(tag, attributes=()):
        encoded_attributes = bytearray()
        for namespace, name, kind, value in attributes:
            value_index = index[value] if kind == 3 else value
            encoded_attributes.extend(struct.pack(
                '<IIIHBBI', NONE if namespace is None else index[namespace],
                index[name], NONE, 8, 0, kind, value_index))
        payload = (struct.pack('<II', 1, NONE)
                   + struct.pack('<IIHHHHHH', NONE, index[tag], 20, 20,
                                 len(attributes), 0, 0, 0)
                   + encoded_attributes)
        return chunk(0x102, 16, payload)

    def end(tag):
        return chunk(0x103, 16, struct.pack('<II', 1, NONE)
                     + struct.pack('<II', NONE, index[tag]))

    body = b''.join((
        pool,
        start('manifest', [(None, 'package', 3, 'org.example'),
                           (ANDROID, 'versionCode', 0x10, 42),
                           (ANDROID, 'versionName', 3, '1.2')]),
        start('uses-permission', [(ANDROID, 'name', 3,
                                   'android.permission.INTERNET')]),
        end('uses-permission'),
        start('application'),
        start('activity', [(ANDROID, 'name', 3, '.Main')]),
        end('activity'), end('application'), end('manifest'),
    ))
    return struct.pack('<HHI', 3, 8, 8 + len(body)) + body


def _synthetic_dex_seed(n_protos=2, n_params=2) -> bytes:
    """Build a minimal valid DEX identifier/prototype table input."""
    strings, types, protos = 112, 116, 120
    parameters = protos + n_protos * 12
    text = parameters + 4 + n_params * 2
    data = bytearray(text + 3)
    data[:8] = b'dex\n035\0'

    def put(offset, value):
        struct.pack_into('<I', data, offset, value)

    put(32, len(data)); put(36, 112); put(40, 0x12345678)
    for offset, count, start in ((56, 1, strings), (64, 1, types),
                                 (72, n_protos, protos)):
        put(offset, count); put(offset + 4, start)
    put(strings, text); put(types, 0)
    for i in range(n_protos):
        struct.pack_into('<III', data, protos + 12 * i, 0, 0, parameters)
    put(parameters, n_params)
    data[text:] = b'\x01V\0'
    return bytes(data)


def _synthetic_aapt_xmltree_seed() -> bytes:
    return (b'E: manifest (line=1)\n'
            b'  A: android:configForSplit(0x01010591)="feature.camera"\n'
            b'  A: android:isFeatureSplit(0x0101055b)=(type 0x12)0x1\n'
            b'  A: android:versionCodeMajor(0x01010576)=(type 0x10)0x2\n'
            b'  A: android:requiredSplitTypes(0x0101064e)="base__abi"\n'
            b'  A: android:splitTypes(0x0101064f)="base__abi"\n'
            b'  E: uses-split (line=2)\n'
            b'    A: android:name(0x01010003)="feature.camera"\n'
            b'  E: uses-permission (line=3)\n'
            b'    A: android:name(0x01010003)="android.permission.INTERNET"\n'
            b'  E: application (line=4)\n'
            b'    A: android:isSplitRequired(0x01010592)=(type 0x12)0x1\n'
            b'    E: activity (line=5)\n'
            b'      A: android:name(0x01010003)=".Main"\n')


def mutate(seed: bytes, rng: random.Random, max_input_bytes: int) -> bytes:
    """Apply one reproducible, bounded mutation to an immutable synthetic seed."""
    data = bytearray(seed)
    if not data:
        return bytes(data)
    operation = rng.randrange(5)
    if operation == 0:
        del data[rng.randrange(len(data) + 1):]
    elif operation == 1:
        index = rng.randrange(len(data))
        data[index] ^= 1 << rng.randrange(8)
    elif operation == 2:
        for _ in range(rng.randrange(1, min(5, len(data)) + 1)):
            index = rng.randrange(len(data))
            data[index] ^= 1 << rng.randrange(8)
    elif operation == 3:
        start = rng.randrange(len(data))
        width = rng.randrange(1, min(65, len(data) - start) + 1)
        data[start:start + width] = bytes(rng.getrandbits(8) for _ in range(width))
    else:
        room = max_input_bytes - len(data)
        if room:
            width = rng.randrange(1, min(129, room) + 1)
            data.extend(rng.getrandbits(8) for _ in range(width))
        else:
            index = rng.randrange(len(data))
            data[index] ^= 1 << rng.randrange(8)
    if len(data) > max_input_bytes:
        raise AssertionError('mutation exceeded the configured input cap')
    return bytes(data)


def _make_zip_seed(manifest_bytes: bytes, dex_bytes: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('AndroidManifest.xml', manifest_bytes)
        archive.writestr('classes.dex', dex_bytes)
    return buffer.getvalue()


def _parse_zip(data: bytes, max_uncompressed_bytes: int) -> dict:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = validate_apk_archive('synthetic.apk', archive,
                                         max_entry=max_uncompressed_bytes,
                                         max_total=max_uncompressed_bytes)
    except (zipfile.BadZipFile, ZlibError, EOFError, OSError, RuntimeError,
            NotImplementedError) as exc:
        raise ValueError('Malformed synthetic APK ZIP: ' + str(exc)) from exc
    return {'entries': len(infos)}


def run_smoke(seed: int=20261114, cases: int=256,
              max_input_bytes: int=1024 * 1024) -> dict:
    """Run deterministic parser-only mutations and return a JSON-safe summary."""
    if not 1 <= cases <= MAX_CASES:
        raise ValueError('cases must be between 1 and ' + str(MAX_CASES))
    if not 1 <= max_input_bytes <= MAX_INPUT_BYTES:
        raise ValueError('max_input_bytes must be between 1 byte and 8 MiB')

    manifest = _synthetic_axml_seed()
    dex = _synthetic_dex_seed(2, 2)
    aapt_text = _synthetic_aapt_xmltree_seed()

    def parse_aapt(parser):
        return lambda data: parser(data.decode('utf-8', 'replace'))

    def parse_zip(data):
        return _parse_zip(data, max_input_bytes)

    sources = (
        ('binary_axml', parse_manifest, manifest),
        ('aapt_dependencies', parse_aapt(parse_dependencies), aapt_text),
        ('aapt_split_types', parse_aapt(parse_split_types), aapt_text),
        ('aapt_manifest', parse_aapt(parse_xmltree), aapt_text),
        ('dex', read_dex, dex),
        ('apk_zip', parse_zip, _make_zip_seed(manifest, dex)),
    )
    if any(len(data) > max_input_bytes for _name, _parser, data in sources):
        raise ValueError('configured input cap is smaller than a synthetic seed')

    parser_results = {}
    unexpected = []
    seed_failures = []
    for parser_index, (name, parser, original) in enumerate(sources):
        parser_seed = seed + parser_index
        digest = hashlib.sha256(original).hexdigest()
        rng = random.Random(parser_seed)
        seed_accepted = True
        try:
            baseline = parser(original)
            if not isinstance(baseline, dict):
                raise TypeError('parser returned a non-dictionary result for its synthetic seed')
        except Exception as exc:
            seed_accepted = False
            seed_failures.append({
                'parser': name,
                'seed': parser_seed,
                'seed_sha256': digest,
                'exception_type': type(exc).__name__,
                'message': str(exc)[:256],
            })
        counts = {'seed': parser_seed, 'seed_sha256': digest,
                  'seed_accepted': seed_accepted,
                  'cases': 0, 'returned': 0, 'rejected_as_invalid': 0}
        for index in range(cases):
            data = mutate(original, rng, max_input_bytes)
            counts['cases'] += 1
            try:
                result = parser(data)
                if not isinstance(result, dict):
                    raise TypeError('parser returned a non-dictionary result')
                counts['returned'] += 1
            except ValueError:
                counts['rejected_as_invalid'] += 1
            except Exception as exc:
                unexpected.append({
                    'parser': name,
                    'seed': parser_seed,
                    'seed_sha256': digest,
                    'case': index,
                    'input_sha256': hashlib.sha256(data).hexdigest(),
                    'exception_type': type(exc).__name__,
                    'message': str(exc)[:256],
                })
        parser_results[name] = counts

    total_cases = cases * len(sources)
    return {
        'mode': 'deterministic_mutation_smoke',
        'harness_version': 3,
        'seed': seed,
        'cases_per_parser': cases,
        'total_cases': total_cases,
        'seed_validation_count': len(sources),
        'max_input_bytes': max_input_bytes,
        'synthetic_inputs_only': True,
        'app_code_executed': False,
        'parsers': parser_results,
        'seed_failures': seed_failures,
        'unexpected_exceptions': unexpected,
        'limitations': [
            'Not coverage-guided and not a security audit',
            'Only selected AXML, AAPT XML-tree, DEX and APK ZIP validation paths are exercised',
            'A clean run does not prove parser correctness or application safety',
        ],
    }
