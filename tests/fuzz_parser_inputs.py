"""Bounded deterministic mutation smoke test for synthetic AXML, DEX, and ZIP inputs.

The ZIP seed is an in-memory synthetic APK archive. This is not coverage-guided
fuzzing, a sandbox, or a security certification; no app code is executed.
"""
import argparse
import hashlib
import io
import json
import random
import sys
import zipfile
from zlib import error as ZlibError
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / 'tests'
for path in (str(ROOT), str(TESTS)):
    if path not in sys.path:
        sys.path.insert(0, path)

from apklab.axml import parse_manifest
from apklab.core import validate_apk_archive
from apklab.dex import read_dex
from test_internal_axml import fixture as axml_seed
from test_t04_dex_limits import dex_with_shared_parameters

MAX_CASES = 10000
MAX_INPUT_BYTES = 8 * 1024 * 1024


def mutate(seed, rng, max_input_bytes):
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


def make_zip_seed(manifest_bytes, dex_bytes):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('AndroidManifest.xml', manifest_bytes)
        archive.writestr('classes.dex', dex_bytes)
    return buffer.getvalue()


def parse_zip(data, max_uncompressed_bytes):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = validate_apk_archive('synthetic.apk', archive,
                                         max_entry=max_uncompressed_bytes,
                                         max_total=max_uncompressed_bytes)
    except (zipfile.BadZipFile, ZlibError, EOFError, OSError, RuntimeError, NotImplementedError) as exc:
        raise ValueError('Malformed synthetic APK ZIP: ' + str(exc)) from exc
    return {'entries': len(infos)}


def run_smoke(seed=20261114, cases=256, max_input_bytes=1024 * 1024):
    """Run deterministic parser-only mutations and return a JSON-safe summary."""
    if not 1 <= cases <= MAX_CASES:
        raise ValueError('cases must be between 1 and ' + str(MAX_CASES))
    if not 1 <= max_input_bytes <= MAX_INPUT_BYTES:
        raise ValueError('max_input_bytes must be between 1 byte and 8 MiB')
    manifest = axml_seed()
    dex = dex_with_shared_parameters(2, 2)

    def parse_apk_zip(data):
        return parse_zip(data, max_input_bytes)

    sources = (
        ('axml', parse_manifest, manifest),
        ('dex', read_dex, dex),
        ('zip', parse_apk_zip, make_zip_seed(manifest, dex)),
    )
    if any(len(data) > max_input_bytes for _name, _parser, data in sources):
        raise ValueError('configured input cap is smaller than a synthetic seed')

    parsers = {}
    unexpected = []
    total_cases = 0
    for parser_index, (name, parser, original) in enumerate(sources):
        parser_seed = seed + parser_index
        source_digest = hashlib.sha256(original).hexdigest()
        rng = random.Random(parser_seed)
        counts = {'seed': parser_seed, 'seed_sha256': source_digest,
                  'cases': 0, 'accepted': 0, 'rejected_as_invalid': 0}
        for index in range(cases):
            data = mutate(original, rng, max_input_bytes)
            total_cases += 1
            counts['cases'] += 1
            try:
                result = parser(data)
                if not isinstance(result, dict):
                    raise TypeError('parser returned a non-dictionary result')
                counts['accepted'] += 1
            except ValueError:
                counts['rejected_as_invalid'] += 1
            except Exception as exc:
                unexpected.append({
                    'parser': name,
                    'seed': parser_seed,
                    'seed_sha256': source_digest,
                    'case': index,
                    'input_sha256': hashlib.sha256(data).hexdigest(),
                    'exception_type': type(exc).__name__,
                    'message': str(exc)[:256],
                })
        parsers[name] = counts

    return {
        'mode': 'deterministic_mutation_smoke',
        'harness_version': 1,
        'seed': seed,
        'cases_per_parser': cases,
        'total_cases': total_cases,
        'max_input_bytes': max_input_bytes,
        'synthetic_inputs_only': True,
        'app_code_executed': False,
        'parsers': parsers,
        'unexpected_exceptions': unexpected,
        'limitations': [
            'Not coverage-guided and not a security audit',
            'Only selected binary AXML, DEX, and APK ZIP validation paths are exercised',
            'A clean run does not prove parser correctness or application safety',
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description='Run bounded synthetic AXML/DEX/ZIP parser mutation smoke tests')
    parser.add_argument('--seed', type=int, default=20261114, help='Deterministic mutation seed')
    parser.add_argument('--cases', type=int, default=256, help='Cases per parser (1-10000)')
    parser.add_argument('--max-input-mib', type=int, default=1, help='Per-input cap (1-8 MiB)')
    args = parser.parse_args(argv)
    try:
        result = run_smoke(args.seed, args.cases, args.max_input_mib * 1024 * 1024)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result['unexpected_exceptions'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
