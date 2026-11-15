import contextlib
import io
import json
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from apklab.axml import ANDROID, NONE, parse_manifest
from apklab.cli import main
from apklab.split_metadata import parse_split_types, read_split_types


def manifest(attrs=()):
    # Each attribute is (namespace, name, typed value kind, value).
    strings = ['manifest', 'package', 'org.example', 'versionCode', ANDROID]
    for ns, name, kind, value in attrs:
        for text in (ns, name, value if kind == 3 else None):
            if text is not None and text not in strings:
                strings.append(text)
    index = {s: i for i, s in enumerate(strings)}
    blob = bytearray(); offsets = []
    for s in strings:
        data = s.encode('utf8'); offsets.append(len(blob))
        blob.extend(bytes([len(s), len(data)]) + data + b'\0')
    blob.extend(b'\0' * (-len(blob) % 4))
    def chunk(kind, head, content):
        return struct.pack('<HHI', kind, head, 8 + len(content)) + content
    pool = chunk(1, 28, struct.pack('<IIIII', len(strings), 0, 0x100, 28 + 4 * len(strings), 0) + b''.join(struct.pack('<I', x) for x in offsets) + blob)
    attrs = [(None, 'package', 3, 'org.example'), (ANDROID, 'versionCode', 0x10, 1)] + list(attrs)
    encoded = b''
    for ns, name, kind, value in attrs:
        encoded += struct.pack('<IIIHBBI', NONE if ns is None else index[ns], index[name], NONE, 8, 0, kind, index[value] if kind == 3 else value)
    start = chunk(0x102, 16, struct.pack('<II', 1, NONE) + struct.pack('<IIHHHHHH', NONE, index['manifest'], 20, 20, len(attrs), 0, 0, 0) + encoded)
    end = chunk(0x103, 16, struct.pack('<IIII', 1, NONE, NONE, index['manifest']))
    body = pool + start + end
    return struct.pack('<HHI', 3, 8, len(body) + 8) + body


def tree(required=None, provided=None, extra=''):
    s = 'E: manifest (line=1)\n'
    if required is not None: s += '  A: android:requiredSplitTypes(0x0101064e)=' + required + '\n'
    if provided is not None: s += '  A: android:splitTypes(0x0101064f)=' + provided + '\n'
    return s + extra


class SplitTypeParserTests(unittest.TestCase):
    def test_literal_empty_absent_and_duplicate_offerings(self):
        parsed = parse_split_types(tree('"base__abi,base__density"', '"base__abi,base__abi"'))
        self.assertEqual(parsed['attributes']['requiredSplitTypes']['types'], ['base__abi', 'base__density'])
        self.assertEqual(parsed['attributes']['splitTypes']['types'], ['base__abi'])
        self.assertEqual(parse_split_types(tree('""'))['attributes']['requiredSplitTypes']['types'], [])
        self.assertEqual(parse_split_types(tree())['attributes']['splitTypes']['status'], 'absent')

    def test_references_duplicates_truncation_namespaces_and_bad_input(self):
        cases = [tree('@0x7f010001'), tree('"@string/types"'),
                 tree('"a"', extra='  A: android:requiredSplitTypes="b"\n'),
                 tree(extra='  A: custom:requiredSplitTypes="a"\n'),
                 tree(extra='  A: requiredSplitTypes="a"\n'),
                 tree(extra='  A: android:requiredSplitTypes(0x0101064f)="a"\n'),
                 tree('"a" (Raw: "b")'), 'not xmltree']
        for text in cases:
            with self.subTest(text=text):
                self.assertEqual(parse_split_types(text)['attributes']['requiredSplitTypes']['status'], 'unknown')
        for text in (tree('"a"'), tree('"a"')[:-1]):
            self.assertEqual(parse_split_types(text, True)['attributes']['requiredSplitTypes']['status'], 'unknown')
        self.assertEqual(parse_split_types(tree(extra='  E: application\n    A: android:requiredSplitTypes="a"\n'))['attributes']['requiredSplitTypes']['status'], 'absent')

    def test_binary_axml_literals_and_unknowns(self):
        parsed = parse_manifest(manifest([(ANDROID, 'requiredSplitTypes', 3, 'base__abi'), (ANDROID, 'splitTypes', 3, '')]))
        self.assertEqual(parsed['split_type_attributes']['requiredSplitTypes']['value'], 'base__abi')
        self.assertEqual(parsed['split_identity']['status'], 'absent')
        for attrs in ([(ANDROID, 'requiredSplitTypes', 1, 0x7f010001)],
                      [('http://example.org/custom', 'requiredSplitTypes', 3, 'base__abi')]):
            self.assertEqual(parse_manifest(manifest(attrs))['split_type_attributes']['requiredSplitTypes']['status'], 'unknown')
        with self.assertRaises(ValueError):
            parse_manifest(manifest([(ANDROID, 'splitTypes', 3, 'x'), (ANDROID, 'splitTypes', 3, 'y')]))
        with self.assertRaises(ValueError): parse_manifest(manifest()[:-1])

    def test_aapt_incomplete_capture_and_fallback(self):
        with patch('apklab.split_metadata.find_tool', return_value='aapt'), patch('apklab.split_metadata.run', return_value={'returncode': 0, 'stdout': tree('"a"'), 'capture_incomplete': True}):
            self.assertEqual(read_split_types('not-read.apk')['attributes']['requiredSplitTypes']['status'], 'unknown')
        with patch('apklab.split_metadata.find_tool', return_value=None):
            self.assertEqual(read_split_types('missing.apk')['source'], 'unavailable')


class SplitTypeCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
    def apk(self, name, content):
        path = self.root / name
        with zipfile.ZipFile(path, 'w') as z: z.writestr('AndroidManifest.xml', content)
        return path
    def call(self, files, mode='fallback', partial=None):
        calls = []
        def find(name): return '/fake/aapt' if mode == 'aapt' and name == 'aapt' else None
        def run(argv, timeout=120):
            path = Path(argv[-2] if 'xmltree' in argv else argv[-1]); calls.append(path)
            with zipfile.ZipFile(path) as z: content = z.read('AndroidManifest.xml').decode()
            if 'badging' in argv:
                split = '' if content.startswith('base:') else (" split='config.fr'" if content.startswith('split2:') else " split='config.en'")
                out = "package: name='org.example' versionCode='1'" + split + '\n'
            else: out = content.split(':', 1)[1]
            return {'returncode': 0, 'stdout': out, 'stderr': '', 'stdout_truncated': partial is not None and content.startswith(partial)}
        stream = io.StringIO()
        with patch('apklab.core.find_tool', side_effect=find), patch('apklab.split_metadata.find_tool', side_effect=find), patch('apklab.core.run', side_effect=run), patch('apklab.split_metadata.run', side_effect=run), contextlib.redirect_stdout(stream):
            code = main(['inspect', *(str(p) for p in files), '--split-types'])
        return code, json.loads(stream.getvalue()), calls
    def test_aapt_match_duplicate_offerings_and_copy(self):
        base = self.apk('base.apk', 'base:' + tree('"base__abi"', '""'))
        split = self.apk('split.apk', 'split:' + tree(provided='"base__abi,base__abi"'))
        before = [p.read_bytes() for p in (base, split)]
        code, result, calls = self.call([base, split], 'aapt')
        self.assertEqual(code, 3); self.assertFalse(result['split_types']['missing']); self.assertFalse(result['split_types']['unknown'])
        self.assertTrue(any(x['subject'] == 'split types' for x in result['verified']))
        self.assertTrue(calls); self.assertTrue(all(p not in (base, split) for p in calls))
        self.assertEqual(result['split_type_observations'][0]['file'], str(base))
        self.assertNotIn('apklab-split-types-', json.dumps(result))
        self.assertEqual([p.read_bytes() for p in (base, split)], before)
    def test_duplicate_provided_across_two_apks(self):
        base = self.apk('base.apk', 'base:' + tree('"base__abi"'))
        first = self.apk('one.apk', 'split:' + tree(provided='"base__abi"'))
        second = self.apk('two.apk', 'split2:' + tree(provided='"base__abi"'))
        code, result, _ = self.call([base, first, second], 'aapt')
        self.assertEqual(code, 3, result)
        self.assertEqual(result['split_types']['provided'], ['base__abi'])
        self.assertEqual(result['split_types']['missing'], [])

    def test_resource_reference_is_unknown_and_never_failure(self):
        base = self.apk('base.apk', 'base:' + tree('"base__abi"'))
        split = self.apk('split.apk', 'split:' + tree(provided='@0x7f010001'))
        _, result, _ = self.call([base, split], 'aapt')
        self.assertTrue(result['split_types']['unknown'])
        self.assertFalse(any(x['subject'] == 'split types' for x in result['failures']))

    def test_aapt_missing_is_failure_only_when_metadata_known(self):
        base = self.apk('base.apk', 'base:' + tree('"base__abi,base__density"'))
        split = self.apk('split.apk', 'split:' + tree(provided='"base__abi"'))
        code, r, _ = self.call([base, split], 'aapt')
        self.assertEqual(code, 1); self.assertEqual(r['split_types']['missing'], ['base__density'])
        self.assertTrue(any('base__density' in x['detail'] for x in r['failures']))
        _, r, _ = self.call([base, split], 'aapt', partial='split:')
        self.assertTrue(r['split_types']['unknown']); self.assertFalse(any(x['subject'] == 'split types' for x in r['failures']))
    def test_matching_fallback_and_missing_base_identity(self):
        base = self.apk('base.apk', manifest([(ANDROID, 'requiredSplitTypes', 3, 'base__abi')]))
        split = self.apk('split.apk', manifest([(None, 'split', 3, 'config.en'), (ANDROID, 'splitTypes', 3, 'base__abi')]))
        _, result, _ = self.call([base, split])
        self.assertEqual(result['split_types']['missing'], [])
        self.assertTrue(any(x['subject'] == 'split types' for x in result['inferences']))
        other_base = self.apk('other.apk', manifest([]))
        _, result, _ = self.call([base, other_base])
        self.assertTrue(result['split_types']['unknown'])
        self.assertIsNone(result['split_types']['missing'])

    def test_corrupt_zip_is_not_compared(self):
        base = self.apk('base.apk', manifest([(ANDROID, 'requiredSplitTypes', 3, 'base__abi')]))
        broken = self.root / 'bad.apk'; broken.write_bytes(b'not a zip')
        _, result, _ = self.call([base, broken])
        self.assertTrue(result['split_types']['unknown'])
        self.assertIsNone(result['split_types']['missing'])
        self.assertFalse(any(x['subject'] == 'split types' for x in result['failures']))

    def test_fallback_result_is_inference_not_verified_or_failure(self):
        base = self.apk('base.apk', manifest([(ANDROID, 'requiredSplitTypes', 3, 'base__abi')]))
        split = self.apk('split.apk', manifest([(None, 'split', 3, 'config.en'), (ANDROID, 'splitTypes', 3, 'base__density')]))
        code, r, _ = self.call([base, split])
        self.assertEqual(code, 3); self.assertEqual(r['split_types']['missing'], ['base__abi'])
        self.assertTrue(any(x['subject'] == 'split types' for x in r['inferences']))
        self.assertFalse(any(x['subject'] == 'split types' for x in r['failures'] + r['verified']))
    def test_unreadable_metadata_never_claims_comparison(self):
        base = self.apk('base.apk', manifest([(ANDROID, 'requiredSplitTypes', 3, 'base__abi')]))
        broken = self.apk('broken.apk', b'bad binary xml')
        _, r, _ = self.call([base, broken])
        self.assertTrue(r['split_types']['unknown']); self.assertIsNone(r['split_types']['missing'])
        self.assertFalse(any(x['subject'] == 'split types' for x in r['failures'] + r['verified']))
    def test_empty_and_absent_fallback_attributes(self):
        base = self.apk('base.apk', manifest([(ANDROID, 'requiredSplitTypes', 3, '')]))
        _, r, _ = self.call([base])
        self.assertEqual(r['split_types']['required'], []); self.assertEqual(r['split_types']['provided'], [])
        self.assertTrue(r['not_tested'])


if __name__ == '__main__': unittest.main()
