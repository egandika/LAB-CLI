"""Bounded, deliberately partial Android binary XML metadata reader.

Only literal manifest metadata is observed; resource references are not resolved.
"""
import struct
import zipfile

MAX_MANIFEST = 8 * 1024 * 1024
MAX_STRINGS = 100000
MAX_NODES = 100000
ANDROID = 'http://schemas.android.com/apk/res/android'
NONE = 0xffffffff
COMPONENTS = {'activity', 'activity-alias', 'service', 'receiver', 'provider'}


def parse_manifest(data: bytes) -> dict:
    """Parse selected literal metadata from binary AXML or raise ValueError."""
    if len(data) > MAX_MANIFEST or len(data) < 8:
        raise ValueError('Binary manifest exceeds limit or is truncated')
    def u16(off): return struct.unpack_from('<H', data, off)[0]
    def u32(off): return struct.unpack_from('<I', data, off)[0]
    def chunk(off, end):
        if off + 8 > end: raise ValueError('Truncated AXML chunk header')
        kind, header, size = struct.unpack_from('<HHI', data, off)
        if header < 8 or size < header or off + size > end or size % 4:
            raise ValueError('Invalid AXML chunk bounds')
        return kind, header, size
    kind, header, size = chunk(0, len(data))
    if kind != 3 or header != 8 or size != len(data): raise ValueError('Not a complete binary AXML document')
    strings = None
    stack = []
    root_seen = False
    closed = False
    count = 0
    result = {'package': None, 'version_code': None, 'version_name': None,
              'permissions': [], 'components': [], 'unresolved': [],
              'split_type_attributes': {}, 'split_identity': {'status': 'absent'}}
    def string(index):
        if index == NONE: return None
        if strings is None or index >= len(strings): raise ValueError('Invalid AXML string index')
        return strings[index]
    off = header
    while off < size:
        count += 1
        if count > MAX_NODES: raise ValueError('AXML chunk count exceeds limit')
        typ, head, length = chunk(off, size)
        end = off + length
        if typ == 1:
            if strings is not None or head < 28 or stack or root_seen: raise ValueError('Invalid AXML string pool')
            n, styles, flags, start, styles_start = struct.unpack_from('<IIIII', data, off + 8)
            if n > MAX_STRINGS or styles > MAX_STRINGS or head + 4 * (n + styles) > length or start < head + 4 * (n + styles) or start > length:
                raise ValueError('Invalid AXML string pool bounds')
            limit = off + (styles_start if styles_start else length)
            if limit < off + start or limit > end: raise ValueError('Invalid AXML string data bounds')
            strings = []
            decoded_size = 0
            def length8(pos):
                if pos >= limit: raise ValueError('Truncated AXML string length')
                x = data[pos]; pos += 1
                if x & 128:
                    if pos >= limit: raise ValueError('Truncated AXML string length')
                    x = ((x & 127) << 8) | data[pos]; pos += 1
                return x, pos
            def length16(pos):
                if pos + 2 > limit: raise ValueError('Truncated AXML string length')
                x = u16(pos); pos += 2
                if x & 0x8000:
                    if pos + 2 > limit: raise ValueError('Truncated AXML string length')
                    x = ((x & 0x7fff) << 16) | u16(pos); pos += 2
                return x, pos
            for i in range(n):
                pos = off + start + u32(off + head + i * 4)
                if pos >= limit: raise ValueError('Invalid AXML string offset')
                try:
                    if flags & 0x100:
                        utf16len, pos = length8(pos); bytelen, pos = length8(pos)
                        if pos + bytelen >= limit or data[pos + bytelen] != 0: raise ValueError('Truncated AXML UTF-8 string')
                        value = data[pos:pos + bytelen].decode('utf-8')
                    else:
                        utf16len, pos = length16(pos); bytelen = utf16len * 2
                        if pos + bytelen + 2 > limit or data[pos + bytelen:pos + bytelen + 2] != b'\0\0': raise ValueError('Truncated AXML UTF-16 string')
                        value = data[pos:pos + bytelen].decode('utf-16-le')
                    if len(value.encode('utf-16-le')) // 2 != utf16len: raise ValueError('AXML string length mismatch')
                except UnicodeError as exc: raise ValueError('Invalid AXML string encoding') from exc
                decoded_size += len(value)
                if decoded_size > 16 * 1024 * 1024: raise ValueError('AXML decoded strings exceed limit')
                strings.append(value)
        elif typ == 0x102:
            if strings is None or head < 16 or length < 36 or closed: raise ValueError('Invalid AXML start element')
            ns, name, attrstart, attrsize, nattrs = struct.unpack_from('<IIHHH', data, off + 16)
            tag = string(name); namespace = string(ns)
            if namespace is not None: raise ValueError('Unsupported namespaced AXML element')
            if not stack:
                if root_seen or tag != 'manifest': raise ValueError('Invalid AXML manifest root')
                root_seen = True
            if len(stack) >= 256 or nattrs > 4096 or attrsize < 20 or attrstart < 20 or off + 16 + attrstart + nattrs * attrsize > end:
                raise ValueError('Invalid AXML attributes or nesting')
            context = stack + [tag]
            attrs = {}
            types = {}
            typed_strings = {}
            for i in range(nattrs):
                p = off + 16 + attrstart + i * attrsize
                ans, aname, raw, vsize, res0, vtype, value = struct.unpack_from('<IIIHBBI', data, p)
                if vsize != 8 or res0: raise ValueError('Invalid AXML typed value')
                key = (string(ans), string(aname))
                if key in attrs: raise ValueError('Duplicate AXML attribute')
                raw_value = string(raw)
                if vtype == 3: val = string(value)
                elif vtype in (0x10, 0x11): val = str(value)
                else: val = None
                # A raw spelling of a reference does not resolve its resource value.
                if raw_value is not None and vtype in (3, 0x10, 0x11): val = raw_value
                attrs[key] = val
                types[key] = vtype
                if vtype == 3: typed_strings[key] = string(value)
            def get(ns, name):
                key = (ns, name)
                if key in attrs and attrs[key] is None: result['unresolved'].append('/'.join(context) + '@' + name)
                return attrs.get(key)
            if context == ['manifest']:
                result['package'] = get(None, 'package')
                result['version_code'] = get(ANDROID, 'versionCode')
                result['version_name'] = get(ANDROID, 'versionName')
                # Retain provenance and typed-value information: a resource reference
                # must never become a literal just because it has a raw spelling.
                for name in ('requiredSplitTypes', 'splitTypes'):
                    key = (ANDROID, name)
                    other = any(k[1] == name and k != key for k in attrs)
                    if other:
                        result['split_type_attributes'][name] = {'status': 'unknown', 'reason': 'unexpected namespace'}
                    elif key not in attrs:
                        result['split_type_attributes'][name] = {'status': 'absent'}
                    elif types[key] != 3 or attrs[key] is None or attrs[key] != typed_strings.get(key):
                        result['split_type_attributes'][name] = {'status': 'unknown', 'reason': 'non-string or resource reference'}
                    else:
                        result['split_type_attributes'][name] = {'status': 'literal', 'value': attrs[key]}
                key = (None, 'split')
                if any(k[1] == 'split' and k != key for k in attrs):
                    result['split_identity'] = {'status': 'unknown', 'reason': 'unexpected namespace'}
                elif key in attrs:
                    if types[key] == 3 and attrs[key] and attrs[key] == typed_strings.get(key):
                        result['split_identity'] = {'status': 'literal', 'value': attrs[key]}
                    else:
                        result['split_identity'] = {'status': 'unknown', 'reason': 'invalid split identity'}
            elif len(context) == 2 and tag in ('uses-permission', 'uses-permission-sdk-23'):
                value = get(ANDROID, 'name')
                if value: result['permissions'].append(value)
                else: result['unresolved'].append(tag + '@name')
            elif len(context) == 3 and context[1] == 'application' and tag in COMPONENTS:
                value = get(ANDROID, 'name')
                if value: result['components'].append({'type': tag, 'name': value})
                else: result['unresolved'].append(tag + '@name')
            stack.append(tag)
        elif typ == 0x103:
            if head < 16 or length < 24 or not stack or string(u32(off + 16)) is not None or string(u32(off + 20)) != stack[-1]:
                raise ValueError('Mismatched AXML end element')
            stack.pop()
            if not stack: closed = True
        elif typ not in (0x100, 0x101, 0x104, 0x180):
            raise ValueError('Unsupported AXML chunk type')
        off = end
    if not root_seen or not closed or stack: raise ValueError('Incomplete AXML document')
    return result


def read_manifest(apk: str) -> dict:
    """Read a capped manifest from an APK; archive validity is checked by callers."""
    with zipfile.ZipFile(apk) as z:
        info = z.getinfo('AndroidManifest.xml')
        if info.file_size > MAX_MANIFEST: raise ValueError('Binary manifest exceeds 8 MiB limit')
        return parse_manifest(z.read(info))
