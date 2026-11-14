"""Read DEX identifier tables and strings without executing APK code.

This is an index, not a decompiler or call-graph analyzer.
"""

from __future__ import annotations
from typing import Any, Optional
import re
import struct

MAX_IDS = 1000000
MAX_TOTAL_PARAMETERS = 1000000
MAX_PROTO_CHARS = 16 * 1024 * 1024
MAX_METHOD_CHARS = 32 * 1024 * 1024
URL = re.compile(r'https?://[^\s\x00<>"\'\\]+', re.I)


def read_uleb32(data: bytes, offset: int) -> tuple:
    value = 0
    for i in range(5):
        if offset >= len(data): raise ValueError('Truncated DEX ULEB128')
        byte = data[offset]; offset += 1
        if i == 4 and byte & 0xf0: raise ValueError('DEX ULEB128 exceeds 32 bits')
        value |= (byte & 0x7f) << (7 * i)
        if not byte & 0x80: return value, offset
    raise ValueError('Invalid DEX ULEB128')


def decode_mutf8(raw: bytes, utf16_size: int) -> str:
    """Decode DEX MUTF-8, retaining even unpaired UTF-16 surrogate units."""
    units = bytearray()
    i = 0
    while i < len(raw):
        first = raw[i]; i += 1
        if 1 <= first <= 0x7f:
            value = first
        elif 0xc0 <= first <= 0xdf:
            if i >= len(raw) or raw[i] & 0xc0 != 0x80: raise ValueError('Invalid DEX MUTF-8 continuation')
            value = ((first & 0x1f) << 6) | (raw[i] & 0x3f); i += 1
            if value < 0x80 and value != 0: raise ValueError('Overlong DEX MUTF-8')
            if value == 0 and first != 0xc0: raise ValueError('Invalid DEX MUTF-8 NUL')
        elif 0xe0 <= first <= 0xef:
            if i + 1 >= len(raw) or raw[i] & 0xc0 != 0x80 or raw[i+1] & 0xc0 != 0x80:
                raise ValueError('Invalid DEX MUTF-8 continuation')
            value = ((first & 0x0f) << 12) | ((raw[i] & 0x3f) << 6) | (raw[i+1] & 0x3f); i += 2
            if value < 0x800: raise ValueError('Overlong DEX MUTF-8')
        else:
            raise ValueError('Invalid DEX MUTF-8 leading byte')
        units.extend((value & 0xff, value >> 8))
        if len(units) // 2 > utf16_size: raise ValueError('DEX UTF-16 length mismatch')
    if len(units) // 2 != utf16_size: raise ValueError('DEX UTF-16 length mismatch')
    return units.decode('utf-16-le', 'surrogatepass')


class UnsupportedDexContainer(ValueError):
    """A recognizable DEX 041 container is not supported by this indexer."""


def read_dex(data: bytes) -> dict:
    if bytes(data[:8]) == b'dex\n041\0':
        if len(data) < 120:
            raise ValueError('Truncated DEX 041 container header')
        file_size, header_size, endian = struct.unpack_from('<III', data, 32)
        container_size, header_offset = struct.unpack_from('<II', data, 112)
        if header_size != 120 or endian != 0x12345678 or file_size < 120 or file_size > len(data) or container_size != len(data) or header_offset != 0:
            raise ValueError('Invalid DEX 041 container header or bounds')
        raise UnsupportedDexContainer('DEX 041 container is not indexed; shared container offsets and additional headers are not validated')
    if len(data) < 112 or bytes(data[:8]) not in {b'dex\n035\0', b'dex\n037\0', b'dex\n038\0', b'dex\n039\0', b'dex\n040\0'}:
        raise ValueError('Invalid or unsupported DEX header')
    u32 = lambda off: struct.unpack_from('<I', data, off)[0]
    if u32(40) != 0x12345678:
        raise ValueError('Unsupported DEX endianness')
    size = u32(32)
    if size != len(data) or u32(36) != 112:
        raise ValueError('Inconsistent DEX file/header size')
    def table(size_off, width):
        count, off = u32(size_off), u32(size_off + 4)
        if count > MAX_IDS or off + count * width > len(data) or (count and (off < 112 or off % 4)):
            raise ValueError('Invalid or oversized DEX table')
        return count, off
    ns, so = table(56, 4)
    nt, to = table(64, 4)
    np, po = table(72, 12)
    table(80, 8)  # field identifiers are not indexed, but their range must be valid
    nm, mo = table(88, 8)
    nc, co = table(96, 32)
    strings = []
    decoded_bytes = 0
    string_cache = {}
    for i in range(ns):
        p = u32(so + i * 4)
        if p < 112 or p >= len(data): raise ValueError('Invalid string offset')
        if p in string_cache:
            value = string_cache[p]
            decoded_bytes += len(value)
            if decoded_bytes > 64 * 1024 * 1024: raise ValueError('DEX strings exceed safety limit')
            strings.append(value)
            continue
        start = p
        utf16_size, p = read_uleb32(data, p)
        if utf16_size > 64 * 1024 * 1024: raise ValueError('DEX string length exceeds safety limit')
        end = data.find(b'\0', p)
        if end < 0: raise ValueError('Unterminated DEX string')
        decoded_bytes += end - p
        if decoded_bytes > 64 * 1024 * 1024: raise ValueError('DEX strings exceed safety limit')
        value = decode_mutf8(data[p:end], utf16_size)
        string_cache[start] = value
        strings.append(value)
    def string(i):
        if i >= len(strings): raise ValueError('Invalid string index')
        return strings[i]
    types = [string(u32(to + i * 4)) for i in range(nt)]
    def typ(i):
        if i >= len(types): raise ValueError('Invalid type index')
        return types[i]
    protos = []
    parameter_cache = {}
    total_parameters = 0
    total_proto_chars = 0
    for i in range(np):
        shorty, ret, params = struct.unpack_from('<III', data, po + i * 12)
        string(shorty)
        if params:
            if params < 112 or params % 4 or params + 4 > len(data): raise ValueError('Invalid parameter offset')
            n = u32(params)
            if n > MAX_IDS or params + 4 + n * 2 > len(data): raise ValueError('Invalid parameter list')
            total_parameters += n
            if total_parameters > MAX_TOTAL_PARAMETERS:
                raise ValueError('DEX total prototype parameters exceed safety limit')
            if params not in parameter_cache:
                pieces = []
                chars = 0
                for j in range(n):
                    value = typ(struct.unpack_from('<H', data, params + 4 + j * 2)[0])
                    chars += len(value) + (2 if j else 0)
                    if chars > MAX_PROTO_CHARS: raise ValueError('DEX prototype text exceeds safety limit')
                    pieces.append(value)
                parameter_cache[params] = ', '.join(pieces)
            param_text = parameter_cache[params]
        else:
            param_text = ''
        return_type = typ(ret)
        total_proto_chars += len(param_text) + len(return_type) + 2
        if total_proto_chars > MAX_PROTO_CHARS: raise ValueError('DEX total prototype text exceeds safety limit')
        protos.append('(' + param_text + ')' + return_type)
    methods = []
    total_method_chars = 0
    for i in range(nm):
        cls, proto, name = struct.unpack_from('<HHI', data, mo + i * 8)
        if proto >= len(protos): raise ValueError('Invalid prototype index')
        cls_name, method_name, prototype = typ(cls), string(name), protos[proto]
        total_method_chars += len(cls_name) + len(method_name) + len(prototype) + 2
        if total_method_chars > MAX_METHOD_CHARS: raise ValueError('DEX total method text exceeds safety limit')
        methods.append(cls_name + '->' + method_name + prototype)
    classes = [typ(u32(co + i * 32)) for i in range(nc)]
    return {"classes": classes, "methods": methods, "strings": strings,
            "endpoints": sorted({m.group(0) for s in strings for m in URL.finditer(s)})}
