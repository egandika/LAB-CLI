"""Read DEX identifier tables and strings without executing APK code.

This is an index, not a decompiler or call-graph analyzer.
"""
import re
import struct

MAX_IDS = 1000000
URL = re.compile(r'https?://[^\s\x00<>"\'\\]+', re.I)


def read_dex(data):
    if len(data) < 112 or not re.match(rb'dex\n\d{3}\x00', data[:8]):
        raise ValueError('Invalid or unsupported DEX header')
    u32 = lambda off: struct.unpack_from('<I', data, off)[0]
    if u32(40) != 0x12345678:
        raise ValueError('Unsupported DEX endianness')
    size = u32(32)
    if size != len(data) or u32(36) != 112:
        raise ValueError('Inconsistent DEX file/header size')
    def table(size_off, width):
        count, off = u32(size_off), u32(size_off + 4)
        if count > MAX_IDS or off + count * width > len(data):
            raise ValueError('Invalid or oversized DEX table')
        return count, off
    ns, so = table(56, 4)
    nt, to = table(64, 4)
    np, po = table(72, 12)
    nm, mo = table(88, 8)
    nc, co = table(96, 32)
    strings = []
    decoded_bytes = 0
    for i in range(ns):
        p = u32(so + i * 4)
        if p >= len(data): raise ValueError('Invalid string offset')
        for _ in range(5):
            if p >= len(data): raise ValueError('Invalid string length')
            b = data[p]; p += 1
            if not b & 128: break
        else: raise ValueError('Invalid ULEB128')
        end = data.find(b'\0', p)
        if end < 0: raise ValueError('Unterminated DEX string')
        decoded_bytes += end - p
        if decoded_bytes > 64 * 1024 * 1024: raise ValueError('DEX strings exceed safety limit')
        strings.append(data[p:end].decode('utf-8', 'replace'))
    def string(i):
        if i >= len(strings): raise ValueError('Invalid string index')
        return strings[i]
    types = [string(u32(to + i * 4)) for i in range(nt)]
    def typ(i):
        if i >= len(types): raise ValueError('Invalid type index')
        return types[i]
    protos = []
    for i in range(np):
        _, ret, params = struct.unpack_from('<III', data, po + i * 12)
        ps = []
        if params:
            if params + 4 > len(data): raise ValueError('Invalid parameter offset')
            n = u32(params)
            if n > MAX_IDS or params + 4 + n * 2 > len(data): raise ValueError('Invalid parameter list')
            ps = [typ(struct.unpack_from('<H', data, params + 4 + j * 2)[0]) for j in range(n)]
        protos.append('(' + ', '.join(ps) + ')' + typ(ret))
    methods = []
    for i in range(nm):
        cls, proto, name = struct.unpack_from('<HHI', data, mo + i * 8)
        if proto >= len(protos): raise ValueError('Invalid prototype index')
        methods.append(typ(cls) + '->' + string(name) + protos[proto])
    classes = [typ(u32(co + i * 32)) for i in range(nc)]
    return {"classes": classes, "methods": methods, "strings": strings,
            "endpoints": sorted({m.group(0) for s in strings for m in URL.finditer(s)})}
