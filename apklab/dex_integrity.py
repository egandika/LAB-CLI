"""Check legacy DEX header digests, not authenticity or bytecode validity."""
import hashlib
import struct
import zlib


def check_integrity(data: bytes) -> dict:
    magic = bytes(data[:8])
    if magic == b'dex\n041\0': return {'status': 'not_tested', 'reason': 'DEX 041 container checksum rules are not supported'}
    if magic not in {b'dex\n035\0', b'dex\n037\0', b'dex\n038\0', b'dex\n039\0', b'dex\n040\0'}:
        return {'status': 'not_tested', 'reason': 'Unsupported DEX version'}
    if len(data) < 112: raise ValueError('Truncated DEX header for integrity check')
    size, header, endian = struct.unpack_from('<III', data, 32)
    if size != len(data) or header != 112 or endian != 0x12345678: raise ValueError('Invalid DEX size, header size or endianness for integrity check')
    actual_sha = hashlib.sha1(data[32:]).digest()
    actual_adler = zlib.adler32(data[12:]) & 0xffffffff
    return {'status': 'checked', 'version': magic[4:7].decode('ascii'),
            'sha1_matches': data[12:32] == actual_sha,
            'adler32_matches': struct.unpack_from('<I', data, 8)[0] == actual_adler}
