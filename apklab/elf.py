"""Bounded ELF program-header checks for 16 KiB load-segment alignment."""
import struct


class UnsupportedElf(ValueError):
    pass


def load_alignment(data: bytes, page_size: int = 16384) -> dict:
    """Check PT_LOAD bounds, p_align and offset/address congruence, not runtime compatibility."""
    if len(data) < 16 or data[:4] != b'\x7fELF': raise ValueError('Invalid ELF magic or truncated identification')
    elf_class, encoding, version = data[4:7]
    if elf_class not in (1, 2) or encoding not in (1, 2): raise UnsupportedElf('Unsupported ELF class or byte order')
    if version != 1: raise ValueError('Invalid ELF identification version')
    endian = '<' if encoding == 1 else '>'
    header = struct.Struct(endian + ('HHIIIIIHHHHHH' if elf_class == 1 else 'HHIQQQIHHHHHH'))
    if len(data) < 16 + header.size: raise ValueError('Truncated ELF header')
    fields = header.unpack_from(data, 16)
    if fields[2] != 1: raise ValueError('Invalid ELF version')
    phoff, ehsize, phentsize, phnum = fields[4], fields[7], fields[8], fields[9]
    if phnum == 0xffff: raise UnsupportedElf('Extended ELF program-header count is unsupported')
    ph = struct.Struct(endian + ('IIIIIIII' if elf_class == 1 else 'IIQQQQQQ'))
    if ehsize < 16 + header.size or not phnum or phnum > 4096 or phentsize < ph.size or phoff < ehsize or phoff + phnum * phentsize > len(data):
        raise ValueError('Invalid ELF program-header table')
    segments = []
    for i in range(phnum):
        entry = ph.unpack_from(data, phoff + i * phentsize)
        if entry[0] != 1: continue
        if elf_class == 1: _, offset, vaddr, _, filesz, memsz, _, align = entry
        else: _, _, offset, vaddr, _, filesz, memsz, align = entry
        if filesz > memsz or offset + filesz > len(data): raise ValueError('Invalid ELF LOAD segment bounds')
        if align > 1 and (align & (align - 1) or (offset - vaddr) % align): raise ValueError('Invalid ELF LOAD p_align or congruence')
        segments.append({'index': i, 'offset': offset, 'vaddr': vaddr, 'align': align,
                         'aligned_16k': align >= page_size and (offset - vaddr) % page_size == 0})
    if not segments: raise ValueError('ELF has no LOAD segments')
    return {'bits': 32 if elf_class == 1 else 64, 'segments': segments,
            'aligned_16k': all(seg['aligned_16k'] for seg in segments)}
