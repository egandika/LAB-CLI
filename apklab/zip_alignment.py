"""Observe uncompressed native library ZIP data offsets, not ELF compatibility."""
import struct
import zipfile
from os import PathLike
from typing import Union


def native_offsets(path: Union[str, PathLike], page_size: int = 16384) -> list:
    if page_size <= 0: raise ValueError('Page size must be positive')
    results = []
    with open(path, 'rb') as raw, zipfile.ZipFile(raw) as archive:
        for index, info in enumerate(archive.infolist()):
            if not (info.filename.startswith('lib/') and info.filename.endswith('.so') and not info.is_dir()): continue
            raw.seek(info.header_offset)
            header = raw.read(30)
            if len(header) != 30: raise ValueError('Truncated local ZIP header')
            magic, _, flags, method, _, _, _, _, _, name_len, extra_len = struct.unpack('<IHHHHHIIIHH', header)
            if magic != 0x04034b50 or flags != info.flag_bits or method != info.compress_type:
                raise ValueError('Local ZIP header disagrees with central directory')
            name = raw.read(name_len)
            try: decoded = name.decode('utf-8' if flags & 0x800 else 'cp437')
            except UnicodeError as exc: raise ValueError('Invalid local ZIP filename') from exc
            if decoded != info.orig_filename or len(raw.read(extra_len)) != extra_len:
                raise ValueError('Local ZIP filename or extra field is inconsistent')
            offset = info.header_offset + 30 + name_len + extra_len
            if offset + info.compress_size > archive.start_dir:
                raise ValueError('ZIP data exceeds local data area')
            item = {'path': info.filename, 'zip_entry_index': index, 'data_offset': offset,
                    'compression': method, 'page_size': page_size}
            if method == zipfile.ZIP_STORED:
                item.update(status='observed', aligned=offset % page_size == 0)
            else:
                item.update(status='not_tested', reason='Compressed library is not directly mmap-aligned')
            results.append(item)
    return results
