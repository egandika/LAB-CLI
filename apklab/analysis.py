"""Conservative static-analysis helpers; outputs are observations, not proof."""

from __future__ import annotations
from typing import Any, Optional
import re

ELEMENT = re.compile(r'^(\s*)E: ([\w-]+)\b')
NAME = re.compile(r'^\s*A: (?:android:)?name(?:\([^)]*\))?="([^"]+)"')
COMPONENTS = {'activity', 'activity-alias', 'service', 'receiver', 'provider'}


def parse_xmltree(text: str) -> dict:
    result = {'permissions': [], 'components': []}
    stack = []
    for line in text.splitlines():
        match = ELEMENT.match(line)
        if match:
            indent, tag = len(match.group(1)), match.group(2)
            while stack and stack[-1][0] >= indent: stack.pop()
            stack.append((indent, tag))
            continue
        name = NAME.match(line)
        if name and stack:
            tag = stack[-1][1]
            if tag in ('uses-permission', 'uses-permission-sdk-23'):
                result['permissions'].append(name.group(1))
            elif tag in COMPONENTS:
                result['components'].append({'type': tag, 'name': name.group(1)})
    return result


def candidates(classes: list, strings: list, limit: int) -> dict:
    short = [c for c in classes if re.search(r'(?:/|\$)[A-Za-z]{1,2};$', c)]
    encoded = [s for s in strings if len(s) >= 24 and len(s) <= 4096 and
               (re.fullmatch(r'(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', s) or
                re.fullmatch(r'(?:[0-9a-fA-F]{2}){12,}', s))]
    return {'short_class_count': len(short), 'short_classes': short[:limit],
            'encoded_string_count': len(encoded), 'encoded_strings': encoded[:limit]}


def magic_type(data: bytes) -> str:
    for prefix, name in ((b'\x7fELF', 'ELF'), (b'\x89PNG\r\n\x1a\n', 'PNG'), (b'\xff\xd8\xff', 'JPEG'),
                         (b'PK\x03\x04', 'ZIP'), (b'dex\n', 'DEX'), (b'%PDF-', 'PDF'),
                         (b'OggS', 'Ogg'), (b'RIFF', 'RIFF'), (b'\x1f\x8b', 'gzip')):
        if data.startswith(prefix): return name
    return 'unknown'
