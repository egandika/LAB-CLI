"""Parse only explicit apksigner verification status lines."""
import re
from typing import Any


def parse_schemes(result: Any) -> dict:
    schemes = {name: 'not_tested' for name in ('v1', 'v2', 'v3', 'v3.1', 'v4')}
    if result.get('returncode') != 0 or result.get('stdout_truncated') or result.get('capture_incomplete'):
        return schemes
    lines = re.findall(r'^Verified using (v1|v2|v3|v3\.1|v4) scheme \([^\r\n]*\): (true|false)\s*$', result.get('stdout', ''), re.MULTILINE | re.IGNORECASE)
    for name in schemes:
        values = [value.lower() for scheme, value in lines if scheme.lower() == name]
        if len(values) == 1: schemes[name] = 'verified' if values[0] == 'true' else 'not_verified'
    return schemes
