"""Conservative observations of split relationships from aapt XML-tree output."""
import re
from .core import find_tool, run

MAX_DEPENDENCIES = 512
MAX_XML_LINES = 10000
_ELEMENT = re.compile(r'^(\s*)E:\s+([\w.-]+)\b')
_ATTRIBUTE = re.compile(r'^\s*A:\s+(?:(android):)?([\w.-]+)(?:\([^)]*\))?=(.*)$')
_STRING = re.compile(r'^"([^"]*)"(?:\s|$)')
_SPLIT_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z')
_TYPED_INT = re.compile(r'^\(type\s+0x1[01]\)0x([0-9a-fA-F]+)(?:\s|$)')
_TYPED_BOOL = re.compile(r'^\(type\s+0x12\)0x([0-9a-fA-F]+)(?:\s|$)')


def parse_dependencies(text, truncated=False):
    """Read selected declarations, marking incomplete or unparseable values unknown.

    Only root manifest attributes, root uses-split elements and the application
    isSplitRequired attribute are considered. Absence is not proof of set completeness.
    """
    if truncated and not text.endswith('\n'):
        text = text.rpartition('\n')[0]
    result = {'status': 'partial' if truncated else 'observed', 'uses_splits': [],
              'config_for_split': None, 'is_feature_split': None,
              'is_split_required': None, 'version_code_major': None, 'unresolved': []}
    stack = []
    uses_nodes = []
    seen = set()
    root_seen = False
    for line_number, line in enumerate(text.splitlines()):
        if line_number >= MAX_XML_LINES:
            result['unresolved'].append('XML-tree line limit')
            break
        element = _ELEMENT.match(line)
        if element:
            indent, tag = len(element.group(1)), element.group(2)
            while stack and stack[-1][0] >= indent: stack.pop()
            parent = stack[-1][1] if stack else None
            node = {'uses_name': None} if tag == 'uses-split' and parent == 'manifest' and len(stack) == 1 else None
            if node is not None:
                if len(uses_nodes) >= MAX_DEPENDENCIES:
                    result['unresolved'].append('uses-split limit')
                    break
                uses_nodes.append(node)
            if tag == 'manifest' and not stack:
                if root_seen: result['unresolved'].append('multiple manifest elements')
                root_seen = True
            stack.append((indent, tag, node))
            continue
        attr = _ATTRIBUTE.match(line)
        if not attr or not stack: continue
        namespace, name, raw = attr.groups()
        context = [item[1] for item in stack]
        if context == ['manifest'] and name in ('configForSplit', 'isFeatureSplit', 'versionCodeMajor'):
            field = {'configForSplit': 'config_for_split', 'isFeatureSplit': 'is_feature_split', 'versionCodeMajor': 'version_code_major'}[name]
        elif context == ['manifest', 'application'] and name == 'isSplitRequired':
            field = 'is_split_required'
        elif context == ['manifest', 'uses-split'] and name == 'name' and namespace == 'android':
            node = stack[-1][2]
            if node is None: continue
            match = _STRING.match(raw)
            if node['uses_name'] is not None or not match or not _SPLIT_NAME.fullmatch(match.group(1)):
                result['unresolved'].append('uses-split name')
            else: node['uses_name'] = match.group(1)
            continue
        else: continue
        if field in seen:
            result['unresolved'].append('duplicate ' + name)
            result[field] = None
            continue
        seen.add(field)
        if field == 'config_for_split':
            match = _STRING.match(raw)
            value = match.group(1) if match else None
            if value and not _SPLIT_NAME.fullmatch(value): value = None
        elif field == 'version_code_major':
            match = _TYPED_INT.match(raw)
            value = int(match.group(1), 16) if match else None
            if value is not None and value > 0xffffffff: value = None
        else:
            match = _TYPED_BOOL.match(raw)
            value = bool(int(match.group(1), 16)) if match else {'true': True, 'false': False}.get(raw.strip())
        result[field] = value
        if value is None: result['unresolved'].append(name)
    if not root_seen: result['unresolved'].append('manifest element')
    for node in uses_nodes:
        if node['uses_name'] is None: result['unresolved'].append('uses-split name')
        else: result['uses_splits'].append(node['uses_name'])
    if result['unresolved']:
        result['status'] = 'partial'
    return result


def read_dependencies(apk):
    tool = find_tool('aapt')
    if not tool: return {'status': 'unavailable', 'reason': 'aapt not found'}
    result = run([tool, 'dump', 'xmltree', apk, 'AndroidManifest.xml'], timeout=120)
    if result['returncode'] != 0:
        return {'status': 'unavailable', 'reason': 'aapt xmltree failed: ' + (result['stderr'] or result['stdout'])[:1000]}
    return parse_dependencies(result['stdout'], bool(result.get('stdout_truncated') or result.get('capture_incomplete')))


def assess_outputs(records):
    """Compare known facts and explicit references; unknowns never imply completeness."""
    issues, unknown = [], []
    apks = [record.get('apk') for record in records]
    for field, label in (('package', 'package names'), ('version_code', 'version codes'), ('signer_sha256', 'signer certificate digest sets')):
        values = [apk.get(field) if apk else None for apk in apks]
        known = {tuple(value) if isinstance(value, list) else value for value in values if value}
        if len(known) > 1: issues.append('Different ' + label + ' found')
        if len(known) == 0 or any(not value for value in values): unknown.append(label)
    names_known = all(apk and apk.get('package') and apk.get('version_code') and 'split' in apk for apk in apks)
    names = [apk.get('split') for apk in apks if apk and apk.get('package') and apk.get('version_code') and 'split' in apk]
    if names_known:
        if names.count(None) != 1: issues.append('Exactly one base candidate is required')
        named = [name for name in names if name]
        if len(named) != len(set(named)): issues.append('Duplicate split names found')
    else:
        unknown.append('base and split names')
        named = [name for name in names if name]
    present = set(named)
    edges = {}
    dependencies_known = True
    for record in records:
        dep = record.get('dependencies', {})
        if dep.get('status') != 'observed': dependencies_known = False
        apk = record.get('apk') or {}
        split = apk.get('split')
        # Partial or ambiguous declarations are displayed but not used for hard decisions.
        refs = list(dep.get('uses_splits', [])) if dep.get('status') == 'observed' else []
        if dep.get('status') == 'observed' and dep.get('config_for_split'): refs.append(dep['config_for_split'])
        if split: edges.setdefault(split, set()).update(refs)
        if names_known:
            for ref in refs:
                if ref not in present:
                    issues.append('Missing declared split dependency: ' + ref + ' (member ' + record['id'] + ')')
    if not dependencies_known:
        unknown.extend(['dependency declarations', 'versionCodeMajor'])
    else:
        # Absence in a complete manifest has Android's default value zero.
        majors = {record['dependencies'].get('version_code_major') or 0 for record in records}
        if len(majors) > 1: issues.append('Different versionCodeMajor values found')
    # Explicit reference cycles are contradictory; omitted declarations are never inferred.
    state = {}
    # Iterative traversal avoids recursion on large split sets.
    cyclic = False
    for node in edges:
        if state.get(node): continue
        stack = [(node, iter(edges[node]))]; state[node] = 1
        while stack and not cyclic:
            current, children = stack[-1]
            target = next(children, None)
            if target is None:
                state[current] = 2; stack.pop(); continue
            if target not in edges: continue
            if state.get(target) == 1:
                cyclic = True; break
            if not state.get(target):
                state[target] = 1; stack.append((target, iter(edges[target])))
        if cyclic: break
    if cyclic: issues.append('Cycle in declared split dependencies')
    return {'issues': issues, 'unknown': unknown,
            'note': 'Observed declarations and signer digests do not establish split completeness, signer rotation compatibility, installability, or runtime behavior.'}
