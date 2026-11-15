"""Conservative observations of split relationships from aapt XML-tree output."""

from __future__ import annotations
from typing import Any, Optional, Union
from os import PathLike
import re
from .core import add, find_tool, run

MAX_DEPENDENCIES = 512
MAX_XML_LINES = 10000
_ELEMENT = re.compile(r'^(\s*)E:\s+([\w.-]+)\b')
_ATTRIBUTE = re.compile(r'^\s*A:\s+(?:(?P<namespace>[\w.-]+):)?(?P<name>[\w.-]+)(?:\([^)]*\))?=(?P<raw>.*)$')
_STRING = re.compile(r'^"([^"]*)"(?:\s|$)')
_SPLIT_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z')
_TYPED_INT = re.compile(r'^\(type\s+0x1[01]\)0x([0-9a-fA-F]+)(?:\s|$)')
_TYPED_BOOL = re.compile(r'^\(type\s+0x12\)0x([0-9a-fA-F]+)(?:\s|$)')


def parse_dependencies(text: str, truncated: bool=False) -> dict:
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
        namespace, name, raw = attr.group('namespace', 'name', 'raw')
        context = [item[1] for item in stack]
        if context == ['manifest'] and name in ('configForSplit', 'isFeatureSplit', 'versionCodeMajor'):
            if namespace != 'android':
                result['unresolved'].append('unexpected namespace for ' + name)
                continue
            field = {'configForSplit': 'config_for_split', 'isFeatureSplit': 'is_feature_split', 'versionCodeMajor': 'version_code_major'}[name]
        elif context == ['manifest', 'application'] and name == 'isSplitRequired':
            if namespace != 'android':
                result['unresolved'].append('unexpected namespace for ' + name)
                continue
            field = 'is_split_required'
        elif context == ['manifest', 'uses-split'] and name == 'name':
            node = stack[-1][2]
            if node is None: continue
            match = _STRING.match(raw)
            if namespace != 'android' or node['uses_name'] is not None or not match or not _SPLIT_NAME.fullmatch(match.group(1)):
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


def read_dependencies(apk: Union[str, PathLike]) -> dict:
    tool = find_tool('aapt')
    if not tool: return {'status': 'unavailable', 'reason': 'aapt not found'}
    result = run([tool, 'dump', 'xmltree', apk, 'AndroidManifest.xml'], timeout=120)
    if result['returncode'] != 0:
        return {'status': 'unavailable', 'reason': 'aapt xmltree failed: ' + (result['stderr'] or result['stdout'])[:1000]}
    return parse_dependencies(result['stdout'], bool(result.get('stdout_truncated') or result.get('capture_incomplete')))


def assess_outputs(records: Any) -> dict:
    """Compare known facts and explicit references; unknowns never imply completeness."""
    issues, unknown, inferences = [], [], []
    apks = [record.get('apk') for record in records]
    for field, label in (('package', 'package names'), ('version_code', 'version codes'), ('signer_sha256', 'signer certificate digest sets')):
        values = [apk.get(field) if apk else None for apk in apks]
        known = {tuple(value) if isinstance(value, list) else value for value in values if value}
        if len(known) > 1:
            inferred = field != 'signer_sha256' and any(apk and apk.get('metadata_source') == 'internal_axml' and apk.get(field) for apk in apks)
            (inferences if inferred else issues).append('Different ' + label + ' found' + (' (includes internal AXML)' if inferred else ''))
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
    # isSplitRequired is an application-level requirement, not a list of split names.
    # A known base requiring splits with no named split cannot satisfy it.
    if names_known and len(names) == 1 and names[0] is None:
        dep = records[0].get('dependencies', {})
        if dep.get('status') == 'observed' and dep.get('is_split_required') is True:
            issues.append('Base manifest requires at least one split APK, but none was supplied')
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
    return {'issues': issues, 'unknown': unknown, 'inferences': inferences,
            'note': 'Observed declarations and signer digests do not establish split completeness, signer rotation compatibility, installability, or runtime behavior.'}

# These attributes are comma-separated names, not split APK filenames.
_TYPE_NAME = re.compile(r'[A-Za-z0-9_.-]+\Z')
_TYPE_ATTR = re.compile(r'^\s*A:\s+(?:(?P<ns>[\w.-]+):)?(?P<name>requiredSplitTypes|splitTypes)(?:\((?P<id>0x[0-9a-fA-F]+)\))?=(?P<raw>.*)$')
_TYPE_LITERAL = re.compile(r'^"([^"\\]*)"(?:\s+\(Raw:\s*"\1"\))?\s*$')
_TYPE_IDS = {'requiredSplitTypes': 0x0101064e, 'splitTypes': 0x0101064f}


def _type_values(attribute: dict) -> dict:
    """Validate a literal without interpreting unresolved or ambiguous values."""
    if attribute.get('status') != 'literal':
        return attribute
    value = attribute['value']
    if value == '':
        return {'status': 'literal', 'value': value, 'types': []}
    parts = value.split(',')
    if len(parts) > MAX_DEPENDENCIES or any(not _TYPE_NAME.fullmatch(x.strip()) for x in parts):
        return {'status': 'unknown', 'reason': 'invalid or unsupported split type list'}
    return {'status': 'literal', 'value': value, 'types': sorted(set(x.strip() for x in parts))}


def parse_split_types(text: str, truncated: bool = False) -> dict:
    """Read root Android split-type attributes from bounded aapt xmltree output."""
    fields = {name: {'status': 'absent'} for name in _TYPE_IDS}
    seen = set()
    stack = []
    root_count = 0
    invalid = truncated
    if truncated and not text.endswith('\n'):
        text = text.rpartition('\n')[0]
    lines = text.splitlines()
    if len(lines) > MAX_XML_LINES:
        invalid = True
    for line in lines[:MAX_XML_LINES]:
        element = _ELEMENT.match(line)
        if element:
            indent, tag = len(element.group(1)), element.group(2)
            while stack and stack[-1][0] >= indent:
                stack.pop()
            if not stack:
                root_count += 1
                if tag != 'manifest': invalid = True
            stack.append((indent, tag))
            continue
        attr = _TYPE_ATTR.match(line)
        if [tag for _, tag in stack] != ['manifest']:
            continue
        if not attr:
            if re.match(r'^\s*A:', line) and re.search(r'\b(?:requiredSplitTypes|splitTypes)\b', line): invalid = True
            continue
        if len(line) - len(line.lstrip()) <= stack[-1][0]:
            invalid = True
            continue
        name, namespace, resource_id, raw = attr.group('name', 'ns', 'id', 'raw')
        if name in seen:
            fields[name] = {'status': 'unknown', 'reason': 'duplicate attribute'}
            continue
        seen.add(name)
        if namespace != 'android' or (resource_id and int(resource_id, 16) != _TYPE_IDS[name]):
            fields[name] = {'status': 'unknown', 'reason': 'unexpected namespace or resource ID'}
            continue
        value = _TYPE_LITERAL.fullmatch(raw)
        fields[name] = _type_values({'status': 'literal', 'value': value.group(1)}) if value else {'status': 'unknown', 'reason': 'non-literal or resource reference'}
    if root_count != 1: invalid = True
    if invalid:
        # Even a complete-looking attribute may be followed by a duplicate.
        return {'source': 'aapt', 'attributes': {name: {'status': 'unknown', 'reason': 'truncated or invalid xmltree'} for name in fields}}
    return {'source': 'aapt', 'attributes': fields}


def read_split_types(apk: Union[str, PathLike]) -> dict:
    """Observe attributes from aapt, falling back to bounded binary AXML."""
    tool = find_tool('aapt')
    reason = 'aapt not found'
    if tool:
        result = run([tool, 'dump', 'xmltree', apk, 'AndroidManifest.xml'], timeout=120)
        if result['returncode'] == 0:
            return parse_split_types(result['stdout'], bool(result.get('stdout_truncated') or result.get('capture_incomplete')))
        reason = 'aapt xmltree failed'
    from .axml import read_manifest
    import zipfile
    try:
        manifest = read_manifest(str(apk))
        return {'source': 'internal_axml', 'fallback_reason': reason,
                'attributes': {name: _type_values(manifest['split_type_attributes'][name]) for name in _TYPE_IDS},
                'split_identity': manifest['split_identity']}
    except (ValueError, KeyError, OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:
        return {'source': 'unavailable', 'reason': reason + '; internal AXML: ' + str(exc),
                'attributes': {name: {'status': 'unknown', 'reason': 'manifest unreadable'} for name in _TYPE_IDS}}


def assess_split_types(records: Any) -> dict:
    """Compare only known declarations for the supplied inputs, never completeness."""
    unknown = []
    identities = []
    for record in records:
        apk = record.get('apk') or {}
        observation = record['types']
        if observation['source'] == 'internal_axml':
            identity = observation.get('split_identity', {'status': 'unknown'})
            identities.append(None if identity['status'] == 'absent' else identity.get('value') if identity['status'] == 'literal' and _SPLIT_NAME.fullmatch(identity.get('value', '')) else False)
        else:
            identities.append(apk.get('split') if apk.get('package') and apk.get('version_code') and 'split' in apk else False)
    bases = [i for i, name in enumerate(identities) if name is None]
    if False in identities or len(bases) != 1:
        unknown.append('base identity is ambiguous or unavailable')
    packages = [(r.get('apk') or {}).get('package') for r in records]
    versions = [(r.get('apk') or {}).get('version_code') for r in records]
    if not all(packages) or not all(versions) or len(set(packages)) != 1 or len(set(versions)) != 1:
        unknown.append('package or version identity is unavailable or inconsistent')
    # versionCodeMajor defaults to zero only when a complete manifest was observed.
    major_values = [r.get('dependencies', {}) for r in records]
    major_known = [d.get('version_code_major') or 0 for d in major_values if d.get('status') == 'observed']
    if len(set(major_known)) > 1:
        unknown.append('versionCodeMajor values are inconsistent')
    identity_not_tested = []
    if len(major_known) != len(records):
        identity_not_tested.append('versionCodeMajor identity comparison is incomplete')
    for record in records:
        for name in _TYPE_IDS:
            attribute = record['types']['attributes'][name]
            if attribute['status'] == 'unknown':
                unknown.append(str(record['id']) + ': ' + name + ' ' + attribute.get('reason', 'unknown'))
    result = {'required': None, 'provided': None, 'missing': None, 'unknown': unknown, 'identity_not_tested': identity_not_tested,
              'note': 'Comparison covers supplied APKs only; split completeness, installability and runtime are not established.'}
    if unknown:
        return result
    required_attr = records[bases[0]]['types']['attributes']['requiredSplitTypes']
    result['required'] = required_attr.get('types', [])
    result['provided'] = sorted({value for record in records for value in record['types']['attributes']['splitTypes'].get('types', [])})
    result['missing'] = sorted(set(result['required']) - set(result['provided']))
    result['source'] = 'internal_axml' if any(record['types']['source'] == 'internal_axml' for record in records) else 'aapt'
    return result


def unavailable_split_types(reason: str) -> dict:
    return {'source': 'unavailable', 'reason': reason,
            'attributes': {name: {'status': 'unknown', 'reason': reason} for name in _TYPE_IDS}}


def report_split_types(records: Any, report: Any) -> dict:
    """Add provenance-aware observations and compare only supplied APKs."""
    for record in records:
        observation = record['types']
        for name, attribute in observation['attributes'].items():
            if attribute['status'] == 'literal':
                category = 'inferences' if observation['source'] == 'internal_axml' else 'verified'
                add(report, category, record['id'], name + ' literal from ' + observation['source'] + ': ' + repr(attribute['value']))
            elif attribute['status'] == 'unknown':
                add(report, 'not_tested', record['id'], name + ': ' + attribute.get('reason', 'unknown'))
        if observation['source'] == 'internal_axml':
            add(report, 'not_tested', record['id'], 'aapt split type reading unavailable; internal AXML observations are inferences')
    result = assess_split_types(records)
    for reason in result['unknown'] + result['identity_not_tested']:
        add(report, 'not_tested', 'split types', reason)
    if not result['unknown']:
        if result['source'] == 'internal_axml' or result['identity_not_tested']:
            add(report, 'inferences', 'split types', 'Compared supplied inputs with inferred or incomplete identity metadata; missing: ' + ', '.join(result['missing']))
            if result['missing']:
                add(report, 'not_tested', 'split types', 'Missing types inferred with incomplete or internal metadata are not independently verified')
        elif result['missing']:
            add(report, 'failures', 'split types', 'Required types not offered by supplied APKs: ' + ', '.join(result['missing']))
        else:
            add(report, 'verified', 'split types', 'No declared required types are missing from the supplied inputs')
    add(report, 'not_tested', 'split types', 'Additional splits may be required; completeness, device selection and installation were not tested')
    return result
