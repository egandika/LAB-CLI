"""Deterministic, non-executing APKLab workflow and skill recommendations."""
from typing import List


# Commands are names, not shell strings; callers must supply their own authorized paths.
ROUTES = {
    ('reverse-engineer', 'apk'): [
        ('inspect', 'Inspect the APK ZIP and available metadata first'),
        (None, 'Choose inventory, DEX indexing, or JADX only when relevant; static clues do not establish runtime behavior'),
    ],
    ('reverse-engineer', 'xapk'): [
        ('xapk inspect', 'Inventory the archive; optionally check bounded contained APK copies'),
        (None, 'Do not unpack by default; preserve unknowns about splits, OBB compatibility, signatures, and runtime behavior'),
    ],
    ('reverse-engineer', 'apks'): [
        ('apks inspect', 'Inventory the archive without selecting splits'),
        (None, 'APKS targeting is not parsed; do not choose device-specific APKs from filenames alone'),
    ],
    ('reverse-engineer', 'splits'): [
        ('inspect', 'Inspect the supplied APKs together'),
        (None, 'Do not infer set completeness; investigate only relevant supplied members'),
    ],
    ('triage', 'apk'): [('inspect', 'Inspect one APK ZIP and available metadata')],
    ('triage', 'xapk'): [('xapk inspect', 'Inventory archive; optional --check-apks inspects bounded temporary copies')],
    ('triage', 'apks'): [('apks inspect', 'Inventory archive without selecting splits')],
    ('triage', 'splits'): [('inspect', 'Inspect supplied APKs together; --split-types uses temporary copies')],
    ('investigate', 'apk'): [('inventory', 'Find relevant asset and native paths'), ('dex', 'Index DEX identifiers and strings if relevant')],
    ('investigate', 'splits'): [('inspect', 'Establish the supplied APK scope'), ('inventory', 'Inspect relevant individual APKs; one inventory is not the whole app'), ('dex', 'Index DEX in relevant individual APKs if needed')],
    ('compare', 'two-apks'): [('diff', 'Compare one validated APK against another')],
    ('split-check', 'splits'): [('inspect', 'Inspect supplied APKs together; optional --split-types uses temporary copies')],
    ('split-check', 'xapk'): [('xapk inspect', 'Inspect archive and optionally check contained APKs; no split selection')],
    ('split-check', 'apks'): [('apks inspect', 'Inventory APK set; targeting is not parsed')],
    ('rebuild', 'apk'): [('work init', 'Create an explicitly approved new workspace'), ('work', 'Follow requested decode, edit, build, align, sign and verify stages')],
    ('rebuild', 'splits'): [('splits init', 'Create an explicitly approved split workspace'), ('splits run', 'Follow requested stages and review each member')],
    ('rebuild', 'xapk'): [
        ('xapk unpack', 'Create an explicitly approved new directory; never overwrite the input archive'),
        (None, 'Process only requested APK members in copies; preserve and review all untouched entries'),
        ('xapk repack', 'Create a new archive and inspect it; repacking does not prove signature, OBB compatibility, or runtime behavior'),
    ],
    ('report', 'report'): [(None, 'Separate verified, inferences, failures and not_tested in the supplied report')],
    ('diagnose', 'report'): [(None, 'Review sanitized error and unknown checks before suggesting a next step')],
    ('review', 'diff'): [(None, 'Review the supplied diff read-only; report actionable evidence and do not modify, commit, push, or merge')],
    ('test', 'source'): [(None, 'Run focused regression tests; distinguish synthetic or mocked results from real Android integration and report skips')],
    ('maintain', 'repo'): [(None, 'Follow repository instructions, preserve unrelated data, add regression tests, and inspect the final diff')],
    ('black-box', 'apk'): [(None, 'Requires separate install/launch approval and an isolated disposable emulator; current device checks confirm only limited install/launcher events, not app behavior or traffic')],
    ('black-box', 'splits'): [(None, 'Establish exact APK member scope first; split completeness and device targeting remain unknown, and installation/launch require separate approval')],
    ('fuzz', 'parser'): [(None, 'Optional `python3 tests/fuzz_parser_inputs.py --seed 20261114 --cases 256 --max-input-mib 1` mutates synthetic AXML/DEX/ZIP only; it is bounded smoke testing, not coverage-guided fuzzing or an app test')],
}

# First skill is primary; later entries are minimal support, not proof a host loaded them.
SKILL_ROUTES = {
    ('reverse-engineer', 'apk'): ('apklab-reverse-engineering', 'apklab-triage'),
    ('reverse-engineer', 'xapk'): ('apklab-reverse-engineering', 'apklab-triage'),
    ('reverse-engineer', 'apks'): ('apklab-reverse-engineering', 'apklab-triage', 'apklab-split-check'),
    ('reverse-engineer', 'splits'): ('apklab-reverse-engineering', 'apklab-triage', 'apklab-split-check'),
    ('triage', 'apk'): ('apklab-triage', 'apklab-report'),
    ('triage', 'xapk'): ('apklab-triage', 'apklab-report'),
    ('triage', 'apks'): ('apklab-triage', 'apklab-report'),
    ('triage', 'splits'): ('apklab-triage', 'apklab-split-check', 'apklab-report'),
    ('investigate', 'apk'): ('apklab-investigate', 'apklab-report'),
    ('investigate', 'splits'): ('apklab-investigate', 'apklab-split-check', 'apklab-report'),
    ('compare', 'two-apks'): ('apklab-investigate', 'apklab-report'),
    ('split-check', 'splits'): ('apklab-split-check', 'apklab-report'),
    ('split-check', 'xapk'): ('apklab-split-check', 'apklab-report'),
    ('split-check', 'apks'): ('apklab-split-check', 'apklab-report'),
    ('rebuild', 'apk'): ('apklab-rebuild', 'apklab-report'),
    ('rebuild', 'splits'): ('apklab-rebuild', 'apklab-report'),
    ('rebuild', 'xapk'): ('apklab-rebuild', 'apklab-report'),
    ('report', 'report'): ('apklab-report',),
    ('diagnose', 'report'): ('apklab-error-triage', 'apklab-report'),
    ('review', 'diff'): ('apklab-code-review',),
    ('test', 'source'): ('apklab-white-box-testing', 'apklab-repo-maintenance'),
    ('maintain', 'repo'): ('apklab-repo-maintenance',),
    ('black-box', 'apk'): ('apklab-black-box-testing', 'apklab-report'),
    ('black-box', 'splits'): ('apklab-black-box-testing', 'apklab-split-check', 'apklab-report'),
    ('fuzz', 'parser'): ('apklab-fuzzing', 'apklab-report'),
}


def _require_supported(goal: str, kind: str) -> None:
    route = (goal, kind)
    if route not in ROUTES or route not in SKILL_ROUTES:
        raise ValueError('Unsupported goal and input type combination; consult agent plan --help')


def plan(goal: str, kind: str) -> List[dict]:
    """Return recommendations only; do not read files, discover tools or run commands."""
    _require_supported(goal, kind)
    return [{'type': 'command' if command is not None else 'guidance',
             'command': command, 'purpose': purpose} for command, purpose in ROUTES[(goal, kind)]]


def recommended_skills(goal: str, kind: str) -> List[str]:
    """Return relevant skill names only; this does not load or execute their instructions."""
    _require_supported(goal, kind)
    return list(SKILL_ROUTES[(goal, kind)])
