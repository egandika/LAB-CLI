"""Deterministic, non-executing APKLab workflow selection."""
from typing import List


# Commands are names, not shell strings; callers must supply their own authorized paths.
ROUTES = {
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
    ('report', 'report'): [(None, 'Separate verified, inferences, failures and not_tested in the supplied report')],
    ('diagnose', 'report'): [(None, 'Review sanitized error and unknown checks before suggesting a next step')],
}


def plan(goal: str, kind: str) -> List[dict]:
    """Return recommendations only; do not read files, discover tools or run commands."""
    if (goal, kind) not in ROUTES:
        raise ValueError('Unsupported goal and input type combination; consult agent plan --help')
    return [{'type': 'command' if command is not None else 'guidance',
             'command': command, 'purpose': purpose} for command, purpose in ROUTES[(goal, kind)]]
