# Changelog

## 0.5.0 (unreleased)

- Upgrade the reverse-engineering workflow with hypotheses, evidence provenance, cross-checks, confidence and explicit stop/unknown conditions.

- Add dedicated, guidance-only black-box testing and bounded parser-fuzzing methods; do not imply current device support is full dynamic analysis or that smoke mutations are coverage-guided fuzzing.

- Add the opt-in `apklab fuzz` command for bounded deterministic mutations across six synthetic parser paths; validate baseline seeds and report input digests without executing APK code or claiming coverage-guided fuzzing.

- Enforce configurable physical input caps for APK and XAPK/APKS archives separately from uncompressed ZIP limits, and bounded per-file/aggregate copies for workspace, split, JADX, and device workflows.

- Preserve ZIP entry indices in inventory evidence and reject ambiguous duplicate-name APK diffs rather than choosing an entry silently.

- Require the Android namespace for AAPT permission, component, and split-metadata attributes to avoid treating similarly named custom attributes as Android declarations.

- Report malformed deflate streams with the affected ZIP entry instead of surfacing an unscoped low-level zlib error.

- Strengthen white-box test design, review findings, debugging/reproduction, split analysis, reports, and reversible repository prototyping guidance.

- Route nine method categories through the existing orchestrator/agent plan and add method-tagged manual evaluation scenarios; real agent/plugin-host behavior remains untested.

- Add read-only-by-default code review guidance with evidence and test limitations.

- Add source-informed white-box testing guidance with mock and integration boundaries.

- Add scoped reverse-engineering guidance that reuses existing analysis and rebuild skills.

- Add an instruction-only orchestrator for selective, goal-directed skill routing.

- Report declared APK ZIP size-limit details and guide agents to review limits before retrying.

- Stop APT package installation after a failed or timed-out package index update.

- Add non-installing goal-specific tool discovery to setup plans; prevent combining goals with the broad APT installer.

- Cover agent-plan subprocess reporting, no-overwrite behavior and unsupported goal/input pairs.

- Distinguish non-executable guidance from real command names in structured agent plans.

- Make baseline agent instructions goal-directed and consistent about permission for probes and extraction.

- Link the triage skill to structured planning and clarify report option placement.

- List supported agent-plan combinations in CLI help and document an optional plugin-host installation example.

- Add a scenario set and manual protocol for evaluating agent behavior and skill activation.

- Add non-executing structured `agent plan` workflow recommendations.

- Add an optional instruction-only portable plugin package mirroring the agent skills; real host compatibility is untested.

- Document agent capability selection, safe error triage and session handoff.

- Add instruction-only skills for split analysis, copy-based workflows, error diagnosis and repository maintenance.

- Add instruction-only agent skills for APKLab triage, static investigation and evidence reporting.

- Clarify agent permission, evidence and untrusted-input guidance; align the copyable prompt with setup approval.

- Select preinstalled Android build-tools 35 for emulator integration to match the real-tool job.

- Fix real-tool split fixture manifest filenames for aapt; cover fixture commands with a mock regression test.

- Apply bounded inner ZIP expansion limits when inspecting contained XAPK APKs.

- Include native ABI directory observations and compression method in APK diffs.

- Check supported DEX header SHA-1 and Adler-32 integrity without claiming authenticity.

- Report explicit per-scheme apksigner verification results when available.

- Inventory selected explicit manifest security attributes as partial AXML inferences, not vulnerability verdicts.

- Add read-only APK set archive inventory without device targeting or extraction.

- Add read-only per-entry APK diff with bounded ZIP validation and inferred metadata.

- Add offline per-library 16 KiB ZIP data-offset observations for existing APKs.

- Add bounded inspection of contained XAPK APKs and comparison of supported size/SHA-256 declarations.

- Add optional split-aware inventory scope warnings using partial internal AXML inference.

- Clarify that an unconfirmed ADB install may still have changed emulator state.

- Clarify that internal AXML may infer, but does not confirm, a base candidate.

- Publish bounded integration-test failure diagnostics in CI annotations; this does not establish that Android integration passes.

- Apply modern split type checks to signed split outputs and opt-in device installation; block only verified missing types, and retain unknowns as untested.

- Correct the apksigner success message in workspace verification reports.

- Bound physical input-copy size and count for opt-in split type inspection.

- Avoid split-type comparisons for known conflicting major version codes and report unverified major versions.

- Preserve internal AXML provenance for split package/version mismatches and avoid duplicate mismatch reports.

- Reject duplicate JSON keys in XAPK manifests in inspection, unpacking, repacking, and OBB layout checks.

- Fail closed on truncated or incomplete ADB safety-check output and do not verify incomplete install/launch output.

- Add opt-in copy-based inspection of modern literal split types, with conservative unknowns and internal AXML inferences; no split selection or completeness claim.

- Expand the CI Python matrix to 3.9–3.13 and annotate public module functions.
- Fail safely when APT installation is requested on hosts without POSIX user IDs; compare resolved paths in portable staging tests. Windows behavior remains unverified natively.
- Lower and sample JADX output caps more frequently (best effort), add optional report redaction, and warn about untrusted execution.
- Check ELF LOAD segment alignment per native library during workspace verification, independently of ZIP alignment.
- Inspect explicit split dependencies and optionally update supported XAPK manifest size/SHA-256 fields for replacements.
- Report recognizable DEX 041 containers as not tested per entry and reject malformed container headers; cache repeated string offsets.
- Add bounded internal binary-AXML literal metadata fallback, a doctor feature/tool table, and broader setup-plan guidance.

- Check duplicate ZIP entries individually, bound subprocess output, and make process cleanup best effort across POSIX and Windows.
- Limit DEX index expansion, decode Modified UTF-8, and report unsupported or malformed inputs rather than silently replacing invalid text.
- Validate APK ZIP structure consistently, report partial manifest output, and stage workspace and XAPK outputs before publication.
- Preserve partial reports, document page-size verification behavior, and include bounded JADX diagnostics.
- Compare verified split-output signer digests and selected explicit manifest dependencies; report missing metadata as untested.
- Improve SDK tool discovery, ZIP ignore patterns, and synthetic regression coverage.
- Pin GitHub Actions to full commit hashes; runtime downloads remain separate dependencies.

These checks do not prove APK installability, full ELF validity or compatibility, split completeness, or runtime behavior. Process cleanup is not a sandbox. The Android-tool and split integration paths require independent real-tool testing.

## 0.4.0

- Added copy-based APK and split workflows, XAPK inspection and extraction, opt-in emulator tests, and JSON evidence reports.
