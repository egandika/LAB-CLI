# Changelog

## 0.5.0 (unreleased)

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
