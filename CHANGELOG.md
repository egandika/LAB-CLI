# Changelog

## 0.5.0 (unreleased)

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
