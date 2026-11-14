# APKLab agent guide

## Starting a new project

1. Read `README.md` and `apklab --help`, then run `apklab doctor --check` and inspect `not_tested`. A successful version/help probe does not prove full functionality.
2. Obtain authorization, preserve the original APK(s), and use only new working copies. Do not run untrusted APKs on a production device. Never commit APKs, extracted data, large builds, secrets, keystores, or personal data.
3. For XAPK, use `apklab xapk inspect` and unpack only to a new directory, then `apklab inspect DIRECTORY --recursive` to inspect contained APKs together. CRC/hash checks do not validate inner APKs, OBB data, split completeness or device compatibility; increase size limits only deliberately. Run `apklab inventory` and `apklab dex` on relevant APKs. Save reports outside version control and redact secrets before sharing. Record verified checks, hypotheses, failures, and untested items separately.
4. Metadata and signature checks require `aapt` and `apksigner`. DEX API/URL/model results are static hints, not behavior or full schemas. Native and dynamic code may hide behavior; use authorized external tools as needed. Do not infer server implementation or availability from client artifacts.
5. For modifications, run `apklab work init`, followed by decode/edit/build/align/sign in the workspace only. Use `apklab work verify` for alignment and signature checks, and inspect its `not_tested` results. These checks do not establish installability, 16 KiB alignment, original-signer compatibility or functionality. Test only with authorization; report missing steps. A different signature can block updates or integrations.
6. Use `apklab setup` to review the installation plan; only run `setup --install` when permitted to modify the machine. It uses configured APT sources and can fail. Check results and use official upstream sources for manual installation. Do not ask for credentials or put passwords in command lines.
7. Run `python3 -m unittest discover -s tests -v` after changes. The real Android-tool integration test is opt-in with `APKLAB_INTEGRATION_APK`; see the README. State clearly what was tested with real external tools versus mocks and whether CI actually ran. Be honest about network, tools, sandbox and device limitations.

Do not install or connect external services without first presenting a setup plan and obtaining the user's approval. Do not push changes unless explicitly authorized.
