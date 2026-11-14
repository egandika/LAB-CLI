# APKLab

APKLab is a general-purpose, evidence-oriented CLI for analyzing Android APKs and preparing copy-based modification workflows. It does **not** automatically recreate a server or prove that a modified app works. Analyze only software you are authorized to examine. Treat APKs, extracted data and third-party tools as untrusted; use an isolated environment.

## Install

Python 3.9+, Git and pip/venv are needed. From an existing checkout (tested):

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
apklab --help
apklab doctor
```

For a new conversation after these changes have been **merged into the repository's default branch**, the intended GitHub installation is:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install 'git+https://github.com/egad13744-collab/LAB-CLI.git'
apklab --help
apklab doctor
```

The GitHub command is not yet tested for this version: it cannot install changes that have not been merged into the default branch. Once published, prefer a reviewed commit SHA or a release tag over a mutable branch. Venv activation above is for Unix; on Windows use `.venv\Scripts\activate`. The CLI has no runtime Python dependencies; pip's build isolation obtains setuptools from the configured package index. No APK or external tool is bundled.

### Prompt untuk percakapan AI baru

Setelah perubahan masuk ke branch utama, salin prompt berikut ke percakapan baru dan berikan APK yang berwenang Anda analisis:

> Instal APKLab dengan `python -m pip install 'git+https://github.com/egad13744-collab/LAB-CLI.git'` dalam virtual environment. Baca README dan AGENTS.md, jalankan `apklab --help` dan `apklab doctor`, lalu bantu analisis APK saya pada salinannya. Pisahkan hasil terverifikasi, dugaan, kegagalan, dan yang belum diuji. Jangan instal atau hubungkan REA tanpa rencana dan persetujuan saya.

## Discover and install tools

```sh
apklab doctor
apklab setup                 # plan only; does not install
apklab setup --install       # opt-in: modifies system via apt-get
```

`doctor` searches PATH, `ANDROID_SDK_ROOT`, `ANDROID_HOME`, `~/Android/Sdk` and, for Ghidra, `GHIDRA_HOME`. It checks executable presence, not whether tools run correctly. `setup --install` is an optional Debian/Ubuntu APT attempt using the machine's configured repositories; it runs `apt-get update` then tries missing `default-jre-headless`, `apktool`, `adb`, `aapt`, `zipalign`, and `apksigner`, and checks executable presence. It requires root or passwordless sudo; it never prompts for a password. Review APT repository configuration and the plan first. Failures are reported individually, and other platforms must install tools manually.

For other tools or missing packages, use their official projects and verify release checksums/signatures as provided:

- [Android SDK command-line tools and build tools](https://developer.android.com/studio#command-line-tools-only) (aapt, zipalign, apksigner, emulator, adb); configure `ANDROID_SDK_ROOT` and install required SDK components via official `sdkmanager`.
- [JADX](https://github.com/skylot/jadx), [apktool](https://apktool.org/), [Eclipse Temurin Java](https://adoptium.net/), [Ghidra](https://github.com/NationalSecurityAgency/ghidra).
- `readelf` from your OS toolchain is optional for native library headers and dynamic dependencies. `doctor` detects JADX/Ghidra but APKLab does not run them automatically; follow their documentation.

Availability varies by OS, SDK layout, and network. `setup` does not install JADX, Ghidra, the emulator or the complete SDK, and cannot configure a device or accept SDK licenses.

## Inspect and analyze

```sh
apklab inspect app.apk
apklab inspect base.apk split_config.arm64_v8a.apk
apklab inspect ./split-directory --report inspection.json
apklab inventory app.apk --search lib --native-details
apklab dex app.apk --search 'login' --limit 50
apklab dex app.apk --report dex-report.json
```

- `inspect` checks ZIP CRCs, native ABI directory names, and AndroidManifest presence. It invokes **aapt** for package and version metadata and **apksigner verify** for signature verification; unavailable tools are reported as `not_tested`, not as passing. A directory expands `*.apk` only; `.apks` containers are not automatically unpacked. Multiple APKs are individually inspected and differing known package names/version codes flagged; complete split compatibility, signer equality, base selection, missing splits, and installation are **not** checked.
- `inventory` lists `assets/`, `res/`, and `lib/<abi>/*.so` paths and uncompressed sizes. `--search` filters paths, not content. `--native-details` invokes `readelf -h -d` if available, not full native reverse engineering.
- `dex` indexes DEX class definitions, method ID references (including references not necessarily called), common API references, string literals and literal HTTP(S) URLs. Model names are a naming heuristic; they are **not** extracted schema definitions. `--search` filters results; `--limit` caps each returned list. Names may be obfuscated, strings encrypted, endpoints assembled dynamically, DEX loaded remotely, and code may reside in native libraries. This is not a decompiler or call graph. Use JADX/Ghidra separately when needed.
- ZIP limits: at most 100,000 entries, 64 MiB per entry and 512 MiB total uncompressed. Larger legitimate APKs are rejected rather than processed. CRC is not signature verification or a security guarantee. Files are not extracted by these analysis commands.

All command output is JSON with `verified`, `inferences`, `failures`, and `not_tested`. `verified` means the stated check happened, not that the app is safe or functional. Exit code 1 indicates a reported failure, 0 means no failures, **not** that every check was run. `--report FILE` writes a new report and refuses to overwrite an existing file; for `work`, place `--report` immediately after `work`. Reports may contain sensitive app strings, endpoints, and file paths: inspect/redact before sharing or committing.

## Copy-based modification workflow

```sh
apklab work init app.apk ./apklab-work-example
apklab work decode ./apklab-work-example
# Edit only files under apklab-work-example/decoded, preserving the original input.
apklab work build ./apklab-work-example
apklab work align ./apklab-work-example
# Supply a keystore you control. Put the password in an environment variable
# using a secure local method; do not put the value in commands, reports or Git.
apklab work sign ./apklab-work-example --keystore /secure/path/key.jks --alias mykey --pass-env APKLAB_KS_PASS
apklab inspect ./apklab-work-example/signed.apk
```

The workspace must be new; `original.apk` is a copy. Stages use `apktool d`, `apktool b`, `zipalign -p 4`, and `apksigner sign` respectively. Each output must be new and inside the workspace. `--input` and `--output` override default paths but remain confined to that workspace. Tools must be installed first. Signing supports a keystore password passed by environment variable name; advanced key password, hardware token, signing configuration, and split-set rebuilding are not implemented. The resulting APK is not claimed installable, playable, correctly signed, compatible with original app data, or functional. Verify separately with `apksigner verify`, `zipalign -c -p 4`, and only with permission test on an isolated device/emulator. A different signing key can prevent updates and invalidate signature-dependent integrations. Some APKs cannot be rebuilt by apktool unchanged.

## Server dependencies

URLs, network API references, models, and native code can suggest server dependencies. They cannot reveal private server code/data, protocol semantics, authentication, operational availability, or guarantee compatibility. Record observations and hypotheses separately; do not contact production endpoints without authorization. Server behavior requires independent documentation and testing. APKLab does not generate a compatible game server.

## Tests and limitations

```sh
python3 -m unittest discover -s tests -v
```

Tests use synthetic APK/DEX files and mock external tools for metadata, signing and workflow stages; the native inspection test also uses the system `readelf` when available. A separate manual smoke test has indexed the public [Androguard TestActivity.apk](https://github.com/androguard/androguard/blob/master/tests/data/APK/TestActivity.apk); it is not included in this repo. Full real-tool decode/rebuild/align/sign and device/emulator tests require the relevant tools and authorized samples; they were not run in the initial environment. No app, private data, build artifacts, secrets or keystores belong in Git. The `.gitignore` is a safety aid, not a guarantee.
