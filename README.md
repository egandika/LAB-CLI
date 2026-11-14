# APKLab

**A CLI toolkit for APK/XAPK inspection and copy-based Android analysis workflows.**

[MIT License](LICENSE) · Python 3.9+ · Designed for users and AI agents

APKLab helps inspect Android packages, explore DEX and assets, and prepare modification workflows without changing the original files. It is a general-purpose toolkit, not specific to any app or game.

> Only analyze applications you are authorized to examine. Rebuilding or signing an APK does **not guarantee** that it can be installed or played. Treat APKs, XAPKs, and third-party tools as untrusted input.

## Features

| Command | Purpose |
| --- | --- |
| `doctor` | Find Android and analysis tools; optionally probe versions or help output. |
| `setup` | Show a plan or attempt a limited installation through APT. |
| `inspect` | Check APK ZIPs, native ABIs, metadata, and signatures, including multiple splits. |
| `xapk` | Inspect and copy the contents of an XAPK into a new directory. |
| `dex` | Index classes, method references, APIs, strings, URLs, and potential models. |
| `inventory` | List assets and native libraries; optionally use `readelf`. |
| `work` | Create a copy-based workspace for decoding, rebuilding, alignment, signing, and verification. |

Some checks require external tools. Results are grouped into `verified`, `inferences`, `failures`, and `not_tested` so checks that were not run are not mistaken for successful ones.

## Installation

Requirements: Python 3.9+, Git, pip/venv, and access to GitHub and a package index for build dependencies. This example is for Linux/macOS:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install 'git+https://github.com/egandika/LAB-CLI.git'
.venv/bin/apklab --help
.venv/bin/apklab doctor
```

On Windows, virtual environment executables are in `.venv\Scripts\`. APKLab does not bundle APKs or Android tools. Direct installation installs the CLI but does not create a checkout for reading the repository guides. For reproducible results, use a reviewed commit or tag.

### Installation for AI agents

The agent needs terminal and network access. If these are unavailable, it should explain the limitation. To install the CLI and read its guides, run the following from a safe working directory:

```sh
git clone https://github.com/egandika/LAB-CLI.git apklab-toolkit
cd apklab-toolkit
cat README.md AGENTS.md
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/apklab --help
.venv/bin/apklab doctor
```

If `apklab-toolkit` already exists, use the correct checkout or choose a new directory; do not delete or overwrite existing files. If each agent command starts in a different directory, return to the checkout or use the full path to `.venv/bin/apklab`. Cloning and installing from the checkout were tested with APKLab 0.2.0 on Linux.

### Copyable agent prompt

Replace `[FILE_PATH]` with the location of the APK/XAPK accessible to the agent, or tell the agent the file will be provided later.

```text
Help me analyze an APK/XAPK that I am authorized to use.
File location: [FILE_PATH]

If APKLab is not available, clone https://github.com/egandika/LAB-CLI.git into a new directory, read README.md and AGENTS.md, and install APKLab in a virtual environment. Run apklab --help and apklab doctor. If you cannot access a terminal or install it, explain the limitation.

Work on copies and do not change or delete the original file. For XAPK, inspect and extract it into a new directory before inspecting the APKs inside. Do not put application files, extracted contents, credentials, or personal data in Git. If additional tools are needed, explain the plan and ask for approval before installing them.

Separate verified results, inferences, failures, and untested items. Do not claim an APK can be installed or played without testing, and do not assume server code or data is available in the APK.
```

## Tool discovery and setup

```sh
apklab doctor
apklab doctor --check        # run limited version/help probes
apklab setup                 # show the plan; do not install tools
apklab setup --install       # opt in to attempting installation through APT
```

`doctor` searches PATH, `ANDROID_SDK_ROOT`, `ANDROID_HOME`, `~/Android/Sdk`, and `GHIDRA_HOME` for Ghidra. `--check` runs short version/help probes for supported tools and reports unsuccessful or unsupported probes as `not_tested`. Finding an executable or receiving a successful version response **does not prove** full functionality. For example, package metadata requires `aapt` and signature verification requires `apksigner`.

`setup --install` is for Debian/Ubuntu-based systems and modifies the system: it runs `apt-get update`, attempts to install missing packages, and checks for their executables. Review the APT sources and plan first. It requires root or passwordless sudo; failures are reported per package. JADX, the full SDK, the emulator, and Ghidra are not installed automatically.

If needed, install tools from official sources and verify provided checksums/signatures:

- [Android SDK command-line tools and build tools](https://developer.android.com/studio#command-line-tools-only): `aapt`, `zipalign`, `apksigner`, emulator, and ADB.
- [apktool](https://apktool.org/), [JADX](https://github.com/skylot/jadx), [Eclipse Temurin Java](https://adoptium.net/), and [Ghidra](https://github.com/NationalSecurityAgency/ghidra).
- `readelf` from the system toolchain is optional for native headers and dependencies. APKLab detects JADX/Ghidra but does not run them automatically.

Tool availability depends on the system and network. SDK installation, acceptance of SDK licenses, and device configuration are not automated.

## Usage

Activate the virtual environment (`. .venv/bin/activate` on Linux/macOS), or replace `apklab` with the full path to its executable in the virtual environment.

### Inspect APKs and splits

```sh
apklab inspect app.apk
apklab inspect base.apk split_config.arm64_v8a.apk
apklab inspect ./split-directory --recursive --report inspection.json
apklab dex app.apk --search login --limit 50
apklab inventory app.apk --search lib --native-details
```

`inspect` checks ZIP CRCs, native ABI directories, and manifest presence. With `aapt` and `apksigner`, it also reads metadata and verifies signatures. For multiple APKs, available package names, version codes, and certificate digest sets are compared, and duplicate non-empty split names reported by `aapt` are flagged. Unavailable checks are marked `not_tested`; matching digests do not prove that a split set is complete or compatible. Base selection, split dependencies, device compatibility, signer rotation, and installation are not fully validated.

`dex` indexes classes and method references, not runtime behavior or call graphs. URLs and model names are hints, not proof that a server is active or that model definitions are complete. Obfuscation, encrypted strings, dynamic DEX, and native code can hide information. `inventory` lists paths and sizes, not the contents of every asset.

### Inspect and extract XAPKs

```sh
apklab xapk inspect game.xapk --verify
apklab xapk unpack game.xapk ./xapk-copy
apklab inspect ./xapk-copy --recursive --max-entry-mib 2048 --max-total-mib 8192
```

`xapk inspect` lists entries; `--verify` reads each file, checks CRC, and computes SHA-256. `unpack` only reads the original archive and copies its contents into a **new** directory, checking CRC and hashes. Path traversal, duplicate or colliding paths, symlinks, special files, encrypted entries, and size-limit violations are rejected.

APK references in a root `manifest.json` with a supported `split_apks` list are compared with entry names; other formats are marked untested. This does not validate manifest completeness, all APK contents, or OBB compatibility. If the manifest reports a failure after extraction, the copied directory may remain. XAPK repacking, OBB placement, device-specific split selection, and installation are not implemented.

Default APK limits are 100,000 entries, 64 MiB per entry, and 512 MiB total uncompressed. For XAPK, the default size limits are 2,048 MiB per entry and 8,192 MiB total. Adjust them deliberately with `--max-entry-mib` and `--max-total-mib`; higher limits may use substantial memory, CPU, and disk space. CRC is not a substitute for signature verification. `.apks` containers are not extracted automatically.

### Copy-based modification workflow

```sh
apklab work init app.apk ./apklab-work-example
apklab work decode ./apklab-work-example
# Edit only files in apklab-work-example/decoded.
apklab work build ./apklab-work-example
apklab work align ./apklab-work-example
apklab work sign ./apklab-work-example --keystore /secure/path/key.jks --alias mykey --pass-env APKLAB_KS_PASS
apklab work verify ./apklab-work-example
apklab inspect ./apklab-work-example/signed.apk
```

The workspace must be new; `original.apk` is a copy. Stages use separately installed `apktool`, `zipalign`, and `apksigner`. Outputs must be new and inside the workspace; `--input` and `--output` can change paths within it. Set the password in an environment variable using a secure local method, not in commands, reports, or Git. Separate key passwords, hardware tokens, and rebuilding a split set are not supported.

`work verify` independently invokes `zipalign -c -p 4` and `apksigner verify` on `signed.apk`, or on a workspace file selected with `--input`. Missing tools are reported as `not_tested`; an exit code of 0 does not mean both checks ran. This checks the specified alignment and signature, not 16 KiB page-size compatibility, signer compatibility with the original, installability, or app behavior. Test installation and behavior only on an authorized, isolated device or emulator. A different signing key may prevent updates to the original app or affect integrations. Not every APK can be rebuilt unchanged with apktool.

### Reports

All output is JSON. Exit code `1` indicates a reported failure; `0` means no failures were reported, **not** that every check ran. `--report FILE` only creates a new file and does not overwrite an existing one. For `work` and `xapk`, place `--report` after the command name and before the subcommand.

Reports may contain sensitive strings, endpoints, or paths. Review and redact them before sharing. Do not put APKs/XAPKs, OBBs, extracted data, keystores, credentials, or personal data in Git; `.gitignore` is a safeguard, not a guarantee.

## Server limitations and testing

URLs, API references, models, and native code may suggest server dependencies, but do not provide private server code or data or prove availability or compatibility. APKLab does not automatically create a compatible game server. Do not contact production endpoints without permission.

Run automated tests with:

```sh
python3 -m unittest discover -s tests -v
```

Most tests use synthetic APK/DEX files and mocks for metadata, signing, and external-tool workflows; the native test also uses system `readelf` when available. An opt-in integration test uses real Java, `keytool`, `apktool`, `aapt`, `zipalign`, and `apksigner` with an authorized test APK. It creates a temporary test keystore, decodes, rebuilds, aligns, signs, and verifies a copy; it does not install or launch the APK:

```sh
APKLAB_INTEGRATION_APK=/path/to/authorized-test.apk python3 -m unittest discover -s tests -p test_integration.py -v
```

Without `APKLAB_INTEGRATION_APK`, this test is skipped. When explicitly enabled, it fails if required tools are missing. The GitHub Actions workflow runs unit tests across Python versions and operating systems, plus the real-tool integration test on Linux using a checksum-pinned [public Androguard test APK](https://github.com/androguard/androguard/blob/0c0af30ca6bd55d3d34aa10d7f32593cd091a483/tests/data/APK/TestActivity.apk), which is not committed here. The real-tool round trip has passed in CI on Linux; check the current workflow results for the latest status. Device/emulator installation and runtime behavior have not been tested.

## License

APKLab is licensed under the [MIT License](LICENSE). The license permits reuse and modification under its terms and provides the software without warranty. It does not grant rights to third-party apps, assets, data, or tools.
