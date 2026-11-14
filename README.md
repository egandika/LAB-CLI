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
| `xapk` | Inspect, extract, or repack an XAPK without overwriting the original. |
| `dex` | Index classes, method references, APIs, strings, URLs, and potential models. |
| `inventory` | List assets and native libraries; search bounded text and inspect native symbols. |
| `work` | Create a copy-based workspace for apktool/JADX, rebuilding, alignment, signing, and verification. |
| `splits` | Apply copy-based workflow stages across multiple APKs. |
| `device` | Opt in to installation and optional launcher-event tests on a disposable emulator. |

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
- `readelf` from the system toolchain is optional for native headers and dependencies. APKLab runs JADX only when explicitly requested with `work jadx`; it detects Ghidra but does not invoke it.

Tool availability depends on the system and network. SDK installation, acceptance of SDK licenses, and device configuration are not automated.

## Usage

Activate the virtual environment (`. .venv/bin/activate` on Linux/macOS), or replace `apklab` with the full path to its executable in the virtual environment.

### Inspect APKs and splits

```sh
apklab inspect app.apk
apklab inspect base.apk split_config.arm64_v8a.apk
apklab inspect ./split-directory --recursive --device-abi arm64-v8a --report inspection.json
apklab dex app.apk --search login --limit 50
apklab inventory app.apk --search lib --native-details --native-symbols
apklab inventory app.apk --text 'example.org'
```

`inspect` checks ZIP CRCs, native ABI directories, and manifest presence. With `aapt` and `apksigner`, it also reads metadata and verifies signatures. For multiple APKs, available package names, version codes, and certificate digest sets are compared, and duplicate non-empty split names reported by `aapt` are flagged. Unavailable checks are marked `not_tested`; matching digests do not prove that a split set is complete or compatible. Base selection, split dependencies, device compatibility, signer rotation, and installation are not fully validated.

When metadata is available, `inspect` lists APKs without a reported split name as **base candidates**, not confirmed bases. `--device-abi` compares native directory names only; it does not establish compatibility or select the correct splits.

`dex` indexes classes and method references, not runtime behavior or call graphs. URLs and model names are hints, not proof that a server is active or that model definitions are complete. Obfuscation, encrypted strings, dynamic DEX, and native code can hide information. `inventory --native-symbols` uses `readelf`; symbols may be stripped. `--text` searches UTF-8 assets/resources only, skips binary or entries over 1 MiB, reads at most 32 MiB total, and returns at most 200 excerpts. Results may contain sensitive data.

### Inspect and extract XAPKs

```sh
apklab xapk inspect game.xapk --verify
apklab xapk unpack game.xapk ./xapk-copy
apklab inspect ./xapk-copy --recursive --max-entry-mib 2048 --max-total-mib 8192
```

`xapk inspect` lists entries; `--verify` reads each file, checks CRC, and computes SHA-256. `unpack` only reads the original archive and copies its contents into a **new** directory, checking CRC and hashes. Path traversal, duplicate or colliding paths, symlinks, special files, encrypted entries, and size-limit violations are rejected.

APK references in a root `manifest.json` with a supported `split_apks` list are compared with entry names; other formats are marked untested. This does not validate manifest completeness, all APK contents, or OBB compatibility. If the manifest reports a failure after extraction, the copied directory may remain.

To create a **new** XAPK and replace selected APK entries with copies you have rebuilt and signed:

```sh
apklab xapk repack game.xapk ./modified.xapk --replace base.apk=/path/to/signed-base.apk
apklab xapk inspect ./modified.xapk --verify
```

Repeat `--replace ENTRY=APK` for other APKs. Source paths are read-only, replacements must be ZIPs containing `AndroidManifest.xml`, and ZIP CRCs are checked. OBB and other entries are copied unchanged. The manifest is **not rewritten**; version, size or checksum fields may be stale. Signature compatibility, OBB compatibility, installer support, device-specific split selection, and app behavior are not verified.

Default APK limits are 100,000 entries, 64 MiB per entry, and 512 MiB total uncompressed. For XAPK, the default size limits are 2,048 MiB per entry and 8,192 MiB total. Adjust them deliberately with `--max-entry-mib` and `--max-total-mib`; higher limits may use substantial memory, CPU, and disk space. CRC is not a substitute for signature verification. `.apks` containers are not extracted automatically.

### Copy-based modification workflow

```sh
apklab work init app.apk ./apklab-work-example
apklab work decode ./apklab-work-example
apklab work jadx ./apklab-work-example   # optional: read decompiled source
# Edit only files in apklab-work-example/decoded.
apklab work build ./apklab-work-example
apklab work align ./apklab-work-example --page-size 16
apklab work sign ./apklab-work-example --keystore /secure/path/key.jks --alias mykey --pass-env APKLAB_KS_PASS
apklab work verify ./apklab-work-example --page-size 16
apklab inspect ./apklab-work-example/signed.apk
```

The workspace must be new; `original.apk` is a copy. Stages use separately installed `apktool`, `jadx`, `zipalign`, and `apksigner`. `work jadx` writes decompiled Java into a new workspace directory; its output is for analysis, not a rebuildable source project. Outputs must be new and inside the workspace; `--input` and `--output` can change paths within it. Set the password in an environment variable using a secure local method, not in commands, reports, or Git. Separate key passwords and hardware tokens are not supported.

`--page-size 16` requires a `zipalign` version advertising `-P` support, such as Android build tools 35.0.0 or later. It aligns/checks uncompressed native libraries in the ZIP; it **does not verify ELF load-segment alignment**, overall 16 KiB device compatibility, or runtime behavior. The default is 4 KiB. `work verify` also invokes `apksigner verify`; missing tools or unsupported 16 KiB checks are `not_tested`, so exit code 0 does not mean both checks ran.

Test installation and behavior only on an authorized, isolated device or emulator. A different signing key may prevent updates to the original app or affect integrations. Not every APK can be rebuilt unchanged with apktool.

### Split workspaces

Create a new workspace from APK files, then run the same stage on each copy. This does not automatically select splits or validate the set:

```sh
apklab splits init ./split-work base.apk split_config.arm64_v8a.apk
apklab splits run ./split-work decode
# Edit each apk-NNNN/decoded directory as needed.
apklab splits run ./split-work build
apklab splits run ./split-work align --page-size 16
apklab splits run ./split-work sign --keystore /secure/path/key.jks --alias mykey --pass-env APKLAB_KS_PASS
apklab splits run ./split-work verify --page-size 16
apklab inspect ./split-work/apk-0000/signed.apk ./split-work/apk-0001/signed.apk
```

Every signing operation uses the supplied keystore and alias; independently compare verified signer digests with `inspect`. Original-copy SHA-256 values are checked before each stage. Stages may partially succeed: read each member report. Existing outputs are never overwritten; use a new workspace or handle failed members individually. Set completeness, installer compatibility, device targeting, and behavior are not guaranteed.

### Disposable-emulator test

`device` reads temporary copies of the selected APKs and explicitly changes emulator state. Use only a **disposable, isolated, single-user emulator** with no personal data. Installing or launching an APK can execute untrusted code and access the network; isolate networking as appropriate. Physical device serials are rejected, but identity checks cannot guarantee the environment is safe.

```sh
apklab device --serial emulator-5554 --confirm-install ./apklab-work-example/signed.apk
# Add --launch only when you intend to execute app code.
```

For split sets, supply the base and all required split APK paths. The command requires `adb`, `aapt`, and `apksigner`; checks emulator identity, package/version/signer consistency, and refuses an already installed package. It does not install OBBs, select splits, uninstall the app, or prove app functionality. A launcher event is not proof of successful execution. Failure may leave a partially changed emulator; discard the disposable emulator when finished.

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

Without `APKLAB_INTEGRATION_APK`, this test is skipped. When enabled, missing required tools cause failure. Set `APKLAB_TEST_16K=1`, `APKLAB_TEST_JADX=1`, or `APKLAB_TEST_SPLITS=1` to opt into the corresponding checks; the split test uses two copies of one APK, not a genuine split set. `APKLAB_EMULATOR_SERIAL=emulator-5554` additionally installs and launches the test APK on that emulator. Only use a disposable, isolated emulator.

GitHub Actions is configured for cross-platform unit tests, real Android tools, and a disposable-emulator test using a checksum-pinned [public Androguard test APK](https://github.com/androguard/androguard/blob/0c0af30ca6bd55d3d34aa10d7f32593cd091a483/tests/data/APK/TestActivity.apk), which is not committed here. CI has successfully exercised JADX, a 16 KiB ZIP-aligned native entry, the multi-copy workflow, XAPK repacking, and installation and a launcher event on an API 30 emulator. The multi-copy fixture is not a genuine split set. Consult the current workflow results for the latest status; installing or launching a sample does not prove that another APK or game will work.

## License

APKLab is licensed under the [MIT License](LICENSE). The license permits reuse and modification under its terms and provides the software without warranty. It does not grant rights to third-party apps, assets, data, or tools.
