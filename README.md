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
| `dex` | Index DEX identifiers, manifest permissions/components, and heuristic obfuscation hints. |
| `jadx` | Decompile a temporary APK copy to a new output directory with monitored limits. |
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
apklab setup --plan          # show official sources/checksums; do not install tools
apklab setup --install       # opt in to attempting installation through APT
```

`doctor` searches PATH, `ANDROID_SDK_ROOT`, `ANDROID_HOME`, the Windows `LOCALAPPDATA` SDK location, `~/Android/Sdk`, and `GHIDRA_HOME` for Ghidra. `--check` runs short version/help probes for supported tools and reports unsuccessful or unsupported probes as `not_tested`. Finding an executable or receiving a successful version response **does not prove** full functionality. The JSON `feature_tools` table lists feature prerequisites, missing executables and presence-only availability. Literal manifest metadata has a partial internal fallback; signature verification requires `apksigner`.

`setup --plan` provides official download URLs, SHA-256 comparison instructions, and Debian/Ubuntu, Termux/Android, other Linux distributions, Windows and macOS guidance. SDK tools are not guaranteed to run on Termux. If an upstream digest is unavailable, integrity remains unverified. `setup --install` is for Debian/Ubuntu-based systems and modifies the system: it runs `apt-get update`, attempts to install missing packages, and checks for their executables. Review the APT sources and plan first. It requires root or passwordless sudo; failures are reported per package. JADX, the full SDK, the emulator, and Ghidra are not installed automatically.

If needed, install tools from official sources and verify provided checksums/signatures:

- [Android SDK command-line tools and build tools](https://developer.android.com/studio#command-line-tools-only): `aapt`, `zipalign`, `apksigner`, emulator, and ADB.
- [apktool](https://apktool.org/), [JADX](https://github.com/skylot/jadx), [Eclipse Temurin Java](https://adoptium.net/), and [Ghidra](https://github.com/NationalSecurityAgency/ghidra).
- `readelf` from the system toolchain is optional for native headers and dependencies. APKLab runs JADX only when explicitly requested with `jadx` or `work jadx`; it detects Ghidra but does not invoke it.

Tool availability depends on the system and network. SDK installation, acceptance of SDK licenses, and device configuration are not automated.

## Usage

Activate the virtual environment (`. .venv/bin/activate` on Linux/macOS), or replace `apklab` with the full path to its executable in the virtual environment.

Android tool discovery prefers `PATH`, then Android SDK roots in `ANDROID_SDK_ROOT`, `ANDROID_HOME`, the Windows `LOCALAPPDATA` SDK directory where applicable, and the default user SDK directory. SDK build-tools folders are ordered by numeric version, with stable releases ahead of previews of the same version. On Windows, SDK `.exe`, `.bat`, and `.cmd` launchers are considered; batch invocations reject shell metacharacters in paths and arguments rather than risk shell interpretation. Windows behavior should still be verified on the target machine.

### Inspect APKs and splits

```sh
apklab inspect app.apk
apklab inspect base.apk split_config.arm64_v8a.apk
apklab inspect ./split-directory --recursive --device-abi arm64-v8a --report inspection.json
apklab dex app.apk --search login --limit 50
apklab jadx app.apk ./jadx-output --timeout 600 --max-output-mib 512
apklab inventory app.apk --search lib --native-details --native-symbols --hash
apklab inventory app.apk --text 'example.org'
```

`inspect`, `dex`, and `inventory` require an APK ZIP with exactly one root manifest and check every entry CRC within the configured ZIP limits. These checks do not validate manifest contents or APK signatures. `inspect` also lists native ABI directories. With `aapt` and `apksigner`, it also reads metadata and verifies signatures. Without `aapt`, a bounded internal binary-AXML parser attempts literal package, version, permission and component metadata and labels it as an inference; resources and split identity are not resolved. Unsupported or malformed manifests remain untested. For multiple APKs, available package names, version codes, and certificate digest sets are compared, and duplicate non-empty split names reported by `aapt` are flagged. Unavailable checks are marked `not_tested`; matching digests do not prove that a split set is complete or compatible. Base selection, split dependencies, device compatibility, signer rotation, and installation are not fully validated.

When metadata is available, `inspect` lists APKs without a reported split name as **base candidates**, not confirmed bases. `--device-abi` compares native directory names only; it does not establish compatibility or select the correct splits.

`dex` indexes classes and method references, not runtime behavior or call graphs. It reads DEX versions 035 and 037–040 and validates indexed ranges and Modified UTF-8, but does not fully validate DEX files, checksums, or executable code; DEX 041 containers are unsupported and reported per file as `not_tested` after only a limited header check; malformed or truncated headers are failures. It lists named permissions and components from `aapt` XML-tree output or, when unavailable, as inferences from a partial internal binary-AXML parser; truncated stdout is explicitly marked partial and is not presented as a complete manifest; resource references and dynamically registered components can be missed. Short class names and encoded-looking strings are heuristics only and can be false positives. `inventory --hash` streams matching entries, computes SHA-256 and checks ZIP CRC; magic-byte labels are hints, not file validation. URLs and model names are hints, not proof that a server is active or that model definitions are complete. Obfuscation, encrypted strings, dynamic DEX, and native code can hide information. `inventory --native-symbols` uses `readelf`; symbols may be stripped. `--text` searches UTF-8 assets/resources only, skips binary or entries over 1 MiB, reads at most 32 MiB total, and returns at most 200 excerpts. Results may contain sensitive data.

### Inspect and extract XAPKs

```sh
apklab xapk inspect game.xapk --verify
apklab xapk unpack game.xapk ./xapk-copy
apklab inspect ./xapk-copy --recursive --max-entry-mib 2048 --max-total-mib 8192
```

`jadx` copies the input to a temporary directory and creates a new output directory. Its JSON report includes up to 4,000 characters of JADX stderr and a truncation flag, including on successful runs; diagnostics may contain sensitive information. It stops the tool when the timeout or monitored output-size limit is exceeded and removes that newly created output on failure. Size checks are sampled and **are not a hard disk quota**; output can briefly exceed the limit. The runner terminates the POSIX process group or Windows job on exit, but detached or escaped processes are not guaranteed to be contained; this is not a sandbox. Use OS-level isolation and disk quotas for untrusted APKs. `work jadx` uses the same process runner and a 512 MiB monitored output limit; workspace stages stage their outputs before publication and clean up on failure. Atomic directory publication requires platform support; a cleanup error can leave a staging directory.

`xapk inspect` lists entries; `--verify` reads each file, checks CRC, and computes SHA-256. `unpack` only reads the original archive and copies its contents into a **new** directory, checking CRC and hashes. Path traversal, duplicate or colliding paths, symlinks, special files, encrypted entries, and size-limit violations are rejected.

APK references in a root `manifest.json` with a supported `split_apks` list are compared with entry names; other formats are marked untested. This does not validate manifest completeness, all APK contents, or OBB compatibility. Unpack and repack stage their outputs and validate supported manifest references before publishing; a manifest failure prevents publication. Unsupported manifest formats remain untested.

To create a **new** XAPK and replace selected APK entries with copies you have rebuilt and signed:

```sh
apklab xapk repack game.xapk ./modified.xapk --replace base.apk=/path/to/signed-base.apk
apklab xapk inspect ./modified.xapk --verify
# Or produce an archive plus a validated OBB directory layout:
apklab xapk repack game.xapk ./new-output --directory --replace base.apk=/path/to/signed-base.apk
```

Repeat `--replace ENTRY=APK` for other APKs. Source paths are read-only, replacements use the same APK ZIP checks as `inspect`, including exactly one root `AndroidManifest.xml` and CRC checks. OBB and other entries are copied unchanged. The manifest is **not rewritten**; version, size or checksum fields may be stale. In `--directory` mode the new directory contains `repacked.xapk` and copies of declared OBBs under `Android/obb/PACKAGE/`. It requires a supported `package_name` and `expansions` list, validates OBB filename, location, and a one-to-one match with archive entries, and rejects unsupported, missing or undeclared OBBs. This validates placement only, not OBB contents or compatibility. Signature compatibility, installer support, device-specific split selection, and app behavior are not verified.

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

`work align --page-size 16` requires a `zipalign` version advertising `-P` support, such as Android build tools 35.0.0 or later. It aligns uncompressed native libraries in the ZIP; it **does not verify ELF load-segment alignment**, overall 16 KiB device compatibility, or runtime behavior. Alignment defaults to 4 KiB. `work verify` independently runs both 4 KiB and 16 KiB ZIP checks plus `apksigner verify`; a missing tool or unsupported 16 KiB check is `not_tested`. The verification `--page-size` option is retained for compatibility but both checks run regardless; the JSON report records this policy. In `splits run`, the option selects alignment for the `align` stage only; `verify` attempts both checks.

Test installation and behavior only on an authorized, isolated device or emulator. A different signing key may prevent updates to the original app or affect integrations. Not every APK can be rebuilt unchanged with apktool; failed builds report available tool diagnostics and suggest reviewing versions, frameworks, and resource edits.

### Split workspaces

Create a new workspace from APK files, then run the same stage on each copy. This does not automatically select splits or establish set completeness:

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

`splits run verify` independently inspects each signed output with `aapt` and `apksigner`, records signer digests and selected manifest declarations (`uses-split`, `configForSplit`, `isFeatureSplit`, `isSplitRequired`, and `versionCodeMajor`), and reports known signer, package, version and dependency contradictions. Missing or truncated metadata is marked untested, not treated as proof of completeness. Every signing operation uses the supplied keystore and alias; original-copy SHA-256 values are checked before each stage. Stages may partially succeed: read each member report. Existing outputs are never overwritten; use a new workspace or handle failed members individually. Set completeness, installer compatibility, device targeting, and behavior are not guaranteed.

### Disposable-emulator test

`device` reads temporary copies of the selected APKs and explicitly changes emulator state. Use only a **disposable, isolated, single-user emulator** with no personal data. Installing or launching an APK can execute untrusted code and access the network; isolate networking as appropriate. Physical device serials are rejected, but identity checks cannot guarantee the environment is safe.

```sh
apklab device --serial emulator-5554 --confirm-install ./apklab-work-example/signed.apk
# Add --launch only when you intend to execute app code.
```

For split sets, supply the base and all required split APK paths. The command requires `adb`, `aapt`, and `apksigner`; checks emulator identity, package/version/signer consistency and observed split dependencies, and refuses an already installed package. A known missing dependency blocks installation; unavailable or incomplete dependency metadata is reported as untested and does not establish completeness. It does not install OBBs, select splits, uninstall the app, or prove app functionality. A launcher event is not proof of successful execution. Failure may leave a partially changed emulator; discard the disposable emulator when finished.

### Reports

Output is JSON by default. Add `--summary` to print a human-readable count and reasons for untested entries above the JSON; counts refer to report entries, not unique underlying tests. `--report FILE` always writes JSON only, creates a new file, and does not overwrite an existing one. For `work` and `xapk`, place `--report` after the command name and before the subcommand.

Exit statuses are **0** (no failures or untested entries), **1** (one or more failures, taking precedence), **3** (no failures but one or more untested entries), and **2** for argument parsing errors. Status 3 is expected for many commands, including `doctor` and verification, because limitations remain. Shell scripts and CI must explicitly handle it; 0 still does not prove functionality beyond the stated checks.

Reports may contain sensitive strings, endpoints, or paths. Prefer output outside the checkout; example output directories and `apklab-report*.json` are ignored as a safeguard, not a guarantee. Review and redact reports before sharing. Do not put APKs/XAPKs, OBBs, extracted data, keystores, credentials, or personal data in Git; `.gitignore` is a safeguard, not a guarantee.

## Limitations

- Static metadata, DEX strings, short names, magic bytes, and decompiled code are observations or heuristics, not proof of behavior, permissions in use, security, or compatibility. Obfuscation, encrypted strings, dynamically loaded DEX and native code can hide behavior; server availability cannot be proven from APK contents. Some data is intentionally capped or untested.
- Split dependency completeness, signer rotation, automatic split selection, and actual installation remain unverified by static checks; split rebuild stages may partially succeed. XAPK OBB placement validation supports only the documented manifest schema and does not verify OBB contents or installer behavior.
- ZIP 16 KiB alignment is not an ELF segment alignment or runtime compatibility check. Rebuilt or re-signed APKs may not install, update, or work. A launcher event does not establish application functionality.
- JADX's monitored output cap is best effort, not a sandbox or hard quota. Use a disposable isolated environment for untrusted code and tools; never run APKs on a production device.
- Reports may contain sensitive data. CRC and hashes do not authenticate an APK; signatures do not establish trust or application safety.

## Server limitations and testing

URLs, API references, models, and native code may suggest server dependencies, but do not provide private server code or data or prove availability or compatibility. APKLab does not automatically create a compatible game server. Do not contact production endpoints without permission.

Run automated tests with:

```sh
python3 -m unittest discover -s tests -v
```

Most tests use synthetic APK/DEX files and mocks for metadata, signing, and external-tool workflows; the native test also uses system `readelf` when available. An opt-in integration test uses real Java, `keytool`, `apktool`, `aapt`, `zipalign`, and `apksigner` with an authorized test APK. It creates a temporary test keystore, decodes, rebuilds, aligns, signs, and verifies a copy; it does not install or launch the APK unless the emulator option is set:

```sh
APKLAB_INTEGRATION_APK=/path/to/authorized-test.apk python3 -m unittest discover -s tests -p test_integration.py -v
```

Without `APKLAB_INTEGRATION_APK`, this test is skipped. When enabled, missing required tools cause failure. Set `APKLAB_TEST_16K=1`, `APKLAB_TEST_JADX=1`, or `APKLAB_TEST_SPLITS=1` to opt into the corresponding checks. The split option requires `ANDROID_HOME` with an installed platform `android.jar`; it generates and signs separate synthetic base and `config.en` APKs, checks their reported identities and runs the split workflow. This does not establish that the split set installs or works on a device. `APKLAB_EMULATOR_SERIAL=emulator-5554` additionally installs and launches the test APK on that emulator. When both this option and `APKLAB_TEST_SPLITS=1` are set, the test also attempts `install-multiple` for the generated signed split set without launching it. Only use a disposable, isolated emulator.

GitHub Actions is configured for cross-platform unit tests, real Android tools, and a disposable-emulator test using a checksum-pinned [public Androguard test APK](https://github.com/androguard/androguard/blob/0c0af30ca6bd55d3d34aa10d7f32593cd091a483/tests/data/APK/TestActivity.apk), which is not committed here. An earlier CI run exercised JADX, a 16 KiB ZIP-aligned native entry, a two-copy workflow, XAPK repacking, and installation and a launcher event on an API 30 emulator. The split integration fixture has since changed; consult the current workflow results before claiming the updated fixture passed. installing or launching a sample does not prove that another APK or game will work.

## License

APKLab is licensed under the [MIT License](LICENSE). The license permits reuse and modification under its terms and provides the software without warranty. It does not grant rights to third-party apps, assets, data, or tools.
