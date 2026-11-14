"""Non-executing, cross-platform tool setup guidance."""

SOURCES = {
    'apktool': ('https://apktool.org/docs/install/', 'Download the official wrapper and versioned JAR; compare the JAR SHA-256 with an upstream published digest when available.'),
    'build-tools': ('https://developer.android.com/studio#command-line-tools-only', 'Download SDK command-line tools for your OS and compare SHA-256 against the digest on the download page; use sdkmanager to install build-tools and platform-tools.'),
    'jadx': ('https://github.com/skylot/jadx/releases', 'Download a versioned release ZIP; compare SHA-256 to the GitHub release asset digest or upstream checksum, if published.'),
    'java': ('https://adoptium.net/temurin/releases/', 'Download a supported JDK and verify the upstream checksum/signature.'),
    'ghidra': ('https://github.com/NationalSecurityAgency/ghidra/releases', 'Download a release and compare its SHA-256 to the upstream release digest.'),
    'binutils': ('https://www.gnu.org/software/binutils/', 'Use a trusted OS package manager and verify its package signatures.'),
}

NEXT = {
    'java': 'Review JDK guidance: apklab setup --plan', 'keytool': 'Install a JDK after reviewing: apklab setup --plan',
    'apktool': 'Review apktool guidance: apklab setup --plan', 'jadx': 'Review JADX guidance: apklab setup --plan',
    'aapt': 'Review Android build-tools guidance: apklab setup --plan', 'aapt2': 'Review Android build-tools guidance: apklab setup --plan',
    'apksigner': 'Review Android build-tools guidance: apklab setup --plan', 'zipalign': 'Review Android build-tools guidance: apklab setup --plan',
    'adb': 'Review Android platform-tools guidance: apklab setup --plan', 'emulator': 'Review SDK emulator guidance: apklab setup --plan',
    'apkanalyzer': 'Review SDK command-line tools guidance: apklab setup --plan', 'ghidra': 'Review Ghidra guidance: apklab setup --plan',
    'readelf': 'Review binutils guidance: apklab setup --plan', 'strings': 'Review binutils guidance: apklab setup --plan',
}


def plan():
    return {
        'sources': {k: {'url': url, 'instructions': instructions} for k, (url, instructions) in SOURCES.items()},
        'checksum': 'For SHA-256, compare sha256sum FILE (Linux/Termux) or shasum -a 256 FILE (macOS) to a digest obtained independently from the official release page. If no digest/signature is published, integrity is not verified.',
        'platforms': {
            'debian_ubuntu': 'Review APT sources and package versions; optional apklab setup --install uses APT only.',
            'termux_android': 'Review Termux packages with pkg search; pkg install openjdk binutils where available. Android SDK desktop binaries and emulator may not run on Android/Termux; use a supported host or compatible builds and verify separately.',
            'other_linux': 'For Fedora, Arch, and other distributions, inspect the distribution package manager and trusted repositories; package names vary. Official upstream archives are an alternative; no installation is performed by this plan.',
            'windows': 'Review the official Windows JDK, Android SDK and tool archives; verify upstream digests and configure PATH manually.',
            'macos': 'Use official macOS archives above or review Homebrew packages (brew search apktool jadx); verify package provenance. Install SDK command-line tools for macOS.',
        },
        'sdk_commands': ['sdkmanager --list', 'sdkmanager "platform-tools" "build-tools;35.0.0"'],
        'note': 'No downloads or installations are performed by --plan. Review licenses, versions and checksums before installation.',
    }
