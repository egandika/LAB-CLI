"""Non-executing, cross-platform tool setup guidance."""

from __future__ import annotations
from typing import Any, Callable, Optional

SOURCES = {
    'apktool': ('https://apktool.org/docs/install/', 'Download the official wrapper and versioned JAR; compare the JAR SHA-256 with an upstream published digest when available.'),
    'build-tools': ('https://developer.android.com/studio#command-line-tools-only', 'Download SDK command-line tools for your OS and compare SHA-256 against the digest on the download page; use sdkmanager to install build-tools and platform-tools.'),
    'jadx': ('https://github.com/skylot/jadx/releases', 'Download a versioned release ZIP; compare SHA-256 to the GitHub release asset digest or upstream checksum, if published.'),
    'java': ('https://adoptium.net/temurin/releases/', 'Download a supported JDK and verify the upstream checksum/signature.'),
    'ghidra': ('https://github.com/NationalSecurityAgency/ghidra/releases', 'Download a release and compare its SHA-256 to the upstream release digest.'),
    'platform-tools': ('https://developer.android.com/tools/releases/platform-tools', 'Review the official platform-tools package for adb and its published checksum.'),
    'emulator': ('https://developer.android.com/studio/run/emulator', 'Review Android Emulator, system image and host requirements; installation and launch require separate approval.'),
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


def plan() -> dict:
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


# These are guidance profiles, not guarantees that tools or APKs will work.
GOALS = {
    'basic': {
        'description': 'Basic APK inspection using internal parsing',
        'required': (), 'optional': ('aapt', 'apksigner'),
        'notes': ['Internal manifest parsing is partial; external metadata and signature checks are separate.'],
    },
    'jadx': {
        'description': 'JADX decompilation for analysis',
        'required': ('java', 'jadx'), 'optional': (),
        'notes': ['Check the chosen JADX release and its Java requirements; decompilation can be incomplete.'],
    },
    'decode': {
        'description': 'Decode and build with apktool',
        'required': ('java', 'apktool'), 'optional': (),
        'notes': ['Check apktool Java requirements and frameworks; successful decoding does not guarantee a rebuild.'],
    },
    'rebuild': {
        'description': 'Decode, build, align, sign and verify',
        'required': ('java', 'apktool', 'zipalign', 'apksigner'),
        'optional': ('aapt', 'readelf'),
        'notes': ['Signing also requires an authorized keystore, alias and password supplied securely; do not commit them.',
                  '16 KiB ZIP alignment support must be checked separately; ELF alignment and runtime compatibility are different checks.'],
    },
    'verify': {
        'description': 'Verify ZIP alignment and APK signature',
        'required': ('zipalign', 'apksigner', 'java'), 'optional': ('readelf',),
        'notes': ['Check 16 KiB ZIP support separately; signature verification does not establish publisher identity or runtime compatibility.'],
    },
    'device': {
        'description': 'Install on an authorized disposable emulator',
        'required': ('adb', 'aapt', 'apksigner', 'java'), 'optional': ('emulator',),
        'notes': ['An already running, isolated single-user emulator is required; the emulator executable may be on another host.',
                  'An emulator, system image, SDK licenses, installation and launching APKs each need separate review and permission.'],
    },
}

TOOL_SOURCES = {
    'java': 'java', 'apktool': 'apktool', 'jadx': 'jadx',
    'zipalign': 'build-tools', 'apksigner': 'build-tools', 'aapt': 'build-tools',
    'adb': 'platform-tools', 'emulator': 'emulator', 'readelf': 'binutils',
}


def goal_plan(goal: str, find_tool: Callable[[str], Optional[str]]) -> dict:
    """Discover relevant executables only; never run them or perform installation."""
    profile = GOALS[goal]
    tools = []
    for category in ('required', 'optional'):
        for name in profile[category]:
            source = TOOL_SOURCES[name]
            tools.append({'name': name, 'category': category, 'path': find_tool(name),
                          'source': source, 'source_url': SOURCES[source][0]})
    return {
        'goal': goal, 'description': profile['description'], 'tools': tools,
        'notes': list(profile['notes']),
        'limitations': [
            'Executable discovery is presence only; versions, compatibility and functionality are not verified.',
            'No version, installation source, destination or package size is selected; review these before any installation.',
            'Android SDK licenses must be reviewed and accepted by the user, not automatically.',
            'This plan does not download, install, execute tools, access a device or run APKs.',
        ],
    }
