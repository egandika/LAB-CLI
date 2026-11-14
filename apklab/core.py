"""Core helpers. APKs and their contents are untrusted input."""
import json
import os
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

MAX_ENTRY = 64 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
TOOLS = {
    "java": ["java"], "keytool": ["keytool"], "jadx": ["jadx"], "apktool": ["apktool"],
    "adb": ["adb"], "emulator": ["emulator"], "zipalign": ["zipalign"],
    "apksigner": ["apksigner"], "aapt": ["aapt"], "aapt2": ["aapt2"],
    "ghidra": ["ghidraRun", "ghidra"], "apkanalyzer": ["apkanalyzer"],
    "readelf": ["readelf", "llvm-readelf"], "strings": ["strings", "llvm-strings"],
}


def find_tool(name):
    names = TOOLS[name]
    for item in names:
        path = shutil.which(item)
        if path:
            return path
    roots = [os.environ.get("ANDROID_SDK_ROOT"), os.environ.get("ANDROID_HOME"), str(Path.home() / "Android/Sdk")]
    for root in filter(None, roots):
        root = Path(root)
        candidates = [root / "platform-tools", root / "emulator", root / "cmdline-tools/latest/bin"]
        build = root / "build-tools"
        if build.is_dir():
            candidates.extend(sorted((p for p in build.iterdir() if p.is_dir()), reverse=True))
        for folder in candidates:
            for item in names:
                path = folder / item
                if path.is_file() and os.access(path, os.X_OK):
                    return str(path)
    ghidra = os.environ.get("GHIDRA_HOME")
    if name == "ghidra" and ghidra:
        path = Path(ghidra) / "ghidraRun"
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return None


def run(args, timeout=120):
    try:
        result = subprocess.run([str(a) for a in args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, errors="replace", timeout=timeout, check=False)
        return {"returncode": result.returncode, "stdout": result.stdout[:200000], "stderr": result.stderr[:20000]}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"returncode": None, "stdout": "", "stderr": str(e)}


def report():
    return {"verified": [], "inferences": [], "failures": [], "not_tested": []}


def add(r, category, subject, detail):
    r[category].append({"subject": subject, "detail": detail})


def emit(r, output=None):
    text = json.dumps(r, indent=2, ensure_ascii=False)
    if output:
        p = Path(output)
        # Reports must not clobber an existing file, including an input APK.
        with p.open("x", encoding="utf-8") as f:
            f.write(text + "\n")
    print(text)


def zip_infos(z, max_entry=MAX_ENTRY, max_total=MAX_TOTAL):
    if max_entry < 1 or max_total < 1:
        raise ValueError('ZIP size limits must be positive')
    infos = z.infolist()
    if len(infos) > 100000 or sum(i.file_size for i in infos) > max_total:
        raise ValueError("ZIP exceeds entry count or total uncompressed size limit")
    if any(i.file_size > max_entry for i in infos):
        raise ValueError("ZIP entry exceeds uncompressed size limit")
    return infos


def inspect_one(path, r, max_entry=MAX_ENTRY, max_total=MAX_TOTAL):
    path = Path(path)
    item = {"file": str(path), "package": None, "version_name": None, "version_code": None, "architectures": [], "signer_sha256": None}
    if path.suffix.lower() == '.xapk':
        add(r, "failures", str(path), "XAPK is an archive, not an APK; use apklab xapk inspect or unpack")
        return item
    try:
        with zipfile.ZipFile(path) as z:
            infos = zip_infos(z, max_entry, max_total)
            bad = z.testzip()
            if bad:
                add(r, "failures", str(path), "ZIP CRC failure: " + bad)
            else:
                add(r, "verified", str(path), "ZIP entries passed CRC checks")
            names = [i.filename for i in infos]
            item["architectures"] = sorted({n.split('/')[1] for n in names if n.startswith('lib/') and len(n.split('/')) >= 3})
            item["entries"] = len(names)
            if "AndroidManifest.xml" not in names:
                add(r, "failures", str(path), "AndroidManifest.xml missing; not a standard APK")
    except (OSError, zipfile.BadZipFile, ValueError, RuntimeError, NotImplementedError) as e:
        add(r, "failures", str(path), "ZIP inspection: " + str(e))
        return item
    tool = find_tool("aapt")
    if tool:
        result = run([tool, "dump", "badging", path])
        if result["returncode"] == 0:
            line = next((line for line in result["stdout"].splitlines() if line.startswith('package:')), '')
            attrs = dict(re.findall(r"([\w]+)='([^']*)'", line))
            if attrs.get('name') and attrs.get('versionCode'):
                item.update(package=attrs['name'], version_code=attrs['versionCode'], version_name=attrs.get('versionName'), split=attrs.get('split'))
                add(r, "verified", str(path), "Package and version code read with aapt")
            else:
                add(r, "failures", str(path), "aapt returned no parseable package metadata")
        else:
            add(r, "failures", str(path), "aapt: " + result["stderr"][:1000])
    else:
        add(r, "not_tested", str(path), "Package/version: aapt not found; binary manifest was not decoded")
    signer = find_tool("apksigner")
    if signer:
        result = run([signer, "verify", "--verbose", "--print-certs", path])
        if result["returncode"] == 0:
            digests = re.findall(r'^Signer #\d+ certificate SHA-256 digest:\s*([0-9a-fA-F:]+)\s*$', result['stdout'], re.MULTILINE)
            if digests and all(len(d.replace(':', '')) == 64 for d in digests):
                item['signer_sha256'] = sorted({d.replace(':', '').lower() for d in digests})
            add(r, "verified", str(path), "apksigner verification passed: " + result["stdout"][:4000])
            if item['signer_sha256'] is None:
                add(r, "not_tested", str(path), "Signer certificate digest could not be parsed")
        else:
            add(r, "failures", str(path), "apksigner verification failed: " + (result["stderr"] or result["stdout"])[:2000])
    else:
        add(r, "not_tested", str(path), "Signature verification: apksigner not found")
    return item
