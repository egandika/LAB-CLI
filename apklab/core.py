"""Core helpers. APKs and their contents are untrusted input."""

from __future__ import annotations
from typing import Any, Optional, Union
from os import PathLike
import json
import contextlib
import functools
import zlib
import os
import re
import shutil
import subprocess
import threading
import time
import signal
import zipfile
from pathlib import Path
from .io_utils import DEFAULT_MAX_ARCHIVE_INPUT_BYTES, file_size_limited

MAX_ENTRY = 64 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
TOOLS = {
    "java": ["java"], "keytool": ["keytool"], "jadx": ["jadx"], "apktool": ["apktool"],
    "adb": ["adb"], "emulator": ["emulator"], "zipalign": ["zipalign"],
    "apksigner": ["apksigner"], "aapt": ["aapt"], "aapt2": ["aapt2"],
    "ghidra": ["ghidraRun", "ghidra"], "apkanalyzer": ["apkanalyzer"],
    "readelf": ["readelf", "llvm-readelf"], "strings": ["strings", "llvm-strings"],
}


def _windows():
    return os.name == 'nt'


def _build_tools_version(path):
    """Sort Android SDK versions numerically, with a final release after its previews."""
    name = path.name
    match = re.fullmatch(r'(\d+(?:\.\d+)*)(?:[-_](.+))?', name)
    if not match: return (0, (), 0, (), name.lower())
    numbers = tuple(int(n) for n in match.group(1).split('.'))
    numbers += (0,) * max(0, 4 - len(numbers))
    preview = match.group(2)
    # Tags are compared as alternating text/numeric chunks (rc10 follows rc2).
    chunks = tuple((1, int(part)) if part.isdigit() else (0, part.lower())
                   for part in re.findall(r'\d+|\D+', preview or ''))
    return (1, numbers, 1 if preview is None else 0, chunks, name.lower())


def _executable_names(item):
    if not _windows(): return [item]
    if os.path.splitext(item)[1]: return [item]
    return [item + ext for ext in ('.exe', '.bat', '.cmd')] + [item]


def find_tool(name: str) -> Optional[str]:
    names = TOOLS[name]
    # Explicit PATH choices take precedence over SDK fallback.
    for item in names:
        path = shutil.which(item)
        if path:
            return path
    roots = [os.environ.get("ANDROID_SDK_ROOT"), os.environ.get("ANDROID_HOME")]
    if _windows() and os.environ.get('LOCALAPPDATA'):
        roots.append(str(Path(os.environ['LOCALAPPDATA']) / 'Android/Sdk'))
    roots.append(str(Path.home() / "Android/Sdk"))
    for root in filter(None, roots):
        root = Path(root)
        candidates = [root / "platform-tools", root / "emulator", root / "cmdline-tools/latest/bin"]
        build = root / "build-tools"
        if build.is_dir():
            candidates.extend(sorted((p for p in build.iterdir() if p.is_dir()), key=_build_tools_version, reverse=True))
        for folder in candidates:
            for item in names:
                for executable in _executable_names(item):
                    path = folder / executable
                    if path.is_file() and os.access(path, os.X_OK):
                        return str(path)
    ghidra = os.environ.get("GHIDRA_HOME")
    if name == "ghidra" and ghidra:
        for executable in _executable_names('ghidraRun'):
            path = Path(ghidra) / executable
            if path.is_file() and os.access(path, os.X_OK):
                return str(path)
    return None


def _validate_windows_batch_args(args):
    """Fail closed for batch arguments that cmd.exe can interpret as syntax."""
    if args and os.path.splitext(str(args[0]))[1].lower() in ('.bat', '.cmd'):
        if any(any(ch in '&|<>()^%!"' or ord(ch) < 32 for ch in str(value)) for value in args):
            raise OSError('Unsafe Windows batch argument; shell metacharacters are not supported')


def run(args: Any, timeout: int=120, monitor: Any=None) -> dict:
    """Run a process with bounded capture and best-effort process-tree cleanup.

    monitor, when supplied, is called during execution and after termination;
    it may raise to abort the process. This is not a sandbox or a disk quota.
    """
    limits = {'stdout': 200000, 'stderr': 20000}
    buffers = {name: bytearray() for name in limits}
    truncated = {name: False for name in limits}
    process = None
    job = None
    threads = []
    timed_out = False
    error = None
    try:
        options = {}
        if os.name == 'nt':
            _validate_windows_batch_args(args)
            from .winjob import WindowsJob
            job = WindowsJob()
            options['creationflags'] = 0x00000004  # CREATE_SUSPENDED
        else:
            options['start_new_session'] = True
        process = subprocess.Popen([str(a) for a in args], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options)
        if job is not None:
            try: job.attach_and_resume(process)
            except BaseException:
                process.kill(); process.wait()
                raise
        def drain(name, stream):
            try:
                while True:
                    chunk = stream.read(8192)
                    if not chunk: break
                    room = max(0, limits[name] - len(buffers[name]))
                    buffers[name].extend(chunk[:room])
                    if len(chunk) > room: truncated[name] = True
            finally:
                stream.close()
        threads = [threading.Thread(target=drain, args=(name, getattr(process, name)), daemon=True) for name in limits]
        for thread in threads: thread.start()
        deadline = time.monotonic() + timeout
        while True:
            if monitor: monitor()
            if process.poll() is not None: break
            if time.monotonic() >= deadline:
                timed_out = True
                break
            time.sleep(min(0.01 if monitor else 0.05, max(0, deadline - time.monotonic())))
    except OSError as exc:
        error = str(exc)
    finally:
        if process is not None:
            if job is not None:
                job.close(); job = None
                if process.poll() is None:
                    process.kill()
            else:
                # The group can outlive its leader, so signal it even after leader exit.
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
            process.wait()
            if not threads:
                for stream in (process.stdout, process.stderr):
                    if stream is not None: stream.close()
        if job is not None: job.close()
        for thread in threads: thread.join(timeout=1)
    if monitor and not timed_out and error is None:
        monitor()  # Include output written just before descendants terminated.
    incomplete = any(thread.is_alive() for thread in threads)
    result = {name: bytes(buffers[name]).decode('utf-8', 'replace') for name in limits}
    result.update(returncode=None if timed_out or error or incomplete else process.returncode,
                  stdout_truncated=truncated['stdout'], stderr_truncated=truncated['stderr'],
                  capture_incomplete=incomplete)
    if timed_out: error = 'Process timed out after ' + str(timeout) + ' seconds'
    if incomplete: error = (error + '; ' if error else '') + 'Output streams did not close after process cleanup'
    if error: result['stderr'] += ('\n' if result['stderr'] else '') + error
    return result


def report() -> dict:
    return {"verified": [], "inferences": [], "failures": [], "not_tested": []}


class PartialReportError(Exception):
    """An operation failed after collecting report entries."""
    def __init__(self, partial_report, original):
        super().__init__(str(original))
        self.report = partial_report
        self.original = original


@contextlib.contextmanager
def preserve_report(partial_report: Any) -> Any:
    try:
        yield
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, NotImplementedError, EOFError, zlib.error) as exc:
        raise PartialReportError(partial_report, exc) from exc


def reported(func: Any) -> Any:
    """Preserve report entries when a command fails after recording progress."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        partial = report()
        with preserve_report(partial):
            return func(*args, _report=partial, **kwargs)
    return wrapper


def add(r: Any, category: str, subject: str, detail: str) -> None:
    r[category].append({"subject": subject, "detail": detail})


def redact_report(value: Any) -> Any:
    """Best-effort recursive report redaction, not a security guarantee."""
    sensitive_key = re.compile(r'(?i)(?:password|passwd|secret|token|api[_-]?key|authorization|credential)')
    def clean(text):
        home = str(Path.home())
        if len(home) > 2:
            text = re.sub(re.escape(home), '[HOME]', text, flags=re.IGNORECASE if _windows() else 0)
        text = re.sub(r'(?i)\b[A-Z]:[\\/]Users[\\/][^\\/\s"\']+', '[HOME]', text)
        text = re.sub(r'(?i)\b(?:https?|wss?|ftp)://[^\s<>"\']+', '[URL]', text)
        text = re.sub(r'(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]+', r'\1[REDACTED]', text)
        text = re.sub(r'(?i)\b(password|passwd|secret|token|api[_-]?key|authorization|credential)(\s*[:=]\s*)([^\s,;]+)', r'\1\2[REDACTED]', text)
        return re.sub(r'(?<![A-Za-z0-9])[A-Za-z0-9_+/=-]{32,}(?![A-Za-z0-9])', '[REDACTED]', text)
    if isinstance(value, str): return clean(value)
    if isinstance(value, list): return [redact_report(item) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            safe_key = clean(key) if isinstance(key, str) else key
            base = safe_key; n = 2
            while safe_key in result:
                safe_key = str(base) + ' #' + str(n); n += 1
            result[safe_key] = '[REDACTED]' if isinstance(key, str) and sensitive_key.search(key) else redact_report(item)
        return result
    return value


def emit(r: Any, output: Optional[Union[str, PathLike]]=None, summary: bool=False, redact: bool=False) -> None:
    if redact: r = redact_report(r)
    # Escape isolated UTF-16 surrogates that valid DEX MUTF-8 can contain.
    text = json.dumps(r, indent=2, ensure_ascii=False).encode('utf-8', 'backslashreplace').decode('utf-8')
    if output:
        p = Path(output)
        # Reports must not clobber an existing file, including an input APK.
        with p.open("x", encoding="utf-8") as f:
            f.write(text + "\n")
    if summary:
        print('Summary: {} reported checks ran ({} verified, {} failed); {} not tested; {} inferences.'.format(
            len(r['verified']) + len(r['failures']), len(r['verified']), len(r['failures']),
            len(r['not_tested']), len(r['inferences'])))
        for item in r['not_tested']:
            print('  Not tested: {} - {}'.format(item['subject'], item['detail']))
        print('JSON report:')
    print(text)


def zip_infos(z: Any, max_entry: int=MAX_ENTRY, max_total: int=MAX_TOTAL) -> list:
    if max_entry < 1 or max_total < 1:
        raise ValueError('ZIP size limits must be positive')
    infos = z.infolist()
    if len(infos) > 100000:
        raise ValueError("ZIP exceeds entry count or total uncompressed size limit: entry count {} exceeds limit 100000".format(len(infos)))
    total = sum(i.file_size for i in infos)
    if total > max_total:
        raise ValueError("ZIP exceeds entry count or total uncompressed size limit: declared total {} bytes exceeds limit {} bytes".format(total, max_total))
    largest = max((i.file_size for i in infos), default=0)
    if largest > max_entry:
        raise ValueError("ZIP entry exceeds uncompressed size limit: largest declared entry {} bytes exceeds limit {} bytes".format(largest, max_entry))
    return infos


def check_zip_crc(z: Any, infos: Any) -> Optional[str]:
    """Read each central-directory entry by identity, including duplicate names."""
    for info in infos:
        if info.is_dir():
            continue
        try:
            with z.open(info) as entry:
                while entry.read(1024 * 1024):
                    pass
        except (zipfile.BadZipFile, zlib.error):
            # CRC mismatches and malformed deflate streams are both failures for this entry.
            return info.filename
    return None


def validate_apk_archive(path: Union[str, PathLike], z: Any, max_entry: int=MAX_ENTRY, max_total: int=MAX_TOTAL) -> list:
    """Validate basic APK ZIP structure and CRCs, not signatures or manifest contents."""
    if Path(path).suffix.lower() == '.xapk':
        raise ValueError('XAPK is an archive, not an APK; use apklab xapk inspect or unpack')
    infos = zip_infos(z, max_entry, max_total)
    manifests = [info for info in infos if info.filename == 'AndroidManifest.xml' and not info.is_dir()]
    if len(manifests) != 1:
        raise ValueError('APK must contain exactly one AndroidManifest.xml')
    bad = check_zip_crc(z, infos)
    if bad: raise ValueError('ZIP CRC/decompression failure: ' + bad)
    return infos


def inspect_one(path: Union[str, PathLike], r: Any, max_entry: int=MAX_ENTRY,
                max_total: int=MAX_TOTAL,
                max_archive_bytes: int=DEFAULT_MAX_ARCHIVE_INPUT_BYTES) -> dict:
    path = Path(path)
    item = {"file": str(path), "package": None, "version_name": None, "version_code": None, "architectures": [], "signer_sha256": None}
    if path.suffix.lower() == '.xapk':
        add(r, "failures", str(path), "XAPK is an archive, not an APK; use apklab xapk inspect or unpack")
        return item
    try:
        item['archive_input_bytes'] = file_size_limited(
            path, max_archive_bytes, 'APK archive input')
        item['archive_limit_bytes'] = max_archive_bytes
        with zipfile.ZipFile(path) as z:
            infos = validate_apk_archive(path, z, max_entry, max_total)
            add(r, "verified", str(path), "ZIP entries passed CRC checks")
            names = [i.filename for i in infos]
            item["architectures"] = sorted({n.split('/')[1] for n in names if n.startswith('lib/') and len(n.split('/')) >= 3})
            item["entries"] = len(names)
    except (OSError, zipfile.BadZipFile, ValueError, RuntimeError, NotImplementedError) as e:
        add(r, "failures", str(path), "ZIP inspection: " + str(e))
        return item
    tool = find_tool("aapt")
    if tool:
        result = run([tool, "dump", "badging", path])
        if result["returncode"] == 0:
            lines = result["stdout"].splitlines(keepends=True)
            line = next((line for line in lines if line.startswith('package:')), '')
            incomplete = bool(result.get('stdout_truncated') and line and not line.endswith(('\n', '\r')))
            attrs = dict(re.findall(r"([\w]+)='([^']*)'", line)) if not incomplete else {}
            if attrs.get('name') and attrs.get('versionCode'):
                item.update(package=attrs['name'], version_code=attrs['versionCode'], version_name=attrs.get('versionName'), split=attrs.get('split'))
                add(r, "verified", str(path), "Package and version code read with aapt")
            elif result.get('stdout_truncated'):
                add(r, "not_tested", str(path), "aapt package metadata unavailable in truncated output")
            else:
                add(r, "failures", str(path), "aapt returned no parseable package metadata")
        else:
            add(r, "failures", str(path), "aapt: " + result["stderr"][:1000])
    else:
        from .axml import read_manifest
        try:
            manifest = read_manifest(str(path))
            item.update(package=manifest['package'], version_code=manifest['version_code'], version_name=manifest['version_name'])
            item['manifest'] = manifest
            item['metadata_source'] = 'internal_axml'
            add(r, "inferences", str(path), "Selected literal metadata read by internal AXML parser; not aapt verification")
            add(r, "not_tested", str(path), "aapt metadata and resource resolution unavailable; internal parser is partial")
        except (ValueError, KeyError, OSError, zipfile.BadZipFile, RuntimeError) as exc:
            add(r, "not_tested", str(path), "Package/version: aapt unavailable and internal AXML parser could not decode manifest: " + str(exc))
    signer = find_tool("apksigner")
    if signer:
        result = run([signer, "verify", "--verbose", "--print-certs", path])
        if result["returncode"] == 0:
            matches = re.findall(r'^Signer #(\d+) certificate SHA-256 digest:\s*([0-9a-fA-F:]+)\s*$', result['stdout'], re.MULTILINE)
            declared = re.search(r'^Number of signers:\s*(\d+)\s*$', result['stdout'], re.MULTILINE)
            numbers = [int(number) for number, _ in matches]
            digests = [digest for _, digest in matches]
            if (digests and not result.get('stdout_truncated') and not result.get('capture_incomplete')
                    and sorted(numbers) == list(range(1, len(numbers) + 1))
                    and (not declared or int(declared.group(1)) == len(numbers))
                    and all(len(d.replace(':', '')) == 64 for d in digests)):
                item['signer_sha256'] = sorted({d.replace(':', '').lower() for d in digests})
            add(r, "verified", str(path), "apksigner verification passed: " + result["stdout"][:4000])
            if item['signer_sha256'] is None:
                add(r, "not_tested", str(path), "Signer certificate digest could not be parsed completely")
        else:
            add(r, "failures", str(path), "apksigner verification failed: " + (result["stderr"] or result["stdout"])[:2000])
    else:
        add(r, "not_tested", str(path), "Signature verification: apksigner not found")
    return item
