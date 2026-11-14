import argparse
import os
import re
import sys
import zipfile
import zlib
from pathlib import Path
from . import __version__
from .core import TOOLS, PartialReportError, add, emit, find_tool, inspect_one, reported, report, run, validate_apk_archive, zip_infos
from .dex import read_dex
from .workflow import init, perform, workspace_input, supports_16k
from .xapk import MIB, examine as examine_xapk, unpack as unpack_xapk, repack as repack_xapk, repack_directory, manifest_info
from .device import install_test
from .splits import init_set, read_set
from .setup_plan import plan as setup_guidance, NEXT
from .jadx import decompile
from .analysis import parse_xmltree, candidates, magic_type


VERSION_ARGS = {
    'java': ['-version'], 'keytool': ['-help'], 'jadx': ['--version'],
    'apktool': ['--version'], 'adb': ['version'], 'emulator': ['-version'],
    'apksigner': ['version'], 'aapt': ['version'], 'aapt2': ['version'],
    'readelf': ['--version'], 'strings': ['--version'],
}


def doctor(args):
    r = report()
    r['tools'] = {}
    if args.check: r['probes'] = {}
    for name in TOOLS:
        path = find_tool(name)
        r['tools'][name] = path
        if path:
            add(r, 'verified', name, 'Executable found: ' + path + ' (presence only)')
            if args.check and name in VERSION_ARGS:
                result = run([path] + VERSION_ARGS[name], timeout=10)
                r['probes'][name] = {'returncode': result['returncode'], 'output': (result['stdout'] or result['stderr'])[:2000]}
                if result['returncode'] == 0:
                    add(r, 'verified', name, 'Version/help probe exited successfully; full functionality is not verified')
                else:
                    add(r, 'not_tested', name, 'Version/help probe did not succeed; inspect probes for details')
            elif args.check:
                add(r, 'not_tested', name, 'No safe version probe configured')
        else: add(r, 'not_tested', name, 'Not found. ' + NEXT[name])
    sdk = os.environ.get('ANDROID_SDK_ROOT') or os.environ.get('ANDROID_HOME')
    if not sdk and (Path.home() / 'Android/Sdk').is_dir(): sdk = str(Path.home() / 'Android/Sdk')
    r['android_sdk'] = sdk
    if sdk and Path(sdk).is_dir(): add(r, 'verified', 'Android SDK', 'Directory exists: ' + sdk)
    else: add(r, 'not_tested', 'Android SDK', 'SDK directory not found')
    add(r, 'not_tested', 'tool functionality', 'A presence or version/help probe does not verify complete functionality')
    return r


def setup(args):
    r = report()
    packages = {'java': 'default-jre-headless', 'apktool': 'apktool', 'adb': 'adb', 'aapt': 'aapt', 'zipalign': 'zipalign', 'apksigner': 'apksigner'}
    r['plan'] = setup_guidance()
    r['plan']['apt_packages'] = packages
    if not args.install:
        add(r, 'not_tested', 'installation', 'Plan only. Run setup --install to attempt missing packages via APT; system configuration will change.')
        return r
    apt = find_executable('apt-get')
    if not apt:
        add(r, 'failures', 'setup', 'apt-get not available; install tools manually')
        return r
    prefix = []
    if os.geteuid() != 0:
        sudo = find_executable('sudo')
        if not sudo or run([sudo, '-n', 'true'])['returncode'] != 0:
            add(r, 'failures', 'setup', 'Root or passwordless sudo required; no password requested')
            return r
        prefix = [sudo, '-n']
    missing = {tool: pkg for tool, pkg in packages.items() if not find_tool(tool)}
    if missing:
        res = run(prefix + [apt, '-o', 'APT::Update::Error-Mode=any', '-o', 'Acquire::Retries=0', '-o', 'Acquire::http::Timeout=10', '-o', 'Acquire::https::Timeout=10', 'update'], timeout=180)
        if res['returncode'] != 0:
            add(r, 'failures', 'apt update', (res['stderr'] or res['stdout'])[-3000:])
        for tool, pkg in missing.items():
            res = run(prefix + [apt, '-y', '-o', 'Acquire::Retries=0', '-o', 'Acquire::http::Timeout=10', '-o', 'Acquire::https::Timeout=10', 'install', pkg], timeout=180)
            found = find_tool(tool)
            if res['returncode'] == 0 and found:
                add(r, 'verified', tool, 'APT installed; executable found: ' + found)
            else:
                add(r, 'failures', tool, 'Install/verification failed: ' + (res['stderr'] or res['stdout'])[-1500:])
    for tool in packages:
        if tool not in missing: add(r, 'verified', tool, 'Already present: ' + find_tool(tool))
    add(r, 'not_tested', 'manual tools', 'JADX, SDK, emulator and Ghidra are not installed by this command; see README')
    return r


def find_executable(name):
    import shutil
    return shutil.which(name)


def apk_paths(inputs, recursive=False):
    paths = []
    for name in inputs:
        p = Path(name)
        if p.is_dir():
            paths.extend(sorted(x for x in (p.rglob('*') if recursive else p.iterdir()) if x.is_file() and x.suffix.lower() == '.apk'))
        else: paths.append(p)
    if not paths: raise ValueError('No APK files found')
    return paths


@reported
def inspect(args, _report):
    r = _report
    r['apks'] = []
    for p in apk_paths(args.apks, args.recursive):
        r['apks'].append(inspect_one(p, r, args.max_entry_mib * MIB, args.max_total_mib * MIB))
    if len(r['apks']) > 1:
        for field, label in [('package', 'package names'), ('version_code', 'version codes'), ('signer_sha256', 'signer certificate digest sets')]:
            values = [tuple(a[field]) if field == 'signer_sha256' and a[field] else a[field] for a in r['apks']]
            known = {v for v in values if v}
            if len(known) > 1:
                add(r, 'failures', 'split set', 'Different ' + label + ' found')
            elif len(known) == 1 and all(values):
                add(r, 'verified', 'split set', 'Matching ' + label + ' across all inspected APKs')
            else:
                add(r, 'not_tested', 'split set', 'Cannot compare ' + label + ' for every APK')
        split_names = [a.get('split') for a in r['apks'] if a.get('split')]
        if all(a.get('package') for a in r['apks']):
            bases = [a['file'] for a in r['apks'] if a.get('split') is None]
            r['split_candidates'] = {'base': bases, 'named_splits': {a['file']: a['split'] for a in r['apks'] if a.get('split')}}
            add(r, 'inferences', 'base candidates', str(len(bases)) + ' APK(s) have no split name in aapt output; base identity and completeness require independent validation')
        if len(split_names) != len(set(split_names)):
            add(r, 'failures', 'split set', 'Duplicate non-empty split names found in aapt metadata')
        if not all(a.get('package') for a in r['apks']):
            add(r, 'not_tested', 'split names', 'Metadata unavailable for one or more APKs')
        add(r, 'not_tested', 'split set', 'Completeness, split dependencies, signer rotation compatibility and installation not verified')
    if args.device_abi:
        present = sorted({abi for apk in r['apks'] for abi in apk['architectures']})
        r['abi_observation'] = {'requested': args.device_abi, 'native_directories': present}
        if args.device_abi in present:
            add(r, 'verified', 'ABI directories', 'Requested ABI appears in at least one inspected APK')
        elif present:
            add(r, 'inferences', 'ABI directories', 'Requested ABI not observed; this alone does not prove incompatibility')
        else:
            add(r, 'not_tested', 'ABI directories', 'No native library directories observed')
        add(r, 'not_tested', 'device compatibility', 'ABI directory names do not verify native code or device compatibility')
    return r


@reported
def xapk(args, _report):
    from .publish import publish_new, staging
    r = _report
    entry, total = args.max_entry_mib * MIB, args.max_total_mib * MIB

    def describe(entries, manifest_path, manifest_directory=False):
        r['entries'] = entries
        if not any(i['kind'] == 'apk' for i in entries):
            add(r, 'failures', 'XAPK', 'No APK entries found')
        manifest = manifest_info(manifest_path, entries, directory=manifest_directory)
        r['manifest'] = manifest
        if manifest['status'] == 'parsed':
            add(r, 'verified', 'XAPK manifest', 'Compared split_apks file references against archive entry names')
            if manifest['missing_apks'] or manifest['duplicate_references']:
                add(r, 'failures', 'XAPK manifest', 'Referenced APKs missing or duplicated: see manifest details')
            if manifest['undeclared_apks']:
                add(r, 'inferences', 'XAPK manifest', 'Archive has APKs not listed in split_apks; their role is unknown')
        elif manifest['status'] == 'invalid':
            add(r, 'failures', 'XAPK manifest', manifest['reason'])
        else:
            add(r, 'not_tested', 'XAPK manifest', 'No supported split_apks list: ' + manifest.get('reason', manifest['status']))
        add(r, 'not_tested', 'contained APKs', 'APK metadata, signatures and split compatibility are not checked here; run inspect on extracted APKs')
        add(r, 'not_tested', 'XAPK layout', 'Manifest completeness, OBB compatibility and installation are not validated')

    if args.action == 'inspect':
        entries = examine_xapk(args.archive, entry, total, args.verify)
        add(r, 'verified', 'XAPK', 'Archive directory and paths checked against safety limits')
        if args.verify:
            add(r, 'verified', 'XAPK', 'All file entries decompressed and CRC-checked; SHA-256 hashes recorded')
        else:
            add(r, 'not_tested', 'XAPK CRC', 'Use --verify to read and CRC-check all file entries')
        describe(entries, args.archive)
        return r

    destination = Path(args.destination)
    if os.path.lexists(destination): raise FileExistsError('Output already exists: ' + str(destination))
    with staging(destination) as staged:
        if args.action == 'unpack':
            entries = unpack_xapk(args.archive, staged, entry, total)
            describe(entries, staged, manifest_directory=True)
            if r['failures']: return r
            publish_new(staged, destination, directory=True)
            add(r, 'verified', 'XAPK', 'Entries copied to a new directory with CRC checks and SHA-256 hashes')
        else:
            replacements = {}
            for value in args.replace:
                name, sep, replacement = value.partition('=')
                if not sep or not name or not replacement or name in replacements:
                    raise ValueError('Each --replace must be a unique ENTRY=FILE pair')
                replacements[name] = replacement
            entries = (repack_directory(args.archive, staged, replacements, entry, total)
                       if args.directory else repack_xapk(args.archive, staged, replacements, entry, total))
            describe(entries, staged / 'repacked.xapk' if args.directory else staged)
            if r['failures']: return r
            publish_new(staged, destination, directory=args.directory)
            add(r, 'verified', 'XAPK', 'Copied validated ZIP entries to a new archive; replacement APK ZIP CRCs were checked')
            if args.directory:
                add(r, 'verified', 'OBB placement', 'Copied OBB files to paths checked against supported manifest expansions and package name')
            add(r, 'not_tested', 'repacked XAPK', 'Signatures, manifest sizes, OBB compatibility, installer support and runtime behavior were not verified')
        r['destination'] = str(destination.resolve())
    return r


@reported
def inventory(args, _report):
    r = _report
    r['files'] = []
    with zipfile.ZipFile(args.apk) as z:
        infos = validate_apk_archive(args.apk, z, args.max_entry_mib * MIB, args.max_total_mib * MIB)
        matches = []
        for info in infos:
            n = info.filename
            category = 'native' if n.startswith('lib/') and n.endswith('.so') else 'asset' if n.startswith(('assets/', 'res/')) else None
            if category and (not args.search or args.search.lower() in n.lower()):
                matches.append(info)
                r['files'].append({'path': n, 'size': info.file_size, 'category': category})
        add(r, 'verified', 'inventory', 'Indexed matching ZIP entry names and sizes')
        import hashlib
        for info, item in zip(matches, r['files']):
            if info.is_dir(): continue
            with z.open(info) as src:
                prefix = src.read(16)
                item['magic_type'] = magic_type(prefix)
                if args.hash:
                    digest = hashlib.sha256(prefix)
                    for chunk in iter(lambda: src.read(1024 * 1024), b''): digest.update(chunk)
                    item['sha256'] = digest.hexdigest()
        add(r, 'inferences', 'file types', 'Magic-byte types are hints, not validation of file format')
        if args.hash: add(r, 'verified', 'inventory hashes', 'SHA-256 computed and ZIP CRC checked for matching files')
        else: add(r, 'not_tested', 'inventory hashes', 'Use --hash to compute SHA-256 for matching entries')
        if args.text:
            r['content_matches'] = []
            skipped = 0; scanned = 0; total_read = 0
            for info, item in zip(matches, r['files']):
                if item['category'] != 'asset' or info.is_dir(): continue
                if info.file_size > MIB or total_read + info.file_size > 32 * MIB:
                    skipped += 1; continue
                data = z.read(info); total_read += len(data)
                if b'\x00' in data:
                    skipped += 1; continue
                try: text = data.decode('utf-8')
                except UnicodeDecodeError:
                    skipped += 1; continue
                scanned += 1
                for number, line in enumerate(text.splitlines(), 1):
                    if args.text.casefold() in line.casefold():
                        r['content_matches'].append({'path': info.filename, 'line': number, 'excerpt': line[:240]})
                        if len(r['content_matches']) >= 200: break
                if len(r['content_matches']) >= 200: break
            add(r, 'verified', 'asset text search', 'Searched ' + str(scanned) + ' UTF-8 entries, capped at 200 results')
            add(r, 'not_tested', 'asset text search', 'Binary, large, unsupported, and remaining entries may be skipped; ' + str(skipped) + ' explicitly skipped')
        if args.native_details or args.native_symbols:
            import tempfile
            tool = find_tool('readelf')
            if not tool: add(r, 'not_tested', 'native details', 'readelf not found')
            else:
                import shutil
                for info, item in zip(matches, r['files']):
                    if item['category'] != 'native': continue
                    with tempfile.TemporaryDirectory(prefix='apklab-native-') as tmp:
                        native = Path(tmp) / 'library.so'
                        with z.open(info) as source, native.open('xb') as output:
                            shutil.copyfileobj(source, output, length=1024 * 1024)
                        for label, flags in ([('readelf', ['-h', '-d'])] if args.native_details else []) + ([('symbols', ['-W', '-s'])] if args.native_symbols else []):
                            res = run([tool] + flags + [native])
                            item[label] = res['stdout'][:20000]
                            if res['returncode'] != 0: add(r, 'failures', item['path'], 'readelf ' + label + ' failed: ' + res['stderr'][:500])
                            else: add(r, 'verified', item['path'], 'readelf ' + label + ' completed (output capped)')
                if args.native_symbols:
                    add(r, 'not_tested', 'native behavior', 'Symbol tables may be stripped; static symbols do not prove runtime behavior')
    return r


@reported
def dex(args, _report):
    r = _report
    r['dex_files'] = []
    with zipfile.ZipFile(args.apk) as z:
        infos = validate_apk_archive(args.apk, z, args.max_entry_mib * MIB, args.max_total_mib * MIB)
        dex_entries = [(index, info) for index, info in enumerate(infos) if re.fullmatch(r'classes(?:[2-9][0-9]*|1[0-9]+)?\.dex', info.filename)]
        if not dex_entries: add(r, 'not_tested', 'DEX', 'No root classes*.dex found')
        for index, info in dex_entries:
            name = info.filename
            try:
                d = read_dex(z.read(info))
                term = args.search.lower() if args.search else None
                match = lambda values: [x for x in values if not term or term in x.lower()][:args.limit]
                classes, methods = d['classes'], d['methods']
                apis = [m for m in methods if m.startswith(('Landroid/', 'Ljava/', 'Ljavax/', 'Lkotlin/', 'Lokhttp3/', 'Lretrofit2/'))]
                models = [c for c in classes if re.search(r'(/model/|/models/|/dto/|Model;|Response;|Request;)', c, re.I)]
                r['dex_files'].append({'file': name, 'zip_entry_index': index, 'counts': {'classes': len(classes), 'methods': len(methods), 'strings': len(d['strings']), 'endpoints': len(d['endpoints'])},
                    'classes': match(classes), 'methods': match(methods), 'apis': match(apis), 'possible_models': match(models), 'endpoints': match(d['endpoints']), 'matching_strings': match(d['strings']) if term else []})
                add(r, 'verified', name, 'Indexed DEX identifier tables and string literals, not code behavior; lists are capped')
                r['dex_files'][-1]['obfuscation_candidates'] = candidates(classes, d['strings'], args.limit)
                add(r, 'inferences', name, 'Model names, URLs, short class names and encoded-looking strings are hints, not proof of obfuscation, use or server availability')
            except (ValueError, IndexError, zipfile.BadZipFile) as e:
                add(r, 'failures', name, str(e))
    tool = find_tool('aapt')
    if not tool:
        add(r, 'not_tested', 'manifest', 'aapt not found; manifest permissions and components not decoded')
    else:
        result = run([tool, 'dump', 'xmltree', args.apk, 'AndroidManifest.xml'], timeout=120)
        if result['returncode'] != 0:
            add(r, 'failures', 'manifest', 'aapt manifest decoding failed: ' + (result['stderr'] or result['stdout'])[:2000])
        else:
            text = result['stdout']
            truncated = bool(result.get('stdout_truncated'))
            if truncated and not text.endswith('\n'):
                text = text.rpartition('\n')[0]  # Do not parse a cut-off final line.
            if not re.search(r'^\s*E: manifest\b', text, re.MULTILINE):
                if truncated:
                    add(r, 'not_tested', 'manifest', 'aapt output was truncated before a complete manifest element could be parsed')
                else:
                    add(r, 'failures', 'manifest', 'aapt returned no parseable manifest element')
            else:
                r['manifest'] = parse_xmltree(text)
                r['manifest']['partial'] = truncated
                if truncated:
                    add(r, 'inferences', 'manifest', 'Partial aapt output only; entries may be missing')
                    add(r, 'not_tested', 'manifest truncation', 'aapt stdout was truncated; manifest observations are incomplete')
                else:
                    add(r, 'verified', 'manifest', 'Listed named permissions and components observed in aapt xmltree output')
                add(r, 'not_tested', 'manifest completeness', 'Resource references, merged manifests and runtime registration are not resolved')
    add(r, 'not_tested', 'server', 'Server code, data, runtime reachability, authentication and compatibility cannot be inferred from an APK alone')
    return r


@reported
def work(args, _report):
    r = _report
    if args.stage == 'init':
        dest = init(args.apk, args.workspace)
        add(r, 'verified', 'workspace', 'Copied input to ' + dest + '/original.apk')
    elif args.stage == 'verify':
        src = workspace_input(args.workspace, args.input or 'signed.apk')
        r['checks'] = {}
        r['page_size_policy'] = 'Both 4 KiB and, when supported, 16 KiB ZIP checks are attempted; --page-size does not select verification checks'
        checks = [('zipalign', 'zipalign', ['-c', '-p', '4']),
                  ('zipalign_16k', 'zipalign', ['-c', '-P', '16', '4']),
                  ('apksigner', 'apksigner', ['verify', '--verbose', '--print-certs'])]
        for label, name, flags in checks:
            tool = find_tool(name)
            if not tool:
                add(r, 'not_tested', label, 'Executable not found')
                continue
            if label == 'zipalign_16k' and not supports_16k(tool):
                add(r, 'not_tested', label, 'zipalign does not advertise -P 16 support')
                continue
            result = run([tool] + flags + [src], timeout=120)
            r['checks'][label] = result
            if result['returncode'] == 0:
                add(r, 'verified', label, 'ZIP verification command succeeded for ' + str(src))
            else:
                add(r, 'failures', label, 'Verification command failed: ' + (result['stderr'] or result['stdout'])[:2000])
        add(r, 'not_tested', 'runtime', 'Installability, ELF segment alignment, signature identity compatibility, and app behavior are not verified')
    else:
        dest, result = perform(args.stage, args.workspace, args.input, args.output_path,
                               getattr(args, 'keystore', None), getattr(args, 'alias', None), getattr(args, 'pass_env', None),
                               getattr(args, 'page_size', 4))
        add(r, 'verified', args.stage, 'Tool exited successfully and output exists: ' + dest)
        r['tool_output'] = result
        add(r, 'not_tested', 'output', 'Installability, runtime behavior, original signature compatibility and functionality are not verified')
        if args.stage == 'sign': add(r, 'not_tested', 'signature', 'Run inspect on signed output to verify its signature independently')
    return r


def jadx(args):
    r = report()
    size = decompile(args.apk, args.output, args.timeout, args.max_output_mib * MIB)
    r['output'] = str(Path(args.output).resolve())
    r['output_bytes'] = size
    add(r, 'verified', 'jadx', 'JADX exited successfully on a temporary APK copy; output size was monitored')
    add(r, 'not_tested', 'jadx', 'Decompiled code is incomplete and not a rebuildable source; runtime behavior not verified. Size monitoring is best effort, not a disk quota.')
    return r


def device(args):
    return install_test(args.serial, args.apks, args.confirm_install, args.launch)


@reported
def splits(args, _report):
    r = _report
    if args.action == 'init':
        r['members'] = init_set(args.workspace, args.apks)
        add(r, 'verified', 'split workspace', 'Copied APKs to new member workspaces and recorded SHA-256 digests')
        add(r, 'not_tested', 'split set', 'Package, signature, base identity and completeness not checked; run inspect separately')
        return r
    root, members = read_set(args.workspace)
    if args.stage == 'sign' and not (args.keystore and args.alias and args.pass_env):
        raise ValueError('sign requires --keystore, --alias and --pass-env')
    r['members'] = []
    for item in members:
        folder = root / item['id']
        result = {'id': item['id'], 'source_name': item.get('source_name')}
        try:
            if args.stage == 'verify':
                sub = work(argparse.Namespace(stage='verify', workspace=str(folder), input=None, page_size=args.page_size))
                result['report'] = sub
                if sub['failures']:
                    add(r, 'failures', item['id'], 'Verification reported failure')
                if sub['verified']:
                    add(r, 'verified', item['id'], 'See individual report for successful checks')
                if sub['not_tested']:
                    add(r, 'not_tested', item['id'], 'See individual verification report for checks not performed')
            else:
                dest, output = perform(args.stage, str(folder), None, None, args.keystore, args.alias, args.pass_env, args.page_size)
                result.update(output=dest, tool_output=output)
                add(r, 'verified', item['id'], args.stage + ' tool returned success and output exists')
        except PartialReportError as e:
            result['report'] = e.report
            add(e.report, 'failures', item['id'], str(e))
            result['error'] = str(e)
            add(r, 'failures', item['id'], str(e))
        except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, NotImplementedError) as e:
            result['error'] = str(e)
            add(r, 'failures', item['id'], str(e))
        r['members'].append(result)
    add(r, 'not_tested', 'split set', 'Operations may partially succeed; completeness, matching signer digests, installability and runtime behavior are not verified')
    return r


def zip_limits(p):
    p.add_argument('--max-entry-mib', type=int, default=64, help='Max uncompressed entry size in MiB (default 64)')
    p.add_argument('--max-total-mib', type=int, default=512, help='Max total uncompressed size in MiB (default 512)')


def parser():
    p = argparse.ArgumentParser(prog='apklab', description='APKLab: evidence-oriented APK analysis and copy-based workflows')
    p.add_argument('--summary', action='store_true', help='Print a human-readable summary above JSON')
    p.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    sub = p.add_subparsers(dest='command', required=True)
    def cmd(name, help, func):
        q = sub.add_parser(name, help=help, description=help)
        q.set_defaults(func=func)
        q.add_argument('--summary', action='store_true', default=argparse.SUPPRESS, help='Print a human-readable summary above JSON')
        q.add_argument('--report', metavar='FILE', help='Write JSON report to a new file (never overwrite)')
        return q
    q = cmd('doctor', 'Find external Android and analysis tools', doctor)
    q.add_argument('--check', action='store_true', help='Run limited version/help probes where supported')
    q = cmd('setup', 'Show or attempt a limited APT installation plan', setup)
    mode = q.add_mutually_exclusive_group()
    mode.add_argument('--plan', action='store_true', help='Show official-source guidance without installing')
    mode.add_argument('--install', action='store_true', help='Actually install missing packages using configured APT repositories')
    q = cmd('inspect', 'Inspect one APK or a split set (files or directories)', inspect)
    q.add_argument('apks', nargs='+')
    q.add_argument('--recursive', action='store_true', help='Include APKs in subdirectories of supplied directories')
    q.add_argument('--device-abi', help='Compare a device ABI with observed native library directory names')
    zip_limits(q)
    q = cmd('xapk', 'Safely inspect or unpack XAPK archives', xapk)
    actions = q.add_subparsers(dest='action', required=True)
    for action in ('inspect', 'unpack', 'repack'):
        x = actions.add_parser(action, help=action + ' an XAPK archive')
        x.add_argument('--summary', action='store_true', default=argparse.SUPPRESS)
        x.add_argument('archive')
        if action == 'unpack': x.add_argument('destination', help='New directory; parent must exist')
        elif action == 'repack':
            x.add_argument('destination', help='New output archive; parent must exist')
            x.add_argument('--directory', action='store_true', help='Create new directory with repacked.xapk and manifest-validated OBB layout')
            x.add_argument('--replace', action='append', default=[], metavar='ENTRY=APK', help='Replace an existing APK entry; repeat as needed')
        else: x.add_argument('--verify', action='store_true', help='Read every entry and verify ZIP CRC')
        x.add_argument('--max-entry-mib', type=int, default=2048, help='Max uncompressed entry size (default 2048 MiB)')
        x.add_argument('--max-total-mib', type=int, default=8192, help='Max total uncompressed size (default 8192 MiB)')
    q = cmd('inventory', 'List asset and native library paths', inventory)
    q.add_argument('apk'); q.add_argument('--search', help='Case-insensitive path substring')
    q.add_argument('--text', help='Search UTF-8 asset contents (bounded and case-insensitive)')
    q.add_argument('--hash', action='store_true', help='Stream matching files to compute SHA-256 and verify ZIP CRC')
    q.add_argument('--native-details', action='store_true', help='Run readelf for matching native libraries')
    q.add_argument('--native-symbols', action='store_true', help='Index available native symbol tables with readelf')
    zip_limits(q)
    q = cmd('dex', 'Index DEX classes, methods, API references, strings, URLs, and possible models', dex)
    q.add_argument('apk'); q.add_argument('--search', help='Case-insensitive substring filter')
    q.add_argument('--limit', type=int, default=200, help='Maximum entries per list (default 200)')
    zip_limits(q)
    q = cmd('jadx', 'Decompile a copy of an APK into a new directory', jadx)
    q.add_argument('apk'); q.add_argument('output')
    q.add_argument('--timeout', type=int, default=600, help='Timeout in seconds (default 600)')
    q.add_argument('--max-output-mib', type=int, default=512, help='Best-effort monitored output cap in MiB (default 512)')
    q = cmd('splits', 'Copy-based multi-APK split workflows', splits)
    actions = q.add_subparsers(dest='action', required=True)
    i = actions.add_parser('init', help='Copy APKs into a new split workspace')
    i.add_argument('--summary', action='store_true', default=argparse.SUPPRESS)
    i.add_argument('workspace'); i.add_argument('apks', nargs='+')
    s = actions.add_parser('run', help='Run a stage for each APK copy')
    s.add_argument('--summary', action='store_true', default=argparse.SUPPRESS)
    s.add_argument('workspace'); s.add_argument('stage', choices=('decode', 'build', 'align', 'sign', 'verify'))
    s.add_argument('--page-size', type=int, choices=(4, 16), default=4, help='Select ZIP alignment for align; verify attempts both 4 and 16 KiB regardless')
    s.add_argument('--keystore'); s.add_argument('--alias'); s.add_argument('--pass-env')
    q = cmd('device', 'Opt-in installation test on a disposable emulator', device)
    q.add_argument('--serial', required=True, help='Explicit emulator-NNNN serial (physical devices refused)')
    q.add_argument('--confirm-install', action='store_true', help='Confirm installation changes emulator state')
    q.add_argument('--launch', action='store_true', help='Also send one launcher event (executes app code)')
    q.add_argument('apks', nargs='+', help='APK files to copy and install, including base and all needed splits')
    q = cmd('work', 'Copy-based decode/build/align/sign workflow', work)
    stages = q.add_subparsers(dest='stage', required=True)
    i = stages.add_parser('init', help='Copy APK to a new workspace'); i.add_argument('--summary', action='store_true', default=argparse.SUPPRESS); i.add_argument('apk'); i.add_argument('workspace')
    v = stages.add_parser('verify', help='Check alignment and signature of an APK in the workspace')
    v.add_argument('--summary', action='store_true', default=argparse.SUPPRESS)
    v.add_argument('workspace'); v.add_argument('--input', help='APK inside workspace (default signed.apk)')
    v.add_argument('--page-size', type=int, choices=(4, 16), default=4, help='Compatibility option only: verify attempts both 4 and 16 KiB ZIP alignment checks regardless')
    for stage in ('decode', 'jadx', 'build', 'align', 'sign'):
        s = stages.add_parser(stage, help=stage + ' within an APKLab workspace')
        s.add_argument('--summary', action='store_true', default=argparse.SUPPRESS)
        s.add_argument('workspace'); s.add_argument('--input', help='Input path inside workspace')
        s.add_argument('--output', dest='output_path', help='New output path inside workspace')
        if stage == 'align': s.add_argument('--page-size', type=int, choices=(4, 16), default=4, help='Native library ZIP alignment in KiB (default 4)')
        if stage == 'sign':
            s.add_argument('--keystore', required=True); s.add_argument('--alias', required=True)
            s.add_argument('--pass-env', required=True, help='Name of environment variable holding keystore password')
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if getattr(args, 'limit', 1) < 1: raise ValueError('--limit must be positive')
        r = args.func(args)
    except PartialReportError as e:
        r = e.report; add(r, 'failures', args.command, str(e))
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, NotImplementedError, EOFError, zlib.error) as e:
        r = report(); add(r, 'failures', args.command, str(e))
    try:
        emit(r, args.report, args.summary)
    except OSError as e:
        add(r, 'failures', 'report', 'Cannot write report: ' + str(e))
        emit(r, summary=args.summary)
    return 1 if r['failures'] else 3 if r['not_tested'] else 0

if __name__ == '__main__':
    sys.exit(main())
