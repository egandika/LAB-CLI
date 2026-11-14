import argparse
import os
import re
import sys
import zipfile
from pathlib import Path
from . import __version__
from .core import TOOLS, add, emit, find_tool, inspect_one, report, run, zip_infos
from .dex import read_dex
from .workflow import init, perform


def doctor(args):
    r = report()
    r['tools'] = {}
    for name in TOOLS:
        path = find_tool(name)
        r['tools'][name] = path
        if path: add(r, 'verified', name, 'Executable found: ' + path + ' (functionality not verified)')
        else: add(r, 'not_tested', name, 'Not found')
    sdk = os.environ.get('ANDROID_SDK_ROOT') or os.environ.get('ANDROID_HOME')
    if not sdk and (Path.home() / 'Android/Sdk').is_dir(): sdk = str(Path.home() / 'Android/Sdk')
    r['android_sdk'] = sdk
    if sdk and Path(sdk).is_dir(): add(r, 'verified', 'Android SDK', 'Directory exists: ' + sdk)
    else: add(r, 'not_tested', 'Android SDK', 'SDK directory not found')
    add(r, 'not_tested', 'tool functionality', 'Presence checks do not confirm versions or operation')
    return r


def setup(args):
    r = report()
    packages = {'java': 'default-jre-headless', 'apktool': 'apktool', 'adb': 'adb', 'aapt': 'aapt', 'zipalign': 'zipalign', 'apksigner': 'apksigner'}
    r['plan'] = {'source': 'configured system APT repositories', 'packages': packages,
                 'manual': ['jadx', 'Android SDK/build-tools', 'emulator', 'Ghidra']}
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
        res = run(prefix + [apt, '-o', 'Acquire::Retries=0', '-o', 'Acquire::http::Timeout=10', '-o', 'Acquire::https::Timeout=10', 'update'], timeout=180)
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


def apk_paths(inputs):
    paths = []
    for name in inputs:
        p = Path(name)
        if p.is_dir(): paths.extend(sorted(p.glob('*.apk')))
        else: paths.append(p)
    if not paths: raise ValueError('No APK files found')
    return paths


def inspect(args):
    r = report()
    r['apks'] = [inspect_one(p, r) for p in apk_paths(args.apks)]
    packages = {a['package'] for a in r['apks'] if a['package']}
    versions = {a['version_code'] for a in r['apks'] if a['version_code']}
    if len(packages) > 1 or len(versions) > 1:
        add(r, 'failures', 'split set', 'Package names or version codes differ between APKs')
    elif len(r['apks']) > 1:
        add(r, 'not_tested', 'split set', 'Full split compatibility, signing identity and installation not verified')
    return r


def inventory(args):
    r = report()
    r['files'] = []
    with zipfile.ZipFile(args.apk) as z:
        infos = zip_infos(z)
        for info in infos:
            n = info.filename
            category = 'native' if n.startswith('lib/') and n.endswith('.so') else 'asset' if n.startswith(('assets/', 'res/')) else None
            if category and (not args.search or args.search.lower() in n.lower()):
                r['files'].append({'path': n, 'size': info.file_size, 'category': category})
        add(r, 'verified', 'inventory', 'Indexed matching ZIP entry names and sizes; file contents not validated')
        if args.native_details:
            import tempfile
            tool = find_tool('readelf')
            if not tool: add(r, 'not_tested', 'native details', 'readelf not found')
            else:
                for item in r['files']:
                    if item['category'] != 'native': continue
                    with tempfile.NamedTemporaryFile() as tmp:
                        tmp.write(z.read(item['path'])); tmp.flush()
                        res = run([tool, '-h', '-d', tmp.name])
                    item['readelf'] = res['stdout'][:20000]
                    if res['returncode'] != 0: add(r, 'failures', item['path'], 'readelf failed: ' + res['stderr'][:500])
                    else: add(r, 'verified', item['path'], 'readelf header and dynamic section')
    return r


def dex(args):
    r = report()
    r['dex_files'] = []
    with zipfile.ZipFile(args.apk) as z:
        infos = zip_infos(z)
        names = [i.filename for i in infos if re.fullmatch(r'classes(?:[2-9][0-9]*|1[0-9]+)?\.dex', i.filename)]
        if not names: add(r, 'not_tested', 'DEX', 'No root classes*.dex found')
        for name in names:
            try:
                d = read_dex(z.read(name))
                term = args.search.lower() if args.search else None
                match = lambda values: [x for x in values if not term or term in x.lower()][:args.limit]
                classes, methods = d['classes'], d['methods']
                apis = [m for m in methods if m.startswith(('Landroid/', 'Ljava/', 'Ljavax/', 'Lkotlin/', 'Lokhttp3/', 'Lretrofit2/'))]
                models = [c for c in classes if re.search(r'(/model/|/models/|/dto/|Model;|Response;|Request;)', c, re.I)]
                r['dex_files'].append({'file': name, 'counts': {'classes': len(classes), 'methods': len(methods), 'strings': len(d['strings']), 'endpoints': len(d['endpoints'])},
                    'classes': match(classes), 'methods': match(methods), 'apis': match(apis), 'possible_models': match(models), 'endpoints': match(d['endpoints']), 'matching_strings': match(d['strings']) if term else []})
                add(r, 'verified', name, 'Indexed DEX identifier tables and string literals, not code behavior; lists are capped')
                add(r, 'inferences', name, 'Model names and URLs are heuristics, not proof of use or server availability')
            except (ValueError, IndexError, zipfile.BadZipFile) as e:
                add(r, 'failures', name, str(e))
    add(r, 'not_tested', 'server', 'Server code, data, runtime reachability, authentication and compatibility cannot be inferred from an APK alone')
    return r


def work(args):
    r = report()
    if args.stage == 'init':
        dest = init(args.apk, args.workspace)
        add(r, 'verified', 'workspace', 'Copied input to ' + dest + '/original.apk')
    else:
        dest, result = perform(args.stage, args.workspace, args.input, args.output_path,
                               getattr(args, 'keystore', None), getattr(args, 'alias', None), getattr(args, 'pass_env', None))
        add(r, 'verified', args.stage, 'Tool exited successfully and output exists: ' + dest)
        r['tool_output'] = result
        add(r, 'not_tested', 'output', 'Installability, runtime behavior, original signature compatibility and functionality are not verified')
        if args.stage == 'sign': add(r, 'not_tested', 'signature', 'Run inspect on signed output to verify its signature independently')
    return r


def parser():
    p = argparse.ArgumentParser(prog='apklab', description='APKLab: evidence-oriented APK analysis and copy-based workflows')
    p.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    sub = p.add_subparsers(dest='command', required=True)
    def cmd(name, help, func):
        q = sub.add_parser(name, help=help, description=help)
        q.set_defaults(func=func)
        q.add_argument('--report', metavar='FILE', help='Write JSON report to a new file (never overwrite)')
        return q
    cmd('doctor', 'Find external Android and analysis tools', doctor)
    q = cmd('setup', 'Show or attempt a limited APT installation plan', setup)
    q.add_argument('--install', action='store_true', help='Actually install missing packages using configured APT repositories')
    q = cmd('inspect', 'Inspect one APK or a split set (files or directories)', inspect)
    q.add_argument('apks', nargs='+')
    q = cmd('inventory', 'List asset and native library paths', inventory)
    q.add_argument('apk'); q.add_argument('--search', help='Case-insensitive path substring')
    q.add_argument('--native-details', action='store_true', help='Run readelf for matching native libraries')
    q = cmd('dex', 'Index DEX classes, methods, API references, strings, URLs, and possible models', dex)
    q.add_argument('apk'); q.add_argument('--search', help='Case-insensitive substring filter')
    q.add_argument('--limit', type=int, default=200, help='Maximum entries per list (default 200)')
    q = cmd('work', 'Copy-based decode/build/align/sign workflow', work)
    stages = q.add_subparsers(dest='stage', required=True)
    i = stages.add_parser('init', help='Copy APK to a new workspace'); i.add_argument('apk'); i.add_argument('workspace')
    for stage in ('decode', 'build', 'align', 'sign'):
        s = stages.add_parser(stage, help=stage + ' within an APKLab workspace')
        s.add_argument('workspace'); s.add_argument('--input', help='Input path inside workspace')
        s.add_argument('--output', dest='output_path', help='New output path inside workspace')
        if stage == 'sign':
            s.add_argument('--keystore', required=True); s.add_argument('--alias', required=True)
            s.add_argument('--pass-env', required=True, help='Name of environment variable holding keystore password')
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if getattr(args, 'limit', 1) < 1: raise ValueError('--limit must be positive')
        r = args.func(args)
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, NotImplementedError) as e:
        r = report(); add(r, 'failures', args.command, str(e))
    try:
        emit(r, args.report)
    except OSError as e:
        add(r, 'failures', 'report', 'Cannot write report: ' + str(e))
        emit(r)
    return 1 if r['failures'] else 0

if __name__ == '__main__':
    sys.exit(main())
