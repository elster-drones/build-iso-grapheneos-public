#!/usr/bin/env python3
"""Build GrapheneOS from its official sources and sign it with the owner's keys.

Upstream owns the source tree, Pixel vendor extraction (adevtool), compilation
and release signing (script/generate-release.sh). This adapter pins a signed
release tag, runs those tools as an unprivileged account, and packages the
signed output with provenance.

The compiled target files depend only on (release tag, device), so they are
built once into the cache and every later build of that pair only signs.

The openfactory-phone variant is OpenFactory Phone, a distinct OS based on
GrapheneOS: the same release compiled once more from a patched copy of the tree
(variants/openfactory-phone), then, per owner, F-Droid apps and an optional
welcome name added to a scratch copy of its target files before the same
upstream signing.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import subprocess
import sys
import time
import xml.sax.saxutils
import zipfile

import fdroid

ROOT = Path(__file__).resolve().parent
MANIFEST_URL = 'https://github.com/GrapheneOS/platform_manifest.git'
BUILD_USER = os.environ.get('GRAPHENEOS_BUILD_USER', 'of-grapheneos')
# Mirrors upstream script/build-releases: these Pixels have no vendor_kernel_boot.
NO_VENDOR_KERNEL_BOOT = {'bluejay', 'raven', 'oriole'}
KEY_SUBJECT = '/CN=OpenFactory GrapheneOS build/'
PRIVATE_KEY_NAME = re.compile(r'(\.pk8|\.pem|\.gpg|id_ed25519)$')
STOCK_KEYS = {'schema_version', 'device', 'model', 'tag', 'manifest_url', 'manifest_commit'}
VARIANT = 'openfactory-phone'
VARIANT_DIR = ROOT / 'variants' / VARIANT
VARIANT_KEYS = {'variant', 'apps', 'display_name'}
APP_ID = re.compile(r'[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+')
DISPLAY_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 .'+-]{0,31}")
MAX_APPS = 25
FDROID_SIGNER = ROOT / 'keys/fdroid-repo.sha256'
# A compile needs about 250 GiB while it runs; the copied tree shares extents.
COMPILE_FREE_BYTES = 300 * 1024 ** 3
# always: a filesystem without reflinks fails here instead of copying ~140 GiB.
REFLINK = '--reflink=always'
SUPER_MARGIN = 256 * 1024 ** 2
NAME_OVERLAY = 'OpenFactoryPhoneName.apk'
SETUP_WIZARD = 'app.grapheneos.setupwizard'


def digest(path, algorithm='sha256'):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, algorithm).hexdigest()


def read_config(path):
    config = json.loads(Path(path).read_text())
    if (config.get('schema_version') != 1
            or not re.fullmatch(r'[a-z][a-z0-9]{2,15}', str(config.get('device', '')))
            or not re.fullmatch(r'20\d{8}', str(config.get('tag', '')))
            or config.get('manifest_url') != MANIFEST_URL
            or not re.fullmatch(r'[0-9a-f]{40}', str(config.get('manifest_commit', '')))
            or not re.fullmatch(r'[A-Za-z0-9 .+-]{1,40}', str(config.get('model', '')))):
        raise ValueError('Invalid pinned GrapheneOS device or release')
    if 'variant' not in config:
        if set(config) - STOCK_KEYS:
            raise ValueError('Unknown configuration keys: ' + ', '.join(sorted(set(config) - STOCK_KEYS)))
        return config
    apps, name = config.get('apps'), config.get('display_name')
    if (set(config) != STOCK_KEYS | VARIANT_KEYS or config['variant'] != VARIANT
            or not isinstance(apps, list) or len(apps) > MAX_APPS
            or not all(isinstance(app, str) and APP_ID.fullmatch(app) for app in apps) or len(set(apps)) != len(apps)
            or not (name is None or isinstance(name, str) and DISPLAY_NAME.fullmatch(name)
                    and 'graphene' not in name.lower())):
        raise ValueError('Invalid OpenFactory Phone variant, apps or display name')
    return config


def secrets_dir(cache):
    value = os.environ.get('GRAPHENEOS_SECRETS_DIR', '')
    path = Path(value).resolve() if value else None
    if (path is None or not path.is_dir() or path.is_relative_to(ROOT.resolve())
            or path.is_relative_to(cache.resolve())):
        raise ValueError('GRAPHENEOS_SECRETS_DIR must be a directory outside the workspace and cache')
    password = (path / 'passphrase').read_text().rstrip('\n')
    if len(password) < 32 or '\n' in password:
        raise ValueError('The signing passphrase is missing or malformed')
    return path, password


def builder_argv(home):
    """Run upstream tools as the build account with no privileges and a clean environment."""
    environment = {'HOME': str(home), 'USER': BUILD_USER, 'LANG': 'C.UTF-8', 'TERM': 'dumb',
        'PATH': f'{home}/bin:/usr/local/bin:/usr/bin:/bin'}
    jobs = os.environ.get('GRAPHENEOS_JOBS', '')
    if re.fullmatch(r'[1-9][0-9]{0,3}', jobs):
        environment['GRAPHENEOS_JOBS'] = jobs
    prefix = []
    if os.geteuid() == 0:
        account = pwd.getpwnam(BUILD_USER)
        prefix = ['setpriv', f'--reuid={account.pw_uid}', f'--regid={account.pw_gid}', '--clear-groups',
            '--no-new-privs', '--inh-caps=-all', '--bounding-set=-all']
    return [*prefix, 'env', '-i', *(f'{key}={value}' for key, value in environment.items())]


def run_tool(home, argv, *, cwd, stdin=None, ok=(0,)):
    """A short upstream tool run as the build account; returns its exit status and stdout."""
    result = subprocess.run([*builder_argv(home), *map(str, argv)], cwd=cwd, input=stdin, capture_output=True)
    if result.returncode not in ok:
        raise RuntimeError(f'{Path(str(argv[0])).name} exited {result.returncode}: '
            + result.stderr.decode(errors='replace').strip()[-2000:])
    return result.returncode, result.stdout.decode(errors='replace')


@contextlib.contextmanager
def compile_lock(cache):
    """One Android compile at a time on this host; other OS caches beside this one share the lock."""
    with (cache.parent / '.android-compile.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('Waiting for another Android compile on this host to finish', flush=True)
            fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def give_to_builder(*paths, only_if_needed=False):
    """chown -R to the build account; with only_if_needed, skip trees it already owns."""
    if os.geteuid() == 0:
        account = pwd.getpwnam(BUILD_USER)
        for path in paths:
            if only_if_needed and Path(path).stat().st_uid == account.pw_uid:
                continue
            subprocess.run(['chown', '-R', f'{account.pw_uid}:{account.pw_gid}', str(path)], check=True)


class Builder:
    def __init__(self, config, cache):
        self.config, self.cache = config, cache
        self.device, self.tag = config['device'], config['tag']
        self.home = cache / 'home'
        # One tree, moved in place to each pinned release so a release bump
        # fetches only what changed instead of a fresh ~136 GiB sync.
        self.tree = cache / 'src'
        self.logs = cache / 'logs'
        self.redact = []

    def step(self, name, script, *, cwd=None, stdin='', variables=None):
        """Run one upstream step; the full log stays in the cache, progress goes to stdout."""
        log = self.logs / f'{self.tag}-{self.device}-{name}.log'
        exports = ''.join(f'export {key}={shlex.quote(str(value))}\n' for key, value in (variables or {}).items())
        argv = [*builder_argv(self.home), 'bash', '-c', 'set -euo pipefail\n' + exports + script]
        print(f'==> {name}', flush=True)
        started = time.monotonic()
        with log.open('ab') as output:
            proc = subprocess.Popen(argv, cwd=cwd or self.tree, stdin=subprocess.PIPE,
                stdout=output, stderr=subprocess.STDOUT)
            proc.stdin.write(stdin.encode())
            proc.stdin.close()
            while True:
                try:
                    code = proc.wait(timeout=60)
                    break
                except subprocess.TimeoutExpired:
                    print(f'{name}: running for {int((time.monotonic() - started) // 60)} min', flush=True)
        if code:
            tail = log.read_text(errors='replace').splitlines()[-40:]
            text = '\n'.join(tail)
            for secret in self.redact:
                text = text.replace(secret, '[redacted]')
            print(text, flush=True)
            raise RuntimeError(f'GrapheneOS step {name} failed; full log: {log}')

    def done(self, step):
        """A step marker names the release it was done for; another release redoes the step."""
        marker = self.tree / f'.openfactory-{step}-{self.device}'
        return marker.is_file() and marker.read_text().strip() == self.tag

    def adopt_legacy_tree(self):
        """Adapters before 2026-11-10 kept src-<tag> per release with empty step markers."""
        legacy = sorted(self.cache.glob('src-20*'))
        if self.tree.exists() or not legacy:
            return
        tag = legacy[-1].name[len('src-'):]
        legacy[-1].rename(self.tree)
        markers = [*self.tree.glob('.openfactory-vendor-*'), *self.tree.glob('.openfactory-compiled-*')]
        for marker in markers:
            if not marker.read_text().strip():
                marker.write_text(tag + '\n')
        give_to_builder(*markers)
        # Fail at the move, not at the next release bump, if repo kept absolute paths.
        self.step('adopt', 'git -C build/make rev-parse HEAD')

    def prepare_cache(self):
        for path in (self.home / 'bin', self.logs):
            path.mkdir(parents=True, exist_ok=True)
        node24 = shutil.which('node-24')
        if node24 and not (self.home / 'bin/node').exists():
            (self.home / 'bin/node').symlink_to(node24)
        shutil.copy2(ROOT / 'keys/grapheneos_allowed_signers', self.home / 'grapheneos_allowed_signers')
        give_to_builder(self.home)
        self.adopt_legacy_tree()
        self.tree.mkdir(exist_ok=True)
        # The synced tree is ~140 GiB; re-owning it every build would take minutes.
        give_to_builder(self.tree, only_if_needed=True)

    def prepare(self, then=None):
        """Sync, extract vendor files and compile, then run then(self): hours under the cache lock.

        The platform admits no build while `.openfactory-preparing` is locked,
        so none waits out its slot on the cache lock. The kernel drops the lock
        with this process however it ends; the pid is only for operators.
        """
        marker = self.cache / '.openfactory-preparing'
        with marker.open('w') as held:
            os.fchmod(held.fileno(), 0o644)  # the platform's API account opens it read-only
            fcntl.flock(held, fcntl.LOCK_EX)
            held.write(f'{os.getpid()}\n')
            held.flush()
            try:
                self.ensure_source()
                self.ensure_vendor()
                self.ensure_compiled()
                if then:
                    then(self)
            finally:
                marker.unlink(missing_ok=True)

    def ensure_source(self):
        marker = self.tree / '.openfactory-manifest'
        if marker.is_file() and marker.read_text().strip() == self.config['manifest_commit']:
            return
        self.step('sync', '''
git config --global user.name >/dev/null || git config --global user.name OpenFactory
git config --global user.email >/dev/null || git config --global user.email builds@openfactory.tech
git config --global color.ui false
repo init -u "$MANIFEST_URL" -b "refs/tags/$TAG"
cd .repo/manifests
git -c gpg.ssh.allowedSignersFile="$HOME/grapheneos_allowed_signers" verify-tag "$TAG"
test "$(git rev-parse "$TAG^{commit}")" = "$COMMIT"
cd ../..
repo sync -j8 --force-sync
"$(command -v yarnpkg || command -v yarn)" --cwd vendor/adevtool/ install --frozen-lockfile
printf '%s\\n' "$COMMIT" > .openfactory-manifest
''', variables={'MANIFEST_URL': MANIFEST_URL, 'TAG': self.tag, 'COMMIT': self.config['manifest_commit']})
        # Compiled output of earlier releases is never signed again.
        for old in (self.tree / 'releases').glob('*'):
            if old.name != self.tag:
                shutil.rmtree(old)

    def ensure_vendor(self):
        if self.done('vendor'):
            return
        self.step('vendor', '''
source build/envsetup.sh >/dev/null
# envsetup.sh defines adevtool as an alias, which a non-interactive shell ignores.
vendor/adevtool/bin/run generate-all -d "$DEVICE"
printf '%s\\n' "$TAG" > ".openfactory-vendor-$DEVICE"
''', variables={'DEVICE': self.device, 'TAG': self.tag})

    def target_files(self):
        releases = self.tree / 'releases' / self.tag
        return releases / f'{self.device}-target_files.zip', releases / f'{self.device}-otatools.zip'

    def compiled(self):
        return self.done('compiled') and all(p.is_file() for p in self.target_files())

    def ensure_compiled(self, min_free=None):
        if self.compiled():
            return
        targets = 'vendorbootimage target-files-package otatools-package'
        if self.device not in NO_VENDOR_KERNEL_BOOT:
            targets = 'vendorbootimage vendorkernelbootimage target-files-package otatools-package'
        with compile_lock(self.cache):
            if min_free and (free := shutil.disk_usage(self.tree).free) < min_free:
                raise RuntimeError(f'Compiling needs {min_free // 1024 ** 3} GiB free beside {self.tree}; '
                    f'{free // 1024 ** 3} GiB is free')
            self.step('compile', f'''
rm -rf out
source build/envsetup.sh >/dev/null
lunch "$DEVICE-cur-user"
m ${{GRAPHENEOS_JOBS:+-j$GRAPHENEOS_JOBS}} {targets}
script/finalize.sh
rm -rf out
printf '%s\\n' "$BUILD_NUMBER" > ".openfactory-compiled-$DEVICE"
''', variables={'DEVICE': self.device, 'BUILD_NUMBER': self.tag})

    def ensure_keys(self, keys, password):
        if (keys / 'releasekey.pk8').is_file():
            return
        keys.mkdir(mode=0o700, parents=True, exist_ok=True)
        give_to_builder(keys)
        # make_key prompts on stdin (blank = no passphrase); encrypt-keys then
        # encrypts every key with the owner's passphrase (old, new, confirm).
        self.step('keys', '''
IFS= read -r password
source "$TREE/script/common.sh"
for key in "${signing_keys[@]}"; do
    # make_key always exits 1 through its EXIT trap; judge it by its outputs.
    printf '\\n' | "$TREE/development/tools/make_key" "$key" "$SUBJECT" >/dev/null || true
    test -s "$key.pk8" && test -s "$key.x509.pem"
done
openssl genrsa 4096 2>/dev/null | openssl pkcs8 -topk8 -nocrypt -out avb.pem
python3 "$TREE/external/avb/avbtool.py" extract_public_key --key avb.pem --output avb_pkmd.bin
printf '\\n%s\\n%s\\n' "$password" "$password" | "$TREE/script/encrypt-keys" .
''', cwd=keys, stdin=password + '\n', variables={'TREE': self.tree, 'SUBJECT': KEY_SUBJECT})

    def sign(self, keys, password):
        link = self.tree / 'keys' / self.device
        (self.tree / 'keys').mkdir(exist_ok=True)
        link.unlink(missing_ok=True)
        link.symlink_to(keys)
        try:
            self.step('sign', '''
IFS= read -r password
export password
script/generate-release.sh "$DEVICE" "$TAG"
''', stdin=password + '\n', variables={'DEVICE': self.device, 'TAG': self.tag})
        finally:
            link.unlink(missing_ok=True)
        return self.tree / 'releases' / self.tag / f'release-{self.device}-{self.tag}'

    def verify(self, release, keys):
        """Prove the images chain to the owner's AVB key and the OTA to their release key."""
        images = release / f'{self.device}-img-{self.tag}.zip'
        work = self.cache / ('verify-' + self.device)
        shutil.rmtree(work, ignore_errors=True)
        work.mkdir()
        with zipfile.ZipFile(images) as archive:
            archive.extractall(work)
        give_to_builder(work)
        self.step('verify', '''
python3 "$TREE/external/avb/avbtool.py" verify_image --image vbmeta.img --follow_chain_partitions
python3 "$TREE/external/avb/avbtool.py" info_image --image vbmeta.img > vbmeta-info.txt
''', cwd=work, variables={'TREE': self.tree})
        match = re.search(r'Public key \(sha1\):\s+([0-9a-f]{40})', (work / 'vbmeta-info.txt').read_text())
        shutil.rmtree(work)
        if not match or match.group(1) != digest(keys / 'avb_pkmd.bin', 'sha1'):
            raise ValueError("vbmeta is not signed with the owner's AVB key")
        with zipfile.ZipFile(release / f'{self.device}-ota_update-{self.tag}.zip') as archive:
            if archive.read('META-INF/com/android/otacert') != (keys / 'releasekey.x509.pem').read_bytes():
                raise ValueError("OTA is not signed with the owner's release key")
        with zipfile.ZipFile(release / f'{self.device}-install-{self.tag}.zip') as archive:
            names = archive.namelist()
            pkmd = [name for name in names if name.endswith('/avb_pkmd.bin')]
            if (not any(name.endswith('/flash-all.sh') for name in names) or len(pkmd) != 1
                    or archive.read(pkmd[0]) != (keys / 'avb_pkmd.bin').read_bytes()):
                raise ValueError('Factory images do not carry the owner verified boot key')


def install_notes(config, fingerprint, *, about=None, unlock=None):
    device, tag = config['device'], config['tag']
    about = about or f'''Unofficial GrapheneOS build for the Google {config['model']} ({device})
Built by OpenFactory from the official GrapheneOS sources, release {tag}.
Signed with your own release and verified boot keys. OpenFactory is not affiliated
with the GrapheneOS project, and this build has not been tested on a phone.
'''
    unlock = unlock or '''1. Follow https://grapheneos.org/install/cli to enable OEM unlocking and run
   `fastboot flashing unlock` from the bootloader.
'''
    return f'''{about}
Verified boot key fingerprint (SHA-256 of avb_pkmd.bin):
{fingerprint}

First install (this erases the phone):
{unlock}2. Unzip images/{device}-install-{tag}.zip and run `bash flash-all.sh` inside it.
   It also installs your verified boot key.
3. Run `fastboot flashing lock` so the phone only boots builds signed with your key.

Updates: this build has no automatic updater. Build the next release in
OpenFactory with the same account and phone model, then sideload the update from
recovery with `adb sideload {device}-ota_update-<release>.zip`. A build signed
with other keys cannot be installed over this one without erasing the phone.
'''


def variant_install_notes(config, fingerprint, apps):
    listed = ''.join(f"- {app['package']} {app['version_name']} (version code {app['version_code']})\n"
        for app in apps) or '- none\n'
    return install_notes(config, fingerprint, about=f'''OpenFactory Phone for the Google {config['model']} ({config['device']})
OpenFactory Phone is a distinct OS based on GrapheneOS, built by OpenFactory from
the GrapheneOS sources of release {config['tag']} with its own branding and the apps
listed below. It is not GrapheneOS and is not affiliated with or endorsed by the
GrapheneOS project, so do not ask the GrapheneOS project for support with it.
This build has not been tested on a phone.

It is signed with your own release and verified boot keys, kept separately from
any stock GrapheneOS keys you have. Moving a phone between stock GrapheneOS and
OpenFactory Phone, in either direction, requires erasing it.

Apps added from F-Droid (https://f-droid.org), unmodified and signed by their
publishers, so F-Droid can keep them updated:
{listed}''', unlock='''1. Enable OEM unlocking in Settings > System > Developer options, then run
   `fastboot flashing unlock` from the bootloader.
''')


def package(config, release, keys, fingerprint, *, distribution='grapheneos', install_text=None, extra=None):
    device, tag = config['device'], config['tag']
    output = ROOT / 'output'
    output.mkdir(exist_ok=True)
    notes = output / 'INSTALL.txt'
    notes.write_text(install_text or install_notes(config, fingerprint))
    files = {f'images/{device}-install-{tag}.zip': release / f'{device}-install-{tag}.zip',
        f'images/{device}-ota_update-{tag}.zip': release / f'{device}-ota_update-{tag}.zip',
        'avb_pkmd.bin': keys / 'avb_pkmd.bin', 'INSTALL.txt': notes, 'LICENSE': ROOT / 'LICENSE'}
    if any(PRIVATE_KEY_NAME.search(name) for name in files):
        raise ValueError('Refusing to package private key material')
    manifest = {'schema_version': 1, 'distribution': distribution, 'board': device, 'device': device,
        'model': config['model'], 'architecture': 'aarch64', 'tag': tag, 'build_number': tag,
        'manifest_url': config['manifest_url'], 'manifest_commit': config['manifest_commit'],
        'avb_key_sha256': fingerprint, 'avb_verified': True, 'hardware_tested': False, 'runtime_tested': False,
        'images': [{'filename': f'images/{device}-install-{tag}.zip', 'type': 'factory'},
                   {'filename': f'images/{device}-ota_update-{tag}.zip', 'type': 'ota'}],
        'source_url': 'https://grapheneos.org/source',
        'builder_revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip(),
        'files': {name: digest(path) for name, path in sorted(files.items())}, **(extra or {})}
    temporary = output / f'{distribution}-factory.zip.tmp'
    with zipfile.ZipFile(temporary, 'w', compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
        for name, path in sorted(files.items()):
            archive.write(path, name)
        archive.writestr('manifest.json', json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    temporary.replace(output / f'{distribution}-factory.zip')
    return manifest


# OpenFactory Phone, part 1: compiled once per (tag, device) from a patched copy of the tree.

def variant_sha256(variant_dir=VARIANT_DIR):
    """Digest of the patch series and replacement files; changing either forces a recompile."""
    hasher = hashlib.sha256()
    for path in sorted(p for part in ('patches', 'files') for p in (variant_dir / part).rglob('*') if p.is_file()):
        hasher.update(f'{path.relative_to(variant_dir).as_posix()}\0{digest(path)}\n'.encode())
    return hasher.hexdigest()


def variant_outputs(cache, config):
    """The kept variant target files and otatools of (tag, device), and their marker."""
    base, device = cache / VARIANT, config['device']
    releases = base / 'releases' / config['tag']
    return (releases / f'{device}-target_files.zip', releases / f'{device}-otatools.zip',
        base / f'.openfactory-compiled-{device}')


def variant_compiled(cache, config, variant_dir=VARIANT_DIR):
    """The marker names the tag and the variant digest the kept outputs were compiled from."""
    *outputs, marker = variant_outputs(cache, config)
    return (marker.is_file() and marker.read_text().split() == [config['tag'], variant_sha256(variant_dir)]
        and all(path.is_file() for path in outputs))


def apply_variant(builder, variant_dir=VARIANT_DIR):
    """Patch the copied tree and replace its brand files; a failure names the patch or file.

    The copy is deleted on any failure, so nothing half-patched is ever compiled.
    """
    files = variant_dir / 'files'
    replacements = sorted(path for path in files.rglob('*') if path.is_file())
    for source in replacements:
        if not (builder.tree / source.relative_to(files)).is_file():
            raise ValueError(f'Variant file {source.relative_to(files)} replaces nothing in release {builder.tag}')
    # Without the ceiling, git would patch relative to a repository above the tree.
    apply = ['env', f'GIT_CEILING_DIRECTORIES={builder.tree.parent}', 'git', 'apply']
    for patch in sorted((variant_dir / 'patches').glob('*.patch')):
        for check in (['--check'], []):
            try:
                run_tool(builder.home, [*apply, *check], cwd=builder.tree, stdin=patch.read_bytes())
            except RuntimeError as error:
                raise ValueError(f'Variant patch {patch.name} does not apply to release {builder.tag}: {error}') from None
    for source in replacements:
        shutil.copyfile(source, builder.tree / source.relative_to(files))


def mentions(tree):
    """Each line naming GrapheneOS in an Android manifest or value resource, as 'path: line'."""
    found = set()
    for directory, subdirectories, files in os.walk(tree):
        here = Path(directory)
        if here == Path(tree):
            subdirectories[:] = [name for name in subdirectories
                if name not in {'.repo', 'out', 'prebuilts', 'releases', 'out_adevtool_deps'}]
        values = here.parent.name == 'res' and here.name.startswith('values')
        for name in files:
            path = here / name
            if (name == 'AndroidManifest.xml' or values and name.endswith('.xml')) and path.is_file():
                found.update(f'{path.relative_to(tree).as_posix()}: {line.decode(errors="replace").strip()}'
                    for line in path.read_bytes().splitlines() if b'GrapheneOS' in line)
    return found


def check_mentions(tree, variant_dir=VARIANT_DIR):
    kept = {line for line in (variant_dir / 'kept-mentions.txt').read_text().splitlines()
        if line.strip() and not line.startswith('#')}
    unlisted = sorted(mentions(tree) - kept)
    if unlisted:
        raise ValueError('OpenFactory Phone still names GrapheneOS where kept-mentions.txt does not allow it:\n  '
            + '\n  '.join(unlisted))


def branding_problems(badging, recovery, bootanimation_sha256, flash_all, variant_dir=VARIANT_DIR):
    """What still carries GrapheneOS branding in compiled or signed output; empty when nothing does."""
    animations = {digest(path) for path in (variant_dir / 'files/branding/bootanimation').glob('*.zip')}
    checks = {
        'the framework label is not OpenFactory Phone': "application-label:'OpenFactory Phone'" in badging.splitlines(),
        'recovery and fastbootd are not titled OpenFactory Phone': b'OpenFactory Phone Recovery' in recovery
            and b'OpenFactory Phone Fastboot' in recovery and b'GrapheneOS Recovery' not in recovery
            and b'GrapheneOS Fastboot' not in recovery,
        'the boot animation is not the OpenFactory Phone one': bootanimation_sha256 in animations,
        "flash-all does not point to the owner's INSTALL.txt": b'FOLLOW THE INSTALL.TXT' in flash_all
            and b'grapheneos.org/install/web' not in flash_all,
    }
    return [problem for problem, passed in checks.items() if not passed]


def check_compiled_variant(variant, variant_dir=VARIANT_DIR):
    """Prove the compiled target files and otatools carry the branding before they are kept."""
    target_files, otatools = variant.target_files()
    work = variant.tree / '.openfactory-check'
    work.mkdir()
    with zipfile.ZipFile(otatools) as archive:
        aapt2 = Path(archive.extract('bin/aapt2', work))
        flash_all = archive.read('device/common/generate-factory-images-common.sh')
    aapt2.chmod(0o755)
    with zipfile.ZipFile(target_files) as archive:
        framework = archive.extract('SYSTEM/framework/framework-res.apk', work)
        recovery = b''.join(archive.read(name) for name in archive.namelist()
            if name.endswith('RAMDISK/system/bin/recovery'))
        animation = hashlib.sha256(archive.read('PRODUCT/media/bootanimation.zip')).hexdigest()
    _, badging = run_tool(variant.home, [aapt2, 'dump', 'badging', framework], cwd=work)
    problems = branding_problems(badging, recovery, animation, flash_all, variant_dir)
    if problems:
        raise ValueError('The compiled OpenFactory Phone is not branded: ' + '; '.join(problems))


def ensure_variant_compiled(stock, variant_dir=VARIANT_DIR):
    """Compile OpenFactory Phone for (tag, device) once, in a patched reflink copy of the stock tree."""
    if variant_compiled(stock.cache, stock.config, variant_dir):
        return
    variant_digest = variant_sha256(variant_dir)
    target_files, otatools, marker = variant_outputs(stock.cache, stock.config)
    variant = Builder(stock.config, stock.cache)
    variant.tree, variant.logs = marker.parent / 'tree', marker.parent / 'logs'
    shutil.rmtree(variant.tree, ignore_errors=True)  # left behind by an interrupted run
    variant.logs.mkdir(parents=True, exist_ok=True)
    variant.tree.mkdir()
    try:
        if os.geteuid() == 0:
            owner = stock.tree.stat()
            os.chown(variant.tree, owner.st_uid, owner.st_gid)
        entries = [str(path) for path in stock.tree.iterdir() if path.name not in {'out', 'releases', 'keys'}]
        subprocess.run(['cp', '-a', REFLINK, *entries, str(variant.tree)], check=True)
        apply_variant(variant, variant_dir)
        check_mentions(variant.tree, variant_dir)
        variant.ensure_compiled(min_free=COMPILE_FREE_BYTES)
        check_compiled_variant(variant, variant_dir)
        for old in target_files.parent.parent.glob('*'):
            if old.name != stock.tag:
                shutil.rmtree(old)
        target_files.parent.mkdir(parents=True, exist_ok=True)
        for built, kept in zip(variant.target_files(), (target_files, otatools)):
            built.replace(kept)
        marker.write_text(f'{stock.tag}\n{variant_digest}\n')
    finally:
        shutil.rmtree(variant.tree, ignore_errors=True)


# OpenFactory Phone, part 2: apps and name added per owner, then the stock signing in a scratch tree.

def build_sdk(target_files):
    with zipfile.ZipFile(target_files) as archive:
        properties = archive.read('SYSTEM/build.prop').decode()
    return int(re.search(r'^ro\.build\.version\.sdk=(\d+)$', properties, re.M).group(1))


def welcome_title(display_name):
    return f'Welcome to {display_name}'


def resource_string(text):
    """text as an Android string resource: XML-escaped, quoted so spacing survives, apostrophes escaped."""
    return '"' + xml.sax.saxutils.escape(text).replace("'", "\\'") + '"'


def build_name_overlay(builder, title, target_files, otatools, sdk, work):
    """A static overlay that retitles the setup wizard's welcome screen, linked by upstream aapt2."""
    (work / 'res/values').mkdir(parents=True)
    with zipfile.ZipFile(otatools) as archive:
        aapt2 = Path(archive.extract('bin/aapt2', work))
    aapt2.chmod(0o755)
    with zipfile.ZipFile(target_files) as archive:
        framework = archive.extract('SYSTEM/framework/framework-res.apk', work)
    (work / 'AndroidManifest.xml').write_text(f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="tech.openfactory.phone.name"
    android:versionCode="1" android:versionName="1">
    <application android:hasCode="false"/>
    <overlay android:isStatic="true" android:priority="100" android:targetPackage="{SETUP_WIZARD}"/>
</manifest>
''')
    (work / 'res/values/strings.xml').write_text(f'''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="welcome_to_grapheneos">{resource_string(title)}</string>
</resources>
''')
    give_to_builder(work)
    run_tool(builder.home, [aapt2, 'compile', '--dir', 'res', '-o', 'res.zip'], cwd=work)
    run_tool(builder.home, [aapt2, 'link', '-o', NAME_OVERLAY, '--manifest', 'AndroidManifest.xml', '-I', framework,
        '--min-sdk-version', sdk, '--target-sdk-version', sdk, 'res.zip'], cwd=work)
    return work / NAME_OVERLAY


def inject(target_files, apks, overlay, stage):
    """Add F-Droid APKs ({package: path}) and the name overlay to a copy of the variant target files.

    APKs stay byte-identical (PRESIGNED), so F-Droid can update them. Their arm64
    libraries are pre-extracted because preinstalled apps never extract them.
    """
    with zipfile.ZipFile(target_files) as archive:
        names = {name.rstrip('/') for name in archive.namelist()}
        apkcerts = archive.read('META/apkcerts.txt').decode()
        fs_config = archive.read('META/product_filesystem_config.txt').decode()
        info = dict(line.split('=', 1) for meta in ('META/misc_info.txt', 'META/dynamic_partitions_info.txt')
            for line in archive.read(meta).decode().splitlines() if '=' in line)
        sizes = {item.filename: item.file_size for item in archive.infolist()}
    entries, certificates = {}, []  # zip member -> source file, or None for a directory
    for package, apk in apks.items():
        name = f'OFApp_{package}'
        folder = f'PRODUCT/app/{name}'
        entries.update({folder: None, f'{folder}/{name}.apk': apk})
        certificates.append(f'name="{name}.apk" certificate="PRESIGNED" private_key="" partition="product"')
        with zipfile.ZipFile(apk) as archive:
            libraries = [member for member in archive.namelist() if member.startswith('lib/') and member.endswith('.so')]
            arm64 = [member for member in libraries if member.count('/') == 2 and member.startswith('lib/arm64-v8a/')]
            if libraries and not arm64:
                raise ValueError(f'{package} carries native code but no arm64-v8a libraries')
            for member in arm64:
                library = stage / folder / 'lib/arm64' / Path(member).name
                library.parent.mkdir(parents=True, exist_ok=True)
                library.write_bytes(archive.read(member))
                entries.update({f'{folder}/lib': None, f'{folder}/lib/arm64': None,
                    f'{folder}/lib/arm64/{library.name}': library})
    if overlay:
        gos = re.search(r'^name="GosOverlay\.apk" (certificate="[^"]*" private_key="[^"]*") partition="product"$',
            apkcerts, re.M)
        if not gos:
            raise ValueError('META/apkcerts.txt has no GosOverlay.apk key mapping to give the name overlay')
        entries[f'PRODUCT/overlay/{NAME_OVERLAY}'] = overlay
        certificates.append(f'name="{NAME_OVERLAY}" {gos.group(1)} partition="product"')
    signed = set(re.findall(r'^name="([^"]+)"', apkcerts, re.M))
    collisions = sorted(set(entries) & names) + sorted({re.match(r'name="([^"]+)"', line).group(1)
        for line in certificates} & signed)
    if collisions:
        raise ValueError('Added apps collide with files already in the image: ' + ', '.join(collisions))
    if not entries:
        return
    group = next((key[len('super_'):-len('_partition_list')] for key, value in info.items()
        if key.startswith('super_') and key.endswith('_partition_list') and 'product' in value.split()), None)
    if group is None:
        raise ValueError('The target files place no product partition in a super partition group')
    limit = min(int(info[f'super_{group}_group_size']), int(info.get('super_partition_error_limit', 1 << 62)))
    used = sum(sizes.get(f'IMAGES/{partition}.img', 0) for partition in info[f'super_{group}_partition_list'].split())
    added = sum(-(-Path(source).stat().st_size // 4096) * 4096 for source in entries.values() if source)
    if used + added + SUPER_MARGIN > limit:
        raise ValueError(f'The added apps need {added // 1024 ** 2} MiB but the super partition has only '
            f'{max(limit - used - SUPER_MARGIN, 0) // 1024 ** 2} MiB to spare')
    for member, source in entries.items():
        target = stage / member
        if source is None:
            target.mkdir(parents=True, exist_ok=True)
        elif Path(source) != target:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(Path(source).resolve())  # zip stores what a link points to
    (stage / 'META').mkdir(parents=True, exist_ok=True)
    (stage / 'META/apkcerts.txt').write_text(apkcerts.rstrip('\n') + '\n' + '\n'.join(certificates) + '\n')
    (stage / 'META/product_filesystem_config.txt').write_text(fs_config.rstrip('\n') + '\n' + ''.join(
        f"product/{member[len('PRODUCT/'):]} 0 0 {'755' if source is None else '644'} capabilities=0x0\n"
        for member, source in entries.items()))
    # One Info-ZIP update rewrites the Zip64 copy once; members it is not given stay as they were.
    subprocess.run(['zip', '-X', '-0', '-q', str(target_files), *(member + '/' if source is None else member
        for member, source in entries.items()), 'META/apkcerts.txt', 'META/product_filesystem_config.txt'],
        cwd=stage, check=True)


def verify_jar(builder, jar):
    """jarsigner -strict exit status and keytool's signer certificates, from the tree's own JDK."""
    jdks = sorted(builder.tree.glob('prebuilts/jdk/jdk*/linux-x86/bin'),
        key=lambda path: int(re.sub(r'\D', '', path.parents[1].name) or 0))
    if not jdks:
        raise RuntimeError('No JDK under prebuilts/jdk to verify F-Droid signatures with')
    status, _ = run_tool(builder.home, [jdks[-1] / 'jarsigner', '-verify', '-strict', jar], cwd=jar.parent,
        ok=range(256))
    _, certificates = run_tool(builder.home, [jdks[-1] / 'keytool', '-printcert', '-rfc', '-jarfile', jar],
        cwd=jar.parent)
    return status, certificates


def read_back(signer, release, apps, title, variant_dir=VARIANT_DIR):
    """Pull each added APK, the name overlay and the branding back out of the signed images."""
    device, tag = signer.device, signer.tag
    work = signer.tree / 'readback'
    (work / 'out').mkdir(parents=True)
    with zipfile.ZipFile(release / f'{device}-img-{tag}.zip') as archive:
        for image in ('product.img', 'system.img', 'vendor_boot.img'):
            archive.extract(image, work)
    wanted = [*(f"/app/OFApp_{app['package']}/OFApp_{app['package']}.apk" for app in apps),
        '/media/bootanimation.zip', *([f'/overlay/{NAME_OVERLAY}'] if title else [])]
    (work / 'product.cmd').write_text(''.join(f'dump {path} out/{index}\n' for index, path in enumerate(wanted)))
    give_to_builder(work)
    signer.step('readback', '''
"$BIN/debugfs_static" -f product.cmd product.img
"$BIN/debugfs_static" -R "dump /system/framework/framework-res.apk framework-res.apk" system.img
"$BIN/aapt2" dump badging framework-res.apk > badging.txt
"$BIN/unpack_bootimg" --boot_img vendor_boot.img --out vendor_boot > /dev/null
for ramdisk in vendor_boot/vendor_ramdisk[0-9]*; do "$BIN/lz4" -d -c "$ramdisk"; done > ramdisk.cpio
if [ -n "$OVERLAY" ]; then "$BIN/aapt2" dump strings "$OVERLAY" > overlay.txt; fi
''', cwd=work, variables={'BIN': release / 'bin', 'OVERLAY': f'out/{len(wanted) - 1}' if title else ''})
    out = [work / 'out' / str(index) for index in range(len(wanted))]
    for app, path in zip(apps, out):
        if not path.is_file() or digest(path) != app['apk_sha256']:
            raise ValueError(f"{app['package']} read back from the signed product image does not match F-Droid's APK")
    with zipfile.ZipFile(release / f'{device}-install-{tag}.zip') as archive:
        flash_all = b''.join(archive.read(name) for name in archive.namelist() if name.endswith('/flash-all.sh'))
    animation = out[len(apps)]
    problems = branding_problems((work / 'badging.txt').read_text(), (work / 'ramdisk.cpio').read_bytes(),
        digest(animation) if animation.is_file() else '', flash_all, variant_dir)
    if problems:
        raise ValueError('The signed OpenFactory Phone images are not branded: ' + '; '.join(problems))
    if not title:
        return {'apps': True, 'branding': True, 'name_overlay': None}
    with zipfile.ZipFile(release / f'{device}-target_files.zip') as archive:
        overlay_sha256 = hashlib.sha256(archive.read(f'PRODUCT/overlay/{NAME_OVERLAY}')).hexdigest()
    strings = [line.split(' : ', 1)[-1] for line in (work / 'overlay.txt').read_text().splitlines()]
    if not out[-1].is_file() or digest(out[-1]) != overlay_sha256 or title not in strings:
        raise ValueError('The name overlay read back from the signed product image is not the one built')
    return {'apps': True, 'branding': True, 'name_overlay': True}


def build_variant(stock, keys, password, variant_dir=VARIANT_DIR):
    """Sign OpenFactory Phone for one owner in a scratch tree; the cached outputs and src are only read."""
    config, cache = stock.config, stock.cache
    *compiled, _marker = variant_outputs(cache, config)
    scratch = cache / VARIANT / f'sign-{stock.device}'
    shutil.rmtree(scratch, ignore_errors=True)
    releases = scratch / 'releases' / stock.tag
    releases.mkdir(parents=True)
    try:
        target_files, otatools = (releases / path.name for path in compiled)
        for source, copy in zip(compiled, (target_files, otatools)):
            subprocess.run(['cp', REFLINK, str(source), str(copy)], check=True)
        # generate-release.sh reads script/, prebuilts/, releases/<tag>/ and keys/<device> relative to the tree.
        for name in ('script', 'prebuilts'):
            (scratch / name).symlink_to(stock.tree / name)
        sdk = build_sdk(target_files)
        apps = []
        if config['apps']:
            index = fdroid.fetch_index(cache / 'fdroid', lambda jar: verify_jar(stock, jar),
                fdroid.pinned_signer(FDROID_SIGNER))
            apps = fdroid.choose(index, config['apps'], sdk)
        apks = fdroid.download_apks(cache / 'fdroid', apps)
        title = config['display_name'] and welcome_title(config['display_name'])
        overlay = title and build_name_overlay(stock, title, target_files, otatools, sdk, scratch / 'overlay')
        inject(target_files, apks, overlay, scratch / 'stage')
        signer = Builder(config, cache)
        signer.tree, signer.logs, signer.redact = scratch, cache / VARIANT / 'logs', stock.redact
        signer.logs.mkdir(exist_ok=True)
        give_to_builder(scratch)
        release = signer.sign(keys, password)
        stock.verify(release, keys)
        readback = read_back(signer, release, apps, title, variant_dir)
        fingerprint = digest(keys / 'avb_pkmd.bin')
        manifest = package(config, release, keys, fingerprint, distribution=VARIANT,
            install_text=variant_install_notes(config, fingerprint, apps), extra={
                'based_on': {'distribution': 'grapheneos', 'tag': config['tag'],
                    'manifest_commit': config['manifest_commit']},
                'variant_sha256': variant_sha256(variant_dir), 'display_name': config['display_name'],
                'apps': [fdroid.manifest_entry(app) for app in apps], 'readback': readback})
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return manifest, fingerprint


def main(argv):
    config = read_config(ROOT / 'config/grapheneos.json')
    cache = Path(os.environ.get('GRAPHENEOS_CACHE_DIR') or ROOT / '.cache').resolve()
    cache.mkdir(parents=True, exist_ok=True)
    prepare_only = argv[1:] == ['prepare']
    variant = config.get('variant')
    if not prepare_only:
        secrets, password = secrets_dir(cache)
    with (cache / '.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        builder = Builder(config, cache)
        builder.prepare_cache()
        if prepare_only:
            builder.prepare(ensure_variant_compiled if variant else None)
            print(json.dumps({'prepared': config['device'], 'tag': config['tag'],
                **({'variant': variant} if variant else {})}), flush=True)
            return
        # Compiling takes hours and needs an operator's resources, not a build slot's.
        if not builder.compiled():
            raise SystemExit(f"GrapheneOS {config['tag']} is not compiled for the {config['model']} "
                f"({config['device']}) in this cache; run ./build.sh prepare for it first")
        if variant and not variant_compiled(cache, config):
            raise SystemExit(f"OpenFactory Phone {config['tag']} is not compiled for the {config['model']} "
                f"({config['device']}) in this cache; run ./build.sh prepare with this configuration first")
        builder.redact.append(password)
        keys = secrets / 'keys' / config['device']
        give_to_builder(secrets)
        builder.ensure_keys(keys, password)
        if variant:
            manifest, fingerprint = build_variant(builder, keys, password)
        else:
            release = builder.sign(keys, password)
            try:
                builder.verify(release, keys)
                fingerprint = digest(keys / 'avb_pkmd.bin')
                manifest = package(config, release, keys, fingerprint)
            finally:
                shutil.rmtree(release, ignore_errors=True)
    print(json.dumps({'artifact': f"output/{manifest['distribution']}-factory.zip", 'board': manifest['board'],
        'avb_key_sha256': fingerprint, 'hardware_tested': False}), flush=True)


if __name__ == '__main__':
    main(sys.argv)
