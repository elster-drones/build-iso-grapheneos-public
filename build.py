#!/usr/bin/env python3
"""Build GrapheneOS from its official sources and sign it with the owner's keys.

Upstream owns the source tree, Pixel vendor extraction (adevtool), compilation
and release signing (script/generate-release.sh). This adapter pins a signed
release tag, runs those tools as an unprivileged account, and packages the
signed output with provenance.

The compiled target files depend only on (release tag, device), so they are
built once into the cache and every later build of that pair only signs.
"""
from __future__ import annotations

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
import zipfile

ROOT = Path(__file__).resolve().parent
MANIFEST_URL = 'https://github.com/GrapheneOS/platform_manifest.git'
BUILD_USER = os.environ.get('GRAPHENEOS_BUILD_USER', 'of-grapheneos')
# Mirrors upstream script/build-releases: these Pixels have no vendor_kernel_boot.
NO_VENDOR_KERNEL_BOOT = {'bluejay', 'raven', 'oriole'}
KEY_SUBJECT = '/CN=OpenFactory GrapheneOS build/'
PRIVATE_KEY_NAME = re.compile(r'(\.pk8|\.pem|\.gpg|id_ed25519)$')


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
        self.tree = cache / ('src-' + self.tag)
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

    def prepare_cache(self):
        for path in (self.home / 'bin', self.logs, self.tree):
            path.mkdir(parents=True, exist_ok=True)
        node24 = shutil.which('node-24')
        if node24 and not (self.home / 'bin/node').exists():
            (self.home / 'bin/node').symlink_to(node24)
        shutil.copy2(ROOT / 'keys/grapheneos_allowed_signers', self.home / 'grapheneos_allowed_signers')
        give_to_builder(self.home)
        # The synced tree is ~140 GiB; re-owning it every build would take minutes.
        give_to_builder(self.tree, only_if_needed=True)

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

    def ensure_vendor(self):
        if (self.tree / f'.openfactory-vendor-{self.device}').is_file():
            return
        self.step('vendor', '''
source build/envsetup.sh >/dev/null
adevtool generate-all -d "$DEVICE"
touch ".openfactory-vendor-$DEVICE"
''', variables={'DEVICE': self.device})

    def target_files(self):
        releases = self.tree / 'releases' / self.tag
        return releases / f'{self.device}-target_files.zip', releases / f'{self.device}-otatools.zip'

    def ensure_compiled(self):
        if (self.tree / f'.openfactory-compiled-{self.device}').is_file() and all(p.is_file() for p in self.target_files()):
            return
        targets = 'vendorbootimage target-files-package otatools-package'
        if self.device not in NO_VENDOR_KERNEL_BOOT:
            targets = 'vendorbootimage vendorkernelbootimage target-files-package otatools-package'
        self.step('compile', f'''
rm -rf out
source build/envsetup.sh >/dev/null
lunch "$DEVICE-cur-user"
m ${{GRAPHENEOS_JOBS:+-j$GRAPHENEOS_JOBS}} {targets}
script/finalize.sh
rm -rf out
touch ".openfactory-compiled-$DEVICE"
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


def install_notes(config, fingerprint):
    device, tag = config['device'], config['tag']
    return f'''Unofficial GrapheneOS build for the Google {config['model']} ({device})
Built by OpenFactory from the official GrapheneOS sources, release {tag}.
Signed with your own release and verified boot keys. OpenFactory is not affiliated
with the GrapheneOS project, and this build has not been tested on a phone.

Verified boot key fingerprint (SHA-256 of avb_pkmd.bin):
{fingerprint}

First install (this erases the phone):
1. Follow https://grapheneos.org/install/cli to enable OEM unlocking and run
   `fastboot flashing unlock` from the bootloader.
2. Unzip images/{device}-install-{tag}.zip and run `bash flash-all.sh` inside it.
   It also installs your verified boot key.
3. Run `fastboot flashing lock` so the phone only boots builds signed with your key.

Updates: this build has no automatic updater. Build the next release in
OpenFactory with the same account and phone model, then sideload the update from
recovery with `adb sideload {device}-ota_update-<release>.zip`. A build signed
with other keys cannot be installed over this one without erasing the phone.
'''


def package(config, release, keys, fingerprint):
    device, tag = config['device'], config['tag']
    output = ROOT / 'output'
    output.mkdir(exist_ok=True)
    notes = output / 'INSTALL.txt'
    notes.write_text(install_notes(config, fingerprint))
    files = {f'images/{device}-install-{tag}.zip': release / f'{device}-install-{tag}.zip',
        f'images/{device}-ota_update-{tag}.zip': release / f'{device}-ota_update-{tag}.zip',
        'avb_pkmd.bin': keys / 'avb_pkmd.bin', 'INSTALL.txt': notes, 'LICENSE': ROOT / 'LICENSE'}
    if any(PRIVATE_KEY_NAME.search(name) for name in files):
        raise ValueError('Refusing to package private key material')
    manifest = {'schema_version': 1, 'distribution': 'grapheneos', 'board': device, 'device': device,
        'model': config['model'], 'architecture': 'aarch64', 'tag': tag, 'build_number': tag,
        'manifest_url': config['manifest_url'], 'manifest_commit': config['manifest_commit'],
        'avb_key_sha256': fingerprint, 'avb_verified': True, 'hardware_tested': False, 'runtime_tested': False,
        'images': [{'filename': f'images/{device}-install-{tag}.zip', 'type': 'factory'},
                   {'filename': f'images/{device}-ota_update-{tag}.zip', 'type': 'ota'}],
        'source_url': 'https://grapheneos.org/source',
        'builder_revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip(),
        'files': {name: digest(path) for name, path in sorted(files.items())}}
    temporary = output / 'grapheneos-factory.zip.tmp'
    with zipfile.ZipFile(temporary, 'w', compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
        for name, path in sorted(files.items()):
            archive.write(path, name)
        archive.writestr('manifest.json', json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    temporary.replace(output / 'grapheneos-factory.zip')
    return manifest


def main(argv):
    config = read_config(ROOT / 'config/grapheneos.json')
    cache = Path(os.environ.get('GRAPHENEOS_CACHE_DIR') or ROOT / '.cache').resolve()
    cache.mkdir(parents=True, exist_ok=True)
    prepare_only = argv[1:] == ['prepare']
    if not prepare_only:
        secrets, password = secrets_dir(cache)
    with (cache / '.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        builder = Builder(config, cache)
        builder.prepare_cache()
        builder.ensure_source()
        builder.ensure_vendor()
        builder.ensure_compiled()
        if prepare_only:
            print(json.dumps({'prepared': config['device'], 'tag': config['tag']}), flush=True)
            return
        builder.redact.append(password)
        keys = secrets / 'keys' / config['device']
        give_to_builder(secrets)
        builder.ensure_keys(keys, password)
        release = builder.sign(keys, password)
        try:
            builder.verify(release, keys)
            fingerprint = digest(keys / 'avb_pkmd.bin')
            manifest = package(config, release, keys, fingerprint)
        finally:
            shutil.rmtree(release, ignore_errors=True)
    print(json.dumps({'artifact': 'output/grapheneos-factory.zip', 'board': manifest['board'],
        'avb_key_sha256': fingerprint, 'hardware_tested': False}), flush=True)


if __name__ == '__main__':
    main(sys.argv)
