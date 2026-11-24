"""Fetch apps from the official F-Droid repository, verified against its pinned signing key.

F-Droid signs entry.jar; entry.json inside it names index-v2.json by SHA-256 and
size, and the index names every APK by SHA-256 and size. So one pinned
certificate fingerprint covers every byte that ends up in an image.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re
import urllib.request
import zipfile

REPO = 'https://f-droid.org/repo'
ARM64 = 'arm64-v8a'
TIMEOUT = 60


def pinned_signer(path):
    """The SHA-256 of F-Droid's repo signing certificate, from keys/fdroid-repo.sha256."""
    value = Path(path).read_text().split()[0].lower()
    if not re.fullmatch(r'[0-9a-f]{64}', value):
        raise ValueError(f'{path} does not hold a SHA-256 fingerprint')
    return value


def certificate_digests(pem):
    """SHA-256 of each certificate in keytool -printcert -rfc output."""
    blocks = re.findall(r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', pem, re.S)
    return [hashlib.sha256(base64.b64decode(''.join(block.split()))).hexdigest() for block in blocks]


def read_entry(jar, jarsigner_status, signer_pem, pinned):
    """entry.json, once jarsigner -strict and the pinned certificate both vouch for it.

    jarsigner -strict exits 4 when the only finding is that the signer is
    self-signed, which F-Droid's repo key is; the pin replaces the chain.
    Unsigned entries, bad digests and unknown signers all fail.
    """
    if jarsigner_status not in (0, 4):
        raise ValueError(f'F-Droid entry.jar failed signature verification (jarsigner exit {jarsigner_status})')
    if certificate_digests(signer_pem) != [pinned]:
        raise ValueError('F-Droid entry.jar is not signed by the pinned F-Droid repo key')
    with zipfile.ZipFile(jar) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or 'entry.json' not in names:
            raise ValueError('F-Droid entry.jar is malformed')
        entry = json.loads(archive.read('entry.json'))
    index = entry.get('index') or {}
    if (index.get('name') != '/index-v2.json' or not re.fullmatch(r'[0-9a-f]{64}', str(index.get('sha256', '')))
            or not isinstance(index.get('size'), int)):
        raise ValueError('F-Droid entry.json does not describe index-v2.json')
    return entry


def download(url, destination, sha256, size):
    """Fetch url to destination unless a verified copy is already there."""
    destination = Path(destination)
    if destination.is_file() and destination.stat().st_size == size and _sha256(destination) == sha256:
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + '.part')
    hasher, length = hashlib.sha256(), 0
    with urllib.request.urlopen(url, timeout=TIMEOUT) as response, temporary.open('wb') as output:
        while chunk := response.read(1 << 20):
            length += len(chunk)
            if length > size:
                break
            hasher.update(chunk)
            output.write(chunk)
    if length != size or hasher.hexdigest() != sha256:
        temporary.unlink()
        raise ValueError(f'{url} does not match the size and SHA-256 its signed F-Droid index gives')
    temporary.replace(destination)
    return destination


def fetch_index(directory, verify_jar, pinned):
    """The verified index-v2.json. verify_jar(path) returns (jarsigner -strict exit, keytool -rfc text)."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    jar = directory / 'entry.jar'
    with urllib.request.urlopen(f'{REPO}/entry.jar', timeout=TIMEOUT) as response:
        jar.write_bytes(response.read(1 << 20))
    entry = read_entry(jar, *verify_jar(jar), pinned)['index']
    path = download(REPO + entry['name'], directory / 'index-v2.json', entry['sha256'], entry['size'])
    return json.loads(path.read_text())


def _sha256(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def choose(index, app_ids, sdk):
    """Pick, per application ID, the newest stable version signed by the app's preferred
    signer that runs on this SDK and on arm64 (or carries no native code)."""
    packages = index.get('packages', {})
    unknown = [app for app in app_ids if app not in packages]
    if unknown:
        raise ValueError('Not in the F-Droid repository: ' + ', '.join(unknown))
    chosen = []
    for app in app_ids:
        versions = [version for version in packages[app].get('versions', {}).values()
            if not version.get('releaseChannels')]
        if not versions:
            raise ValueError(f'{app} has no stable release on F-Droid')
        newest = max(versions, key=lambda version: version['manifest']['versionCode'])
        signer = packages[app].get('metadata', {}).get('preferredSigner') or newest['manifest']['signer']['sha256'][0]
        usable = [version for version in versions
            if signer in version['manifest'].get('signer', {}).get('sha256', [])
            and version['manifest'].get('usesSdk', {}).get('minSdkVersion', 1) <= sdk
            and version['manifest'].get('usesSdk', {}).get('maxSdkVersion', sdk) >= sdk]
        runs = [version for version in usable
            if not version['manifest'].get('nativecode') or ARM64 in version['manifest']['nativecode']]
        if not runs:
            if usable:
                raise ValueError(f'{app} has no arm64-v8a build on F-Droid (only '
                    + ', '.join(sorted({abi for v in usable for abi in v['manifest']['nativecode']})) + ')')
            raise ValueError(f'{app} has no stable F-Droid release signed by its developer key for SDK {sdk}')
        version = max(runs, key=lambda version: version['manifest']['versionCode'])
        chosen.append({'package': app, 'version_code': version['manifest']['versionCode'],
            'version_name': version['manifest'].get('versionName', ''), 'apk_sha256': version['file']['sha256'],
            'signer_sha256': signer, 'anti_features': sorted(version.get('antiFeatures') or {}),
            'file': version['file']['name'], 'size': version['file']['size']})
    return chosen


def download_apks(directory, chosen):
    """Each chosen APK, by SHA-256, as {package: path}."""
    apks = Path(directory) / 'apks'
    return {app['package']: download(REPO + app['file'], apks / f"{app['apk_sha256']}.apk", app['apk_sha256'],
        app['size']) for app in chosen}


def manifest_entry(app):
    """The fields manifest.json records for an app."""
    return {key: app[key] for key in ('package', 'version_code', 'version_name', 'apk_sha256', 'signer_sha256',
        'anti_features')}

