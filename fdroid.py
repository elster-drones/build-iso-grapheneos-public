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
import time
import urllib.request
import zipfile

REPO = 'https://f-droid.org/repo'
ARM64 = 'arm64-v8a'
TIMEOUT = 60
# The whole fetch (entry, index, APKs) must finish within this; downloads kept so far let a retry resume.
DEADLINE = 5 * 60
MAX_AGE_MS = 30 * 24 * 3600 * 1000


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

    jarsigner -strict exits 4 for a certificate chain it cannot validate: F-Droid's
    self-signed repo key, but also an expired certificate. It exits 0 for a jar
    that carries no signature at all. So the exit status only rules out bad
    digests (1) and unsigned entries (16); the pin is what decides, and a jar with
    no signer or another signer fails it.
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
    if (not isinstance(entry.get('timestamp'), int) or index.get('name') != '/index-v2.json' or not re.fullmatch(r'[0-9a-f]{64}', str(index.get('sha256', '')))
            or not isinstance(index.get('size'), int)):
        raise ValueError('F-Droid entry.json does not describe index-v2.json')
    return entry


def _time_left(deadline):
    """Seconds a network operation may still take, or a loud failure once the deadline has passed."""
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError(f'Fetching from F-Droid took longer than {DEADLINE // 60} minutes; '
            'verified downloads are kept, so a retry continues from them')
    return min(TIMEOUT, left)


def _chunks(url, deadline):
    """The body of url in chunks. Each read returns what one receive brings and may not block past the
    deadline, so a server dripping bytes cannot hold the fetch beyond it either."""
    with urllib.request.urlopen(url, timeout=_time_left(deadline)) as response:
        sock = getattr(getattr(getattr(response, 'fp', None), 'raw', None), '_sock', None)
        read = getattr(response, 'read1', response.read)
        while True:
            if sock is not None:
                sock.settimeout(_time_left(deadline))
            try:
                chunk = read(1 << 20)
            except TimeoutError:
                _time_left(deadline)
                raise
            if not chunk:
                return
            _time_left(deadline)
            yield chunk


def download(url, destination, sha256, size, deadline=None):
    """Fetch url to destination unless a verified copy is already there."""
    deadline = deadline or time.monotonic() + DEADLINE
    destination = Path(destination)
    if destination.is_file() and destination.stat().st_size == size and _sha256(destination) == sha256:
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + '.part')
    hasher, length = hashlib.sha256(), 0
    try:
        with temporary.open('wb') as output:
            for chunk in _chunks(url, deadline):
                length += len(chunk)
                if length > size:
                    break
                hasher.update(chunk)
                output.write(chunk)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    if length != size or hasher.hexdigest() != sha256:
        temporary.unlink()
        raise ValueError(f'{url} does not match the size and SHA-256 its signed F-Droid index gives')
    temporary.replace(destination)
    return destination


def check_fresh(directory, timestamp, now_ms=None):
    """Refuse an entry older than one already seen here (a replay) or older than 30 days."""
    seen = Path(directory) / 'entry-timestamp'
    last = int(seen.read_text()) if seen.is_file() else 0
    if timestamp < last:
        raise ValueError(f'F-Droid served an index older than one already seen ({timestamp} < {last}); '
            'refusing a replayed index')
    if timestamp < (now_ms or time.time() * 1000) - MAX_AGE_MS:
        raise ValueError('F-Droid served an index more than 30 days old; refusing a stale index')
    return seen


def fetch_index(directory, verify_jar, pinned, deadline=None):
    """The verified index-v2.json. verify_jar(path) returns (jarsigner -strict exit, keytool -rfc text)."""
    deadline = deadline or time.monotonic() + DEADLINE
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    jar = directory / 'entry.jar'
    data = b''
    for chunk in _chunks(f'{REPO}/entry.jar', deadline):
        data += chunk
        if len(data) > 1 << 20:
            raise ValueError('F-Droid entry.jar is larger than 1 MiB')
    jar.write_bytes(data)
    entry = read_entry(jar, *verify_jar(jar), pinned)
    seen = check_fresh(directory, entry['timestamp'])
    path = download(REPO + entry['index']['name'], directory / 'index-v2.json', entry['index']['sha256'],
        entry['index']['size'], deadline)
    index = json.loads(path.read_text())
    seen.write_text(f"{entry['timestamp']}\n")
    return index


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


def download_apks(directory, chosen, deadline=None):
    """Each chosen APK, by SHA-256, as {package: path}."""
    deadline = deadline or time.monotonic() + DEADLINE
    apks = Path(directory) / 'apks'
    return {app['package']: download(REPO + app['file'], apks / f"{app['apk_sha256']}.apk", app['apk_sha256'],
        app['size'], deadline) for app in chosen}


def manifest_entry(app):
    """The fields manifest.json records for an app."""
    return {key: app[key] for key in ('package', 'version_code', 'version_name', 'apk_sha256', 'signer_sha256',
        'anti_features')}

