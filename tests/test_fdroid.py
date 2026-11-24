import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('fdroid', ROOT / 'fdroid.py')
fdroid = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fdroid)

PINNED = fdroid.pinned_signer(ROOT / 'keys/fdroid-repo.sha256')
DEVELOPER, OTHER = 'd' * 64, 'e' * 64
# keytool -printcert -rfc shape; the body is any DER, its SHA-256 is what is pinned.
PEM = '-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n'
NOW_MS = int(time.time() * 1000)
DER = b'pinned-der'
SIGNER = PEM.format(base64.b64encode(DER).decode())


def version(code, *, signer=DEVELOPER, abis=None, min_sdk=24, beta=False, anti=None):
    manifest = {'versionCode': code, 'versionName': f'1.{code}', 'signer': {'sha256': [signer]},
        'usesSdk': {'minSdkVersion': min_sdk, 'targetSdkVersion': 35}}
    if abis is not None:
        manifest['nativecode'] = abis
    entry = {'file': {'name': f'/app_{code}.apk', 'sha256': f'{code:064x}', 'size': code}, 'manifest': manifest}
    if beta:
        entry['releaseChannels'] = ['Beta']
    if anti:
        entry['antiFeatures'] = {name: {'en-US': 'why'} for name in anti}
    return entry


def index(**packages):
    return {'packages': {name: {'metadata': {'preferredSigner': DEVELOPER}, 'versions': {str(i): v
        for i, v in enumerate(versions)}} for name, versions in packages.items()}}


class ChooseTests(unittest.TestCase):
    def test_picks_the_newest_stable_arm64_or_universal_version_from_the_preferred_signer(self):
        chosen = fdroid.choose(index(**{
            'org.example.app': [version(10), version(12, abis=['arm64-v8a', 'armeabi-v7a'], anti=['Tracking']),
                version(13, beta=True), version(14, signer=OTHER), version(15, min_sdk=40),
                version(16, abis=['x86_64'])]}), ['org.example.app'], 37)
        self.assertEqual([(app['version_code'], app['signer_sha256'], app['anti_features']) for app in chosen],
            [(12, DEVELOPER, ['Tracking'])])
        self.assertEqual(fdroid.manifest_entry(chosen[0]), {'package': 'org.example.app', 'version_code': 12,
            'version_name': '1.12', 'apk_sha256': f'{12:064x}', 'signer_sha256': DEVELOPER,
            'anti_features': ['Tracking']})

    def test_universal_apps_without_native_code_are_accepted(self):
        self.assertEqual(fdroid.choose(index(**{'org.example.app': [version(3)]}), ['org.example.app'], 37)[0]
            ['version_code'], 3)

    def test_unknown_ids_32_bit_only_and_unsigned_apps_fail_loudly(self):
        repo = index(**{'org.example.old': [version(5, abis=['armeabi-v7a', 'x86'])],
            'org.example.foreign': [version(5, signer=OTHER)], 'org.example.beta': [version(5, beta=True)]})
        with self.assertRaisesRegex(ValueError, 'org.missing.one, org.missing.two'):
            fdroid.choose(repo, ['org.example.old', 'org.missing.one', 'org.missing.two'], 37)
        with self.assertRaisesRegex(ValueError, 'no arm64-v8a build.*armeabi-v7a, x86'):
            fdroid.choose(repo, ['org.example.old'], 37)
        with self.assertRaisesRegex(ValueError, 'signed by its developer key'):
            fdroid.choose(repo, ['org.example.foreign'], 37)
        with self.assertRaisesRegex(ValueError, 'no stable release'):
            fdroid.choose(repo, ['org.example.beta'], 37)


class EntryTests(unittest.TestCase):
    def entry_jar(self, directory, entry=None, extra=()):
        jar = Path(directory) / 'entry.jar'
        with zipfile.ZipFile(jar, 'w') as archive:
            archive.writestr('entry.json', json.dumps(entry or {'timestamp': NOW_MS, 'index': {
                'name': '/index-v2.json', 'sha256': 'a' * 64, 'size': 10}}))
            for name in extra:
                archive.writestr(name, b'x')
        return jar

    def test_accepts_the_pinned_self_signed_repo_key_only(self):
        der = b'pinned-der'
        pem = PEM.format(base64.b64encode(der).decode())
        with tempfile.TemporaryDirectory() as directory:
            jar = self.entry_jar(directory)
            pinned = hashlib.sha256(der).hexdigest()
            self.assertEqual(fdroid.read_entry(jar, 4, pem, pinned)['index']['size'], 10)
            self.assertEqual(fdroid.read_entry(jar, 0, pem, pinned)['index']['size'], 10)
            for status in (1, 16, 20):  # bad digest, unsigned entry, unsigned entry and self-signed
                with self.assertRaisesRegex(ValueError, 'signature verification'):
                    fdroid.read_entry(jar, status, pem, pinned)
            with self.assertRaisesRegex(ValueError, 'pinned'):
                fdroid.read_entry(jar, 4, pem, PINNED)
            with self.assertRaisesRegex(ValueError, 'pinned'):
                fdroid.read_entry(jar, 4, pem + pem, pinned)

    def test_entry_must_name_index_v2_by_hash_and_size(self):
        der = b'pinned-der'
        pem = PEM.format(base64.b64encode(der).decode())
        with tempfile.TemporaryDirectory() as directory:
            for entry in [{'timestamp': NOW_MS, 'index': {'name': '/index-v1.json', 'sha256': 'a' * 64, 'size': 1}},
                    {'index': {'name': '/index-v2.json', 'sha256': 'a' * 64, 'size': 1}}]:
                jar = self.entry_jar(directory, entry)
                with self.assertRaisesRegex(ValueError, 'index-v2'):
                    fdroid.read_entry(jar, 4, pem, hashlib.sha256(der).hexdigest())

    def test_a_replayed_or_month_old_index_is_refused_and_a_fresh_one_remembered(self):
        with tempfile.TemporaryDirectory() as directory:
            repo, cache = Path(directory) / 'repo', Path(directory) / 'cache'
            repo.mkdir()
            index = json.dumps({'packages': {}}).encode()

            def publish(timestamp):
                self.entry_jar(repo, {'timestamp': timestamp, 'index': {'name': '/index-v2.json',
                    'sha256': hashlib.sha256(index).hexdigest(), 'size': len(index)}})
                (repo / 'index-v2.json').write_bytes(index)

            def fetch():
                return fdroid.fetch_index(cache, lambda jar: (4, SIGNER), hashlib.sha256(DER).hexdigest())

            with patch.object(fdroid, 'REPO', repo.as_uri()):
                publish(NOW_MS)
                self.assertEqual(fetch(), {'packages': {}})
                self.assertEqual((cache / 'entry-timestamp').read_text().strip(), str(NOW_MS))
                self.assertEqual(fetch(), {'packages': {}})
                publish(NOW_MS - 1000)
                with self.assertRaisesRegex(ValueError, 'replayed'):
                    fetch()
                self.assertEqual((cache / 'entry-timestamp').read_text().strip(), str(NOW_MS))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, '30 days'):
                fdroid.check_fresh(directory, NOW_MS - fdroid.MAX_AGE_MS - 1000)

    def test_the_pinned_fingerprint_is_f_droids_repo_key(self):
        self.assertEqual(PINNED, '43238d512c1e5eb2d6569f4a3afbf5523418b82e0a3ed1552770abb9a9c9ccab')


class DownloadTests(unittest.TestCase):
    def test_downloads_by_sha256_and_rejects_a_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'app.apk'
            source.write_bytes(b'apk bytes')
            sha256 = hashlib.sha256(b'apk bytes').hexdigest()
            target = Path(directory) / 'apks' / f'{sha256}.apk'
            self.assertEqual(fdroid.download(source.as_uri(), target, sha256, 9), target)
            self.assertEqual(target.read_bytes(), b'apk bytes')
            with patch.object(fdroid.urllib.request, 'urlopen', side_effect=AssertionError('fetched again')):
                fdroid.download(source.as_uri(), target, sha256, 9)
            for wrong in [('b' * 64, 9), (sha256, 8)]:
                with self.assertRaisesRegex(ValueError, 'does not match'):
                    fdroid.download(source.as_uri(), Path(directory) / 'other.apk', *wrong)
            self.assertFalse((Path(directory) / 'other.apk').exists())
            with self.assertRaisesRegex(TimeoutError, 'longer than 5 minutes'):
                fdroid.download(source.as_uri(), Path(directory) / 'late.apk', sha256, 9, time.monotonic() - 1)
            self.assertFalse(list(Path(directory).rglob('*.part')))


if __name__ == '__main__':
    unittest.main()
