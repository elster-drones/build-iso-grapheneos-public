import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('builder', ROOT / 'build.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

GOOD = {'schema_version': 1, 'device': 'frankel', 'model': 'Pixel 10', 'tag': '2026110800',
    'manifest_url': builder.MANIFEST_URL, 'manifest_commit': 'a' * 40}
PASSWORD = 'p' * 40


class FakeAccount:
    pw_uid, pw_gid = 990, 990


def write_release(release, device='frankel', tag='2026110800', *, pkmd=b'owner-avb-key', otacert=b'release-cert', flash=True):
    release.mkdir(parents=True)
    with zipfile.ZipFile(release / f'{device}-install-{tag}.zip', 'w') as archive:
        archive.writestr(f'{device}-install-{tag}/avb_pkmd.bin', pkmd)
        if flash:
            archive.writestr(f'{device}-install-{tag}/flash-all.sh', '#!/bin/sh\n')
    with zipfile.ZipFile(release / f'{device}-ota_update-{tag}.zip', 'w') as archive:
        archive.writestr('META-INF/com/android/otacert', otacert)
    with zipfile.ZipFile(release / f'{device}-img-{tag}.zip', 'w') as archive:
        archive.writestr('vbmeta.img', b'vbmeta')


def write_keys(keys):
    keys.mkdir(parents=True)
    (keys / 'avb_pkmd.bin').write_bytes(b'owner-avb-key')
    (keys / 'releasekey.x509.pem').write_bytes(b'release-cert')


class ConfigTests(unittest.TestCase):
    def test_accepts_pinned_release_and_rejects_unsafe_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'grapheneos.json'
            path.write_text(json.dumps(GOOD))
            self.assertEqual(builder.read_config(path), GOOD)
            for change in [{'device': '../x'}, {'device': 'Frankel'}, {'tag': 'latest'},
                    {'manifest_url': 'https://example.invalid/manifest.git'}, {'manifest_commit': 'HEAD'},
                    {'model': 'Pixel; id'}, {'schema_version': 2}]:
                path.write_text(json.dumps({**GOOD, **change}))
                with self.assertRaises(ValueError):
                    builder.read_config(path)

    def test_secrets_must_live_outside_workspace_and_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            cache, secrets = Path(directory) / 'cache', Path(directory) / 'secrets'
            cache.mkdir()
            secrets.mkdir()
            (secrets / 'passphrase').write_text(PASSWORD + '\n')
            with patch.dict(os.environ, {'GRAPHENEOS_SECRETS_DIR': str(secrets)}):
                self.assertEqual(builder.secrets_dir(cache), (secrets.resolve(), PASSWORD))
            inside = cache / 'secrets'
            inside.mkdir()
            (inside / 'passphrase').write_text(PASSWORD)
            for value in ['', str(inside), str(ROOT), str(Path(directory) / 'missing')]:
                with patch.dict(os.environ, {'GRAPHENEOS_SECRETS_DIR': value}):
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        builder.secrets_dir(cache)
            (secrets / 'passphrase').write_text('short')
            with patch.dict(os.environ, {'GRAPHENEOS_SECRETS_DIR': str(secrets)}):
                with self.assertRaises(ValueError):
                    builder.secrets_dir(cache)


class PrivilegeTests(unittest.TestCase):
    def test_root_drops_to_build_account_with_clean_environment(self):
        with patch.object(builder.os, 'geteuid', return_value=0), \
                patch.object(builder.pwd, 'getpwnam', return_value=FakeAccount), \
                patch.dict(os.environ, {'GRAPHENEOS_SECRETS_DIR': '/run/secret', 'GRAPHENEOS_JOBS': '24'}):
            argv = builder.builder_argv(Path('/cache/home'))
        for flag in ['setpriv', '--reuid=990', '--regid=990', '--clear-groups', '--no-new-privs',
                '--inh-caps=-all', '--bounding-set=-all', 'env', '-i', 'GRAPHENEOS_JOBS=24']:
            self.assertIn(flag, argv)
        self.assertFalse(any('/run/secret' in item or 'SECRETS' in item for item in argv))

    def test_passphrase_only_on_stdin_and_redacted_from_failure_output(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            run = builder.Builder(GOOD, cache)
            run.logs.mkdir()
            run.redact.append(PASSWORD)
            seen = []
            real_popen = subprocess.Popen

            def popen(argv, **kwargs):
                seen.append(argv)
                return real_popen(argv, **kwargs)

            output = io.StringIO()
            with patch.object(builder.subprocess, 'Popen', popen), contextlib.redirect_stdout(output):
                with self.assertRaises(RuntimeError):
                    run.step('sign', 'IFS= read -r password\necho "using $password"\nexit 3\n',
                        cwd=cache, stdin=PASSWORD + '\n')
            self.assertFalse(any(PASSWORD in item for item in seen[0]))
            self.assertIn('using [redacted]', output.getvalue())
            self.assertNotIn(PASSWORD, output.getvalue())

    def test_completed_steps_are_not_repeated(self):
        with tempfile.TemporaryDirectory() as directory:
            run = builder.Builder(GOOD, Path(directory))
            run.tree.mkdir()
            (run.tree / '.openfactory-manifest').write_text(GOOD['manifest_commit'] + '\n')
            (run.tree / '.openfactory-vendor-frankel').touch()
            (run.tree / '.openfactory-compiled-frankel').touch()
            for path in run.target_files():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'zip')
            with patch.object(run, 'step', side_effect=AssertionError('repeated')):
                run.ensure_source()
                run.ensure_vendor()
                run.ensure_compiled()
            (run.tree / '.openfactory-manifest').write_text('b' * 40)
            with patch.object(run, 'step') as step:
                run.ensure_source()
            self.assertEqual(step.call_args.kwargs['variables']['COMMIT'], GOOD['manifest_commit'])


class VerifyAndPackageTests(unittest.TestCase):
    def verify(self, directory, **release):
        run = builder.Builder(GOOD, Path(directory))
        keys = Path(directory) / 'keys'
        write_keys(keys)
        target = Path(directory) / 'release'
        write_release(target, **release)

        def step(name, script, *, cwd=None, **kwargs):
            sha1 = hashlib.sha1(b'owner-avb-key').hexdigest()
            (cwd / 'vbmeta-info.txt').write_text(f'Public key (sha1):        {sha1}\n')

        with patch.object(run, 'step', step):
            run.verify(target, keys)

    def test_accepts_images_signed_with_the_owner_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            self.verify(directory)

    def test_rejects_wrong_release_key_avb_key_or_missing_flash_script(self):
        for change in [{'otacert': b'other'}, {'pkmd': b'other-key'}, {'flash': False}]:
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
                self.verify(directory, **change)

    def test_package_covers_every_member_and_never_private_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            keys = root / 'keys'
            write_keys(keys)
            (keys / 'releasekey.pk8').write_bytes(b'secret')
            (keys / 'avb.pem').write_bytes(b'secret')
            release = root / 'release'
            write_release(release)
            (root / 'LICENSE').write_text('MIT')
            fingerprint = hashlib.sha256(b'owner-avb-key').hexdigest()
            with patch.object(builder, 'ROOT', root), \
                    patch.object(builder.subprocess, 'check_output', return_value=b'c' * 40):
                manifest = builder.package(GOOD, release, keys, fingerprint)
            with zipfile.ZipFile(root / 'output/grapheneos-factory.zip') as archive:
                names = set(archive.namelist())
                self.assertEqual(set(manifest['files']), names - {'manifest.json'})
                self.assertFalse(any(builder.PRIVATE_KEY_NAME.search(name) for name in names))
                self.assertIn(fingerprint, archive.read('INSTALL.txt').decode())
            self.assertEqual(manifest['files']['avb_pkmd.bin'], fingerprint)
            self.assertEqual((manifest['board'], manifest['hardware_tested'], manifest['avb_verified']),
                ('frankel', False, True))

    def test_gitignore_keeps_keys_and_outputs_out_of_build_branches(self):
        ignored = (ROOT / '.gitignore').read_text().split()
        for pattern in ['keys/*/', '*.pk8', '*.pem', 'output/', 'config/grapheneos.json']:
            self.assertIn(pattern, ignored)


if __name__ == '__main__':
    unittest.main()
