"""The stock GrapheneOS path is pinned: config keys, steps (names and scripts), manifest and INSTALL.txt.

tests/golden/ was recorded from the adapter before OpenFactory Phone existed.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / 'tests/golden'
spec = importlib.util.spec_from_file_location('builder', ROOT / 'build.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

STOCK = {'schema_version': 1, 'device': 'frankel', 'model': 'Pixel 10', 'tag': '2026110800',
    'manifest_url': builder.MANIFEST_URL, 'manifest_commit': 'a' * 40}
PASSWORD = 'p' * 40


def fake_step(record):
    """Stand in for upstream tools: record each step and leave the files it would."""
    def step(self, name, script, *, cwd=None, stdin='', variables=None):
        record.append({'name': name, 'script_sha256': hashlib.sha256(script.encode()).hexdigest(),
            'variables': sorted(variables or {}), 'tree': self.tree.name})
        cwd = Path(cwd or self.tree)
        if name == 'keys':
            (cwd / 'avb_pkmd.bin').write_bytes(b'owner-avb-key')
            (cwd / 'releasekey.x509.pem').write_bytes(b'release-cert')
            (cwd / 'releasekey.pk8').write_bytes(b'secret')
        elif name == 'sign':
            device, tag = variables['DEVICE'], variables['TAG']
            release = cwd / 'releases' / tag / f'release-{device}-{tag}'
            release.mkdir(parents=True)
            with zipfile.ZipFile(release / f'{device}-install-{tag}.zip', 'w') as archive:
                archive.writestr(f'{device}-install-{tag}/avb_pkmd.bin', b'owner-avb-key')
                archive.writestr(f'{device}-install-{tag}/flash-all.sh', '#!/bin/sh\n')
            with zipfile.ZipFile(release / f'{device}-ota_update-{tag}.zip', 'w') as archive:
                archive.writestr('META-INF/com/android/otacert', b'release-cert')
            with zipfile.ZipFile(release / f'{device}-img-{tag}.zip', 'w') as archive:
                archive.writestr('vbmeta.img', b'vbmeta')
        elif name == 'verify':
            sha1 = hashlib.sha1(b'owner-avb-key').hexdigest()
            (cwd / 'vbmeta-info.txt').write_text(f'Public key (sha1):        {sha1}\n')
    return step


def warm_stock_cache(cache, config):
    """The cache as prepare leaves it: synced, vendor files extracted, release compiled."""
    tree = cache / 'src'
    tree.mkdir(parents=True)
    (tree / '.openfactory-manifest').write_text(config['manifest_commit'] + '\n')
    for step in ('vendor', 'compiled'):
        (tree / f".openfactory-{step}-{config['device']}").write_text(config['tag'] + '\n')
    releases = tree / 'releases' / config['tag']
    releases.mkdir(parents=True)
    for name in ('target_files', 'otatools'):
        (releases / f"{config['device']}-{name}.zip").write_bytes(b'zip')
    return tree


def run_main(directory, config, argv=('build.py',), warm=True, step=None):
    """Run build.main() in a scratch workspace and cache; returns (steps, stdout, root, cache)."""
    root, cache, secrets = Path(directory) / 'adapter', Path(directory) / 'cache', Path(directory) / 'secrets'
    if warm:
        warm_stock_cache(cache, config)
    (root / 'config').mkdir(parents=True)
    (root / 'keys').mkdir()
    (root / 'config/grapheneos.json').write_text(json.dumps(config))
    (root / 'keys/grapheneos_allowed_signers').write_text('signer\n')
    (root / 'LICENSE').write_text('MIT')
    secrets.mkdir()
    (secrets / 'passphrase').write_text(PASSWORD + '\n')
    steps, output = [], io.StringIO()
    with patch.object(builder, 'ROOT', root), \
            patch.object(builder.Builder, 'step', step or fake_step(steps)), \
            patch.object(builder.subprocess, 'check_output', return_value=b'c' * 40), \
            patch.object(builder.shutil, 'which', return_value=None), \
            patch.dict(os.environ, {'GRAPHENEOS_CACHE_DIR': str(cache), 'GRAPHENEOS_SECRETS_DIR': str(secrets)}), \
            contextlib.redirect_stdout(output):
        builder.main(list(argv))
    return steps, output.getvalue(), root, cache


class StockGoldenTests(unittest.TestCase):
    def test_a_stock_build_runs_the_recorded_steps_and_touches_no_variant_path(self):
        with tempfile.TemporaryDirectory() as directory:
            steps, output, root, cache = run_main(directory, STOCK)
            golden = json.loads((GOLDEN / 'stock-steps.json').read_text())
            self.assertEqual(steps, golden['build'])
            self.assertEqual(json.loads(output.strip().splitlines()[-1])['artifact'], 'output/grapheneos-factory.zip')
            self.assertEqual(sorted(path.name for path in cache.iterdir()), ['.lock', 'home', 'logs', 'src'])
            self.assertFalse(list(Path(directory).rglob('*openfactory-phone*')))
            self.assertFalse(list(Path(directory).rglob('fdroid')))
            self.assertEqual(sorted(path.name for path in (root / 'output').iterdir()),
                ['INSTALL.txt', 'grapheneos-factory.zip'])

    def test_stock_prepare_runs_the_recorded_steps(self):
        with tempfile.TemporaryDirectory() as directory:
            steps, output, _root, _cache = run_main(directory, STOCK, ('build.py', 'prepare'), warm=False)
            self.assertEqual(steps, json.loads((GOLDEN / 'stock-steps.json').read_text())['prepare'])
            self.assertEqual(json.loads(output.strip().splitlines()[-1]), {'prepared': 'frankel', 'tag': '2026110800'})
            self.assertFalse(list(Path(directory).rglob('*openfactory-phone*')))

    def test_stock_manifest_and_install_notes_are_unchanged(self):
        fingerprint = hashlib.sha256(b'owner-avb-key').hexdigest()
        self.assertEqual(builder.install_notes(STOCK, fingerprint), (GOLDEN / 'stock-INSTALL.txt').read_text())
        with tempfile.TemporaryDirectory() as directory:
            _steps, _output, root, _cache = run_main(directory, STOCK)
            with zipfile.ZipFile(root / 'output/grapheneos-factory.zip') as archive:
                names = sorted(archive.namelist())
                manifest = json.loads(archive.read('manifest.json'))
                notes = archive.read('INSTALL.txt').decode()
        golden = json.loads((GOLDEN / 'stock-manifest.json').read_text())
        self.assertEqual(names, golden['zip_names'])
        self.assertEqual(sorted(manifest), golden['manifest_keys'])
        self.assertEqual(sorted(manifest['files']), golden['file_names'])
        self.assertEqual({key: value for key, value in manifest.items() if key != 'files'}, golden['manifest'])
        self.assertEqual(notes, (GOLDEN / 'stock-INSTALL.txt').read_text())

    def test_stock_config_is_exactly_the_six_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'grapheneos.json'
            path.write_text(json.dumps(STOCK))
            self.assertEqual(builder.read_config(path), STOCK)
            self.assertEqual(set(builder.read_config(path)), set(json.loads((GOLDEN / 'stock-steps.json')
                .read_text())['config_keys']))


if __name__ == '__main__':
    unittest.main()
