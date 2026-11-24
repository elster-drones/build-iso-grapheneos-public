"""OpenFactory Phone: config, patch series, mentions, compile marker, injection, readback and packaging."""
import hashlib
import json
from pathlib import Path
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ElementTree
import zipfile

from test_stock_golden import STOCK, builder, fake_step, run_main, warm_stock_cache

VARIANT_CONFIG = {**STOCK, 'variant': 'openfactory-phone', 'apps': ['org.fdroid.fdroid', 'com.termux'],
    'display_name': "Erik's Phone"}
VARIANT_DIR = builder.VARIANT_DIR
ANIMATION = (VARIANT_DIR / 'files/branding/bootanimation/1080.zip').read_bytes()
GOS_OVERLAY = ('name="GosOverlay.apk" certificate="build/make/target/product/security/testkey.x509.pem" '
    'private_key="build/make/target/product/security/testkey.pk8" partition="product"')


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def write_zip(path, members):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, 'w') as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return path


def fake_target_files(path, *, group_size=10 ** 9, extra=None):
    """A small target-files zip with the members injection reads."""
    return write_zip(path, {
        'META/apkcerts.txt': GOS_OVERLAY + '\nname="Existing.apk" certificate="PRESIGNED" private_key="" '
            'partition="product"\n',
        'META/product_filesystem_config.txt': ' 0 0 755 capabilities=0x0\nproduct/app 0 0 755 capabilities=0x0\n',
        'META/misc_info.txt': 'super_partition_error_limit=900000000\n',
        'META/dynamic_partitions_info.txt': f'super_partition_groups=main\nsuper_main_group_size={group_size}\n'
            'super_main_partition_list=system product\n',
        'IMAGES/system.img': b'\0' * 4096, 'IMAGES/product.img': b'\0' * 4096,
        'PRODUCT/app/Existing/Existing.apk': b'existing', 'SYSTEM/build.prop': 'ro.build.version.sdk=37\n',
        **(extra or {})})


def fake_apk(path, libraries=()):
    return write_zip(path, {'AndroidManifest.xml': b'manifest', 'classes.dex': b'dex',
        **{name: name.encode() for name in libraries}})


def variant_dir_with(directory, patch_text, files=None):
    """A variant folder holding one patch, its replacement files and an empty mention list."""
    variant = Path(directory) / 'variant'
    (variant / 'patches').mkdir(parents=True)
    (variant / 'patches/0001-greeting.patch').write_text(patch_text)
    for name, data in (files or {'branding/bootanimation/1080.zip': ANIMATION}).items():
        (variant / 'files' / name).parent.mkdir(parents=True, exist_ok=True)
        (variant / 'files' / name).write_bytes(data)
    (variant / 'kept-mentions.txt').write_text('# none\n')
    return variant


GREETING_PATCH = '''Subject: greeting

--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -1,3 +1,3 @@
 <resources>
-    <string name="hello">Hello GrapheneOS</string>
+    <string name="hello">Hello OpenFactory Phone</string>
 </resources>
'''


def stock_tree(cache):
    tree = warm_stock_cache(cache, STOCK)
    (tree / 'res/values').mkdir(parents=True)
    (tree / 'res/values/strings.xml').write_text(
        '<resources>\n    <string name="hello">Hello GrapheneOS</string>\n</resources>\n')
    (tree / 'branding/bootanimation').mkdir(parents=True)
    (tree / 'branding/bootanimation/1080.zip').write_bytes(b'stock animation')
    (tree / 'vendor/google_devices/frankel').mkdir(parents=True)
    (tree / 'vendor/google_devices/frankel/frankel.mk').write_text(
        '$(call soong_config_set,bootanimation_zip,canvas_size,1080)\n')
    for name in ('script', 'prebuilts'):
        (tree / name).mkdir()
    return tree


class ConfigTests(unittest.TestCase):
    def read(self, config):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'grapheneos.json'
            path.write_text(json.dumps(config))
            return builder.read_config(path)

    def test_accepts_the_variant_keys(self):
        self.assertEqual(self.read(VARIANT_CONFIG), VARIANT_CONFIG)
        for change in [{'apps': []}, {'display_name': None}, {'display_name': 'A'}, {'display_name': 'Ab+1 .-' + 'x' * 24},
                {'apps': [f'org.example.app{i}' for i in range(25)]}]:
            self.assertEqual(self.read({**VARIANT_CONFIG, **change}), {**VARIANT_CONFIG, **change})

    def test_rejects_bad_variant_values_and_variant_keys_without_a_variant(self):
        for change in [{'variant': 'lineageos'}, {'apps': 'org.fdroid.fdroid'}, {'apps': ['fdroid']},
                {'apps': ['org.fdroid.fdroid', 'org.fdroid.fdroid']}, {'apps': ['org.fdroid.fdroid;rm']},
                {'apps': [f'org.example.app{i}' for i in range(26)]}, {'apps': [{'id': 'org.fdroid.fdroid'}]},
                {'display_name': ''}, {'display_name': ' Erik'}, {'display_name': 'x' * 33},
                {'display_name': 'My GrapheneOS'}, {'display_name': 'my grapheneOS'}, {'display_name': 'Erik"s'},
                {'display_name': 'Erik<b>'}, {'display_name': 7}, {'extra': 1}]:
            with self.assertRaises(ValueError, msg=change):
                self.read({**VARIANT_CONFIG, **change})
        missing = dict(VARIANT_CONFIG)
        del missing['display_name']
        for config in [missing, {**STOCK, 'apps': []}, {**STOCK, 'display_name': None}, {**STOCK, 'other': 1}]:
            with self.assertRaises(ValueError, msg=config):
                self.read(config)


class PatchAndMentionTests(unittest.TestCase):
    def builder_for(self, directory):
        run = builder.Builder(STOCK, Path(directory) / 'cache')
        run.home.mkdir(parents=True)
        run.tree = stock_tree(run.cache)
        return run

    def test_the_series_applies_and_replaces_files(self):
        with tempfile.TemporaryDirectory() as directory:
            run = self.builder_for(directory)
            builder.apply_variant(run, variant_dir_with(directory, GREETING_PATCH))
            self.assertIn('Hello OpenFactory Phone', (run.tree / 'res/values/strings.xml').read_text())
            self.assertEqual((run.tree / 'branding/bootanimation/1080.zip').read_bytes(), ANIMATION)

    def test_a_stale_patch_fails_with_its_name(self):
        with tempfile.TemporaryDirectory() as directory:
            run = self.builder_for(directory)
            (run.tree / 'res/values/strings.xml').write_text('<resources>\n    <string name="hello">Hi</string>\n'
                '</resources>\n')
            with self.assertRaisesRegex(ValueError, '0001-greeting.patch does not apply'):
                builder.apply_variant(run, variant_dir_with(directory, GREETING_PATCH))

    def test_a_replacement_file_without_a_target_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            run = self.builder_for(directory)
            variant = variant_dir_with(directory, GREETING_PATCH, {'branding/bootanimation/1344.zip': ANIMATION})
            with self.assertRaisesRegex(ValueError, 'branding/bootanimation/1344.zip replaces nothing'):
                builder.apply_variant(run, variant)
            self.assertIn('Hello GrapheneOS', (run.tree / 'res/values/strings.xml').read_text())

    def test_an_unlisted_mention_fails_and_a_listed_one_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            run = self.builder_for(directory)
            variant = variant_dir_with(directory, GREETING_PATCH)
            builder.apply_variant(run, variant)
            builder.check_mentions(run.tree, variant)
            manifest = run.tree / 'packages/apps/New/AndroidManifest.xml'
            manifest.parent.mkdir(parents=True)
            manifest.write_text('<manifest>\n  <application android:label="GrapheneOS Thing"/>\n</manifest>\n')
            (run.tree / 'out/res/values').mkdir(parents=True)
            (run.tree / 'out/res/values/strings.xml').write_text('GrapheneOS in build output is not scanned\n')
            line = 'packages/apps/New/AndroidManifest.xml: <application android:label="GrapheneOS Thing"/>'
            with self.assertRaisesRegex(ValueError, 'kept-mentions.txt') as raised:
                builder.check_mentions(run.tree, variant)
            self.assertIn(line, str(raised.exception))
            self.assertNotIn('build output', str(raised.exception))
            (variant / 'kept-mentions.txt').write_text(line + '\n')
            builder.check_mentions(run.tree, variant)

    def test_the_real_kept_list_names_only_lines_with_mentions(self):
        for line in (VARIANT_DIR / 'kept-mentions.txt').read_text().splitlines():
            if line.strip() and not line.startswith('#'):
                path, _, text = line.partition(': ')
                self.assertIn('GrapheneOS', text, line)
                self.assertTrue(path.endswith('.xml'), line)


class CompileTests(unittest.TestCase):
    def compile_step(self, steps):
        def step(run, name, script, *, cwd=None, stdin='', variables=None):
            steps.append((name, run.tree.name))
            for path in run.target_files():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'variant ' + path.name.encode())
            (run.tree / '.openfactory-compiled-frankel').write_text(STOCK['tag'] + '\n')
        return step

    def test_compiles_once_in_a_patched_copy_and_again_when_the_series_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            stock = builder.Builder(STOCK, Path(directory) / 'cache')
            stock_tree(stock.cache)
            stock.home.mkdir(parents=True)
            variant = variant_dir_with(directory, GREETING_PATCH)
            steps = []
            with patch.object(builder, 'REFLINK', '--reflink=auto'), patch.object(builder, 'COMPILE_FREE_BYTES', 1), \
                    patch.object(builder.Builder, 'step', self.compile_step(steps)), \
                    patch.object(builder, 'check_compiled_variant') as checked:
                builder.ensure_variant_compiled(stock, variant)
                self.assertEqual(steps, [('compile', 'tree')])
                self.assertEqual(checked.call_count, 1)
                target_files, otatools, marker = builder.variant_outputs(stock.cache, STOCK)
                self.assertEqual(target_files.read_bytes(), b'variant frankel-target_files.zip')
                self.assertEqual(marker.read_text().split(), [STOCK['tag'], builder.variant_sha256(variant)])
                self.assertFalse((marker.parent / 'tree').exists())
                self.assertIn('Hello GrapheneOS', (stock.tree / 'res/values/strings.xml').read_text())
                self.assertEqual((stock.tree / 'releases' / STOCK['tag'] / 'frankel-target_files.zip').read_bytes(),
                    b'zip')
                self.assertTrue((stock.cache.parent / '.android-compile.lock').is_file())
                builder.ensure_variant_compiled(stock, variant)
                self.assertEqual(len(steps), 1)
                patch_file = variant / 'patches/0001-greeting.patch'
                patch_file.write_text(patch_file.read_text().replace('Subject: greeting', 'Subject: greeting, reworded'))
                self.assertFalse(builder.variant_compiled(stock.cache, STOCK, variant))
                builder.ensure_variant_compiled(stock, variant)
                self.assertEqual(len(steps), 2)

    def test_a_failed_patch_keeps_no_copy_and_no_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            stock = builder.Builder(STOCK, Path(directory) / 'cache')
            stock_tree(stock.cache)
            stock.home.mkdir(parents=True)
            variant = variant_dir_with(directory, GREETING_PATCH.replace('Hello GrapheneOS', 'Hi GrapheneOS'))
            with patch.object(builder, 'REFLINK', '--reflink=auto'), \
                    patch.object(builder.Builder, 'step', side_effect=AssertionError('compiled')):
                with self.assertRaisesRegex(ValueError, '0001-greeting.patch'):
                    builder.ensure_variant_compiled(stock, variant)
            *_outputs, marker = builder.variant_outputs(stock.cache, STOCK)
            self.assertFalse(marker.exists())
            self.assertFalse((marker.parent / 'tree').exists())

    def test_a_canvas_without_a_boot_animation_is_refused_before_copying(self):
        with tempfile.TemporaryDirectory() as directory:
            stock = builder.Builder(STOCK, Path(directory) / 'cache')
            stock_tree(stock.cache)
            (stock.tree / 'vendor/google_devices/frankel/frankel.mk').write_text(
                '$(call soong_config_set,bootanimation_zip,canvas_size,1344)\n')
            with patch.object(builder.subprocess, 'run', side_effect=AssertionError('copied')):
                with self.assertRaisesRegex(ValueError, 'No OpenFactory Phone boot animation for canvas 1344'):
                    builder.ensure_variant_compiled(stock, variant_dir_with(directory, GREETING_PATCH))
            self.assertFalse((stock.cache / 'openfactory-phone/tree').exists())

    def test_leftovers_of_a_killed_run_are_removed_by_prepare_but_never_by_a_stock_build(self):
        def leave_leftovers(cache):
            for stale in ('tree/frameworks', 'sign-frankel/releases', 'releases'):
                (cache / 'openfactory-phone' / stale).mkdir(parents=True, exist_ok=True)
            return cache / 'openfactory-phone'

        with tempfile.TemporaryDirectory() as directory:
            variant = leave_leftovers(Path(directory) / 'cache')
            run_main(directory, STOCK)
            self.assertEqual(sorted(path.name for path in variant.iterdir()), ['releases', 'sign-frankel', 'tree'])
        with tempfile.TemporaryDirectory() as directory:
            variant = leave_leftovers(Path(directory) / 'cache')
            preparing = Path(directory) / 'cache/.openfactory-preparing'
            remove = builder.remove_variant_leftovers

            def while_preparing(cache):
                self.assertTrue(preparing.is_file())
                remove(cache)

            with patch.object(builder, 'remove_variant_leftovers', side_effect=while_preparing) as removed:
                run_main(directory, STOCK, ('build.py', 'prepare'), warm=False)
            self.assertEqual(removed.call_count, 1)
            self.assertEqual(sorted(path.name for path in variant.iterdir()), ['releases'])

    def test_an_unset_canvas_size_means_1080_as_in_branding(self):
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory)
            self.assertEqual(builder.canvas_size(tree, 'frankel'), '1080')
            (tree / 'vendor/google_devices/frankel').mkdir(parents=True)
            (tree / 'vendor/google_devices/frankel/frankel.mk').write_text('PRODUCT_NAME := frankel\n')
            self.assertEqual(builder.canvas_size(tree, 'frankel'), '1080')
            (tree / 'vendor/google_devices/frankel/frankel.mk').write_text(
                '$(call soong_config_set,bootanimation_zip,canvas_size,1280)\n')
            self.assertEqual(builder.canvas_size(tree, 'frankel'), '1280')

    def test_the_compile_lock_refuses_a_symlink_or_a_non_file(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / 'cache'
            lock = Path(directory) / '.android-compile.lock'
            target = Path(directory) / 'elsewhere'
            target.write_text('keep')
            lock.symlink_to(target)
            with self.assertRaises(OSError):
                with builder.compile_lock(cache):
                    pass
            lock.unlink()
            os.mkfifo(lock)
            with self.assertRaisesRegex(RuntimeError, 'not a regular file'):
                with builder.compile_lock(cache):
                    pass
            lock.unlink()
            with builder.compile_lock(cache):
                self.assertEqual(lock.stat().st_mode & 0o777, 0o600)
            self.assertEqual(target.read_text(), 'keep')

    def test_a_build_refuses_until_prepare_compiled_the_variant(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(SystemExit, 'OpenFactory Phone 2026110800 is not compiled for the Pixel 10'):
                run_main(directory, VARIANT_CONFIG)
            self.assertFalse((Path(directory) / 'adapter/output').exists())

    def test_prepare_compiles_the_stock_release_then_the_variant_while_marked_preparing(self):
        with tempfile.TemporaryDirectory() as directory:
            preparing = Path(directory) / 'cache/.openfactory-preparing'
            with patch.object(builder, 'ensure_variant_compiled',
                    side_effect=lambda run: self.assertTrue(preparing.is_file())) as variant:
                steps, output, _root, _cache = run_main(directory, VARIANT_CONFIG, ('build.py', 'prepare'),
                    warm=False)
            self.assertEqual([step['name'] for step in steps], ['sync', 'vendor', 'compile'])
            self.assertEqual(variant.call_count, 1)
            self.assertFalse(preparing.exists())
            self.assertEqual(json.loads(output.strip().splitlines()[-1]),
                {'prepared': 'frankel', 'tag': STOCK['tag'], 'variant': 'openfactory-phone'})


class InjectionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.cached = fake_target_files(self.root / 'cache/frankel-target_files.zip')
        self.cached_sha256 = sha256(self.cached.read_bytes())
        self.copy = self.root / 'scratch/frankel-target_files.zip'
        self.copy.parent.mkdir()
        shutil.copyfile(self.cached, self.copy)
        self.apks = {'org.example.native': fake_apk(self.root / 'native.apk', ['lib/arm64-v8a/libone.so',
            'lib/arm64-v8a/libtwo.so', 'lib/armeabi-v7a/libone.so', 'lib/x86_64/libone.so']),
            'org.example.plain': fake_apk(self.root / 'plain.apk')}
        self.overlay = self.root / 'OpenFactoryPhoneName.apk'
        self.overlay.write_bytes(b'overlay apk')

    def tearDown(self):
        self.directory.cleanup()

    def test_adds_presigned_apps_arm64_libraries_and_the_overlay(self):
        builder.inject(self.copy, self.apks, self.overlay, self.root / 'stage')
        with zipfile.ZipFile(self.copy) as archive:
            names = archive.namelist()
            self.assertEqual(len(names), len(set(names)))
            app = 'PRODUCT/app/OFApp_org.example.native'
            self.assertEqual(archive.read(f'{app}/OFApp_org.example.native.apk'), self.apks['org.example.native']
                .read_bytes())
            self.assertEqual(sorted(name for name in names if '/lib/' in name), [f'{app}/lib/', f'{app}/lib/arm64/',
                f'{app}/lib/arm64/libone.so', f'{app}/lib/arm64/libtwo.so'])
            self.assertEqual(archive.read(f'{app}/lib/arm64/libone.so'), b'lib/arm64-v8a/libone.so')
            self.assertNotIn('PRODUCT/app/OFApp_org.example.plain/lib/', names)
            self.assertEqual(archive.read('PRODUCT/overlay/OpenFactoryPhoneName.apk'), b'overlay apk')
            self.assertEqual(archive.read('PRODUCT/app/Existing/Existing.apk'), b'existing')
            apkcerts = archive.read('META/apkcerts.txt').decode().splitlines()
            fs_config = archive.read('META/product_filesystem_config.txt').decode().splitlines()
        self.assertEqual(apkcerts[-3:], [
            'name="OFApp_org.example.native.apk" certificate="PRESIGNED" private_key="" partition="product"',
            'name="OFApp_org.example.plain.apk" certificate="PRESIGNED" private_key="" partition="product"',
            GOS_OVERLAY.replace('GosOverlay.apk', 'OpenFactoryPhoneName.apk')])
        self.assertEqual(fs_config[:2], [' 0 0 755 capabilities=0x0', 'product/app 0 0 755 capabilities=0x0'])
        self.assertEqual(fs_config[2:], [
            'product/app/OFApp_org.example.native 0 0 755 capabilities=0x0',
            'product/app/OFApp_org.example.native/OFApp_org.example.native.apk 0 0 644 capabilities=0x0',
            'product/app/OFApp_org.example.native/lib 0 0 755 capabilities=0x0',
            'product/app/OFApp_org.example.native/lib/arm64 0 0 755 capabilities=0x0',
            'product/app/OFApp_org.example.native/lib/arm64/libone.so 0 0 644 capabilities=0x0',
            'product/app/OFApp_org.example.native/lib/arm64/libtwo.so 0 0 644 capabilities=0x0',
            'product/app/OFApp_org.example.plain 0 0 755 capabilities=0x0',
            'product/app/OFApp_org.example.plain/OFApp_org.example.plain.apk 0 0 644 capabilities=0x0',
            'product/overlay/OpenFactoryPhoneName.apk 0 0 644 capabilities=0x0'])
        self.assertEqual(sha256(self.cached.read_bytes()), self.cached_sha256)

    def test_nothing_to_add_leaves_the_copy_untouched(self):
        before = sha256(self.copy.read_bytes())
        builder.inject(self.copy, {}, None, self.root / 'stage')
        self.assertEqual(sha256(self.copy.read_bytes()), before)

    def test_32_bit_only_apps_collisions_and_a_full_super_partition_fail(self):
        old = {'org.example.old': fake_apk(self.root / 'old.apk', ['lib/armeabi-v7a/libone.so'])}
        with self.assertRaisesRegex(ValueError, 'no arm64-v8a libraries'):
            builder.inject(self.copy, old, None, self.root / 'stage-old')
        taken = fake_target_files(self.root / 'taken.zip', extra={
            'PRODUCT/app/OFApp_org.example.plain/OFApp_org.example.plain.apk': b'x'})
        with self.assertRaisesRegex(ValueError, 'collide.*OFApp_org.example.plain'):
            builder.inject(taken, self.apks, None, self.root / 'stage-taken')
        listed = fake_target_files(self.root / 'listed.zip', extra={'META/apkcerts.txt': GOS_OVERLAY +
            '\nname="OpenFactoryPhoneName.apk" certificate="PRESIGNED" private_key="" partition="product"\n'})
        with self.assertRaisesRegex(ValueError, 'collide.*OpenFactoryPhoneName.apk'):
            builder.inject(listed, {}, self.overlay, self.root / 'stage-listed')
        full = fake_target_files(self.root / 'full.zip', group_size=builder.SUPER_MARGIN + 8192)
        with self.assertRaisesRegex(ValueError, 'super partition'):
            builder.inject(full, self.apks, None, self.root / 'stage-full')
        self.assertEqual(sha256(self.cached.read_bytes()), self.cached_sha256)


class NameTests(unittest.TestCase):
    def test_owner_names_are_escaped_as_android_string_resources(self):
        self.assertEqual(builder.resource_string("Erik's Phone"), '"Erik\\\'s Phone"')
        self.assertEqual(builder.resource_string('A & B <c>'), '"A &amp; B &lt;c&gt;"')
        title = builder.welcome_title("Erik's  Phone+1")
        xml = f'<resources><string name="welcome_to_grapheneos">{builder.resource_string(title)}</string></resources>'
        self.assertEqual(ElementTree.fromstring(xml)[0].text, '"Welcome to Erik\\\'s  Phone+1"')


class ReadbackTests(unittest.TestCase):
    APPS = [{'package': 'org.example.plain', 'apk_sha256': sha256(b'plain apk')}]

    def release(self, root, flash_all=b'# FOLLOW THE INSTALL.TXT THAT CAME WITH THESE IMAGES INSTEAD.\n'):
        release = root / 'release'
        write_zip(release / 'frankel-img-2026110800.zip', {'product.img': b'p', 'system.img': b's',
            'vendor_boot.img': b'v'})
        write_zip(release / 'frankel-install-2026110800.zip', {'frankel-install-2026110800/flash-all.sh': flash_all})
        write_zip(release / 'frankel-target_files.zip', {'PRODUCT/overlay/OpenFactoryPhoneName.apk': b'signed overlay'})
        return release

    def readback_step(self, *, apk=b'plain apk', label='OpenFactory Phone', shown="Welcome to Erik's Phone"):
        def step(run, name, script, *, cwd=None, stdin='', variables=None):
            self.assertEqual(name, 'readback')
            commands = (cwd / 'product.cmd').read_text().splitlines()
            self.assertEqual(commands[0], 'dump /app/OFApp_org.example.plain/OFApp_org.example.plain.apk out/0')
            (cwd / 'out/0').write_bytes(apk)
            (cwd / 'out/1').write_bytes(ANIMATION)
            if variables['OVERLAY']:
                (cwd / variables['OVERLAY']).write_bytes(b'signed overlay')
                (cwd / 'overlay.txt').write_text(f'String pool of 1 unique UTF-8\nString #0 : {shown}\n')
            (cwd / 'badging.txt').write_text(f"package: name='android'\napplication-label:'{label}'\n")
            (cwd / 'ramdisk.cpio').write_bytes(b'..OpenFactory Phone Recovery..OpenFactory Phone Fastboot..')
        return step

    def read_back(self, title="Welcome to Erik's Phone", **step):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            signer = builder.Builder(STOCK, root / 'cache')
            signer.tree = root / 'scratch'
            signer.tree.mkdir()
            release = self.release(root)
            with patch.object(builder.Builder, 'step', self.readback_step(**step)):
                return builder.read_back(signer, release, self.APPS, title)

    def test_passes_when_apps_overlay_and_branding_read_back(self):
        self.assertEqual(self.read_back(), {'apps': True, 'branding': True, 'name_overlay': True})
        self.assertEqual(self.read_back(title=None), {'apps': True, 'branding': True, 'name_overlay': None})

    def test_fails_on_a_changed_apk_missing_name_or_stock_branding(self):
        with self.assertRaisesRegex(ValueError, 'org.example.plain read back'):
            self.read_back(apk=b'other apk')
        with self.assertRaisesRegex(ValueError, 'name overlay'):
            self.read_back(shown='Welcome to GrapheneOS')
        with self.assertRaisesRegex(ValueError, 'framework label'):
            self.read_back(label='GrapheneOS')

    def test_branding_problems_name_each_failed_check(self):
        good = builder.branding_problems("application-label:'OpenFactory Phone'",
            b'OpenFactory Phone Recovery OpenFactory Phone Fastboot', sha256(ANIMATION), b'FOLLOW THE INSTALL.TXT')
        self.assertEqual(good, [])
        bad = builder.branding_problems("application-label:'GrapheneOS'", b'GrapheneOS Recovery', sha256(b'stock'),
            b'https://grapheneos.org/install/web')
        self.assertEqual(len(bad), 4)


class VariantBuildTests(unittest.TestCase):
    """build_variant end to end, with F-Droid, aapt2 and the signing tools faked."""

    def index_outside_cache_lock(self, cache):
        def fetch(directory, verify, pinned, deadline):
            with (cache / '.lock').open('w') as lock:
                builder.fcntl.flock(lock, builder.fcntl.LOCK_EX | builder.fcntl.LOCK_NB)  # raises if held
            self.assertTrue((directory / '.lock').is_file())
            return {'packages': {}}
        return fetch

    def test_signs_in_a_scratch_tree_and_packages_the_variant_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / 'cache'
            stock_tree(cache)
            target_files, otatools, marker = builder.variant_outputs(cache, STOCK)
            fake_target_files(target_files)
            write_zip(otatools, {'bin/aapt2': b'aapt2'})
            (cache / 'openfactory-phone/sign-frankel/releases').mkdir(parents=True)  # left by a killed build
            marker.write_text(f"{STOCK['tag']}\n{builder.variant_sha256()}\n")
            cached = {path: sha256(path.read_bytes()) for path in (target_files, otatools)}
            apks = {'org.fdroid.fdroid': fake_apk(Path(directory) / 'fdroid.apk'),
                'com.termux': fake_apk(Path(directory) / 'termux.apk', ['lib/arm64-v8a/libtermux.so'])}
            apps = [{'package': package, 'version_code': 7, 'version_name': '1.7',
                'apk_sha256': sha256(apk.read_bytes()), 'signer_sha256': 'd' * 64, 'anti_features': [],
                'file': f'/{package}.apk', 'size': 1} for package, apk in apks.items()]
            overlay = Path(directory) / 'built-overlay.apk'
            overlay.write_bytes(b'unsigned overlay')
            base_step = fake_step([])
            steps = []

            def step(run, name, script, *, cwd=None, stdin='', variables=None):
                steps.append((name, Path(cwd or run.tree)))
                base_step(run, name, script, cwd=cwd, stdin=stdin, variables=variables)
                if name == 'sign':
                    release = run.tree / 'releases' / STOCK['tag'] / f"release-frankel-{STOCK['tag']}"
                    self.assertEqual((run.tree / 'script').resolve(), (cache / 'src/script').resolve())
                    shutil.copyfile(run.tree / 'releases' / STOCK['tag'] / 'frankel-target_files.zip',
                        release / 'frankel-target_files.zip')
                    write_zip(release / f"frankel-img-{STOCK['tag']}.zip", {'vbmeta.img': b'v', 'product.img': b'p',
                        'system.img': b's', 'vendor_boot.img': b'b'})
                    write_zip(release / f"frankel-install-{STOCK['tag']}.zip", {
                        f"frankel-install-{STOCK['tag']}/avb_pkmd.bin": b'owner-avb-key',
                        f"frankel-install-{STOCK['tag']}/flash-all.sh": b'FOLLOW THE INSTALL.TXT'})
                elif name == 'readback':
                    release = Path(variables['BIN']).parent
                    with zipfile.ZipFile(release / 'frankel-target_files.zip') as archive:
                        for index, line in enumerate((cwd / 'product.cmd').read_text().splitlines()):
                            member = 'PRODUCT' + line.split()[1]
                            data = ANIMATION if member.endswith('bootanimation.zip') else archive.read(member)
                            (cwd / 'out' / str(index)).write_bytes(data)
                    (cwd / 'overlay.txt').write_text("String #0 : Welcome to Erik's Phone\n")
                    (cwd / 'badging.txt').write_text("application-label:'OpenFactory Phone'\n")
                    (cwd / 'ramdisk.cpio').write_bytes(b'OpenFactory Phone Recovery OpenFactory Phone Fastboot')

            with patch.object(builder, 'REFLINK', '--reflink=auto'), \
                    patch.object(builder.fdroid, 'fetch_index',
                        side_effect=self.index_outside_cache_lock(cache)) as fetched, \
                    patch.object(builder.fdroid, 'choose', return_value=apps) as chosen, \
                    patch.object(builder.fdroid, 'download_apks', return_value=apks), \
                    patch.object(builder, 'build_name_overlay', return_value=overlay) as named:
                _steps, output, root, cache = run_main(directory, VARIANT_CONFIG, warm=False, step=step)
            self.assertEqual(chosen.call_args.args[1:], (['org.fdroid.fdroid', 'com.termux'], 37))
            self.assertEqual(fetched.call_args.args[0], cache / 'fdroid')
            self.assertEqual(named.call_args.args[1], "Welcome to Erik's Phone")
            self.assertEqual([name for name, _cwd in steps], ['keys', 'sign', 'verify', 'readback'])
            self.assertEqual(steps[1][1], cache / 'openfactory-phone/sign-frankel')
            self.assertEqual(json.loads(output.strip().splitlines()[-1])['artifact'],
                'output/openfactory-phone-factory.zip')
            self.assertFalse((cache / 'openfactory-phone/sign-frankel').exists())
            self.assertEqual({path: sha256(path.read_bytes()) for path in cached}, cached)
            self.assertFalse((cache / 'src/keys').exists())
            with zipfile.ZipFile(root / 'output/openfactory-phone-factory.zip') as archive:
                manifest = json.loads(archive.read('manifest.json'))
                notes = archive.read('INSTALL.txt').decode()
                names = sorted(archive.namelist())
        golden = json.loads((Path(__file__).parent / 'golden/stock-manifest.json').read_text())
        self.assertEqual(names, golden['zip_names'])
        self.assertTrue(set(golden['manifest_keys']) <= set(manifest))
        self.assertEqual(manifest['distribution'], 'openfactory-phone')
        self.assertEqual({key: value for key, value in manifest.items()
            if key in golden['manifest'] and key not in ('distribution', 'avb_key_sha256')},
            {key: value for key, value in golden['manifest'].items() if key not in ('distribution', 'avb_key_sha256')})
        self.assertEqual(manifest['based_on'], {'distribution': 'grapheneos', 'tag': STOCK['tag'],
            'manifest_commit': STOCK['manifest_commit']})
        self.assertEqual(manifest['variant_sha256'], builder.variant_sha256())
        self.assertEqual(manifest['display_name'], "Erik's Phone")
        self.assertEqual(manifest['readback'], {'apps': True, 'branding': True, 'name_overlay': True})
        self.assertEqual([app['package'] for app in manifest['apps']], ['org.fdroid.fdroid', 'com.termux'])
        self.assertEqual(set(manifest['apps'][0]), {'package', 'version_code', 'version_name', 'apk_sha256',
            'signer_sha256', 'anti_features'})
        self.assertIn('OpenFactory Phone is a distinct OS based on GrapheneOS', notes)
        self.assertIn('It is not GrapheneOS and is not affiliated with or endorsed by the\nGrapheneOS project', notes)
        self.assertIn('do not ask the GrapheneOS project for support', notes)
        self.assertIn('kept separately from\nany stock GrapheneOS keys', notes)
        self.assertIn('requires erasing it', notes)
        self.assertIn('- com.termux 1.7 (version code 7)', notes)
        self.assertNotIn('grapheneos.org/install', notes)
        self.assertIn(manifest['avb_key_sha256'], notes)


if __name__ == '__main__':
    unittest.main()
