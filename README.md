# GrapheneOS images for Google Pixel

Thin adapter around the official GrapheneOS build
(https://grapheneos.org/build). Upstream owns the source tree, Pixel vendor
extraction (adevtool), compilation and release signing
(`script/generate-release.sh`). This repository pins a release, runs those tools
as an unprivileged account and packages the signed result. Its stock build does
not modify the GrapheneOS sources, so its output is an unofficial build of the
official sources in the sense of the GrapheneOS trademark FAQ. The OpenFactory
Phone variant described below does modify them and is a separate, renamed OS.
The adapter is not affiliated with the GrapheneOS project.

The platform writes `config/grapheneos.json`:

```json
{"schema_version": 1, "device": "frankel", "model": "Pixel 10", "tag": "2026110800",
 "manifest_url": "https://github.com/GrapheneOS/platform_manifest.git",
 "manifest_commit": "<commit of the signed tag>"}
```

`./build.sh prepare` syncs the tag (verified against `keys/grapheneos_allowed_signers`
and the pinned commit), generates the Pixel vendor files and compiles the
release target files. The result depends only on the tag and device, so it is
cached in `GRAPHENEOS_CACHE_DIR` and done once per release and device.

`./build.sh` then signs for one owner. `GRAPHENEOS_SECRETS_DIR` must be outside
this workspace and the cache and hold `passphrase` and, after the first build,
`keys/<device>/` with that owner's encrypted keys. A missing key set is created
with upstream `make_key` and encrypted with upstream `script/encrypt-keys`. The
signed images are checked against the owner's verified boot key and release key,
then written to `output/grapheneos-factory.zip` with `INSTALL.txt` and a manifest
of SHA-256 digests. Private keys are never packaged.

Run as root, the adapter installs prerequisites with `install-dependencies.sh`
and runs every upstream step as the `of-grapheneos` account through `setpriv`
(`--no-new-privs`, empty capability bounding set, clean environment). The
cache keeps one source tree (`src`, about 140 GiB) and moves it in place to each
newly pinned release, so a release bump fetches only what changed; compiled
output of earlier releases is deleted. Expect about 250 GiB more while
compiling and 32 GiB of RAM or more. Set `GRAPHENEOS_JOBS` to limit compile
parallelism. Pixels pinned to different release tags at the same time would
move the one tree back and forth; that needs a shared repo mirror first.

The build proves compilation and signatures only. Flashing, boot, radios and
updates must be tested on the exact phone. The stock Updater is not included
because `OFFICIAL_BUILD` is not set.

## OpenFactory Phone (variant `openfactory-phone`)

OpenFactory Phone is a distinct OS based on GrapheneOS. It is not GrapheneOS and
is not affiliated with or endorsed by the GrapheneOS project. As the GrapheneOS
trademark FAQ asks of derivatives, it carries its own name instead of the
GrapheneOS branding and says that it is based on GrapheneOS. Unlike the stock
build above, this variant does modify the GrapheneOS sources: the patch series and
replacement files in `variants/openfactory-phone/` rename the framework label,
setup wizard welcome, recovery and fastbootd titles, boot animation and the
`flash-all.sh` install comments. GrapheneOS-run services stay the defaults and all
bundled apps stay; `variants/openfactory-phone/kept-mentions.txt` lists every
remaining "GrapheneOS" in the scanned resources.

The variant config adds three keys to the six above (and the adapter refuses
unknown keys, or these keys without `variant`):

```json
{"variant": "openfactory-phone", "apps": ["org.fdroid.fdroid"], "display_name": "Erik's Phone"}
```

`apps` are up to 25 F-Droid application IDs; `display_name` (or `null`) replaces
"OpenFactory Phone" in the first-boot welcome title only.

`./build.sh prepare` with this config compiles the stock release as above, then
compiles the variant once per release and device: a reflink copy of `src`
(without `out`, `releases` and `keys`) is patched, every Android manifest and
value resource is checked for unlisted "GrapheneOS" mentions, the stock compile
step runs on the copy (with at least 300 GiB free), and the framework label,
recovery titles, boot animation and `flash-all.sh` comments are checked before
the outputs move to `GRAPHENEOS_CACHE_DIR/openfactory-phone/releases/<tag>/`. The
copy is then deleted. The marker `openfactory-phone/.openfactory-compiled-<device>`
holds the tag and the SHA-256 of the patches and files, so changing either
recompiles. Every compile, stock or variant, takes the host-wide lock
`.android-compile.lock` in the cache's parent directory.

`./build.sh` with this config never compiles: it refuses unless both compiles
exist. Before it takes the cache lock, and within five minutes, it fetches
F-Droid's `entry.jar`, verifies it with the tree's `jarsigner` against the
pinned signer in `keys/fdroid-repo.sha256` (F-Droid's published repo key),
refuses an index older than one already seen or than 30 days, then fetches
`index-v2.json` and each APK by SHA-256 and size into `GRAPHENEOS_CACHE_DIR/fdroid`. Per app it
takes the newest stable version from the app's preferred signer that supports
the build's SDK and arm64 (or has no native code); unknown IDs and 32-bit-only
apps fail. The APKs, unmodified and `PRESIGNED` so F-Droid can update them, their
pre-extracted arm64 libraries and an optional name overlay (built with the
release's `aapt2`) are added to a reflink copy of the variant target files in a
scratch tree, which links `script` and `prebuilts` to `src`. Upstream
`script/generate-release.sh` signs there with keys kept apart from any stock
GrapheneOS keys, the stock signature check runs, and each APK, the overlay and the
branding are read back from the signed images with the release's `debugfs`,
`aapt2`, `unpack_bootimg` and `lz4`. The result is
`output/openfactory-phone-factory.zip`; its manifest adds `based_on`,
`variant_sha256`, `display_name`, `apps` and `readback`. The cached outputs and
`src` are only read, and the scratch tree is deleted.

The adapter is MIT-licensed. GrapheneOS and AOSP retain their own licences;
sources are available from https://grapheneos.org/source.
