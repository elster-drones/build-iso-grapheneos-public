# GrapheneOS images for Google Pixel

Thin adapter around the official GrapheneOS build
(https://grapheneos.org/build). Upstream owns the source tree, Pixel vendor
extraction (adevtool), compilation and release signing
(`script/generate-release.sh`). This repository pins a release, runs those tools
as an unprivileged account and packages the signed result. It does not modify
the GrapheneOS sources, so its output is an unofficial build of the official
sources in the sense of the GrapheneOS trademark FAQ. It is not affiliated with
the GrapheneOS project.

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

The adapter is MIT-licensed. GrapheneOS and AOSP retain their own licences;
sources are available from https://grapheneos.org/source.
