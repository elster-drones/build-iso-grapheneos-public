# OpenFactory Phone, based on GrapheneOS

Everything that turns a GrapheneOS release into OpenFactory Phone at compile
time. `build.py` applies it to a reflink copy of the synced tree; the synced tree
itself is never changed. The SHA-256 over `patches/` and `files/` is the
`variant_sha256` in the compile marker and in each build's manifest, so editing
anything here recompiles every Pixel at its next prepare.

- `patches/NNNN-*.patch`: applied in order with `git apply` from the tree root,
  written against release 2026110800. A patch that no longer applies fails the
  compile with its name.
  - 0001: the framework `android` label (it heads system notifications).
  - 0002: the 32-bit app warning (`deprecated_abi_message_grapheneos`).
  - 0003: SetupWizard2 welcome title, icon description, description and
    data-restore text.
  - 0004: recovery and fastbootd titles.
  - 0005: the `flash-all.sh` comments, which point to the owner's `INSTALL.txt`
    instead of the GrapheneOS installer.
- `files/`: replacements at the same path in the tree. A file whose target is
  missing fails the compile.
  - `branding/bootanimation/1080.zip`: the boot animation for 1080-pixel canvases
    (frankel and rango). Pixels with another canvas size (blazer 1280, mustang
    1344) need their own `<size>.zip` here first; until then their compile fails
    the boot animation check rather than ship the GrapheneOS animation.
  - `packages/apps/SetupWizard2/res/drawable/grapheneos_icon.xml`: the setup
    wizard icon, the OpenFactory rings mark reduced for 64 dp.
- `kept-mentions.txt`: every line still naming GrapheneOS in the scanned
  manifests and value resources, and why it stays.
- `previews/`: PNG renderings of the boot animation's last frame and the icon.

The boot animation and icon are drafts: plain Open Sans text on black and the
OpenFactory mark. They ship only after Erik approves them.
