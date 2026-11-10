#!/bin/sh
# ./build.sh          build and sign config/grapheneos.json with GRAPHENEOS_SECRETS_DIR
# ./build.sh prepare  sync, extract vendor files and compile only (operator pre-warm)
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
"$root/install-dependencies.sh"
exec python3 "$root/build.py" "$@"
