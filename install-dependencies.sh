#!/bin/sh
# Host prerequisites for building GrapheneOS from source (https://grapheneos.org/build).
set -eu
user=${GRAPHENEOS_BUILD_USER:-of-grapheneos}
check() {
    for tool in python3 git git-lfs repo rsync unzip zip openssl diff setpriv hostname; do
        command -v "$tool" >/dev/null 2>&1 || return 1
    done
    { command -v yarnpkg || command -v yarn; } >/dev/null 2>&1 || return 1
    { command -v node-24 || node --version 2>/dev/null | grep -q '^v24\.'; } >/dev/null 2>&1 || return 1
    id -u "$user" >/dev/null 2>&1
}
if check; then exit 0; fi
if [ "${1:-}" = --check ] || [ "$(id -u)" != 0 ]; then
    echo "GrapheneOS build prerequisites or the '$user' build account are missing. Run install-dependencies.sh as root." >&2
    exit 1
fi
if command -v dnf >/dev/null 2>&1; then
    dnf install -y git git-lfs repo python3 rsync unzip zip openssl diffutils util-linux-core hostname \
        fontconfig freetype gnupg2 openssh-clients nodejs24 yarnpkg
elif command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git git-lfs repo python3 rsync \
        unzip zip openssl diffutils util-linux hostname fontconfig libfreetype6 gnupg openssh-client nodejs yarnpkg
else
    echo 'Install the GrapheneOS build prerequisites for this host distribution.' >&2
    exit 1
fi
id -u "$user" >/dev/null 2>&1 || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$user"
check
