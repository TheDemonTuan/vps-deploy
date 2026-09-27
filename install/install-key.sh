#!/usr/bin/env bash
set -euo pipefail
[[ $(id -u) == 0 && $# == 1 && -f $1 && ! -L $1 ]] || { echo 'Usage: install-key.sh <operator-reviewed-public-key-file>' >&2; exit 1; }
id deploy-9router >/dev/null
[[ $(wc -l < "$1") == 1 ]] || { echo EXPECT_ONE_PUBLIC_KEY >&2; exit 1; }
read -r algorithm encoded _ < "$1"
[[ $algorithm == ssh-ed25519 && $encoded =~ ^[A-Za-z0-9+/=]+$ ]] || { echo UNSUPPORTED_PUBLIC_KEY >&2; exit 1; }
HOME_DIR=$(getent passwd deploy-9router | cut -d: -f6)
[[ $HOME_DIR == /home/deploy-9router && ! -L $HOME_DIR ]] || { echo UNSAFE_HOME >&2; exit 1; }
chown root:root "$HOME_DIR"; chmod 0755 "$HOME_DIR"
install -d -o root -g root -m 0755 "$HOME_DIR/.ssh"
printf 'restrict,command="sudo -n /usr/local/libexec/vps-deploy-9router" %s %s\n' "$algorithm" "$encoded" | install -o root -g root -m 0644 /dev/stdin "$HOME_DIR/.ssh/authorized_keys"
