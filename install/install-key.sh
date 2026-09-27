#!/usr/bin/env bash
set -euo pipefail
[[ $(id -u) == 0 && $# == 3 && $1 == --app && $2 =~ ^[a-z0-9]([a-z0-9-]{0,22}[a-z0-9])?$ && -f $3 && ! -L $3 ]] || { echo 'Usage: install-key.sh --app <id> <operator-reviewed-ed25519-public-key-file>' >&2; exit 1; }
APP=$2; KEY=$3
[[ $(wc -l < "$KEY") == 1 ]] || { echo EXPECT_ONE_PUBLIC_KEY >&2; exit 1; }
read -r algorithm encoded _ < "$KEY"
[[ $algorithm == ssh-ed25519 && $encoded =~ ^[A-Za-z0-9+/=]+$ ]] || { echo UNSUPPORTED_PUBLIC_KEY >&2; exit 1; }
ssh-keygen -lf "$KEY" >/dev/null || { echo INVALID_PUBLIC_KEY >&2; exit 1; }
if ! id "deploy-$APP" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/sh --user-group "deploy-$APP"
fi
[[ $(id -nG "deploy-$APP") == "deploy-$APP" ]] || { echo UNSAFE_DEPLOY_GROUP >&2; exit 1; }
HOME_DIR=$(getent passwd "deploy-$APP" | cut -d: -f6)
[[ $HOME_DIR == "/home/deploy-$APP" && ! -L $HOME_DIR ]] || { echo UNSAFE_HOME >&2; exit 1; }
# '*' disables password authentication without locking OpenSSH public-key login.
usermod -p '*' "deploy-$APP"
chown root:root "$HOME_DIR"; chmod 0755 "$HOME_DIR"
install -d -o root -g root -m 0755 "$HOME_DIR/.ssh"
printf 'restrict,command="sudo -n /usr/local/libexec/vps-deploy-%s" %s %s\n' "$APP" "$algorithm" "$encoded" | install -o root -g root -m 0644 /dev/stdin "$HOME_DIR/.ssh/authorized_keys"
