#!/bin/sh
# relay.sh <db>: the reading side of platform/sync, run in the rclone container `relay` of
# platform/litestream/compose.yml (mc-hub-api) and platform/crowdsec/litestream.yml (crowdsec).
# Keeps /relay/copy a mirror of the writer's Litestream copy of <db> (/litestream/<db><LTX_SUFFIX>
# on its read-only SFTP), which this node's follower reads as a local replica (type file).
# Litestream's own SFTP client waits one round trip per small read (about 1 KB) and lists every
# level each second: from 250 ms away (vps-n4) a 4.5 MB restore took 40 minutes. rclone keeps its
# SSH connections (rcd) and pipelines transfers.
# Level 0 (each new transaction, kept there at least 5 minutes) every second, the other levels (a
# restore's base, the follower's gap fill) every minute. /relay/at: when a pass last reached the
# writer (unix seconds), first written after a complete copy; the follower starts on it and
# peer.sh checks its age. role.sh and lapi.sh empty /relay on every switch.
# Env: PRIMARY_SSH (<ip>:22), PRIMARY_HOST_KEY (pinned) and LTX_SUFFIX, from role.sh's
# litestream-primary.env or lapi.sh's crowdsec-lapi.env.
set -eu
host=${PRIMARY_SSH%:22}
printf '%s %s\n' "$host" "$PRIMARY_HOST_KEY" >/tmp/known_hosts
# Each SFTP connection is an sshd and sftp-server pair (~18 MB) on the writer: at most 8, kept
# 75 s so the every-minute pass reuses them (unbounded, two relays on three nodes held 160).
export RCLONE_CONFIG_W_TYPE=sftp RCLONE_CONFIG_W_HOST="$host" RCLONE_CONFIG_W_USER=platform-sync \
  RCLONE_CONFIG_W_KEY_FILE=/etc/relay/sync_key RCLONE_CONFIG_W_KNOWN_HOSTS_FILE=/tmp/known_hosts \
  RCLONE_CONFIG_W_HOST_KEY_ALGORITHMS="${PRIMARY_HOST_KEY%% *}" RCLONE_CONFIG_W_SHELL_TYPE=none \
  RCLONE_CONFIG_W_DISABLE_HASHCHECK=true RCLONE_CONFIG_W_CONNECTIONS=8 RCLONE_CONFIG_W_IDLE_TIMEOUT=75s
src=w:/litestream/$1${LTX_SUFFIX:-}
# The control socket stays inside this container (/tmp is its own tmpfs).
rclone rcd --rc-addr unix:///tmp/rc.sock --rc-no-auth &
rcd=$!
mirror() {
  kill -0 "$rcd"
  rclone rc --unix-socket /tmp/rc.sock --timeout 1h sync/sync srcFs="$1" dstFs="$2" _filter="$3" \
    _config='{"SizeOnly":true,"Transfers":8,"Checkers":4}' >/dev/null
}
# Both passes name the same source, so they share its connection pool.
rest() { mirror "$src" /relay/copy '{"ExcludeRule":["/ltx/0/**"]}'; }
level0() {
  mirror "$src" /relay/copy '{"IncludeRule":["/ltx/0/**"]}'
  date +%s >/relay/at.tmp && mv -f /relay/at.tmp /relay/at
}
until [ -S /tmp/rc.sock ]; do kill -0 "$rcd"; sleep 0.2; done
# A failed first pass ends the container (restart: unless-stopped) before the follower may start.
rest
level0
(while sleep 60; do rest || true; done) &
while sleep 1; do
  kill -0 "$rcd" || exit 1
  level0 || true
done
