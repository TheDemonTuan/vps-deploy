#!/usr/bin/env bash
# platform-peer: runs every minute on each edge node (platform-peer.timer). It reaches the other
# nodes only through their read-only SFTP (platform/sync) and through the edge.
# 1. Renews this node's edge lease (cloudflare/edge-lb) with its replication position and, when
#    the lease's writer no longer matches this node's database role (or a replica follows another
#    node), starts platform-role.service (role.sh) to switch it. First, so a slow check cannot
#    starve it. It also keeps mc-hub-api's writer-lease file: touched while the lease names this
#    node as the primary, aged at once when another node holds it; a primary takes no writes once
#    the file is 150 s old, so a writer cut off from the lease stops before the edge (3 minutes)
#    may give it to another node. The CrowdSec LAPI follows the writer too: platform-lapi.service
#    (platform/crowdsec/lapi.sh) when this node neither holds nor follows it. The edge checks every
#    node's sites itself (cron) and alerts; this node alerts after two failed renewals.
# 2. On the writer: the R2 mirror runs only while the lease confirms this node, and the day's
#    database backup goes to /data/backups (the mirror copies it to R2) and to OCI Object Storage.
#    On the LAPI node, the same way, the CrowdSec controller (Telegram bot, Cloudflare edge list).
# 3. On the other nodes, checks that the Litestream followers (mc-hub-api's database, the LAPI's)
#    keep up with the writer. Telegram after two bad runs in a row, and again when it recovers.
# CrowdSec shares bans through its one LAPI (roles/crowdsec), not here.
# /etc/platform/peer.env: NODE, NODE_IP, ROLE (primary|replica before any failover), LEASE_URL,
# TELEGRAM_CHAT_ID. /etc/platform/nodes: "<id> <ip> <ecdsa host key>" per edge node (ansible).
# /etc/platform/telegram-token: bot token, /etc/platform/edge-node-key: the Worker's NODE_KEY,
# /etc/platform/oci-backup-url: a write-only pre-authenticated request for the OCI bucket, ending
# in /o/ (all root 0600).
set -uo pipefail
export LC_ALL=C
. /etc/platform/peer.env
state=/var/lib/platform-peer
volume=/var/lib/docker/volumes/mc-hub-api-data/_data
peers=$(awk -v me="$NODE" '!/^#/ && NF >= 2 && $1 != me {print $1, $2}' /etc/platform/nodes)

# peer_sftp <ip>: batch commands on stdin.
peer_sftp() {
  # ServerAlive: a peer that accepts the connection and then stalls fails within ~15 s.
  sftp -q -b - -i /etc/platform/sync_key -o BatchMode=yes -o ConnectTimeout=10 \
    -o ServerAliveInterval=5 -o ServerAliveCountMax=2 \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/platform/known_hosts "platform-sync@$1"
}

notify() {
  # The token goes through curl's config on stdin, never on a command line.
  printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "$(cat /etc/platform/telegram-token)" |
    curl -fsS -m 15 -o /dev/null -K - --data-urlencode "chat_id=$TELEGRAM_CHAT_ID" --data-urlencode "text=[$NODE] $1" ||
    echo "telegram failed: $1" >&2
}

# report <check> ok|fail <detail>
report() {
  local key fails
  key=$(printf '%s' "$1" | tr -c 'A-Za-z0-9._-' _)
  fails=$(cat "$state/$key.fails" 2>/dev/null || echo 0)
  if [ "$2" = ok ]; then
    if [ -e "$state/$key.alerted" ]; then notify "OK again: $1 ($3)"; rm -f "$state/$key.alerted"; fi
    echo 0 >"$state/$key.fails"
    return
  fi
  fails=$((fails + 1))
  echo "$fails" >"$state/$key.fails"
  echo "check failed ($fails): $1: $3" >&2
  if [ "$fails" -ge 2 ] && [ ! -e "$state/$key.alerted" ]; then notify "PROBLEM: $1 ($3)"; touch "$state/$key.alerted"; fi
}

# --- 1. Lease
role=$(cat "$volume/role" 2>/dev/null || echo "$ROLE")
# When this node's database was last known current (unix seconds): now on the primary, the last
# good follower check on a replica. The edge reads a stale replica last and promotes only a
# replica that was current when the writer was last seen healthy.
synced=$(date +%s)
[ "$role" = primary ] || synced=$(cat "$state/synced" 2>/dev/null || echo 0)
# Litestream position (16 hex digits): the primary's newest LTX, a replica's follower. The edge
# promotes only a replica (nearly) as far as the writer's last report.
if [ "$role" = primary ]; then
  txid=$(ls -1 /srv/platform-sync/litestream/mc-hub-api/ltx/*/*.ltx 2>/dev/null | sed -n 's/.*-\([0-9a-f]\{16\}\)\.ltx$/\1/p' | sort | tail -1)
else
  txid=$(tr -d '\n' <"$volume/mc-hub.db-txid" 2>/dev/null)
fi
[[ $txid =~ ^[0-9a-f]{16}$ ]] || txid=""
renewed=0 writer=$(cat "$state/writer" 2>/dev/null || echo unknown)
read -r begin _ </proc/uptime
if lease=$(printf 'header = "Authorization: Bearer %s"\n' "$(cat /etc/platform/edge-node-key)" |
  curl -fsS -m 20 -K - -H 'content-type: application/json' -d "{\"op\":\"beat\",\"synced\":$synced${txid:+,\"txid\":\"$txid\"}}" "$LEASE_URL") &&
  writer=$(jq -er '.writer' <<<"$lease"); then
  renewed=1
  if [ "$(jq -r '.lapiGrant' <<<"$lease")" = true ] && [ "$writer" = "$NODE" ]; then
    printf '%s\n' "${begin%%.*}" >/run/platform-peer/lapi.tmp && mv /run/platform-peer/lapi.tmp /run/platform-peer/lapi
  else
    rm -f /run/platform-peer/lapi
  fi
  echo "$writer" >"$state/writer"
  report "edge lease" ok "writer $writer"
fi
writer_ip=$(awk -v n="$writer" '$1 == n {print $2}' /etc/platform/nodes)
followed=$(sed -n 's/^PRIMARY_SSH=\(.*\):22$/\1/p' /etc/platform/litestream-primary.env 2>/dev/null)
if [ "$renewed" = 1 ]; then
  # A failed renewal leaves the file to age. A node the lease just named becomes primary through
  # role.sh, which touches the file itself.
  if [ "$writer" = "$NODE" ]; then
    [ "$role" != primary ] || touch "$volume/writer-lease"
  elif [ "$role" = primary ] || [ -e "$volume/writer-lease" ]; then
    touch -d @0 "$volume/writer-lease"
  fi
  # role.sh leaves stopped-apps behind when a step-down did not finish: run it again.
  if { [ "$writer" = "$NODE" ] && [ "$role" != primary ]; } || { [ "$writer" != "$NODE" ] && [ "$role" = primary ]; } ||
    { [ "$writer" != "$NODE" ] && [ "$writer_ip" != "$followed" ]; } || [ -e "$state/stopped-apps" ]; then
    echo "lease writer $writer, this node $role following ${followed:-nothing}: switching" >&2
    systemctl start --no-block platform-role.service
  fi
  # The CrowdSec LAPI follows the writer as well (platform/crowdsec/lapi.sh, a unit of its own: a
  # switch stuck there never holds up the database's).
  lapi_want=here
  [ "$writer" = "$NODE" ] || lapi_want=$writer
  lapi=$(cat "$state/lapi" 2>/dev/null)
  if [ "$lapi" = "$lapi_want" ]; then
    report "crowdsec lapi" ok "$lapi"
  elif [ -n "$lapi" ]; then
    report "crowdsec lapi" fail "the writer is $writer, this node's crowdsec LAPI: ${lapi:-unsettled} (here or the node it follows)"
    systemctl start --no-block platform-lapi.service
  fi
else
  report "edge lease" fail "renewal failed"
fi

# --- 2. Writer duties
if [ "$role" = primary ]; then
  confirmed=0
  [ "$renewed" = 1 ] && [ "$writer" = "$NODE" ] && confirmed=1
  # The mirror (platform/litestream, restart "no") runs only here: an old primary back from a
  # reboot, or cut off from the lease, would otherwise replace the writer's R2 copy with its own.
  # Three failed renewals in a row (the edge's 3-minute lease) stop it as well.
  mirror=$(docker inspect -f '{{.State.Running}}' litestream-mirror 2>/dev/null)
  if [ "$confirmed" = 1 ]; then
    [ "$mirror" = true ] || docker start litestream-mirror >/dev/null || echo "litestream-mirror did not start" >&2
  elif [ "$mirror" = true ] && { [ "$renewed" = 1 ] || [ "$(cat "$state/edge_lease.fails")" -ge 3 ]; }; then
    docker stop litestream-mirror >/dev/null
  fi
  # A consistent copy per UTC day (VACUUM INTO), 14 kept here; R2 keeps every one (rclone copy).
  backup=daily-$(date -u +%F).db
  if [ "$confirmed" = 1 ] && [ ! -e "$volume/backups/$backup" ]; then
    app=$(docker ps --format '{{.Names}}' | grep -m1 -E '^mc-hub-api-(blue|green)$')
    rm -f "$volume/backups/.$backup"
    if [ -n "$app" ] && timeout 30 docker exec "$app" /app/mc-hub-api backup "/data/backups/.$backup" >/dev/null &&
      mv "$volume/backups/.$backup" "$volume/backups/$backup"; then
      find "$volume/backups" -maxdepth 1 -name 'daily-*.db' -mtime +14 -delete
      report "daily backup" ok "$backup"
    else
      rm -f "$volume/backups/.$backup"
      report "daily backup" fail "${app:-no mc-hub-api container}: backup failed"
    fi
  elif [ "$confirmed" = 1 ] && [ "$(cat "$state/oci-backup" 2>/dev/null)" != "$backup" ]; then
    # A copy off Cloudflare, once a day in a later run than the backup (both would not fit
    # TimeoutStartSec). The URL can only write, never read, list or delete, and the bucket's
    # versioning keeps what an overwrite replaces. It stays off the command line.
    if printf 'url = "%s%s"\n' "$(cat /etc/platform/oci-backup-url)" "$backup" |
      curl -fsS -m 20 -o /dev/null -K - -T "$volume/backups/$backup"; then
      echo "$backup" >"$state/oci-backup"
      report "oci backup" ok "$backup"
    else
      report "oci backup" fail "upload of $backup failed"
    fi
  fi
fi

# The CrowdSec controller (Telegram bot, ban notifications, Cloudflare edge list) runs on the LAPI
# node only, and like the mirror only while the lease confirms it: two would fight over the bot
# and the list. It is not enabled at boot (ansible/roles/crowdsec/tasks/controller.yml).
ctl=(crowdsec-telegram-controller.service crowdsec-telegram-health.timer)
if [ "$renewed" = 1 ] && [ "$writer" = "$NODE" ] && [ "$(cat "$state/lapi" 2>/dev/null)" = here ]; then
  if systemctl start crowdsec && systemctl start "${ctl[@]}" && systemctl is-active --quiet "${ctl[0]}"; then
    report "crowdsec controller" ok running
  else
    report "crowdsec controller" fail "did not start"
  fi
elif [ -s "$state/lapi" ] && { [ "$renewed" = 1 ] || [ "$(cat "$state/edge_lease.fails" 2>/dev/null || echo 0)" -ge 3 ]; }; then
  systemctl stop "${ctl[@]}" 2>/dev/null || true
fi

# --- 3. Followers
lag=""
[ "$role" = primary ] && lag=0
if [ -n "$writer_ip" ] && [ "$writer" != "$NODE" ]; then
  # One SFTP session lists the writer's copies, the CrowdSec LAPI's and mc-hub-api's ("-": a
  # missing one does not end the batch). A copy's position is its highest LTX end txid on any
  # level; ours is the follower's -txid file. Behind what the writer had a minute ago means the
  # follower is stuck; ahead means the writer started a new lineage (reset or promotion) and this
  # node needs a fresh restore.
  listing=$(printf '%s\n' '-ls -1 /litestream/crowdsec/ltx/*/*.ltx' 'ls -1 /litestream/mc-hub-api/ltx/*/*.ltx' |
    peer_sftp "$writer_ip" 2>/dev/null)
  newest() { sed -n "s#.*/litestream/$1/ltx/.*-\([0-9a-f]\{16\}\)\.ltx\$#\1#p" <<<"$listing" | sort | tail -1; }
  if [ "$role" = replica ]; then
    primary=$(newest mc-hub-api)
    replica=$(tr -d '\n' <"$volume/mc-hub.db-txid" 2>/dev/null)
    before=$(cat "$state/primary-txid" 2>/dev/null)
    if [ -n "$primary" ]; then
      echo "$primary" >"$state/primary-txid"
      [ -n "$replica" ] && lag=$((16#$primary - 16#$replica))
      if [ -z "$replica" ] || [[ $replica > $primary ]]; then
        report "litestream follower" fail "replica txid ${replica:-none}, primary $primary"
      elif [ -n "$before" ] && [[ $replica < $before ]]; then
        report "litestream follower" fail "replica txid $replica behind primary's $before from a minute ago"
      else
        report "litestream follower" ok "txid $replica"
        date +%s >"$state/synced"
      fi
    else
      # The follower reads over the same SFTP link: this copy no longer gets the primary's writes.
      report "litestream follower" fail "cannot list the primary's LTX files over SFTP (replica txid ${replica:-none})"
    fi
  fi
  # The copy this node takes the LAPI over from (platform/crowdsec/lapi.sh).
  if [ "$(cat "$state/lapi" 2>/dev/null)" = "$writer" ]; then
    held=$(newest crowdsec)
    copy=$(tr -d '\n' </var/lib/crowdsec/follow/crowdsec.db-txid 2>/dev/null)
    before=$(cat "$state/crowdsec-txid" 2>/dev/null)
    if [ -z "$held" ]; then
      report "crowdsec follower" fail "no copy of the LAPI database on $writer over SFTP (ours: txid ${copy:-none})"
    else
      echo "$held" >"$state/crowdsec-txid"
      if [ -z "$copy" ] || [[ $copy > $held ]]; then
        report "crowdsec follower" fail "copy txid ${copy:-none}, LAPI node $held"
      elif [ -n "$before" ] && [[ $copy < $before ]]; then
        report "crowdsec follower" fail "copy txid $copy behind the LAPI node's $before from a minute ago"
      else
        report "crowdsec follower" ok "txid $copy"
        printf '%s\n' "$writer" >"$state/crowdsec-synced"
      fi
    fi
  fi
fi

# Metrics for the monitoring agent's node-exporter (platform/monitor), written atomically. No lag
# sample when it could not be measured: a gap in the panel, never a false 0.
metrics=/var/lib/node-exporter/platform.prom
cat >"$metrics.tmp" <<EOF
# HELP platform_lease_renewed 1 when this run renewed the edge lease.
platform_lease_renewed $renewed
# HELP platform_lease_writer The writer the edge lease named, as this node last saw it.
platform_lease_writer{writer="$writer"} 1
# HELP platform_role_primary 1 when this node's mc-hub-api database is the primary.
platform_role_primary $([ "$role" = primary ] && echo 1 || echo 0)
# HELP platform_replica_lag_txids Transactions the replica is behind the primary (0 on the primary).
${lag:+platform_replica_lag_txids $lag}
EOF
mv -f "$metrics.tmp" "$metrics"
exit 0
