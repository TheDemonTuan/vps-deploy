#!/usr/bin/env bash
# platform-peer: runs every minute on each edge node (platform-peer.timer). It reaches the other
# node only through that node's read-only SFTP (platform/sync) and through the edge.
# 1. Renews this node's edge lease (cloudflare/edge-lb) and, when the lease's writer no longer
#    matches this node's database role, starts platform-role.service (role.sh) to switch it.
#    First, so a slow ban exchange cannot starve it. The edge checks every node's sites itself
#    (cron) and alerts; this node alerts after two failed renewals.
# 2. On the writer: the R2 mirror runs only while the lease confirms this node, and the day's
#    database backup goes to /data/backups (the mirror copies it to R2).
# 3. CrowdSec: publishes this node's own HTTP bans and adds the other node's as
#    `peer/<id>:<scenario>`, so each node blocks what the other detected and the CrowdSec →
#    Cloudflare controller on n1 puts both on the edge list (it skips `cscli decisions import`).
#    Removing a ban on either node (cscli, the Telegram bot) removes it on both (unbans.json).
#    SSH bans stay per node, as the controller keeps them off the edge list.
# 4. On a replica, checks that the Litestream follower keeps up with the primary. Telegram after
#    two bad runs in a row, and again when it recovers.
# /etc/platform/peer.env: NODE, NODE_IP, PEER, PEER_IP, ROLE (primary|replica before any
# failover), LEASE_URL, TELEGRAM_CHAT_ID. /etc/platform/telegram-token: bot token,
# /etc/platform/edge-node-key: the Worker's NODE_KEY (both root 0600).
# shortcut: one peer (two nodes); with a third node, loop the exchange and checks over the peers.
set -uo pipefail
export LC_ALL=C
. /etc/platform/peer.env
state=/var/lib/platform-peer
shared=/srv/platform-sync/crowdsec
volume=/var/lib/docker/volumes/mc-hub-api-data/_data

peer_sftp() {
  # ServerAlive: a peer that accepts the connection and then stalls fails within ~15 s.
  sftp -q -b - -i /etc/platform/sync_key -o BatchMode=yes -o ConnectTimeout=10 \
    -o ServerAliveInterval=5 -o ServerAliveCountMax=2 \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/platform/known_hosts "platform-sync@$PEER_IP"
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
renewed=0 writer=$(cat "$state/writer" 2>/dev/null || echo unknown)
if lease=$(printf 'header = "Authorization: Bearer %s"\n' "$(cat /etc/platform/edge-node-key)" |
  curl -fsS -m 20 -K - -H 'content-type: application/json' -d '{"op":"beat"}' "$LEASE_URL") &&
  writer=$(jq -er '.writer' <<<"$lease"); then
  renewed=1
  echo "$writer" >"$state/writer"
  report "edge lease" ok "writer $writer"
  # role.sh leaves stopped-apps behind when a step-down did not finish: run it again.
  if { [ "$writer" = "$NODE" ] && [ "$role" != primary ]; } || { [ "$writer" != "$NODE" ] && [ "$role" = primary ]; } ||
    [ -e "$state/stopped-apps" ]; then
    echo "lease writer $writer, this node $role: switching" >&2
    systemctl start --no-block platform-role.service
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
  fi
fi

# --- 3. CrowdSec bans
# Each node publishes its own HTTP bans with their ids (decisions.json) and the ids of the peer's
# bans whose copy an operator removed here (unbans.json, from copies.jq). Without the second file
# the copy came straight back within a minute and the controller put the IP back on Cloudflare.
rm -f "$state/peer-decisions.json" "$state/peer-unbans.json"
printf 'get /crowdsec/decisions.json %s\n-get /crowdsec/unbans.json %s\n' \
  "$state/peer-decisions.json" "$state/peer-unbans.json" | peer_sftp >/dev/null 2>&1

if [ -s "$state/peer-unbans.json" ]; then
  cscli decisions list -o json --origin crowdsec |
    jq -r --slurpfile gone "$state/peer-unbans.json" \
      '[$gone[0][]? | numbers] as $gone | .[]?.decisions[]? | select(.id | IN($gone[])) | .id' |
    while read -r id; do cscli decisions delete --id "$id" >/dev/null; done
fi
own=$(cscli decisions list -o json --origin crowdsec) &&
  jq '[.[]?.decisions[]? | select(.type == "ban" and .scope == "Ip" and (.scenario | test("ssh"; "i") | not)
       and (.duration | startswith("-") | not)) | {id, value, scenario, duration: (.duration | sub("\\.[0-9]+s$"; "s"))}]' \
    <<<"$own" >"$shared/decisions.json.tmp" && mv -f "$shared/decisions.json.tmp" "$shared/decisions.json"

if [ -f "$state/peer-decisions.json" ] && mine=$(cscli decisions list -o json --origin cscli) &&
  for f in copies tombstones; do [ -s "$state/$f.json" ] || echo '[]' >"$state/$f.json"; done &&
  plan=$(jq -r --arg tag "peer/$PEER:" --arg skip "$NODE_IP $PEER_IP" \
    --slurpfile peer "$state/peer-decisions.json" --slurpfile copies "$state/copies.json" \
    --slurpfile tomb "$state/tombstones.json" -f "$(dirname "${BASH_SOURCE[0]}")/copies.jq" <<<"$mine"); then
  : >"$state/copies.new"
  : >"$state/tombstones.new"
  while read -r op a b c d; do
    case $op in
      tomb) echo "$a" >>"$state/tombstones.new" ;;
      keep) echo "$a $b $c" >>"$state/copies.new" ;;
      add) cscli decisions add -i "$b" -d "$c" -R "$d" >/dev/null && echo "$a $b $d" >>"$state/copies.new" ;;
      del) cscli decisions delete --id "$a" >/dev/null ;;
    esac
  done <<<"$plan"
  jq -R -s '[split("\n")[] | select(length > 0) | split(" ") | {ids: [.[0] | split(",")[] | tonumber?], value: .[1], scenario: .[2]}]' \
    "$state/copies.new" >"$state/copies.json"
  jq -R -s '[split("\n")[] | select(length > 0) | tonumber]' "$state/tombstones.new" >"$state/tombstones.json"
  cp "$state/tombstones.json" "$shared/unbans.json.tmp" && mv -f "$shared/unbans.json.tmp" "$shared/unbans.json"
fi

# --- 4. Follower
lag=""
[ "$role" = primary ] && lag=0
if [ "$role" = replica ]; then
  # The primary's replica position is the highest LTX end txid on any level; ours is the follower's
  # -txid file. Behind what the primary had a minute ago means the follower is stuck; ahead means
  # the primary started a new lineage (reset or promotion) and this node needs a fresh restore.
  primary=$(echo 'ls -1 /litestream/mc-hub-api/ltx/*/*.ltx' | peer_sftp 2>/dev/null |
    sed -n 's/.*-\([0-9a-f]\{16\}\)\.ltx$/\1/p' | sort | tail -1)
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
    fi
  else
    # The follower reads over the same SFTP link: this copy no longer gets the primary's writes.
    report "litestream follower" fail "cannot list the primary's LTX files over SFTP (replica txid ${replica:-none})"
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
