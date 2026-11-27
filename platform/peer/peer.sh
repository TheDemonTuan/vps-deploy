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
#    keep up with the writer. Telegram after two bad runs in a row (explain: what the check
#    guards, its impact, where to start, the fleet's writer and LAPI), and a reply to that message
#    when it recovers, with how long it lasted.
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
. "$(dirname "$0")/write-position.sh"
peers=$(awk -v me="$NODE" '!/^#/ && NF >= 2 && $1 != me {print $1, $2}' /etc/platform/nodes)

# peer_sftp <ip>: batch commands on stdin.
peer_sftp() {
  # ServerAlive: a peer that accepts the connection and then stalls fails within ~15 s.
  sftp -q -b - -i /etc/platform/sync_key -o BatchMode=yes -o ConnectTimeout=10 \
    -o ServerAliveInterval=5 -o ServerAliveCountMax=2 \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/platform/known_hosts "platform-sync@$1"
}

esc() { sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' <<<"$1"; }
# A Litestream position (16 hex digits) as the transaction number.
tx() { if [[ ${1:-} =~ ^[0-9a-f]{16}$ ]]; then printf '#%d' "$((16#$1))"; else printf none; fi; }

# notify <html> [<message id>]: a Telegram message, a reply to that one when given. Prints the new
# message's id.
notify() {
  local reply=()
  [[ ${2:-} =~ ^[0-9]+$ ]] && reply=(--data-urlencode "reply_parameters={\"message_id\":$2,\"allow_sending_without_reply\":true}")
  # The token goes through curl's config on stdin, never on a command line.
  printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "$(cat /etc/platform/telegram-token)" |
    curl -fsS -m 15 -K - --data-urlencode "chat_id=$TELEGRAM_CHAT_ID" -d parse_mode=HTML --data-urlencode "text=$1" "${reply[@]}" |
    jq -r '.result.message_id' || echo "telegram failed: $1" >&2
}

# explain <check>: sets title, what (the check in plain words), impact and look (where to start)
# for whoever reads the alert, and lapi_node.
explain() {
  lapi_node=$(cat "$state/lapi" 2>/dev/null)
  [ "$lapi_node" = here ] && lapi_node=$NODE
  lapi_node=${lapi_node:-unsettled}
  look="sudo journalctl -u platform-peer -n 30"
  case $1 in
    "edge lease")
      title="cannot renew its edge lease"
      what="Every minute $NODE renews its lease with the Cloudflare edge (edge-lb Worker), which names the writer; the last two renewals failed."
      impact="A writer stops taking writes 150 s after its last renewal and the edge hands writing to a current replica after 3 min. A replica is read last and never promoted." ;;
    "crowdsec lapi")
      title="CrowdSec LAPI has not moved to the writer"
      what="The fleet's one CrowdSec LAPI (the ban database) follows the writer, $writer. $NODE has been switching for 5 min without finishing."
      impact="Until it settles $NODE may miss new bans and unbans and cannot send its own. platform-lapi retries every minute."
      look="sudo journalctl -u platform-lapi -n 50" ;;
    "daily backup")
      title="daily database backup failed"
      what="The writer, $NODE, keeps one copy of mc-hub-api's database a day (VACUUM INTO), which then goes to R2 and OCI."
      impact="No restore point for today yet; earlier days stay in /data/backups, R2 and OCI. Retried every minute." ;;
    "oci backup")
      title="OCI backup upload failed"
      what="Today's backup is on $NODE and in R2, but its upload to OCI Object Storage (the copy outside Cloudflare) failed."
      impact="Only today's copy outside Cloudflare is missing. Retried every minute; an expired pre-authenticated request URL fails every time." ;;
    "crowdsec controller")
      title="CrowdSec controller is not running"
      what="The controller runs on the LAPI node, $NODE: ban messages and unban buttons in this chat, and the Cloudflare edge ban list."
      impact="Bans still block on every node, but no ban messages arrive and the Cloudflare edge list stops following bans and unbans."
      look="sudo journalctl -u crowdsec-telegram-controller -n 50" ;;
    "litestream follower")
      title="mc-hub database copy is behind"
      what="$NODE follows the writer $writer's mc-hub-api database over SFTP. If every replica reports this, the cause is on $writer."
      impact="The edge reads from $NODE last and will not promote it; pages served from $NODE may show older data."
      look="sudo docker logs --tail 50 litestream" ;;
    "crowdsec follower")
      title="CrowdSec ban database copy is behind"
      what="$NODE keeps a live copy of the ban database from the LAPI on $lapi_node, to take the LAPI over if $lapi_node fails. If every other node reports this, the cause is on $lapi_node."
      impact="None on blocking now: $NODE asks the LAPI on $lapi_node live. Only a takeover by $NODE could miss the newest bans and unbans, and it refuses one without a copy verified in the last 10 min."
      look="sudo docker logs --tail 50 litestream-crowdsec" ;;
    *) title=$1 what="" impact="unknown" ;;
  esac
}

# report <check> ok|fail <detail> [<failed runs in a row before alerting, default 2>]
report() {
  local key fails since sent
  key=$(printf '%s' "$1" | tr -c 'A-Za-z0-9._-' _)
  fails=$(cat "$state/$key.fails" 2>/dev/null || echo 0)
  if [ "$2" = ok ]; then
    if [ -e "$state/$key.alerted" ]; then
      read -r since sent <"$state/$key.alerted"
      explain "$1"
      notify "✅ <b>$NODE: resolved${since:+ after $((($(date +%s) - since + 59) / 60)) min}</b> · $title
<b>Now:</b> $(esc "$3")" "${sent:-}" >/dev/null
      rm -f "$state/$key.alerted"
    fi
    echo 0 >"$state/$key.fails"
    return
  fi
  fails=$((fails + 1))
  echo "$fails" >"$state/$key.fails"
  [ "$fails" -gt 1 ] || date +%s >"$state/$key.since"
  echo "check failed ($fails): $1: $3" >&2
  if [ "$fails" -ge "${4:-2}" ] && [ ! -e "$state/$key.alerted" ]; then
    explain "$1"
    since=$(cat "$state/$key.since" 2>/dev/null || date +%s)
    sent=$(notify "🔴 <b>$NODE: $title</b>
$what
<b>Impact:</b> $impact
<b>Start with:</b> <code>$look</code> on $NODE
<b>Seen:</b> $(esc "$3")
<i>Writer $writer · CrowdSec LAPI $lapi_node · checked every minute; a ✅ reply follows when it clears.</i>")
    echo "$since $sent" >"$state/$key.alerted"
  fi
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
proof=$(position) || proof=null
read -r begin _ </proc/uptime
if lease=$(printf 'header = "Authorization: Bearer %s"\n' "$(cat /etc/platform/edge-node-key)" |
  curl -fsS -m 20 -K - -H 'content-type: application/json' -d "{\"op\":\"beat\",\"synced\":$synced,\"position\":$proof${txid:+,\"txid\":\"$txid\"}}" "$LEASE_URL") &&
  writer=$(jq -er '.writer' <<<"$lease"); then
  renewed=1
  if [ "$(jq -r '.lapiGrant' <<<"$lease")" = true ] && [ "$writer" = "$NODE" ]; then
    printf '%s\n' "${begin%%.*}" >/run/platform-peer/lapi.tmp && mv /run/platform-peer/lapi.tmp /run/platform-peer/lapi
  else
    rm -f /run/platform-peer/lapi
  fi
  printf '%s\n' "$lease" >"$state/lease.tmp" && mv -f "$state/lease.tmp" "$state/lease" || exit 1
  echo "$writer" >"$state/writer"
  report "edge lease" ok "writer $writer"
fi
writer_ip=$(awk -v n="$writer" '$1 == n {print $2}' /etc/platform/nodes)
followed=$(sed -n 's/^PRIMARY_SSH=\(.*\):22$/\1/p' /etc/platform/litestream-primary.env 2>/dev/null)
if [ "$renewed" = 1 ]; then
  # A failed renewal leaves the file to age. A node the lease just named becomes primary through
  # role.sh, which touches the file itself.
  if [ "$writer" = "$NODE" ]; then
    if [ "$role" = primary ] && [ ! -e "$state/promoting" ]; then touch "$volume/writer-lease"; fi
  elif [ "$role" = primary ] || [ -e "$volume/writer-lease" ]; then
    touch -d @0 "$volume/writer-lease"
  fi
  # role.sh leaves stopped-apps behind when a step-down did not finish: run it again.
  if { [ "$writer" = "$NODE" ] && [ "$role" != primary ]; } || { [ "$writer" != "$NODE" ] && [ "$role" = primary ]; } ||
    { [ "$writer" != "$NODE" ] && [ "$writer_ip" != "$followed" ]; } || [ -e "$state/stopped-apps" ] || [ -e "$state/promoting" ] ||
    { [ -f "$volume/write-quorum.json" ] && [ "$writer" != "$NODE" ] && [ "$(jq -r '.epoch' <<<"$lease")" != "$(cat "$volume/follower-epoch" 2>/dev/null)" ]; }; then
    echo "lease writer $writer, this node $role following ${followed:-nothing}: switching" >&2
    systemctl start --no-block platform-role.service
  fi
  # The CrowdSec LAPI follows the writer as well (platform/crowdsec/lapi.sh, a unit of its own: a
  # switch stuck there never holds up the database's).
  lapi_want=here
  [ "$writer" = "$NODE" ] || lapi_want=$writer
  lapi=$(cat "$state/lapi" 2>/dev/null)
  if [ "$lapi" = "$lapi_want" ]; then
    report "crowdsec lapi" ok "the LAPI is on ${lapi/#here/$NODE}"
  elif [ -n "$lapi" ]; then
    # 5: a switch waits out the old writer's last lease (3 min) before it may serve.
    report "crowdsec lapi" fail "the writer is $writer, but $NODE still $([ "$lapi" = here ] && echo "serves the LAPI itself" || echo "follows the LAPI on $lapi")" 5
    systemctl start --no-block platform-lapi.service
  fi
else
  report "edge lease" fail "the edge did not answer or refused the renewal"
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
  # Ours first: read after the writer's listing, a copy could already hold a transaction the
  # listing missed (the LAPI writes every few seconds) and looked ahead of it. Read before, ours
  # can only trail the listing, so ahead means the writer started a new lineage.
  replica=$(tr -d '\n' <"$volume/mc-hub.db-txid" 2>/dev/null)
  copy=$(tr -d '\n' </var/lib/crowdsec/follow/crowdsec.db-txid 2>/dev/null)
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
    before=$(cat "$state/primary-txid" 2>/dev/null)
    if [ -n "$primary" ]; then
      echo "$primary" >"$state/primary-txid"
      [ -n "$replica" ] && lag=$((16#$primary - 16#$replica))
      if [ -z "$replica" ]; then
        report "litestream follower" fail "no local copy yet (its restore has not finished); $writer is at $(tx "$primary")"
      elif [[ $replica > $primary ]]; then
        report "litestream follower" fail "ours is at $(tx "$replica"), past $writer's newest $(tx "$primary"): $writer started a new history, so ours needs a fresh restore"
      elif [ -n "$before" ] && [[ $replica < $before ]]; then
        report "litestream follower" fail "ours is stuck at $(tx "$replica"), behind where $writer was a minute ago ($(tx "$before"))"
      else
        report "litestream follower" ok "ours is at $(tx "$replica"), $writer at $(tx "$primary")"
        date +%s >"$state/synced"
      fi
    else
      # The follower reads over the same SFTP link: this copy no longer gets the primary's writes.
      report "litestream follower" fail "cannot read $writer's copy over SFTP (the follower uses the same link); ours is at $(tx "$replica")"
    fi
  fi
  # The copy this node takes the LAPI over from (platform/crowdsec/lapi.sh).
  if [ "$(cat "$state/lapi" 2>/dev/null)" = "$writer" ]; then
    held=$(newest crowdsec)
    before=$(cat "$state/crowdsec-txid" 2>/dev/null)
    if [ -z "$held" ]; then
      report "crowdsec follower" fail "cannot read the LAPI's copy on $writer over SFTP (the follower uses the same link); ours is at $(tx "$copy")"
    else
      echo "$held" >"$state/crowdsec-txid"
      if [ -z "$copy" ]; then
        report "crowdsec follower" fail "no local copy yet (its restore has not finished); the LAPI on $writer is at $(tx "$held")"
      elif [[ $copy > $held ]]; then
        report "crowdsec follower" fail "ours is at $(tx "$copy"), past the newest on $writer ($(tx "$held")): its copy started over, so ours needs a fresh restore"
      elif [ -n "$before" ] && [[ $copy < $before ]]; then
        report "crowdsec follower" fail "ours is stuck at $(tx "$copy"), behind where the LAPI on $writer was a minute ago ($(tx "$before"))"
      else
        report "crowdsec follower" ok "ours is at $(tx "$copy"), the LAPI on $writer at $(tx "$held")"
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
