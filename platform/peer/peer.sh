#!/usr/bin/env bash
# platform-peer: runs every minute on each edge node (platform-peer.timer). It reaches the other
# node only through that node's read-only SFTP (platform/sync) and through the edge.
# 1. CrowdSec: publishes this node's own HTTP bans and adds the other node's as
#    `peer/<id>:<scenario>`, so each node blocks what the other detected and the CrowdSec →
#    Cloudflare controller on n1 puts both on the edge list (it skips `cscli decisions import`).
#    SSH bans stay per node, as the controller keeps them off the edge list.
# 2. Renews this node's edge lease (cloudflare/edge-lb) and, when the lease's writer no longer
#    matches this node's database role, starts platform-role.service (role.sh) to switch it.
#    The edge checks every node's sites itself (cron) and alerts.
# 3. On a replica, checks that the Litestream follower keeps up with the primary. Telegram after
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

peer_sftp() {
  sftp -q -b - -i /etc/platform/sync_key -o BatchMode=yes -o ConnectTimeout=10 \
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

# --- 1. CrowdSec bans
own=$(cscli decisions list -o json --origin crowdsec) &&
  jq '[.[]?.decisions[]? | select(.type == "ban" and .scope == "Ip" and (.scenario | test("ssh"; "i") | not)
       and (.duration | startswith("-") | not)) | {value, scenario, duration: (.duration | sub("\\.[0-9]+s$"; "s"))}]' \
    <<<"$own" >"$shared/decisions.json.tmp" && mv -f "$shared/decisions.json.tmp" "$shared/decisions.json"

if printf 'get /crowdsec/decisions.json %s\n' "$state/peer-decisions.json" | peer_sftp >/dev/null 2>&1; then
  tag="peer/$PEER:"
  # The other node is trusted for bans, not for their shape: plain IPs only (no ranges), never a node.
  cscli decisions list -o json --origin cscli |
    jq -r --arg tag "$tag" --arg skip "$NODE_IP $PEER_IP" --slurpfile peer "$state/peer-decisions.json" '
      ($skip | split(" ")) as $skip
      | [$peer[0][]? | select((.value | type == "string" and test("^[0-9a-fA-F.:]{2,45}$")) and (.value | IN($skip[]) | not)
          and (.scenario | type == "string" and test("^[A-Za-z0-9_./-]{1,100}$"))
          and (.duration | type == "string" and test("^([0-9]+h)?([0-9]+m)?([0-9]+s)?$")))] as $want
      | [.[]?.decisions[]? | select(.scenario | startswith($tag))] as $mine
      | ($want | map({(.value + " " + $tag + .scenario): true}) | add // {}) as $wanted
      | ($mine | map({(.value + " " + .scenario): true}) | add // {}) as $have
      | ($want[] | select($have[.value + " " + $tag + .scenario] | not) | "add \(.value) \(.duration) \($tag + .scenario)"),
        ($mine[] | select($wanted[.value + " " + .scenario] | not) | "del \(.id)")' |
    while read -r op a b c; do
      if [ "$op" = add ]; then cscli decisions add -i "$a" -d "$b" -R "$c" >/dev/null; else cscli decisions delete --id "$a" >/dev/null; fi
    done
fi

# --- 2. Lease
role=$(cat /var/lib/docker/volumes/mc-hub-api-data/_data/role 2>/dev/null || echo "$ROLE")
if lease=$(printf 'header = "Authorization: Bearer %s"\n' "$(cat /etc/platform/edge-node-key)" |
  curl -fsS -m 20 -K - -H 'content-type: application/json' -d '{"op":"beat"}' "$LEASE_URL") &&
  writer=$(jq -er '.writer' <<<"$lease"); then
  echo "$writer" >"$state/writer"
  if { [ "$writer" = "$NODE" ] && [ "$role" != primary ]; } || { [ "$writer" != "$NODE" ] && [ "$role" = primary ]; }; then
    echo "lease writer $writer, this node $role: switching" >&2
    systemctl start --no-block platform-role.service
  fi
else
  echo "lease renewal failed" >&2
fi

# --- 3. Follower
if [ "$role" = replica ]; then
  # The primary's replica position is the highest LTX end txid on any level; ours is the follower's
  # -txid file. Behind what the primary had a minute ago means the follower is stuck; ahead means
  # the primary started a new lineage (reset or promotion) and this node needs a fresh restore.
  primary=$(echo 'ls -1 /litestream/mc-hub-api/ltx/*/*.ltx' | peer_sftp 2>/dev/null |
    sed -n 's/.*-\([0-9a-f]\{16\}\)\.ltx$/\1/p' | sort | tail -1)
  replica=$(tr -d '\n' </var/lib/docker/volumes/mc-hub-api-data/_data/mc-hub.db-txid 2>/dev/null)
  before=$(cat "$state/primary-txid" 2>/dev/null)
  if [ -n "$primary" ]; then
    echo "$primary" >"$state/primary-txid"
    if [ -z "$replica" ] || [[ $replica > $primary ]]; then
      report "litestream follower" fail "replica txid ${replica:-none}, primary $primary"
    elif [ -n "$before" ] && [[ $replica < $before ]]; then
      report "litestream follower" fail "replica txid $replica behind primary's $before from a minute ago"
    else
      report "litestream follower" ok "txid $replica"
    fi
  fi
fi
exit 0
