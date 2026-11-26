#!/usr/bin/env bash
# role.sh: switch this node's mc-hub-api database between primary (the single writer) and replica.
# The edge lease (cloudflare/edge-lb, Durable Object "mc-hub-api") names the writer; the Worker
# sends writes only there, so two nodes never take writes at once.
#   role.sh promote [--force]  take the lease, then become primary. Refused while the writer
#                              renewed it in the last 3 minutes; --force takes it anyway.
#   role.sh reconcile          become what the lease says (platform-role.service; peer.sh starts
#                              it when its renewal shows the role changed, or that a replica
#                              follows a node that is no longer the writer)
# Promotion loses what the old primary had not replicated yet (normally about a second). The old
# primary, once back, steps down by itself: its database moves aside to fenced-<time>/ in the
# volume and it follows the new primary; so does every other replica (a new lineage). A step-down
# whose restore does not finish leaves stopped-apps behind: peer.sh runs it again, and the apps
# start once the copy is in place.
set -euo pipefail
. /etc/platform/peer.env
# One switch at a time: a manual promote and the timer's reconcile would otherwise run together.
exec 9>/run/platform-role.lock
flock 9
volume=/var/lib/docker/volumes/mc-hub-api-data/_data
writer_file=/var/lib/platform-peer/writer
stopped=/var/lib/platform-peer/stopped-apps
. "$(dirname "$0")/write-position.sh"
lease_file=/var/lib/platform-peer/lease

source_epoch() {
  local path tmp
  tmp=$(mktemp -d)
  path=$tmp/epoch
  printf 'get /litestream/mc-hub-api-%s/epoch %s\n' "$2" "$path" |
    sftp -q -b - -i /etc/platform/sync_key -o BatchMode=yes -o ConnectTimeout=5 \
      -o ServerAliveInterval=3 -o ServerAliveCountMax=2 -o StrictHostKeyChecking=yes \
      -o UserKnownHostsFile=/etc/platform/known_hosts "platform-sync@$1" >/dev/null 2>&1 || true
  if [ -s "$path" ]; then cat "$path"; fi
  rm -rf "$tmp"
}
# The writer a replica follows (PRIMARY_SSH, PRIMARY_HOST_KEY for platform/litestream/replica.yml),
# from /etc/platform/nodes: "<id> <ip> <ecdsa host key>" (Litestream's SSH client pins ECDSA).
follows=/etc/platform/litestream-primary.env

litestream() {
  docker compose --env-file /etc/platform/litestream.env --project-directory /opt/platform/litestream \
    -f /opt/platform/litestream/compose.yml "$@"
}

# become primary | become replica <writer>
become() {
  local want=$1 current apps follow=""
  local epoch='' floor='' checked peer_ip expected=''
  if [ -f "$volume/write-quorum.json" ]; then
    checked=$(cat "$lease_file")
    expected=${2:-$NODE}
    jq -e --arg writer "$expected" '.writer == $writer and (.epoch | type == "number")' <<<"$checked" >/dev/null
    epoch=$(jq -r .epoch <<<"$checked")
    [[ $epoch =~ ^[0-9]{1,15}$ ]] || return 1
    floor=$(jq -c '.floor // empty' <<<"$checked")
  fi
  current=$(cat "$volume/role" 2>/dev/null || echo "$ROLE")
  if [ "$want" = replica ]; then
    follow=$(awk -v n="$2" '$1 == n && NF >= 4 {printf "PRIMARY_SSH=%s:22\nPRIMARY_HOST_KEY=%s %s\n", $2, $3, $4}' /etc/platform/nodes)
    [ -n "$follow" ] || { echo "writer $2 is not in /etc/platform/nodes" >&2; exit 1; }
    [ -z "$epoch" ] || follow+=$'\n'"LTX_SUFFIX=-$epoch"
  fi
  if [ "$current" = "$want" ] && [ ! -e "$stopped" ]; then
    if [ "$want" = primary ]; then
      [ -z "$epoch" ] || [ "$(cat "$volume/writer-epoch" 2>/dev/null)" = "$epoch" ] || { echo 'primary on a different epoch; refusing to relabel its database' >&2; return 1; }
      return 0
    fi
    if [ "$(cat "$follows" 2>/dev/null)" = "$follow" ] && { [ -z "$epoch" ] || [ "$(cat "$volume/follower-epoch" 2>/dev/null)" = "$epoch" ]; }; then return 0; fi
  fi
  if [ "$want" = replica ] && [ -n "$epoch" ]; then
    peer_ip=$(sed -n 's/^PRIMARY_SSH=\(.*\):22$/\1/p' <<<"$follow")
    [ "$(source_epoch "$peer_ip" "$epoch")" = "$epoch" ] || { echo 'writer has not published the new replication epoch' >&2; return 1; }
  fi
  echo "mc-hub-api: $current -> $want${2:+ of $2}"
  apps=$(docker ps --format '{{.Names}}' | grep -E '^mc-hub-api-(blue|green)$' || true)
  # The follower check compares against the old lineage's position otherwise.
  rm -f /var/lib/platform-peer/primary-txid
  if [ "$want" = primary ]; then
    # Edge isolates keep the old writer for up to 30 s (edge-lb timing.leaseMs), and a live old
    # writer still answers those writes with 200: keep following it until they have all switched.
    sleep 35
  fi
  litestream --profile primary --profile replica down
  if [ "$want" = primary ] && [ -n "$floor" ]; then
    checked=$(position) || { echo 'missing durable follower position' >&2; return 1; }
    jq -e --argjson floor "$floor" '.epoch == $floor.epoch and .txid >= $floor.txid' <<<"$checked" >/dev/null ||
      { echo 'local database does not cover the durable floor' >&2; return 1; }
  fi
  rm -f "$volume/follower-epoch" "$volume/writer-epoch"
  # Any switch ends this node's lineage. Its served copy must go, or a replica pointed here before
  # this node's new snapshot restores the old one and stays stuck on it; its local LTX state
  # (.mc-hub.db-litestream) must go, or a new primary tries to continue the old lineage. The
  # CrowdSec LAPI's copy beside it is lapi.sh's.
  rm -rf /srv/platform-sync/litestream/mc-hub-api
  rm -rf "$volume/.mc-hub.db-litestream"
  if [ "$want" = primary ]; then
    echo primary >"$volume/role"
    # mc-hub-api takes writes while this is under 150 s old; peer.sh keeps it from now on.
    touch "$volume/writer-lease"
    rm -f "$follows"
    if [ -n "$epoch" ]; then
      local lineage=/srv/platform-sync/litestream/mc-hub-api-$epoch
      [ ! -e "$lineage" ] || { echo 'refusing to reuse an existing replication epoch' >&2; return 1; }
      install -d -o 1000 -g 1000 "$lineage"
      ln -s "mc-hub-api-$epoch" /srv/platform-sync/litestream/mc-hub-api
    fi
    litestream --profile primary up -d
    if [ -n "$epoch" ]; then
      printf '%s\n' "$epoch" >"$lineage/epoch"
      printf '%s\n' "$epoch" >"$volume/writer-epoch.tmp"
      mv -f "$volume/writer-epoch.tmp" "$volume/writer-epoch"
    fi
    # Also the apps an unfinished step-down left stopped (docker restart starts them).
    apps=$({ printf '%s\n' $apps; cat "$stopped" 2>/dev/null || true; } | sort -u)
    [ -z "$apps" ] || docker restart $apps
    rm -f "$stopped"
  else
    echo replica >"$volume/role"
    touch "$stopped"
    [ -z "$apps" ] || { printf '%s\n' $apps >>"$stopped"; docker stop $apps; }
    if [ -n "$(find "$volume" -maxdepth 1 -name 'mc-hub.db*' -print -quit)" ]; then
      aside=$(mktemp -d "$volume/fenced-$(date -u +%Y%m%dT%H%M%SZ)-XXXX")
      find "$volume" -maxdepth 1 -name 'mc-hub.db*' -exec mv -t "$aside" {} +
    fi
    printf '%s\n' "$follow" >"$follows.tmp" && mv -f "$follows.tmp" "$follows"
    litestream --profile replica up -d
    for _ in $(seq 300); do [ -s "$volume/mc-hub.db-txid" ] && break; sleep 1; done
    [ -s "$volume/mc-hub.db-txid" ] || { echo "replica restore did not finish; mc-hub-api stays stopped until the next try" >&2; exit 1; }
    if [ -n "$epoch" ]; then
      [ "$(source_epoch "$peer_ip" "$epoch")" = "$epoch" ] || { echo 'source changed during restore' >&2; return 1; }
      printf '%s\n' "$epoch" >"$volume/follower-epoch.tmp"
      mv -f "$volume/follower-epoch.tmp" "$volume/follower-epoch"
    fi
    apps=$(sort -u "$stopped")
    [ -z "$apps" ] || docker start $apps
    rm -f "$stopped"
  fi
}

case "${1:-}" in
  prepare-quorum)
    lease=$(cat "$lease_file")
    epoch=$(jq -er --arg n "$NODE" 'select(.writer == $n and .floor == null) | .epoch' <<<"$lease")
    [[ $epoch =~ ^[0-9]{1,15}$ && $(cat "$volume/role") = primary ]]
    base=/srv/platform-sync/litestream/mc-hub-api
    if [ ! -L "$base" ]; then
      [ -d "$base/ltx" ] && [ ! -e "$base-$epoch" ]
      litestream --profile primary --profile replica down
      mv "$base" "$base-$epoch"
      ln -s "mc-hub-api-$epoch" "$base"
    fi
    [ "$(readlink "$base")" = "mc-hub-api-$epoch" ]
    litestream --profile primary up -d
    printf '%s\n' "$epoch" >"$base/epoch"
    printf '%s\n' "$epoch" >"$volume/writer-epoch"
    ;;
  enable-quorum)
    lease=$(cat "$lease_file")
    writer=$(jq -er '.writer' <<<"$lease")
    epoch=$(jq -er '.epoch' <<<"$lease")
    if [ "$writer" = "$NODE" ]; then
      [ "$(cat "$volume/writer-epoch")" = "$epoch" ] && [ -S "$volume/litestream.sock" ]
    fi
    umask 077
    printf 'quorum:%s' "$(cat /etc/platform/edge-node-key)" | sha256sum | cut -d' ' -f1 |
      jq -Rn --arg url "$LEASE_URL" '{url:$url,key:input}' >"$volume/write-quorum.json.tmp"
    chown 1000:1000 "$volume/write-quorum.json.tmp"
    mv -f "$volume/write-quorum.json.tmp" "$volume/write-quorum.json"
    if [ "$writer" = "$NODE" ]; then
      apps=$(docker ps --format '{{.Names}}' | grep -E '^mc-hub-api-(blue|green)$')
      docker restart $apps
    else
      become replica "$writer"
    fi
    ;;
  promote)
    force=false
    [ "${2:-}" = --force ] && force=true
    proof=$(position) || proof=null
    reply=$(printf 'header = "Authorization: Bearer %s"\n' "$(cat /etc/platform/edge-node-key)" |
      curl -sS -m 20 -K - -H 'content-type: application/json' -d "{\"op\":\"promote\",\"force\":$force,\"position\":$proof}" -w '\n%{http_code}' "$LEASE_URL")
    code=${reply##*$'\n'}
    if [ "$code" != 200 ]; then
      echo "promote refused (HTTP $code): ${reply%$'\n'*}" >&2
      exit 1
    fi
    printf '%s\n' "${reply%$'\n'*}" >"$lease_file.tmp"
    mv -f "$lease_file.tmp" "$lease_file"
    echo "$NODE" >"$writer_file"
    become primary
    ;;
  reconcile)
    writer=$(cat "$writer_file" 2>/dev/null || true)
    [ -n "$writer" ] || exit 0
    if [ "$writer" = "$NODE" ]; then become primary; else become replica "$writer"; fi
    ;;
  *)
    echo "usage: $0 promote [--force] | reconcile" >&2
    exit 2
    ;;
esac
