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
relay=/var/lib/platform-relay/mc-hub-api
promoting=/var/lib/platform-peer/promoting
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

# Public role/epoch markers are read by unprivileged services even under a private operator umask.
publish_marker() {
  local tmp
  tmp=$(mktemp "${1}.XXXXXXXX")
  printf '%s\n' "$2" >"$tmp"
  chmod 0644 "$tmp"
  mv -fT "$tmp" "$1"
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
  if [ "$current" = "$want" ] && [ ! -e "$stopped" ] && [ ! -e "$promoting" ]; then
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
  apps=$(docker ps --format '{{.Names}}' | awk '/^mc-hub-api-(blue|green)$/')
  # The follower check compares against the old lineage's position otherwise.
  rm -f /var/lib/platform-peer/primary-txid
  local base=/srv/platform-sync/litestream/mc-hub-api lineage='' term=''
  if [ "$want" = primary ]; then
    term=$(jq -er --arg n "$NODE" 'select(.writer == $n) | .epoch' "$lease_file")
    [[ $term =~ ^[0-9]{1,15}$ && ( -z $epoch || $epoch = "$term" ) ]]
    [ -z "$epoch" ] || lineage=$base-$epoch
  fi
  if [ "$want" = primary ] && [ -e "$promoting" ]; then
    [ "$(cat "$promoting")" = "$term" ] || { echo 'unfinished promotion belongs to another lease epoch' >&2; return 1; }
  else
    if [ "$want" = primary ]; then
      [ -z "$lineage" ] || { [ ! -e "$lineage" ] && [ ! -L "$lineage" ]; } || { echo 'replication epoch already exists' >&2; return 1; }
      # Continue following until the edge isolates' old writer selection expires.
      sleep 35
    fi
    litestream --profile primary --profile replica down
    if [ "$want" = primary ] && [ -n "$floor" ]; then
      checked=$(position) || { echo 'missing durable follower position' >&2; return 1; }
      jq -e --argjson floor "$floor" '.epoch == $floor.epoch and .txid >= $floor.txid' <<<"$checked" >/dev/null ||
        { echo 'local database does not cover the durable floor' >&2; return 1; }
    fi
    rm -rf "$base" "$volume/.mc-hub.db-litestream"
    # The relay's mirror of the writer followed until now (platform/sync/relay.sh).
    [ ! -d "$relay" ] || find "$relay" -mindepth 1 -delete
    if [ "$want" = primary ]; then
      printf '%s\n' $apps >>"$stopped"
      # From here on retries must preserve the new LTX files and the validated database.
      printf '%s\n' "$term" >"$promoting.tmp"
      mv -fT "$promoting.tmp" "$promoting"
    fi
  fi
  rm -f "$volume/follower-epoch"
  if [ "$want" = primary ]; then
    rm -f "$follows"
    if [ -n "$lineage" ]; then
      install -d -o 1000 -g 1000 "$lineage"
      [ -L "$base" ] || ln -sT "mc-hub-api-$epoch" "$base"
      [ "$(readlink "$base")" = "mc-hub-api-$epoch" ]
    fi
    litestream --profile primary up -d
    if [ -n "$epoch" ]; then
      publish_marker "$lineage/epoch" "$epoch"
      publish_marker "$volume/writer-epoch" "$epoch"
    fi
    jq -e --arg n "$NODE" --argjson term "$term" '.writer == $n and .epoch == $term' "$lease_file" >/dev/null
    touch -r "$lease_file" "$volume/writer-lease"
    publish_marker "$volume/role" primary
    # Also the apps an unfinished step-down left stopped (docker restart starts them).
    apps=$({ printf '%s\n' $apps; cat "$stopped" 2>/dev/null || true; } | sort -u)
    [ -z "$apps" ] || docker restart $apps
    rm -f "$stopped" "$promoting"
  else
    publish_marker "$volume/role" replica
    touch "$stopped"
    rm -f "$promoting" "$volume/writer-epoch"
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
      publish_marker "$volume/follower-epoch" "$epoch"
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
      [[ -d $base/ltx && ! -e $base-$epoch && ! -L $base-$epoch ]]
      litestream --profile primary --profile replica down
      mv "$base" "$base-$epoch"
      ln -s "mc-hub-api-$epoch" "$base"
    fi
    [ "$(readlink "$base")" = "mc-hub-api-$epoch" ]
    litestream --profile primary up -d
    publish_marker "$base/epoch" "$epoch"
    publish_marker "$volume/writer-epoch" "$epoch"
    ;;
  enable-quorum)
    lease=$(cat "$lease_file")
    writer=$(jq -er '.writer' <<<"$lease")
    epoch=$(jq -er '.epoch' <<<"$lease")
    if [ "$writer" = "$NODE" ]; then
      [[ $(cat "$volume/writer-epoch") = "$epoch" && -S $volume/litestream.sock ]]
    fi
    secret=$(mktemp "$volume/.write-quorum.XXXXXXXX")
    trap 'rm -f "$secret"' EXIT
    node_key=$(cat /etc/platform/edge-node-key)
    [ -n "$node_key" ]
    printf 'quorum:%s' "$node_key" | sha256sum | cut -d' ' -f1 |
      jq -Rn --arg url "$LEASE_URL" '{url:$url,key:input}' >"$secret"
    chown 1000:1000 "$secret"
    mv -fT "$secret" "$volume/write-quorum.json"
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
