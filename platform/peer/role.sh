#!/usr/bin/env bash
# role.sh: switch this node's mc-hub-api database between primary (the single writer) and replica.
# The edge lease (cloudflare/edge-lb, Durable Object "mc-hub-api") names the writer; the Worker
# sends writes only there, so two nodes never take writes at once.
#   role.sh promote [--force]  take the lease, then become primary. Refused while the writer
#                              renewed it in the last 3 minutes; --force takes it anyway.
#   role.sh reconcile          become what the lease says (platform-role.service; peer.sh starts
#                              it when its renewal shows the role changed)
# Promotion loses what the old primary had not replicated yet (normally about a second). The old
# primary, once back, steps down by itself: its database moves aside to fenced-<time>/ in the
# volume and it follows the new primary. A step-down whose restore does not finish leaves
# stopped-apps behind: peer.sh runs it again, and the apps start once the copy is in place.
set -euo pipefail
. /etc/platform/peer.env
# One switch at a time: a manual promote and the timer's reconcile would otherwise run together.
exec 9>/run/platform-role.lock
flock 9
volume=/var/lib/docker/volumes/mc-hub-api-data/_data
writer_file=/var/lib/platform-peer/writer
stopped=/var/lib/platform-peer/stopped-apps

litestream() {
  docker compose --env-file /etc/platform/litestream.env --project-directory /opt/platform/litestream \
    -f /opt/platform/litestream/compose.yml "$@"
}

become() {
  local want=$1 current apps
  current=$(cat "$volume/role" 2>/dev/null || echo "$ROLE")
  [ "$current" = "$want" ] && [ ! -e "$stopped" ] && return
  echo "mc-hub-api: $current -> $want"
  apps=$(docker ps --format '{{.Names}}' | grep -E '^mc-hub-api-(blue|green)$' || true)
  # The follower check compares against the old lineage's position otherwise.
  rm -f /var/lib/platform-peer/primary-txid
  if [ "$want" = primary ]; then
    # Edge isolates keep the old writer for up to 30 s (edge-lb timing.leaseMs), and a live old
    # writer still answers those writes with 200: keep following it until they have all switched.
    sleep 35
  fi
  litestream --profile primary --profile replica down
  if [ "$want" = primary ]; then
    # A new lineage from this node's copy; the old primary's files would not continue it.
    find /srv/platform-sync/litestream -mindepth 1 -delete
    echo primary >"$volume/role"
    litestream --profile primary up -d
    # Also the apps an unfinished step-down left stopped (docker restart starts them).
    apps=$({ printf '%s\n' $apps; cat "$stopped" 2>/dev/null || true; } | sort -u)
    [ -z "$apps" ] || docker restart $apps
    rm -f "$stopped"
  else
    echo replica >"$volume/role"
    touch "$stopped"
    [ -z "$apps" ] || { printf '%s\n' $apps >>"$stopped"; docker stop $apps; }
    if [ -n "$(find "$volume" -maxdepth 1 -name 'mc-hub.db*' -print -quit)" ]; then
      aside="$volume/fenced-$(date -u +%Y%m%dT%H%M%SZ)"
      mkdir "$aside"
      find "$volume" -maxdepth 1 -name 'mc-hub.db*' -exec mv -t "$aside" {} +
    fi
    litestream --profile replica up -d
    for _ in $(seq 300); do [ -s "$volume/mc-hub.db-txid" ] && break; sleep 1; done
    [ -s "$volume/mc-hub.db-txid" ] || { echo "replica restore did not finish; mc-hub-api stays stopped until the next try" >&2; exit 1; }
    apps=$(sort -u "$stopped")
    [ -z "$apps" ] || docker start $apps
    rm -f "$stopped"
  fi
}

case "${1:-}" in
  promote)
    force=false
    [ "${2:-}" = --force ] && force=true
    reply=$(printf 'header = "Authorization: Bearer %s"\n' "$(cat /etc/platform/edge-node-key)" |
      curl -sS -m 20 -K - -H 'content-type: application/json' -d "{\"op\":\"promote\",\"force\":$force}" -w '\n%{http_code}' "$LEASE_URL")
    code=${reply##*$'\n'}
    if [ "$code" != 200 ]; then
      echo "promote refused (HTTP $code): ${reply%$'\n'*}" >&2
      exit 1
    fi
    echo "$NODE" >"$writer_file"
    become primary
    ;;
  reconcile)
    writer=$(cat "$writer_file" 2>/dev/null || true)
    [ -n "$writer" ] || exit 0
    if [ "$writer" = "$NODE" ]; then become primary; else become replica; fi
    ;;
  *)
    echo "usage: $0 promote [--force] | reconcile" >&2
    exit 2
    ;;
esac
