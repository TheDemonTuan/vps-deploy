#!/usr/bin/env bash
# lapi.sh: keep the fleet's one CrowdSec LAPI on the edge lease's writer (the node platform/peer
# last saw named), so it moves with mc-hub-api's database and a lost node does not take it along.
#   lapi.sh reconcile [<writer>]   platform-lapi.service (peer.sh starts it when this node neither
#                                  holds nor follows the writer); ansible/ passes the writer
#   lapi.sh publish                crowdsec-follow-position.service: this node's copy, for the
#                                  LAPI node's write confirmations (below)
# The LAPI node runs crowdsec with the API server (lapi.yaml.local) and Litestream replicating
# crowdsec.db (litestream.yml, profile primary). Every other node runs the agent only
# (agent.yaml.local) behind crowdsec-lapi.service, an SSH forward to the LAPI node's
# 172.31.254.1:8080, and follows that copy into /var/lib/crowdsec/follow. Taking the LAPI over
# makes the copy this node's database (machines, bouncer keys, decisions and their history, about
# a second old); a node without one refuses and stays an agent. Giving it up moves the database to
# /var/lib/crowdsec/data/fenced-<time>/ (each kept 14 days). The Telegram/Cloudflare
# controller runs only on the LAPI node (peer.sh starts it there).
# State: /var/lib/platform-peer/lapi, "here" or the node followed, written once settled.
set -euo pipefail
umask 077
# A grant belongs to this boot. Its age starts before the renewal request, not at response time.
permit() {
  local start now unused
  read -r start </run/platform-peer/lapi && read -r now unused </proc/uptime &&
    [[ $start =~ ^[0-9]+$ ]] && (( ${now%%.*} >= start && ${now%%.*} - start < 120 ))
}
case ${1:-} in
  permit) permit; exit ;;
  agent-or-permit) grep -q '^ *enable: false' /etc/crowdsec/config.yaml.local || permit; exit ;;
  guard)
    if ! permit 2>/dev/null; then
      systemctl stop --no-block crowdsec-telegram-controller.service crowdsec-telegram-health.timer
      grep -q '^ *enable: false' /etc/crowdsec/config.yaml.local || systemctl stop --no-block crowdsec.service
    fi
    exit ;;
  # The LAPI node's controller acknowledges a ban once every other node's copy has it (its
  # replica.py reads this over SFTP): "<node followed> <copy's txid> <when peer.sh last verified
  # the copy against that node>". The LAPI node itself publishes none.
  publish)
    out=/srv/platform-sync/crowdsec-follow last=unset
    while :; do
      line=
      lapi=$(cat /var/lib/platform-peer/lapi 2>/dev/null || true)
      txid=$(cat /var/lib/crowdsec/follow/crowdsec.db-txid 2>/dev/null || true)
      if [[ $lapi =~ ^n[0-9]{1,3}$ && $txid =~ ^[0-9a-f]{16}$ ]]; then
        verified=0
        if [ "$(cat /var/lib/platform-peer/crowdsec-synced 2>/dev/null || true)" = "$lapi" ]; then
          verified=$(stat -c %Y /var/lib/platform-peer/crowdsec-synced 2>/dev/null || echo 0)
        fi
        line="$lapi $txid $verified"
      fi
      if [ "$line" != "$last" ]; then
        if [ -n "$line" ]; then
          printf '%s\n' "$line" >"$out.tmp" && chmod 0644 "$out.tmp" && mv -f "$out.tmp" "$out"
        else
          rm -f "$out"
        fi
        last=$line
      fi
      sleep 1
    done ;;
esac
[ -n "${NODE:-}" ] || . /etc/platform/peer.env
exec 9>/run/platform-lapi.lock
flock 9
state=/var/lib/platform-peer/lapi
env=/etc/platform/crowdsec-lapi.env
conf=/etc/crowdsec/config.yaml.local
modes=/etc/platform/crowdsec
data=/var/lib/crowdsec/data
follow=/var/lib/crowdsec/follow
served=/srv/platform-sync/litestream/crowdsec

copy() { docker compose -f /opt/platform/crowdsec/litestream.yml "$@"; }
answers() {
  for _ in $(seq 30); do curl -fsS -m 5 -o /dev/null http://172.31.254.1:8080/health && return; sleep 2; done
  return 1
}
# An agent's configuration turns the API server off; anything else serves it.
serving() { ! grep -q '^ *enable: false' "$conf" 2>/dev/null; }
# use lapi|agent: install that configuration; true when the file changed.
use() {
  cmp -s "$modes/$1.yaml.local" "$conf" && return 1
  cp "$modes/$1.yaml.local" "$conf.tmp" && mv -f "$conf.tmp" "$conf"
}
# This node's database out of the way, with its WAL.
fence() {
  [ -n "$(find "$data" -maxdepth 1 -name 'crowdsec.db*' -print -quit)" ] || return 0
  # Preserve earlier lineages as well: a failed retry must never erase the recovery copy.
  local aside
  aside=$(mktemp -d "$data/fenced-$(date -u +%Y%m%dT%H%M%SZ)-XXXX")
  find "$data" -maxdepth 1 -name 'crowdsec.db*' -exec mv -t "$aside" {} +
}

[ "${1:-}" = reconcile ] || { echo "usage: $0 reconcile [<writer>]" >&2; exit 2; }
writer=${2:-$(cat /var/lib/platform-peer/writer 2>/dev/null || true)}
[ -n "$writer" ] || exit 0
want=here
[ "$writer" = "$NODE" ] || want=$writer
if [ "$(cat "$state" 2>/dev/null)" = "$want" ]; then
  if [ "$want" = here ]; then permit && systemctl start crowdsec || exit 1; fi
  exit 0
fi
echo "crowdsec LAPI: $(cat "$state" 2>/dev/null || echo unset) -> $want"
# peer.sh's follower check would compare against the old copy's position.
rm -f /var/lib/platform-peer/crowdsec-txid

if [ "$want" = here ]; then
  restart=false
  permit || { echo 'no live local grant for LAPI promotion' >&2; exit 1; }
  if ! serving; then
    synced=/var/lib/platform-peer/crowdsec-synced
    [ -s "$state" ] && [ -s "$synced" ] && cmp -s "$synced" "$state" &&
      (( $(date +%s) - $(stat -c %Y "$synced") < 600 )) &&
      [[ $(cat "$follow/crowdsec.db-txid" 2>/dev/null) =~ ^[0-9a-f]{16}$ ]] && [ -s "$follow/crowdsec.db" ] || { echo 'no recently verified LAPI follower' >&2; exit 1; }
    copy --profile replica down
    # Retain the follower on failure and include committed WAL in the promoted snapshot.
    python3 - "$follow/crowdsec.db" "$data/.lapi-promote.tmp" <<'PY'
import sqlite3, sys
with sqlite3.connect('file:' + sys.argv[1] + '?mode=ro', uri=True) as src, sqlite3.connect(sys.argv[2]) as dst:
    src.backup(dst)
    if dst.execute('pragma quick_check').fetchall() != [('ok',)] or not dst.execute('select 1 from bouncers limit 1').fetchone():
        raise SystemExit('invalid or unregistered LAPI copy')
PY
    permit
    systemctl stop crowdsec-lapi.service crowdsec
    fence
    mv -f "$data/.lapi-promote.tmp" "$data/crowdsec.db"
    # A new lineage: the old LAPI node's copy and this node's Litestream state end here.
    rm -rf "$served" "$data/.crowdsec.db-litestream"
    restart=true
  fi
  rm -f "$env"
  use lapi && restart=true
  [ "$restart" = false ] || systemctl restart crowdsec
  answers || { echo "the LAPI does not answer on 172.31.254.1:8080" >&2; exit 1; }
  copy --profile primary up -d
  # The LAPI node follows nobody: the copy it just promoted is stale from here on.
  [ ! -d "$follow" ] || find "$follow" -mindepth 1 -delete
else
  line=$(awk -v n="$want" '$1 == n && NF >= 4 {print $2, $3, $4}' /etc/platform/nodes)
  [ -n "$line" ] || { echo "writer $want is not in /etc/platform/nodes" >&2; exit 1; }
  read -r ip kind key <<<"$line"
  systemctl stop crowdsec-telegram-controller.service crowdsec-telegram-health.timer 2>/dev/null || true
  copy --profile primary down
  if serving; then
    systemctl stop crowdsec
    rm -rf "$served" "$data/.crowdsec.db-litestream"
    fence
  fi
  if ! cmp -s "$modes/agent.yaml.local" "$conf"; then use agent; fi
  printf 'LAPI_SSH=%s\nPRIMARY_SSH=%s:22\nPRIMARY_HOST_KEY=%s %s\n' "$ip" "$ip" "$kind" "$key" >"$env.tmp"
  mv -f "$env.tmp" "$env"
  systemctl restart crowdsec-lapi.service
  answers || { echo "no LAPI on $want through crowdsec-lapi.service" >&2; exit 1; }
  # The agent logs in at start: only once the LAPI answers.
  if [ -z "${2:-}" ] || cscli lapi status >/dev/null 2>&1; then systemctl restart crowdsec; fi
  copy --profile replica down
  find "$follow" -mindepth 1 -delete
  copy --profile replica up -d
fi
echo "$want" >"$state.tmp" && mv -f "$state.tmp" "$state"
# Every recovery copy outlives any retry of a switch; after two weeks the LAPI has moved on.
find "$data" -maxdepth 1 -type d -name 'fenced-*' -mtime +14 -exec rm -rf {} +
