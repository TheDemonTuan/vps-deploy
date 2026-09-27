#!/usr/bin/env bash
set -euo pipefail

# Retained direct identity and drain protocol from legacy 9router deployment.
direct_slot_healthy() {
  local slot="$1" mode="${2:-health}" container="9router-$1" hostname health
  hostname="$(docker inspect "$container" --format '{{.Config.Hostname}}' 2>/dev/null)" || return 1
  [[ -n "$hostname" ]] || return 1
  health="$(timeout 6 docker exec "$container" wget -T 5 -qO- http://127.0.0.1:20128/api/health 2>/dev/null)" || return 1
  python3 - "$slot" "$hostname" "$health" "$mode" <<'PY'
import json, sys

def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result
try:
    data = json.loads(sys.argv[3], object_pairs_hook=unique_pairs)
    identity = data.get('instance_id')
    prefix = sys.argv[2] + '-'
    if not (data.get('ok') is True and data.get('deployment_slot') == sys.argv[1]
            and isinstance(identity, str) and identity.startswith(prefix)
            and identity[len(prefix):].isdecimal() and int(identity[len(prefix):]) > 0):
        raise ValueError('DIRECT_IDENTITY')
    if sys.argv[4] == 'idle' and not (data.get('active_requests_known') is True
            and type(data.get('active_requests')) is int and data['active_requests'] == 0):
        raise ValueError('DRAIN_UNSAFE')
    print(json.dumps(data, separators=(',', ':')))
except (ValueError, TypeError, KeyError):
    sys.exit(1)
PY
}

rtk_healthy() {
  local container="$1"
  docker exec "$container" bun -e 'const h=await fetch("http://127.0.0.1:8080/health"); const v=await fetch("http://127.0.0.1:8080/version"); if(!h.ok || !(await h.json()).ok || !v.ok || (await v.json()).protocolVersion!==1)process.exit(1)' >/dev/null 2>&1 &&
    docker exec "$container" bun -e 'const content=Array.from({length:50},(_,i)=>`src/a.ts:${i+1}:KEEP_${i+1} ${"padding ".repeat(12)}`).join("\n"); const r=await fetch("http://127.0.0.1:8080/filter",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({content,filter:"grep"})}); const data=await r.json(); if(!r.ok || data.protocolVersion!==1 || !data.content.includes("KEEP_1") || Buffer.byteLength(data.content)>=Buffer.byteLength(content))process.exit(1)' >/dev/null 2>&1
}

compose_app() {
  local release="$1" config="$2"; shift 2
  local args=(--env-file "$config/runtime.env" -p 9router -f "$release/apps/9router/docker-compose.prod.yml")
  if [[ -n "${CHATGPT_WEB_SOCKET_GID:-}" ]]; then
    args+=(-f "$release/apps/9router/docker-compose.chatgpt-web.yml")
  fi
  docker compose "${args[@]}" --ansi=never --progress=plain "$@"
}

pull_image() {
  local release="$1" config="$2" slot="$3" attempt rc heartbeat
  for attempt in 1 2; do
    (
      trap 'exit 0' TERM INT
      while true; do sleep 15 || break; printf '[pull] %s still downloading\n' "$slot" >&2; done
    ) &
    heartbeat=$!
    if timeout 300 compose_app "$release" "$config" pull "9router-$slot"; then
      kill -TERM "$heartbeat" 2>/dev/null || true
      pkill -TERM -P "$heartbeat" 2>/dev/null || true
      wait "$heartbeat" 2>/dev/null || true
      return 0
    else
      rc=$?
      kill -TERM "$heartbeat" 2>/dev/null || true
      pkill -TERM -P "$heartbeat" 2>/dev/null || true
      wait "$heartbeat" 2>/dev/null || true
      printf '[pull] attempt %s/2 failed (%s)\n' "$attempt" "$rc" >&2
    fi
    [[ $attempt == 2 ]] || sleep 5
  done
  return 1
}

wait_healthy() {
  local slot="$1" remaining
  for ((remaining=60;remaining>0;remaining-=2)); do
    if direct_slot_healthy "$slot" >/dev/null; then return 0; fi
    sleep 2
  done
  return 1
}

start_candidate() {
  local release="$1" config="$2" slot="$3" name="9router-$3" state
  state="$(docker inspect "$name" --format '{{.State.Status}}' 2>/dev/null || true)"
  if [[ $state == running ]]; then
    direct_slot_healthy "$slot" idle >/dev/null || { echo DRAIN_UNSAFE >&2; return 1; }
    compose_app "$release" "$config" stop "$name"
  fi
  compose_app "$release" "$config" up -d --no-deps --pull never "$name"
  wait_healthy "$slot"
}

start_previous() {
  local slot="$1" name="9router-$1" state
  state="$(docker inspect "$name" --format '{{.State.Status}}')" || return 1
  if [[ $state != running ]]; then docker start "$name" >/dev/null; fi
  wait_healthy "$slot"
}

handoff() {
  local slot="$1" remaining
  for ((remaining=3;remaining>0;remaining--)); do
    if direct_slot_healthy "$slot" idle >/dev/null; then printf 'IDLE\n'; return 0; fi
    sleep 1
  done
  printf 'DRAINING\n'
}

case "${1:-}" in
  health) [[ $# == 2 || $# == 3 ]] && direct_slot_healthy "$2" "${3:-health}" ;;
  rtk) [[ $# == 2 ]] && rtk_healthy "$2" ;;
  pull) [[ $# == 4 ]] && pull_image "$2" "$3" "$4" ;;
  candidate) [[ $# == 4 ]] && start_candidate "$2" "$3" "$4" ;;
  rollback) [[ $# == 2 ]] && start_previous "$2" ;;
  handoff) [[ $# == 2 ]] && handoff "$2" ;;
  *) exit 2 ;;
esac
