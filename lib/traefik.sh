#!/usr/bin/env bash
set -euo pipefail
probe_observed_slot() {
  local tmp status probe
  tmp="$(mktemp -d /tmp/9router-probe.XXXXXXXX)" || return 1
  trap 'rm -rf -- "$tmp"' EXIT
  probe="$(python3 -c 'import uuid;print(uuid.uuid4().hex)')"
  status="$(curl --silent --show-error --connect-timeout 2 --max-time 5 \
    -H 'Cache-Control: no-cache' -H 'Pragma: no-cache' \
    --dump-header "$tmp/headers" --output "$tmp/body" --write-out '%{http_code}' \
    "https://${API_HOST}/api/health?deploy_probe=${probe}")" || return 1
  python3 - "$status" "$tmp/headers" "$tmp/body" <<'PY'
import json, re, sys

def pairs(rows):
    result={}
    for key, value in rows:
        if key in result:
            raise ValueError('duplicate key')
        result[key]=value
    return result

try:
    status, header_path, body_path = sys.argv[1:]
    headers={}
    for line in open(header_path, encoding='iso-8859-1'):
        if line.startswith('HTTP/'):
            headers.clear()
        elif ':' in line:
            key, value=line.split(':',1)
            headers.setdefault(key.strip().lower(), []).append(value.strip())
    if status != '200' or any(not age.isdecimal() or int(age)>0 for age in headers.get('age', [])):
        raise ValueError('status/cache')
    if any(value.upper() in ('HIT','STALE','UPDATING','REVALIDATED') for value in headers.get('cf-cache-status', [])):
        raise ValueError('cache hit')
    cache=headers.get('cache-control', [])
    if len(cache) != 1 or 'no-store' not in cache[0].lower():
        raise ValueError('cache-control')
    generations=headers.get('x-9router-route-generation', [])
    if len(generations)!=1 or not re.fullmatch('[0-9a-fA-F]{32}', generations[0]):
        raise ValueError('generation')
    with open(body_path,encoding='utf-8') as source:
        payload=json.load(source,object_pairs_hook=pairs)
    if (not isinstance(payload,dict) or payload.get('ok') is not True
            or payload.get('deployment_slot') not in ('blue','green')):
        raise ValueError('identity')
    print(payload['deployment_slot'], generations[0].lower())
except (ValueError, OSError, UnicodeError, KeyError):
    sys.exit(1)
PY
}
wait_route_slot() {
  local api="$1" slot="$2" generation="$3" deadline=$((SECONDS+30)) seen streak=0
  while (( SECONDS < deadline )); do
    seen="$(bash "${BASH_SOURCE[0]}" probe "$api" 2>/dev/null || true)"
    if [[ $seen == "$slot $generation" ]]; then
      streak=$((streak+1))
      if (( streak == 2 )); then return 0; fi
    else
      streak=0
    fi
    sleep 1
  done
  return 1
}

cutover() {
  [[ $# == 11 ]] || exit 2
  local api="$1" path="$2" snapshot="$3" candidate="$4" old_hash="$5" new_hash="$6" old_slot="$7" old_gen="$8" new_slot="$9" new_gen="${10}" publisher="${11}"
  [[ $old_slot == blue || $old_slot == green ]] && [[ $new_slot == blue || $new_slot == green ]] || exit 2
  [[ $old_hash =~ ^[0-9a-f]{64}$ && $new_hash =~ ^[0-9a-f]{64}$ && $old_gen =~ ^[0-9a-f]{32}$ && $new_gen =~ ^[0-9a-f]{32}$ ]] || exit 2
  if python3 "$publisher" publish "$path" "$candidate" "$old_hash"; then
    if [[ -n "${VPS_DEPLOY_FIXTURE_FAULT:-}" && -f "${VPS_DEPLOY_FIXTURE_FAULT}" && ! -L "${VPS_DEPLOY_FIXTURE_FAULT}" && $(stat -c %u "${VPS_DEPLOY_FIXTURE_FAULT}") == 0 && $(stat -c %a "${VPS_DEPLOY_FIXTURE_FAULT}") == 600 && $(cat "${VPS_DEPLOY_FIXTURE_FAULT}") == after_rename ]]; then
      kill -KILL "$PPID"
      kill -KILL "$$"
    fi
    if wait_route_slot "$api" "$new_slot" "$new_gen"; then return 0; fi
  fi
  local current
  current="$(sha256sum -- "$path")" || return 20
  current="${current%% *}"
  if [[ $current == "$new_hash" ]]; then
    python3 "$publisher" publish "$path" "$snapshot" "$new_hash" || return 20
  elif [[ $current != "$old_hash" ]]; then
    return 20
  fi
  wait_route_slot "$api" "$old_slot" "$old_gen" || return 20
  return 10
}

case "${1:-}" in
  probe)
    [[ $# == 2 && $2 =~ ^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$ ]] || exit 2
    API_HOST="$2"; probe_observed_slot ;;
  cutover)
    shift; cutover "$@" ;;
  *) exit 2 ;;
esac
