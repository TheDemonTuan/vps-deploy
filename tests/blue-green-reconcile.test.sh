#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
rendered=$(mktemp)
trap 'rm -f -- "$rendered"' EXIT
bash "$root/apps/9router/adapter.sh" green 0123456789abcdef0123456789abcdef dashboard.test.invalid legacy.test.invalid api.test.invalid > "$rendered"
python3 - "$rendered" <<'PY'
import sys, yaml
with open(sys.argv[1], encoding='utf-8') as source:
    route = yaml.safe_load(source)['http']
routers = route['routers']
assert set(routers) == {'9router-deny-internal', '9router-api-deny-admin', '9router-api-router', '9router-api-fallback', '9router-dashboard-router'}
assert routers['9router-deny-internal']['priority'] > routers['9router-api-router']['priority']
assert routers['9router-api-deny-admin']['priority'] > routers['9router-api-router']['priority']
assert 'Host(`legacy.test.invalid`)' in routers['9router-dashboard-router']['rule']
assert 'Host(`legacy.test.invalid`)' in routers['9router-deny-internal']['rule']
assert 'PathPrefix(`/api/settings`)' in routers['9router-api-deny-admin']['rule']
assert 'PathPrefix(`/internal`)' in routers['9router-deny-internal']['rule']
assert routers['9router-api-router']['middlewares'] == ['9router-route-generation', 'tunnel-only', 'public-api-rate-limit', 'security-headers']
assert route['services']['9router-service']['loadBalancer']['responseForwarding']['flushInterval'] == '100ms'
assert route['services']['9router-service']['loadBalancer']['servers'] == [{'url':'http://9router-green:20128'}]
assert route['middlewares']['9router-route-generation']['headers']['customResponseHeaders']['X-9Router-Route-Generation'] == '0123456789abcdef0123456789abcdef'
PY
if bash "$root/apps/9router/adapter.sh" blue 0123456789abcdef0123456789abcdef 'bad`' '' api.test.invalid > /dev/null 2>&1; then echo UNSAFE_HOST_ACCEPTED >&2; exit 1; fi
helper="$root/lib/traefik.sh"
for bad in '/a/../healthz X-Demo-Route-Generation' '/healthz Bad:Header' '/healthz X-Demo-Route-Generation?'; do
  read -r path header <<< "$bad"
  if bash "$helper" probe demo.fixture.test "$path" "$header" >/dev/null 2>&1; then echo UNSAFE_PROBE_ACCEPTED >&2; exit 1; fi
done
if bash "$helper" cutover api.test.invalid /tmp/path /tmp/old /tmp/new "$(printf 'a%.0s' {1..64})" "$(printf 'b%.0s' {1..64})" blue "$(printf 'c%.0s' {1..32})" green "$(printf 'd%.0s' {1..32})" /tmp/publisher '/healthz?query' X-Demo-Route-Generation 30 >/dev/null 2>&1; then echo UNSAFE_CUTOVER_ACCEPTED >&2; exit 1; fi
