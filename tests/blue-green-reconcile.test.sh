#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
rendered=$(mktemp)
trap 'rm -f -- "$rendered"' EXIT
bash "$root/apps/omniroute/adapter.sh" green 0123456789abcdef0123456789abcdef dashboard.test.invalid '' api.test.invalid > "$rendered"
python3 - "$rendered" <<'PY'
import sys, yaml
with open(sys.argv[1], encoding='utf-8') as source:
    route = yaml.safe_load(source)['http']
routers = route['routers']
assert set(routers) == {'omniroute-deny-internal', 'omniroute-api-router', 'omniroute-api-fallback', 'omniroute-dashboard-router'}
assert routers['omniroute-deny-internal']['priority'] > routers['omniroute-api-router']['priority']
assert 'PathPrefix(`/internal`)' in routers['omniroute-deny-internal']['rule']
assert routers['omniroute-api-router']['middlewares'] == ['omniroute-api-key-only', 'omniroute-route-generation', 'tunnel-only', 'public-api-rate-limit', 'security-headers']
assert route['services']['omniroute-service']['loadBalancer']['responseForwarding']['flushInterval'] == '100ms'
assert route['services']['omniroute-service']['loadBalancer']['servers'] == [{'url':'http://omniroute-green:20128'}]
assert route['middlewares']['omniroute-route-generation']['headers']['customResponseHeaders']['X-OmniRoute-Route-Generation'] == '0123456789abcdef0123456789abcdef'
PY
if bash "$root/apps/omniroute/adapter.sh" blue 0123456789abcdef0123456789abcdef 'bad`' '' api.test.invalid > /dev/null 2>&1; then echo UNSAFE_HOST_ACCEPTED >&2; exit 1; fi
helper="$root/lib/traefik.sh"
for bad in '/a/../healthz X-Demo-Route-Generation' '/healthz Bad:Header' '/healthz X-Demo-Route-Generation?'; do
  read -r path header <<< "$bad"
  if bash "$helper" probe demo.fixture.test "$path" "$header" >/dev/null 2>&1; then echo UNSAFE_PROBE_ACCEPTED >&2; exit 1; fi
done
if bash "$helper" cutover api.test.invalid /tmp/path /tmp/old /tmp/new "$(printf 'a%.0s' {1..64})" "$(printf 'b%.0s' {1..64})" blue "$(printf 'c%.0s' {1..32})" green "$(printf 'd%.0s' {1..32})" /tmp/publisher '/healthz?query' X-Demo-Route-Generation 30 >/dev/null 2>&1; then echo UNSAFE_CUTOVER_ACCEPTED >&2; exit 1; fi
