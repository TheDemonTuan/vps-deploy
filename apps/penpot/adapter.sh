#!/usr/bin/env bash
set -euo pipefail
[[ $# == 5 ]] || exit 2
slot="$1"; generation="$2"; dashboard="$3"; alias="$4"; api="$5"
[[ $slot == single && -z $dashboard && -z $alias ]] || exit 2
[[ $generation =~ ^[0-9a-f]{32}$ ]] || exit 2
python3 - "$api" <<'PY'
import ipaddress, re, sys
host = sys.argv[1]
labels = host.split('.')
if len(host) > 253 or len(labels) < 2 or not all(0 < len(label) <= 63 and re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?', label) for label in labels):
    sys.exit(2)
try:
    ipaddress.ip_address(host)
except ValueError:
    pass
else:
    sys.exit(2)
PY
cat <<EOF
# Managed by vps-deploy; Penpot-owned route only.
http:
  middlewares:
    penpot-route-generation:
      headers:
        customResponseHeaders:
          X-Penpot-Route-Generation: "$generation"
  routers:
    penpot-internal-health:
      rule: "Host(\`penpot.internal.invalid\`) && Path(\`/readyz\`)"
      entryPoints: [slot-probe]
      priority: 500
      middlewares: [penpot-route-generation]
      service: penpot-service
    penpot-public-router:
      rule: "Host(\`$api\`)"
      entryPoints: [web]
      priority: 100
      middlewares: [penpot-route-generation, tunnel-only, crowdsec-ip]
      service: penpot-service
  services:
    penpot-service:
      loadBalancer:
        passHostHeader: true
        responseForwarding:
          flushInterval: "-1ms"
        servers:
          - url: "http://penpot-frontend:8080"
        healthCheck:
          path: "/readyz"
          interval: "5s"
          timeout: "2s"
EOF
