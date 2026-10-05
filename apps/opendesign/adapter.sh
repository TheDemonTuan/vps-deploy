#!/usr/bin/env bash
set -euo pipefail
[[ $# == 5 ]] || exit 2
slot="$1"; generation="$2"; dashboard="$3"; alias="$4"; api="$5"
[[ $slot == single ]] || exit 2
[[ $generation =~ ^[0-9a-f]{32}$ ]] || exit 2
python3 - "$api" <<'PY'
import ipaddress, re, sys
host = sys.argv[1]
labels = host.split('.')
if len(host) > 253 or len(labels) < 2 or not all(0 < len(label) <= 63 and re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?', label) for label in labels):
    sys.exit(2)
try:
    ipaddress.ip_address(host)
    sys.exit(2)
except ValueError:
    pass
PY

cat <<EOF
# Managed by vps-deploy; opendesign-owned route only.
http:
  middlewares:
    opendesign-route-generation:
      headers:
        customResponseHeaders:
          X-OpenDesign-Route-Generation: "$generation"
    opendesign-headers:
      headers:
        customResponseHeaders:
          X-Content-Type-Options: "nosniff"
          Referrer-Policy: "strict-origin-when-cross-origin"
  routers:
    opendesign-deny-deployment:
      rule: "Host(\`$api\`) && PathPrefix(\`/api/deployment\`)"
      entryPoints: [web]
      priority: 1000
      middlewares: [deny-internal]
      service: opendesign-service
    opendesign-internal-health:
      rule: "Host(\`opendesign.internal.invalid\`) && Path(\`/api/health\`)"
      entryPoints: [slot-probe]
      priority: 500
      middlewares: [opendesign-route-generation]
      service: opendesign-service
    opendesign-public-router:
      rule: "Host(\`$api\`)"
      entryPoints: [web]
      priority: 100
      middlewares: [opendesign-route-generation, tunnel-only, crowdsec-ip, opendesign-headers]
      service: opendesign-service
  services:
    opendesign-service:
      loadBalancer:
        passHostHeader: true
        responseForwarding:
          flushInterval: "-1ms"
        servers:
          - url: "http://opendesign-$slot:7456"
        healthCheck:
          path: "/api/health"
          interval: "5s"
          timeout: "2s"
EOF
