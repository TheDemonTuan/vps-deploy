#!/usr/bin/env bash
set -euo pipefail
[[ $# == 5 ]] || exit 2
slot="$1"; generation="$2"; dashboard="$3"; alias="$4"; api="$5"
[[ $slot == blue || $slot == green ]] || exit 2
[[ $generation =~ ^[0-9a-f]{32}$ && -z $alias ]] || exit 2
python3 - "$dashboard" "$api" <<'PY'
import ipaddress, re, sys
for host in sys.argv[1:]:
    labels = host.split('.')
    if len(host) > 253 or len(labels) < 2 or not all(0 < len(label) <= 63 and re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?', label) for label in labels):
        sys.exit(2)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        continue
    sys.exit(2)
if sys.argv[1] == sys.argv[2]:
    sys.exit(2)
PY
cat <<EOF
# Managed by vps-deploy; OmniRoute-owned route only.
http:
  middlewares:
    omniroute-route-generation:
      headers:
        customResponseHeaders:
          X-OmniRoute-Route-Generation: "$generation"
  routers:
    omniroute-deny-internal:
      rule: "(Host(\`$dashboard\`) || Host(\`$api\`)) && PathPrefix(\`/internal\`)"
      entryPoints: [web]
      priority: 1000
      middlewares: [deny-internal]
      service: omniroute-service
    omniroute-api-router:
      rule: "Host(\`$api\`) && (PathPrefix(\`/v1/\`) || PathPrefix(\`/api/v1/\`) || PathPrefix(\`/v1beta/\`) || PathPrefix(\`/api/v1beta/\`) || Path(\`/api/health\`))"
      entryPoints: [web]
      priority: 500
      middlewares: [omniroute-route-generation, tunnel-only, public-api-rate-limit, security-headers]
      service: omniroute-service
    omniroute-api-fallback:
      rule: "Host(\`$api\`)"
      entryPoints: [web]
      priority: 400
      middlewares: [deny-internal]
      service: omniroute-service
    omniroute-dashboard-router:
      rule: "Host(\`$dashboard\`)"
      entryPoints: [web]
      priority: 100
      middlewares: [omniroute-route-generation, tunnel-only, security-headers]
      service: omniroute-service
  services:
    omniroute-service:
      loadBalancer:
        passHostHeader: true
        responseForwarding:
          flushInterval: "100ms"
        servers:
          - url: "http://omniroute-$slot:20128"
        healthCheck:
          path: "/api/health"
          interval: "5s"
          timeout: "2s"
EOF
