#!/usr/bin/env bash
set -euo pipefail
[[ $# == 5 ]] || exit 2
slot="$1"; generation="$2"; dashboard="$3"; alias="$4"; api="$5"
[[ $slot == blue || $slot == green ]] || exit 2
[[ $generation =~ ^[0-9a-f]{32}$ ]] || exit 2
python3 - "$dashboard" "$alias" "$api" <<'PY'
import ipaddress, re, sys
for host in (sys.argv[1],sys.argv[3],*([sys.argv[2]] if sys.argv[2] else [])):
    labels=host.split('.')
    if len(host)>253 or len(labels)<2 or not all(0<len(label)<=63 and re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?',label) for label in labels):
        sys.exit(2)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        continue
    sys.exit(2)
PY
rule="Host(\`$dashboard\`)"
[[ -z $alias ]] || rule="$rule || Host(\`$alias\`)"
internal="$rule || Host(\`$api\`)"
cat <<EOF
# Managed by vps-deploy; fixture-app-owned route only.
http:
  middlewares:
    fixture-app-route-generation:
      headers:
        customResponseHeaders:
          X-Fixture-App-Route-Generation: "$generation"
  routers:
    fixture-app-deny-internal:
      rule: "($internal) && PathPrefix(\`/internal\`)"
      entryPoints: [web]
      priority: 1000
      middlewares: [deny-internal]
      service: fixture-app-service
    fixture-app-api-deny-admin:
      rule: "Host(\`$api\`) && (Path(\`/\`) || PathPrefix(\`/dashboard\`) || PathPrefix(\`/settings\`) || PathPrefix(\`/login\`) || PathPrefix(\`/api/settings\`))"
      entryPoints: [web]
      priority: 900
      middlewares: [deny-internal]
      service: fixture-app-service
    fixture-app-api-router:
      rule: "Host(\`$api\`) && (PathPrefix(\`/v1\`) || PathPrefix(\`/api/v1\`) || PathPrefix(\`/v1beta\`) || PathPrefix(\`/api/v1beta\`) || Path(\`/api/health\`))"
      entryPoints: [web]
      priority: 500
      middlewares: [fixture-app-route-generation, tunnel-only, public-api-rate-limit, security-headers]
      service: fixture-app-service
    fixture-app-api-fallback:
      rule: "Host(\`$api\`)"
      entryPoints: [web]
      priority: 400
      middlewares: [deny-internal]
      service: fixture-app-service
    fixture-app-dashboard-router:
      rule: "$rule"
      entryPoints: [web]
      priority: 100
      middlewares: [fixture-app-route-generation, tunnel-only, security-headers]
      service: fixture-app-service
  services:
    fixture-app-service:
      loadBalancer:
        passHostHeader: true
        responseForwarding:
          flushInterval: "100ms"
        servers:
          - url: "http://fixture-app-$slot:20128"
        healthCheck:
          path: "/api/health"
          interval: "5s"
          timeout: "2s"
EOF
