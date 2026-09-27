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
# Managed by vps-deploy; 9router-owned route only.
http:
  middlewares:
    9router-route-generation:
      headers:
        customResponseHeaders:
          X-9Router-Route-Generation: "$generation"
  routers:
    9router-deny-internal:
      rule: "($internal) && PathPrefix(\`/internal\`)"
      entryPoints: [web]
      priority: 1000
      middlewares: [deny-internal]
      service: 9router-service
    9router-api-deny-admin:
      rule: "Host(\`$api\`) && (Path(\`/\`) || PathPrefix(\`/dashboard\`) || PathPrefix(\`/settings\`) || PathPrefix(\`/login\`) || PathPrefix(\`/api/settings\`) || PathPrefix(\`/api/keys\`) || PathPrefix(\`/api/providers\`) || PathPrefix(\`/api/provider-nodes\`) || PathPrefix(\`/api/proxy-pools\`) || PathPrefix(\`/api/combos\`) || PathPrefix(\`/api/usage\`) || PathPrefix(\`/api/oauth\`) || PathPrefix(\`/api/cloud\`) || PathPrefix(\`/api/media-providers\`) || PathPrefix(\`/api/pricing\`) || PathPrefix(\`/api/tags\`) || PathPrefix(\`/api/cli-tools\`) || PathPrefix(\`/api/mcp\`) || PathPrefix(\`/api/translator\`) || PathPrefix(\`/api/tunnel\`) || PathPrefix(\`/api/auth\`) || PathPrefix(\`/api/shutdown\`) || PathPrefix(\`/api/version\`))"
      entryPoints: [web]
      priority: 900
      middlewares: [deny-internal]
      service: 9router-service
    9router-api-router:
      rule: "Host(\`$api\`) && (PathPrefix(\`/v1\`) || PathPrefix(\`/api/v1\`) || PathPrefix(\`/v1beta\`) || PathPrefix(\`/api/v1beta\`) || PathPrefix(\`/chat\`) || PathPrefix(\`/responses\`) || PathPrefix(\`/models\`) || PathPrefix(\`/codex\`) || Path(\`/api/health\`))"
      entryPoints: [web]
      priority: 500
      middlewares: [9router-route-generation, tunnel-only, public-api-rate-limit, security-headers]
      service: 9router-service
    9router-api-fallback:
      rule: "Host(\`$api\`)"
      entryPoints: [web]
      priority: 400
      middlewares: [deny-internal]
      service: 9router-service
    9router-dashboard-router:
      rule: "$rule"
      entryPoints: [web]
      priority: 100
      middlewares: [9router-route-generation, tunnel-only, security-headers]
      service: 9router-service
  services:
    9router-service:
      loadBalancer:
        passHostHeader: true
        responseForwarding:
          flushInterval: "100ms"
        servers:
          - url: "http://9router-$slot:20128"
        healthCheck:
          path: "/api/health"
          interval: "5s"
          timeout: "2s"
EOF
