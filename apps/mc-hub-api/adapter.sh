#!/usr/bin/env bash
set -euo pipefail
[[ $# == 5 ]] || exit 2
slot="$1"; generation="$2"; dashboard="$3"; alias="$4"; api="$5"
[[ $slot == blue || $slot == green ]] || exit 2
[[ $generation =~ ^[0-9a-f]{32}$ ]] || exit 2
[[ -z $dashboard && -z $alias && $api == minecraft-api.tuannguyenviet.site ]] || exit 2
site=minecraft.tuannguyenviet.site
cat <<EOF
# Managed by vps-deploy; mc-hub-api-owned routes only.
# Also serves /api/ and /media/ on the mc-hub site host so the browser stays same-origin.
http:
  middlewares:
    mc-hub-api-route-generation:
      headers:
        customResponseHeaders:
          X-MC-Hub-API-Route-Generation: "$generation"
    mc-hub-api-security-headers:
      headers:
        customResponseHeaders:
          X-Content-Type-Options: "nosniff"
          X-Frame-Options: "DENY"
          Referrer-Policy: "strict-origin-when-cross-origin"
          Permissions-Policy: "camera=(), microphone=(), geolocation=()"
  routers:
    mc-hub-api-deny-internal:
      rule: "Host(\`$api\`) && PathPrefix(\`/internal\`)"
      entryPoints: [web]
      priority: 1000
      middlewares: [deny-internal]
      service: mc-hub-api-service
    mc-hub-api-router:
      rule: "Host(\`$api\`)"
      entryPoints: [web]
      priority: 100
      middlewares: [mc-hub-api-route-generation, tunnel-only, mc-hub-api-security-headers]
      service: mc-hub-api-service
    mc-hub-api-site-router:
      rule: "Host(\`$site\`) && (PathPrefix(\`/api/\`) || PathPrefix(\`/media/\`))"
      entryPoints: [web]
      priority: 200
      middlewares: [mc-hub-api-route-generation, tunnel-only, mc-hub-api-security-headers]
      service: mc-hub-api-service
  services:
    mc-hub-api-service:
      loadBalancer:
        passHostHeader: true
        servers:
          - url: "http://mc-hub-api-$slot:8080"
        healthCheck:
          path: "/healthz"
          interval: "5s"
          timeout: "2s"
EOF
