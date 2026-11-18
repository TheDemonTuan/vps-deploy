#!/usr/bin/env bash
set -euo pipefail
[[ $# == 5 ]] || exit 2
slot="$1"; generation="$2"; dashboard="$3"; alias="$4"; api="$5"
[[ $slot == blue || $slot == green ]] || exit 2
[[ $generation =~ ^[0-9a-f]{32}$ ]] || exit 2
[[ -z $dashboard && -z $alias && $api == tuannguyenviet.site ]] || exit 2
cat <<EOF
# Managed by vps-deploy; mc-hub-owned route only.
# Own headers instead of shared security-headers: its CSP blocks AdSense and YouTube embeds.
http:
  middlewares:
    mc-hub-route-generation:
      headers:
        customResponseHeaders:
          X-MC-Hub-Route-Generation: "$generation"
    mc-hub-security-headers:
      headers:
        customResponseHeaders:
          X-Content-Type-Options: "nosniff"
          X-Frame-Options: "SAMEORIGIN"
          Referrer-Policy: "strict-origin-when-cross-origin"
          Permissions-Policy: "camera=(), microphone=(), geolocation=()"
  routers:
    mc-hub-deny-internal:
      rule: "Host(\`$api\`) && PathPrefix(\`/internal\`)"
      entryPoints: [web]
      priority: 1000
      middlewares: [deny-internal]
      service: mc-hub-service
    mc-hub-router:
      rule: "Host(\`$api\`)"
      entryPoints: [web]
      priority: 100
      middlewares: [mc-hub-route-generation, tunnel-only, mc-hub-security-headers]
      service: mc-hub-service
  services:
    mc-hub-service:
      loadBalancer:
        passHostHeader: true
        servers:
          - url: "http://mc-hub-$slot:8080"
        healthCheck:
          path: "/healthz"
          interval: "5s"
          timeout: "2s"
EOF
