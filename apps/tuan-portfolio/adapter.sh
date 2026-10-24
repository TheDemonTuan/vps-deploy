#!/usr/bin/env bash
set -euo pipefail
[[ $# == 5 ]] || exit 2
slot="$1"; generation="$2"; dashboard="$3"; alias="$4"; api="$5"
[[ $slot == blue || $slot == green ]] || exit 2
[[ $generation =~ ^[0-9a-f]{32}$ ]] || exit 2
[[ -z $dashboard && -z $alias && $api == tuannguyenviet.site ]] || exit 2
cat <<EOF
# Managed by vps-deploy; portfolio-owned route only.
http:
  middlewares:
    tuan-portfolio-route-generation:
      headers:
        customResponseHeaders:
          X-Portfolio-Route-Generation: "$generation"
  routers:
    tuan-portfolio-deny-internal:
      rule: "Host(\`$api\`) && PathPrefix(\`/internal\`)"
      entryPoints: [web]
      priority: 1000
      middlewares: [deny-internal]
      service: tuan-portfolio-service
    tuan-portfolio-router:
      rule: "Host(\`$api\`)"
      entryPoints: [web]
      priority: 100
      middlewares: [tuan-portfolio-route-generation, tunnel-only, security-headers]
      service: tuan-portfolio-service
  services:
    tuan-portfolio-service:
      loadBalancer:
        passHostHeader: true
        servers:
          - url: "http://tuan-portfolio-$slot:8080"
        healthCheck:
          path: "/healthz"
          interval: "5s"
          timeout: "2s"
EOF
