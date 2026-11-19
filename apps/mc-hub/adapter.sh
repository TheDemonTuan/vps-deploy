#!/usr/bin/env bash
set -euo pipefail
[[ $# == 5 ]] || exit 2
slot="$1"; generation="$2"; dashboard="$3"; alias="$4"; api="$5"
[[ $slot == blue || $slot == green ]] || exit 2
[[ $generation =~ ^[0-9a-f]{32}$ ]] || exit 2
# Hosts come from hosts/<host>.yml: $api is the site's domain, $alias (optional) the previous one,
# kept routed as a fallback while Cloudflare 301s it to $api (README: "Moving mc-hub to another domain").
name='^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
[[ -z $dashboard && $api =~ $name && ( -z $alias || $alias =~ $name ) ]] || exit 2
hosts="Host(\`$api\`)"
[[ -z $alias ]] || hosts+=" || Host(\`$alias\`)"
cat <<EOF
# Managed by vps-deploy; mc-hub-owned route only.
# Own headers instead of shared security-headers: its CSP blocks AdSense and YouTube embeds.
# Per-visitor limits key on CF-Connecting-IP, which only cloudflared (tunnel-only) can set.
# Edge-cached pages never reach them, so they only bound cache misses and scrapers.
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
    mc-hub-rate-limit:
      rateLimit:
        average: 20
        period: 1s
        burst: 60
        sourceCriterion:
          requestHeaderName: CF-Connecting-IP
    mc-hub-inflight:
      inFlightReq:
        amount: 16
        sourceCriterion:
          requestHeaderName: CF-Connecting-IP
  routers:
    mc-hub-deny-internal:
      rule: "($hosts) && PathPrefix(\`/internal\`)"
      entryPoints: [web]
      priority: 1000
      middlewares: [deny-internal]
      service: mc-hub-service
    mc-hub-router:
      rule: "$hosts"
      entryPoints: [web]
      priority: 100
      middlewares: [mc-hub-route-generation, tunnel-only, mc-hub-rate-limit, mc-hub-inflight, mc-hub-security-headers]
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
