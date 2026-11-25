#!/usr/bin/env bash
set -euo pipefail
[[ $# == 5 ]] || exit 2
slot="$1"; generation="$2"; dashboard="$3"; alias="$4"; api="$5"
[[ $slot == blue || $slot == green ]] || exit 2
[[ $generation =~ ^[0-9a-f]{32}$ ]] || exit 2
# Hosts come from hosts/<host>.yml: $api is the SSR API host, $alias (optional) the previous one,
# kept routed as a fallback (README: "Moving mc-hub to another domain").
name='^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
[[ -z $dashboard && $api =~ $name && ( -z $alias || $alias =~ $name ) ]] || exit 2
api_hosts="Host(\`$api\`)"
[[ -z $alias ]] || api_hosts+=" || Host(\`$alias\`)"
# The site's hosts: mc-hub's api_host and fallback alias (tests/test_mc_hub_api.py keeps them equal).
site_hosts="Host(\`thedemontuan.dev\`) || Host(\`tuannguyenviet.site\`)"
cat <<EOF
# Managed by vps-deploy; mc-hub-api-owned routes only.
# Also serves /api/ and /media/ on the mc-hub site host so the browser stays same-origin;
# admin and login run only there, behind the "MC Hub Admin" Cloudflare Access app.
# The API host keeps only the reads frontend SSR makes (and the session check its cache purge
# needs) for health probes and fallback; everything else on it is denied. SSR itself calls the
# same reads on this node through the plain-HTTP "internal" entrypoint (internal-only: loopback
# and the mc-hub network), so it never leaves the VPS. Neither gets a per-IP limit. Browser
# traffic on the site host does, keyed on CF-Connecting-IP (only cloudflared reaches "web");
# public writes get a stricter budget and a 64 KiB body cap. The API keeps its own per-action
# limits (comments, feedback, login).
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
    mc-hub-api-rate-limit:
      rateLimit:
        average: 10
        period: 1s
        burst: 30
        sourceCriterion:
          requestHeaderName: CF-Connecting-IP
    mc-hub-api-write-rate-limit:
      rateLimit:
        average: 30
        period: 1m
        burst: 10
        sourceCriterion:
          requestHeaderName: CF-Connecting-IP
    mc-hub-api-inflight:
      inFlightReq:
        amount: 8
        sourceCriterion:
          requestHeaderName: CF-Connecting-IP
    mc-hub-api-write-body-limit:
      buffering:
        maxRequestBodyBytes: 65536
  routers:
    mc-hub-api-deny-internal:
      rule: "($api_hosts) && PathPrefix(\`/internal\`)"
      entryPoints: [web]
      priority: 1000
      middlewares: [deny-internal]
      service: mc-hub-api-service
    mc-hub-api-router:
      rule: "($api_hosts) && (Path(\`/healthz\`) || Path(\`/api/posts\`) || PathPrefix(\`/api/posts/\`) || PathPrefix(\`/api/pages/\`) || Path(\`/api/settings\`) || Path(\`/api/stats\`) || Path(\`/api/auth/me\`))"
      entryPoints: [web]
      priority: 500
      middlewares: [mc-hub-api-route-generation, tunnel-only, mc-hub-api-security-headers]
      service: mc-hub-api-service
    mc-hub-api-fallback:
      rule: "$api_hosts"
      entryPoints: [web]
      priority: 400
      middlewares: [deny-internal]
      service: mc-hub-api-service
    mc-hub-api-site-router:
      rule: "($site_hosts) && (PathPrefix(\`/api/\`) || PathPrefix(\`/media/\`))"
      entryPoints: [web]
      priority: 200
      middlewares: [mc-hub-api-route-generation, tunnel-only, mc-hub-api-rate-limit, mc-hub-api-inflight, mc-hub-api-security-headers]
      service: mc-hub-api-service
    mc-hub-api-site-write:
      rule: "($site_hosts) && Method(\`POST\`) && PathPrefix(\`/api/\`) && !PathPrefix(\`/api/admin/\`)"
      entryPoints: [web]
      priority: 300
      middlewares: [mc-hub-api-route-generation, tunnel-only, mc-hub-api-write-rate-limit, mc-hub-api-inflight, mc-hub-api-write-body-limit, mc-hub-api-security-headers]
      service: mc-hub-api-service
    mc-hub-api-internal:
      rule: "Path(\`/api/posts\`) || PathPrefix(\`/api/posts/\`) || PathPrefix(\`/api/pages/\`) || Path(\`/api/settings\`) || Path(\`/api/stats\`) || Path(\`/api/auth/me\`)"
      entryPoints: [internal]
      priority: 500
      middlewares: [internal-only, mc-hub-api-security-headers]
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
