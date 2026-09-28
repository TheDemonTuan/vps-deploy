#!/usr/bin/env bash
set -euo pipefail
[[ $# == 5 && ( $1 == blue || $1 == green ) && $2 =~ ^[0-9a-f]{32}$ && -z $3 && -z $4 && $5 =~ ^[a-z0-9.-]+$ ]] || exit 2
slot=$1 generation=$2 api=$5
cat <<EOF
http:
  middlewares:
    demo-route-generation:
      headers:
        customResponseHeaders:
          X-Demo-Route-Generation: "$generation"
  routers:
    demo-api-router:
      rule: "Host(\`$api\`)"
      entryPoints: [web]
      middlewares: [demo-route-generation, security-headers]
      service: demo-service
  services:
    demo-service:
      loadBalancer:
        passHostHeader: true
        servers:
          - url: "http://demo-$slot:18081"
        healthCheck:
          path: "/healthz"
          interval: "5s"
          timeout: "2s"
EOF
