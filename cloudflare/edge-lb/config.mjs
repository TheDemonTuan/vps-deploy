export default {
  "nodes": {
    "n1": {
      "ip": "134.185.89.192",
      "weight": 30
    },
    "n2": {
      "ip": "217.142.186.194",
      "weight": 70
    }
  },
  "rules": {
    "mc-hub": {
      "edge_cache": {
        "paths": [
          "^/api/posts(/[^/]+)?$",
          "^/(?!api/|admin|_astro/|media/)"
        ],
        "stale_seconds": 86400,
        "ttl_seconds": 30
      },
      "fanout": [
        {
          "delay_seconds": 8,
          "method": "POST",
          "path": "^/admin/revalidate$"
        }
      ],
      "immutable_paths": [
        "^/_astro/"
      ],
      "primary_cookies": [
        "__Host-mch_session"
      ],
      "primary_paths": [
        "^/admin(/|$)",
        "^/api/(admin|auth|push)/",
        "^/api/dl(/|$)"
      ],
      "public_bucket": {
        "binding": "MEDIA",
        "bucket": "mc-hub-media",
        "headers": {
          "Cache-Control": "public, max-age=31536000, immutable",
          "Content-Security-Policy": "default-src 'none'; sandbox",
          "Content-Type": "image/jpeg",
          "X-Content-Type-Options": "nosniff"
        },
        "key_prefix": "media/",
        "path": "^/media/[0-9a-f]{32}(-sm)?\\.jpg$",
        "strip": "/media/"
      },
      "queue_paths": [
        "^/api/posts/[^/]+/(views|comments|compat)$",
        "^/api/feedback$",
        "^/api/feedback/[0-9]+/vote$"
      ],
      "sticky_seconds": 15
    },
    "mc-hub-api": {
      "edge_cache": null,
      "fanout": [],
      "immutable_paths": [],
      "primary_cookies": [],
      "primary_paths": [
        "^/api/(admin|auth|push)/",
        "^/api/dl(/|$)"
      ],
      "public_bucket": null,
      "queue_paths": [],
      "sticky_seconds": 0
    }
  },
  "sites": {
    "api.thedemontuan.dev": {
      "lease": "mc-hub-api",
      "nodes": [
        "n1",
        "n2"
      ],
      "primary": "n1",
      "rules": "mc-hub-api",
      "zone": "thedemontuan.dev"
    },
    "thedemontuan.dev": {
      "lease": "mc-hub-api",
      "nodes": [
        "n1",
        "n2"
      ],
      "primary": "n1",
      "rules": "mc-hub",
      "zone": "thedemontuan.dev"
    }
  }
};
