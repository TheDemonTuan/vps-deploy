export default {
  "nodes": {
    "n1": {
      "weight": 30
    },
    "n2": {
      "weight": 70
    }
  },
  "rules": {
    "mc-hub": {
      "fanout": [
        {
          "delay_seconds": 8,
          "method": "POST",
          "path": "^/admin/revalidate$"
        }
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
      "sticky_seconds": 15
    },
    "mc-hub-api": {
      "fanout": [],
      "primary_cookies": [],
      "primary_paths": [
        "^/api/(admin|auth|push)/",
        "^/api/dl(/|$)"
      ],
      "public_bucket": null,
      "sticky_seconds": 0
    }
  },
  "sites": {
    "api.thedemontuan.dev": {
      "nodes": [
        "n1",
        "n2"
      ],
      "primary": "n1",
      "rules": "mc-hub-api",
      "zone": "thedemontuan.dev"
    },
    "thedemontuan.dev": {
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
