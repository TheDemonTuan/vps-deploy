# What the MC hub's origins refuse anyway (their Traefik routes, apps/mc-hub*/adapter.sh) stops
# here, before the edge-lb Worker and the tunnels. Free plan: 5 custom rules and 1 rate limiting
# rule per zone, no regex, and a rate limiting rule may only test the path and verified bots.
locals {
  # From hosts/oracle-main.yml; tests/test_mc_hub_api.py keeps these and the paths below equal.
  mc_hub_site      = "thedemontuan.dev"
  mc_hub_api_host  = "api.thedemontuan.dev"
  mc_hub_api_alias = "minecraft-api.tuannguyenviet.site"

  # The one route Traefik keeps on an API host (mc-hub-api-router); it answers 403 to everything
  # else. Readers use the site's /api/, SSR the node's internal entrypoint.
  api_host_paths    = ["/healthz"]
  api_host_prefixes = []
  api_host_reads = join(" or ", concat(
    [for p in local.api_host_paths : "http.request.uri.path eq \"${p}\""],
    [for p in local.api_host_prefixes : "starts_with(http.request.uri.path, \"${p}\")"],
  ))
  api_host_refused = "not (http.request.method in {\"GET\" \"HEAD\"} and (${local.api_host_reads}))"
  # Lease renewals (platform/peer) come from the nodes' own addresses; the Worker checks the key.
  edge_node_ips = join(" ", sort([for host in values(local.edge_hosts) : host.ssh.address]))

  probe_paths    = "(http.request.uri.path contains \"/.\" and not starts_with(http.request.uri.path, \"/.well-known/\")) or ends_with(lower(http.request.uri.path), \".php\") or lower(http.request.uri.path) contains \"/wp-admin\" or lower(http.request.uri.path) contains \"/wp-includes\" or lower(http.request.uri.path) contains \"/wp-content\""
  scanner_probes = join(" or ", [for a in ["acunetix", "dirbuster", "feroxbuster", "fuzz faster u fool", "gobuster", "l9explore", "masscan", "netsparker", "nikto", "nmap scripting engine", "nuclei", "sqlmap", "wpscan", "zgrab"] : "lower(http.user_agent) contains \"${a}\""])
  # Traefik denies /internal on the site. Outside /_astro/ (build) and /media/ (uploads) it serves
  # only these file types: public/ files, feeds, sitemap, ads.txt, the search index, and HTML a
  # verifier may ask for. Any other extension is a probe the site would answer with its 404 page.
  site_extensions = join(" ", [for e in ["avif", "css", "gif", "htm", "html", "ico", "jpeg", "jpg", "js", "json", "png", "svg", "txt", "webmanifest", "webp", "woff", "woff2", "xml"] : "\"${e}\""])
  site_probes     = "http.host eq \"${local.mc_hub_site}\" and (starts_with(http.request.uri.path, \"/internal\") or (http.request.uri.path.extension ne \"\" and not http.request.uri.path.extension in {${local.site_extensions}} and not starts_with(http.request.uri.path, \"/_astro/\") and not starts_with(http.request.uri.path, \"/media/\") and not starts_with(http.request.uri.path, \"/cdn-cgi/\") and not starts_with(http.request.uri.path, \"/.well-known/\")))"
  # The site takes writes only under /api/ and /admin (Access); /cdn-cgi/ is Cloudflare's own
  # (Web Analytics beacons, challenges, Access login).
  site_methods = "http.host eq \"${local.mc_hub_site}\" and not starts_with(http.request.uri.path, \"/cdn-cgi/\") and (not http.request.method in {\"GET\" \"HEAD\" \"POST\" \"PUT\" \"DELETE\"} or (not http.request.method in {\"GET\" \"HEAD\"} and not starts_with(http.request.uri.path, \"/api/\") and http.request.uri.path ne \"/admin\" and not starts_with(http.request.uri.path, \"/admin/\")))"
  # Every Worker's subrequest into these zones arrives from one shared Cloudflare address
  # (2a06:98c0:3600::103), which CrowdSec therefore never bans (ansible cloudflare_workers_ip).
  # Only our own Workers may reach the origins that way: edge-lb (route on thedemontuan.dev),
  # this account's workers.dev (UptimeFlare) and the tuannguyenviet.site Workers.
  foreign_workers = "not cf.worker.upstream_zone in {\"\" \"thedemontuan.dev\" \"tuannguyenviet.site\" \"nguyenviettuanbp.workers.dev\"}"
  # Attack mode: a managed challenge on the site's pages (paths without an extension) for every
  # visitor but verified bots, the nodes (deploy probes, lease) and our own Workers' subrequests
  # (UptimeFlare). Assets, images, /api/ (the page's own calls, after its challenge) stay open.
  # It does what "I'm Under Attack" would, which cannot spare the nodes on the Free plan.
  site_pages = "http.host eq \"${local.mc_hub_site}\" and http.request.method in {\"GET\" \"HEAD\"} and http.request.uri.path.extension eq \"\" and not starts_with(http.request.uri.path, \"/api/\") and not starts_with(http.request.uri.path, \"/cdn-cgi/\") and not starts_with(http.request.uri.path, \"/.well-known/\") and not cf.client.bot and cf.worker.upstream_zone eq \"\" and not ip.src in {${local.edge_node_ips}}"
}

resource "cloudflare_ruleset" "thedemontuan_dev_custom_waf" {
  provider    = cloudflare.waf
  zone_id     = var.zones["thedemontuan.dev"]
  name        = "default"
  kind        = "zone"
  phase       = "http_request_firewall_custom"
  description = ""

  rules = [
    {
      action      = "block"
      description = "Edge IP bans"
      enabled     = true
      expression  = "ip.src in $edge_bans"
      ref         = "crowdsec_edge_block"
    },
    {
      # One rule for both (Free plan: 5 custom rules). The controller (crowdsec-telegram) checks
      # that crowdsec_edge_block is exactly "ip.src in $edge_bans", so that one stays alone.
      action      = "block"
      description = "edge-probe-paths, foreign-workers"
      enabled     = true
      expression  = "${local.probe_paths} or (${local.site_probes}) or ${local.scanner_probes} or ${local.foreign_workers}"
      ref         = "ef7d847cf4094f29a25d1ca321d0110c"
    },
    {
      # The nodes renew edge-lb's lease with POST /__edge/lease/<name> (platform/peer).
      action      = "block"
      description = "mc-hub-api-host"
      enabled     = true
      expression  = "http.host eq \"${local.mc_hub_api_host}\" and ${local.api_host_refused} and not (http.request.method eq \"POST\" and starts_with(http.request.uri.path, \"/__edge/lease/\") and ip.src in {${local.edge_node_ips}})"
      ref         = "mc_hub_api_host"
    },
    {
      action      = "block"
      description = "mc-hub-methods"
      enabled     = true
      expression  = local.site_methods
      ref         = "mc_hub_methods"
    },
    {
      # Off until an attack gets past the rate limit (README "Under attack"): turn it on in the
      # dashboard for an immediate effect, then here so the next apply keeps it.
      action      = "managed_challenge"
      description = "attack-mode"
      enabled     = false
      expression  = local.site_pages
      ref         = "mc_hub_attack_mode"
    }
  ]
}

import {
  to = cloudflare_ruleset.thedemontuan_dev_custom_waf
  id = "zones/${var.zones["thedemontuan.dev"]}/97a6486f4a0b4451b9d16dc9f7ec4a33"
}

resource "cloudflare_ruleset" "tuannguyenviet_site_custom_waf" {
  provider    = cloudflare.waf
  zone_id     = var.zones["tuannguyenviet.site"]
  name        = "default"
  kind        = "zone"
  phase       = "http_request_firewall_custom"
  description = "OmniRoute custom WAF"

  rules = [
    {
      action     = "block"
      enabled    = true
      expression = "(http.host eq \"omniroute-api.tuannguyenviet.site\") and (not (starts_with(http.request.uri.path, \"/v1/\") or starts_with(http.request.uri.path, \"/api/v1/\") or starts_with(http.request.uri.path, \"/v1beta/\") or starts_with(http.request.uri.path, \"/api/v1beta/\") or http.request.uri.path eq \"/api/health\") or starts_with(lower(http.request.uri.path), \"/v1/management\") or starts_with(lower(http.request.uri.path), \"/api/v1/management\") or starts_with(lower(http.request.uri.path), \"/v1/registered-keys\") or starts_with(lower(http.request.uri.path), \"/api/v1/registered-keys\") or starts_with(lower(http.request.uri.path), \"/v1/agents\") or starts_with(lower(http.request.uri.path), \"/api/v1/agents\") or starts_with(lower(http.request.uri.path), \"/v1/accounts\") or starts_with(lower(http.request.uri.path), \"/api/v1/accounts\") or starts_with(lower(http.request.uri.path), \"/v1/providers\") or starts_with(lower(http.request.uri.path), \"/api/v1/providers\") or starts_with(lower(http.request.uri.path), \"/v1/issues\") or starts_with(lower(http.request.uri.path), \"/api/v1/issues\") or starts_with(lower(http.request.uri.path), \"/v1/quotas\") or starts_with(lower(http.request.uri.path), \"/api/v1/quotas\"))"
      ref        = "omniroute_api_paths"
    },
    {
      action      = "block"
      description = "Edge IP bans"
      enabled     = true
      expression  = "ip.src in $edge_bans"
      ref         = "crowdsec_edge_block"
    },
    {
      action      = "block"
      description = "foreign-workers"
      enabled     = true
      expression  = local.foreign_workers
      ref         = "foreign_workers"
    },
    {
      action      = "block"
      description = "edge-probe-paths"
      enabled     = true
      expression  = "${local.probe_paths} or ${local.scanner_probes}"
      ref         = "19bf78541ff445faa190cc973746875c"
    },
    {
      action      = "block"
      description = "mc-hub-api-host"
      enabled     = true
      expression  = "http.host eq \"${local.mc_hub_api_alias}\" and ${local.api_host_refused}"
      ref         = "mc_hub_api_host"
    }
  ]
}

import {
  to = cloudflare_ruleset.tuannguyenviet_site_custom_waf
  id = "zones/${var.zones["tuannguyenviet.site"]}/227397dab92f416eaaea64bf4a491766"
}

resource "cloudflare_ruleset" "thedemontuan_dev_ratelimit" {
  provider    = cloudflare.waf
  zone_id     = var.zones["thedemontuan.dev"]
  name        = "default"
  kind        = "zone"
  phase       = "http_ratelimit"
  description = ""

  rules = [
    {
      # Every path but hashed assets and images (a page pulls dozens; the edge cache and R2 serve
      # them, never a node), so a flood of edge-cached pages stops here too, before the Worker.
      # Above what Traefik lets one visitor through (pages 20/s burst 60, /api/ 10/s burst 30) with
      # room for many readers behind one carrier address (CGNAT). Replaces the leaked-credential
      # rule: every password form sits behind Access. /api/admin/ is Access-only; vmagent
      # (metrics.) flushes its disk buffer in bursts.
      action      = "block"
      description = "mc-hub-api-flood"
      enabled     = true
      expression  = "not starts_with(http.request.uri.path, \"/_astro/\") and not starts_with(http.request.uri.path, \"/media/\") and not starts_with(http.request.uri.path, \"/api/admin/\") and http.request.uri.path ne \"/api/v1/write\" and not cf.bot_management.verified_bot"
      ref         = "mc_hub_api_flood"
      ratelimit = {
        characteristics     = ["ip.src", "cf.colo.id"]
        mitigation_timeout  = 10
        period              = 10
        requests_per_period = 300
      }
    }
  ]
}

import {
  to = cloudflare_ruleset.thedemontuan_dev_ratelimit
  id = "zones/${var.zones["thedemontuan.dev"]}/b4857595d2b54aa2b44eb4af236beae8"
}

resource "cloudflare_ruleset" "tuannguyenviet_site_ratelimit" {
  provider    = cloudflare.waf
  zone_id     = var.zones["tuannguyenviet.site"]
  name        = "default"
  kind        = "zone"
  phase       = "http_ratelimit"
  description = "Zone rate limit ruleset"
  rules       = []
}

import {
  to = cloudflare_ruleset.tuannguyenviet_site_ratelimit
  id = "zones/${var.zones["tuannguyenviet.site"]}/e72b8df46fad4f14b9c309c7f9a7aa94"
}

resource "cloudflare_ruleset" "thedemontuan_dev_managed_waf" {
  provider    = cloudflare.waf
  zone_id     = var.zones["thedemontuan.dev"]
  name        = "zone http_request_firewall_managed"
  kind        = "zone"
  phase       = "http_request_firewall_managed"
  description = ""

  rules = [
    {
      action = "execute"
      action_parameters = {
        id      = "77454fe2d30c4220b5701f6fdfb893ba"
        version = "latest"
      }
      description = "edge-free-managed"
      enabled     = true
      expression  = "not http.host in {\"monitor.thedemontuan.dev\" \"metrics.thedemontuan.dev\"}"
      ref         = "30562db188ce44ebb5bd3d94eba6acaa"
    }
  ]
}

import {
  to = cloudflare_ruleset.thedemontuan_dev_managed_waf
  id = "zones/${var.zones["thedemontuan.dev"]}/7f13c11b24f9406fb811f4429f42b1c9"
}

resource "cloudflare_ruleset" "tuannguyenviet_site_managed_waf" {
  provider    = cloudflare.waf
  zone_id     = var.zones["tuannguyenviet.site"]
  name        = "OmniRoute managed WAF"
  kind        = "zone"
  phase       = "http_request_firewall_managed"
  description = "Execute Cloudflare Managed Free Ruleset"

  rules = [
    {
      action = "execute"
      action_parameters = {
        id      = "77454fe2d30c4220b5701f6fdfb893ba"
        version = "latest"
      }
      description = "Execute Cloudflare Managed Free Ruleset for OmniRoute"
      enabled     = true
      expression  = "(http.host eq \"omniroute-api.tuannguyenviet.site\" or http.host eq \"omniroute-admin.tuannguyenviet.site\")"
      ref         = "d17eef5d7c364ca7bf126ff2369c096b"
    }
  ]
}

import {
  to = cloudflare_ruleset.tuannguyenviet_site_managed_waf
  id = "zones/${var.zones["tuannguyenviet.site"]}/3ccbb157b12f44bfa0cb0574a67d8b6d"
}
