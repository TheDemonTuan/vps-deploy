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
      action      = "block"
      description = "edge-probe-paths"
      enabled     = true
      expression  = "(http.request.uri.path contains \"/.\" and not starts_with(http.request.uri.path, \"/.well-known/\")) or ends_with(lower(http.request.uri.path), \".php\") or lower(http.request.uri.path) contains \"/wp-admin\" or lower(http.request.uri.path) contains \"/wp-includes\" or lower(http.request.uri.path) contains \"/wp-content\""
      ref         = "ef7d847cf4094f29a25d1ca321d0110c"
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
      description = "edge-probe-paths"
      enabled     = true
      expression  = "(http.request.uri.path contains \"/.\" and not starts_with(http.request.uri.path, \"/.well-known/\")) or ends_with(lower(http.request.uri.path), \".php\") or lower(http.request.uri.path) contains \"/wp-admin\" or lower(http.request.uri.path) contains \"/wp-includes\" or lower(http.request.uri.path) contains \"/wp-content\""
      ref         = "19bf78541ff445faa190cc973746875c"
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
      action      = "block"
      description = "Leaked credential check"
      enabled     = true
      expression  = "(cf.waf.credential_check.password_leaked)"
      ref         = "24bf4553484c4980a9b5f8f4df4c491a"
      ratelimit = {
        characteristics     = ["ip.src", "cf.colo.id"]
        mitigation_timeout  = 10
        period              = 10
        requests_per_period = 5
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
