locals {
  static_dns_records = {
    # thedemontuan.dev (11 records)
    "tdt_cname_api" = {
      zone_id  = var.zones["thedemontuan.dev"]
      id       = "e175381251d70c2945b3c563894f622a"
      name     = "api.thedemontuan.dev"
      type     = "CNAME"
      content  = "09575df7-5465-4201-94c0-130e16472dce.cfargotunnel.com"
      proxied  = true
      ttl      = 1
      comment  = null
      priority = null
    }
    "tdt_cname_apex" = {
      zone_id  = var.zones["thedemontuan.dev"]
      id       = "f741768ea00b4dee197b994e529c84f9"
      name     = "thedemontuan.dev"
      type     = "CNAME"
      content  = "09575df7-5465-4201-94c0-130e16472dce.cfargotunnel.com"
      proxied  = true
      ttl      = 1
      comment  = null
      priority = null
    }
    "tdt_cname_metrics" = {
      zone_id  = var.zones["thedemontuan.dev"]
      id       = "06f566661d5f7dfa56d0608b1068dc18"
      name     = "metrics.thedemontuan.dev"
      type     = "CNAME"
      content  = "09575df7-5465-4201-94c0-130e16472dce.cfargotunnel.com"
      proxied  = true
      ttl      = 1
      comment  = null
      priority = null
    }
    "tdt_cname_monitor" = {
      zone_id  = var.zones["thedemontuan.dev"]
      id       = "500609bdd33ccd66c35c284e09bc817f"
      name     = "monitor.thedemontuan.dev"
      type     = "CNAME"
      content  = "09575df7-5465-4201-94c0-130e16472dce.cfargotunnel.com"
      proxied  = true
      ttl      = 1
      comment  = null
      priority = null
    }
    "tdt_txt_dkim" = {
      zone_id  = var.zones["thedemontuan.dev"]
      id       = "f7b49f0b0ba4c3d05428997050485962"
      name     = "cf2024-1._domainkey.thedemontuan.dev"
      type     = "TXT"
      content  = "\"v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiweykoi+o48IOGuP7GR3X0MOExCUDY/BCRHoWBnh3rChl7WhdyCxW3jgq1daEjPPqoi7sJvdg5hEQVsgVRQP4DcnQDVjGMbASQtrY4WmB1VebF+RPJB2ECPsEDTpeiI5ZyUAwJaVX7r6bznU67g7LvFq35yIo4sdlmtZGV+i0H4cpYH9+3JJ78k\" \"m4KXwaf9xUJCWF6nxeD+qG6Fyruw1Qlbds2r85U9dkNDVAS3gioCvELryh1TxKGiVTkg4wqHTyHfWsp7KD3WQHYJn0RyfJJu6YEmL77zonn7p2SRMvTMP3ZEXibnC9gz3nnhR6wcYL8Q7zXypKTMD58bTixDSJwIDAQAB\""
      proxied  = false
      ttl      = 1
      comment  = null
      priority = null
    }
    "tdt_txt_google" = {
      zone_id  = var.zones["thedemontuan.dev"]
      id       = "7bc54208e5299df24fe06bb392aff0d7"
      name     = "thedemontuan.dev"
      type     = "TXT"
      content  = "\"google-site-verification=YgUJCfrKYpHXZRWwQYTDZ5iGxlPRHoXcetlDbwg6YQ4\""
      proxied  = false
      ttl      = 1
      comment  = "Google Search Console domain property"
      priority = null
    }
    "tdt_txt_yandex" = {
      zone_id  = var.zones["thedemontuan.dev"]
      id       = "4a7aefca8bd91ed1d9158edc311e869c"
      name     = "thedemontuan.dev"
      type     = "TXT"
      content  = "\"yandex-verification: 31a2f19d15c39ae5\""
      proxied  = false
      ttl      = 1
      comment  = null
      priority = null
    }
    "tdt_txt_spf" = {
      zone_id  = var.zones["thedemontuan.dev"]
      id       = "7c82e185953191d381629afec20d0805"
      name     = "thedemontuan.dev"
      type     = "TXT"
      content  = "\"v=spf1 include:_spf.mx.cloudflare.net ~all\""
      proxied  = false
      ttl      = 1
      comment  = null
      priority = null
    }
    "tdt_mx_1" = {
      zone_id  = var.zones["thedemontuan.dev"]
      id       = "5a3052da9ce862a2df3c4e41033021e6"
      name     = "thedemontuan.dev"
      type     = "MX"
      content  = "route1.mx.cloudflare.net"
      proxied  = false
      ttl      = 1
      comment  = null
      priority = 80
    }
    "tdt_mx_2" = {
      zone_id  = var.zones["thedemontuan.dev"]
      id       = "49681b69aad9428a5dbeeb7b156cde7b"
      name     = "thedemontuan.dev"
      type     = "MX"
      content  = "route2.mx.cloudflare.net"
      proxied  = false
      ttl      = 1
      comment  = null
      priority = 64
    }
    "tdt_mx_3" = {
      zone_id  = var.zones["thedemontuan.dev"]
      id       = "0770457c11846708b159c482a6bd0a01"
      name     = "thedemontuan.dev"
      type     = "MX"
      content  = "route3.mx.cloudflare.net"
      proxied  = false
      ttl      = 1
      comment  = null
      priority = 42
    }

    # tuannguyenviet.site (16 records)
    "tnv_cname_apex" = {
      zone_id  = var.zones["tuannguyenviet.site"]
      id       = "a3ca8bc4334cb2ce17d7c91e080219a3"
      name     = "tuannguyenviet.site"
      type     = "CNAME"
      content  = "09575df7-5465-4201-94c0-130e16472dce.cfargotunnel.com"
      proxied  = true
      ttl      = 1
      comment  = null
      priority = null
    }
    "tnv_cname_bank" = {
      zone_id  = var.zones["tuannguyenviet.site"]
      id       = "f47fc91c5a20ca0897a77cf6710788f3"
      name     = "bank.tuannguyenviet.site"
      type     = "CNAME"
      content  = "09575df7-5465-4201-94c0-130e16472dce.cfargotunnel.com"
      proxied  = true
      ttl      = 1
      comment  = null
      priority = null
    }
    "tnv_cname_bark" = {
      zone_id  = var.zones["tuannguyenviet.site"]
      id       = "7282863256e030b4515a89d2cf7903a0"
      name     = "bark.tuannguyenviet.site"
      type     = "CNAME"
      content  = "09575df7-5465-4201-94c0-130e16472dce.cfargotunnel.com"
      proxied  = true
      ttl      = 1
      comment  = null
      priority = null
    }
    "tnv_cname_minecraft" = {
      zone_id  = var.zones["tuannguyenviet.site"]
      id       = "2ae52ded72fca43ea4f5f00f5a61999e"
      name     = "minecraft.tuannguyenviet.site"
      type     = "CNAME"
      content  = "09575df7-5465-4201-94c0-130e16472dce.cfargotunnel.com"
      proxied  = true
      ttl      = 1
      comment  = null
      priority = null
    }
    "tnv_cname_minecraft_api" = {
      zone_id  = var.zones["tuannguyenviet.site"]
      id       = "247aaba1c338963abf6a71f63eccadbc"
      name     = "minecraft-api.tuannguyenviet.site"
      type     = "CNAME"
      content  = "09575df7-5465-4201-94c0-130e16472dce.cfargotunnel.com"
      proxied  = true
      ttl      = 1
      comment  = null
      priority = null
    }
    "tnv_cname_omniroute" = {
      zone_id  = var.zones["tuannguyenviet.site"]
      id       = "f95f28b489c10fa045cce9f8a0626280"
      name     = "omniroute.tuannguyenviet.site"
      type     = "CNAME"
      content  = "09575df7-5465-4201-94c0-130e16472dce.cfargotunnel.com"
      proxied  = true
      ttl      = 1
      comment  = null
      priority = null
    }
    "tnv_cname_omniroute_api" = {
      zone_id  = var.zones["tuannguyenviet.site"]
      id       = "a5c3b6f755c9063ce8802778f4173ed4"
      name     = "omniroute-api.tuannguyenviet.site"
      type     = "CNAME"
      content  = "09575df7-5465-4201-94c0-130e16472dce.cfargotunnel.com"
      proxied  = true
      ttl      = 1
      comment  = null
      priority = null
    }
    "tnv_cname_transactions" = {
      zone_id  = var.zones["tuannguyenviet.site"]
      id       = "8ff17b165df95406992bc954fad126ac"
      name     = "transactions.tuannguyenviet.site"
      type     = "CNAME"
      content  = "09575df7-5465-4201-94c0-130e16472dce.cfargotunnel.com"
      proxied  = true
      ttl      = 1
      comment  = "Public Transaction Viewer Tunnel"
      priority = null
    }
    "tnv_aaaa_status" = {
      zone_id  = var.zones["tuannguyenviet.site"]
      id       = "b5766fa47327ce7b576dbfc90533b16d"
      name     = "status.tuannguyenviet.site"
      type     = "AAAA"
      content  = "100::"
      proxied  = true
      ttl      = 1
      comment  = null
      priority = null
    }
    "tnv_txt_dkim" = {
      zone_id  = var.zones["tuannguyenviet.site"]
      id       = "9f752475cdc62be3112d52da119584a7"
      name     = "cf2024-1._domainkey.tuannguyenviet.site"
      type     = "TXT"
      content  = "\"v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiweykoi+o48IOGuP7GR3X0MOExCUDY/BCRHoWBnh3rChl7WhdyCxW3jgq1daEjPPqoi7sJvdg5hEQVsgVRQP4DcnQDVjGMbASQtrY4WmB1VebF+RPJB2ECPsEDTpeiI5ZyUAwJaVX7r6bznU67g7LvFq35yIo4sdlmtZGV+i0H4cpYH9+3JJ78k\" \"m4KXwaf9xUJCWF6nxeD+qG6Fyruw1Qlbds2r85U9dkNDVAS3gioCvELryh1TxKGiVTkg4wqHTyHfWsp7KD3WQHYJn0RyfJJu6YEmL77zonn7p2SRMvTMP3ZEXibnC9gz3nnhR6wcYL8Q7zXypKTMD58bTixDSJwIDAQAB\""
      proxied  = false
      ttl      = 1
      comment  = null
      priority = null
    }
    "tnv_txt_google" = {
      zone_id  = var.zones["tuannguyenviet.site"]
      id       = "8f604154e962917155ce03f8c4e781cf"
      name     = "tuannguyenviet.site"
      type     = "TXT"
      content  = "\"google-site-verification=tUCYZRJLfRbG5Vcf9gotNHTPJnYEit9i4rvjW9UrpfI\""
      proxied  = false
      ttl      = 1
      comment  = "Google Search Console domain property"
      priority = null
    }
    "tnv_txt_ad" = {
      zone_id  = var.zones["tuannguyenviet.site"]
      id       = "9cfabd655bff574884d28ebea6d702da"
      name     = "tuannguyenviet.site"
      type     = "TXT"
      content  = "\"1851418f378111da976809ae7f8c5d4438a732fa\""
      proxied  = false
      ttl      = 1
      comment  = null
      priority = null
    }
    "tnv_txt_spf" = {
      zone_id  = var.zones["tuannguyenviet.site"]
      id       = "8a9b3c1a7c51a55d4999bd8401d2790b"
      name     = "tuannguyenviet.site"
      type     = "TXT"
      content  = "\"v=spf1 include:_spf.mx.cloudflare.net ~all\""
      proxied  = false
      ttl      = 1
      comment  = null
      priority = null
    }
    "tnv_mx_1" = {
      zone_id  = var.zones["tuannguyenviet.site"]
      id       = "9663ceb03b54f9a6e3058c5dfd35a54e"
      name     = "tuannguyenviet.site"
      type     = "MX"
      content  = "route1.mx.cloudflare.net"
      proxied  = false
      ttl      = 1
      comment  = null
      priority = 78
    }
    "tnv_mx_2" = {
      zone_id  = var.zones["tuannguyenviet.site"]
      id       = "6bcaedcd8f3e4dcd8ff41712ecdf213a"
      name     = "tuannguyenviet.site"
      type     = "MX"
      content  = "route2.mx.cloudflare.net"
      proxied  = false
      ttl      = 1
      comment  = null
      priority = 43
    }
    "tnv_mx_3" = {
      zone_id  = var.zones["tuannguyenviet.site"]
      id       = "cb246a4b227e1fc09683f2e899c6e619"
      name     = "tuannguyenviet.site"
      type     = "MX"
      content  = "route3.mx.cloudflare.net"
      proxied  = false
      ttl      = 1
      comment  = null
      priority = 37
    }
  }
}

# Per-edge host origin CNAME records
resource "cloudflare_dns_record" "origin" {
  for_each = local.edge_hosts

  zone_id = var.zones["thedemontuan.dev"]
  name    = "${each.value.edge.id}-origin.thedemontuan.dev"
  type    = "CNAME"
  content = "${try(each.value.edge.tunnel, cloudflare_zero_trust_tunnel_cloudflared.edge[each.key].id)}.cfargotunnel.com"
  proxied = true
  ttl     = 1
  comment = "mc-hub-edge origin selector (resolveOverride target)"
}

import {
  for_each = {
    for k, v in local.edge_hosts :
    k => v.edge.id
    if k == "oracle-main" || k == "oracle-sg2"
  }
  to = cloudflare_dns_record.origin[each.key]
  id = "${var.zones["thedemontuan.dev"]}/${each.value == "n1" ? "19ef7e43f98681d6ec949d74dfeccd4c" : "935b4472408272bb6eacaef48a20ce05"}"
}

# Static DNS records
resource "cloudflare_dns_record" "records" {
  for_each = local.static_dns_records

  zone_id  = each.value.zone_id
  name     = each.value.name
  type     = each.value.type
  content  = each.value.content
  proxied  = each.value.proxied
  ttl      = each.value.ttl
  comment  = each.value.comment
  priority = each.value.priority
}

import {
  for_each = local.static_dns_records
  to       = cloudflare_dns_record.records[each.key]
  id       = "${each.value.zone_id}/${each.value.id}"
}
