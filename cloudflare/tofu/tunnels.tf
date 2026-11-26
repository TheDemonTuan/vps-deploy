locals {
  default_origin_request = {
    ca_pool       = "/etc/cloudflare-origin-ca/origin-ca.pem"
    no_tls_verify = false
  }

  tunnel_ingress = {
    "oracle-main" = [
      { hostname = "tuannguyenviet.site", origin_server_name = "tuannguyenviet.site" },
      { hostname = "bank.tuannguyenviet.site", origin_server_name = "bank.tuannguyenviet.site", match_sn_ito_host = false },
      { hostname = "transactions.tuannguyenviet.site", origin_server_name = "transactions.tuannguyenviet.site", match_sn_ito_host = false },
      { hostname = "bark.tuannguyenviet.site", origin_server_name = "bark.tuannguyenviet.site", match_sn_ito_host = false },
      { hostname = "omniroute-api.tuannguyenviet.site", origin_server_name = "omniroute-api.tuannguyenviet.site" },
      { hostname = "omniroute.tuannguyenviet.site", origin_server_name = "omniroute.tuannguyenviet.site" },
      { hostname = "minecraft.tuannguyenviet.site", origin_server_name = "minecraft.tuannguyenviet.site" },
      { hostname = "minecraft-api.tuannguyenviet.site", origin_server_name = "minecraft-api.tuannguyenviet.site" },
      { hostname = "thedemontuan.dev", origin_server_name = "thedemontuan.dev" },
      { hostname = "api.thedemontuan.dev", origin_server_name = "api.thedemontuan.dev" },
      { hostname = "monitor.thedemontuan.dev", origin_server_name = "monitor.thedemontuan.dev" },
      { hostname = "metrics.thedemontuan.dev", origin_server_name = "metrics.thedemontuan.dev" },
    ],
    "oracle-sg2" = [
      { hostname = "thedemontuan.dev", origin_server_name = "thedemontuan.dev" },
      { hostname = "api.thedemontuan.dev", origin_server_name = "api.thedemontuan.dev" },
    ],
  }

  default_tunnel_ingress = [
    { hostname = "thedemontuan.dev", origin_server_name = "thedemontuan.dev" },
    { hostname = "api.thedemontuan.dev", origin_server_name = "api.thedemontuan.dev" },
  ]
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "edge" {
  for_each   = local.edge_hosts
  account_id = var.account_id
  name       = each.key == "oracle-main" ? "shared-edge-vps" : each.key == "oracle-sg2" ? "shared-edge-vps-n2" : "shared-edge-${each.key}"
  config_src = "cloudflare"
}

import {
  for_each = {
    for k, v in local.edge_hosts :
    k => v.edge.tunnel
    if try(v.edge.tunnel, null) != null && try(v.edge.tunnel, "") != ""
  }
  to = cloudflare_zero_trust_tunnel_cloudflared.edge[each.key]
  id = "${var.account_id}/${each.value}"
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "edge" {
  for_each   = local.edge_hosts
  account_id = var.account_id
  tunnel_id  = try(each.value.edge.tunnel, cloudflare_zero_trust_tunnel_cloudflared.edge[each.key].id)

  config = {
    ingress = concat(
      [
        for item in lookup(local.tunnel_ingress, each.key, local.default_tunnel_ingress) : {
          hostname = item.hostname
          service  = "https://172.31.250.4:8080"
          origin_request = {
            ca_pool            = local.default_origin_request.ca_pool
            no_tls_verify      = local.default_origin_request.no_tls_verify
            origin_server_name = item.origin_server_name
            match_sn_ito_host  = lookup(item, "match_sn_ito_host", null)
          }
        }
      ],
      [
        {
          service = "http_status:404"
        }
      ]
    )
  }
}

import {
  for_each = {
    for k, v in local.edge_hosts :
    k => v.edge.tunnel
    if try(v.edge.tunnel, null) != null && try(v.edge.tunnel, "") != ""
  }
  to = cloudflare_zero_trust_tunnel_cloudflared_config.edge[each.key]
  id = "${var.account_id}/${each.value}"
}
