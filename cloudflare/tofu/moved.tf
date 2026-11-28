# Host ids renamed to n<edge id>-<provider>-<region>-<arch>-<size> (2026-11-28); vps-n4 also
# became edge n3.
moved {
  from = cloudflare_zero_trust_tunnel_cloudflared.edge["oracle-main"]
  to   = cloudflare_zero_trust_tunnel_cloudflared.edge["n1-oci-sin1-arm-4c24g"]
}
moved {
  from = cloudflare_zero_trust_tunnel_cloudflared.edge["oracle-sg2"]
  to   = cloudflare_zero_trust_tunnel_cloudflared.edge["n2-oci-sin2-arm-4c24g"]
}
moved {
  from = cloudflare_zero_trust_tunnel_cloudflared.edge["vps-n4"]
  to   = cloudflare_zero_trust_tunnel_cloudflared.edge["n3-vhs-buf-x86-4c16g"]
}
moved {
  from = cloudflare_zero_trust_tunnel_cloudflared_config.edge["oracle-main"]
  to   = cloudflare_zero_trust_tunnel_cloudflared_config.edge["n1-oci-sin1-arm-4c24g"]
}
moved {
  from = cloudflare_zero_trust_tunnel_cloudflared_config.edge["oracle-sg2"]
  to   = cloudflare_zero_trust_tunnel_cloudflared_config.edge["n2-oci-sin2-arm-4c24g"]
}
moved {
  from = cloudflare_zero_trust_tunnel_cloudflared_config.edge["vps-n4"]
  to   = cloudflare_zero_trust_tunnel_cloudflared_config.edge["n3-vhs-buf-x86-4c16g"]
}
moved {
  from = cloudflare_dns_record.origin["oracle-main"]
  to   = cloudflare_dns_record.origin["n1-oci-sin1-arm-4c24g"]
}
moved {
  from = cloudflare_dns_record.origin["oracle-sg2"]
  to   = cloudflare_dns_record.origin["n2-oci-sin2-arm-4c24g"]
}
moved {
  from = cloudflare_dns_record.origin["vps-n4"]
  to   = cloudflare_dns_record.origin["n3-vhs-buf-x86-4c16g"]
}
