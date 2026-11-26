output "tunnel_ids" {
  description = "Zero Trust tunnel IDs per edge host"
  value = {
    for k, v in cloudflare_zero_trust_tunnel_cloudflared.edge :
    k => v.id
  }
}
