resource "cloudflare_r2_bucket" "buckets" {
  for_each   = toset(["mc-hub-db", "mc-hub-media"])
  account_id = var.account_id
  name       = each.value

  lifecycle {
    prevent_destroy = true
  }
}

import {
  for_each = toset(["mc-hub-db", "mc-hub-media"])
  to       = cloudflare_r2_bucket.buckets[each.value]
  id       = "${var.account_id}/${each.value}/default"
}
