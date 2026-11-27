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

# The daily database copies (platform/peer, rclone copy to backups/) cannot be deleted or
# overwritten for 30 days, even with a leaked R2 token. Only backups/: the Litestream mirror under
# litestream/ is an rclone sync that deletes what the replica dropped.
resource "cloudflare_r2_bucket_lock" "mc_hub_db_backups" {
  account_id  = var.account_id
  bucket_name = cloudflare_r2_bucket.buckets["mc-hub-db"].name
  rules = [
    {
      id        = "backups-30-days"
      enabled   = true
      prefix    = "backups/"
      condition = { type = "Age", max_age_seconds = 30 * 24 * 3600 }
    }
  ]
}
