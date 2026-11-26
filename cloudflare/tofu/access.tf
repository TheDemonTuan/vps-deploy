resource "cloudflare_zero_trust_access_application" "fleet_monitor" {
  account_id                 = var.account_id
  name                       = "Fleet Monitor (Grafana)"
  domain                     = "monitor.thedemontuan.dev"
  type                       = "self_hosted"
  app_launcher_visible       = true
  allowed_idps               = ["dc16ea82-1aa4-438a-8778-964be748df75"]
  session_duration           = "24h"
  enable_binding_cookie      = false
  http_only_cookie_attribute = true
  options_preflight_bypass   = false
  auto_redirect_to_identity  = false

  destinations = [
    {
      type = "public"
      uri  = "monitor.thedemontuan.dev"
    }
  ]

  policies = [
    {
      id         = "b5daf662-7ad5-4374-a242-2134bc101c43"
      precedence = 1
    },
    {
      id         = "7a952631-4ddf-488f-9373-6ceb1e4572ee"
      precedence = 2
    }
  ]
}

import {
  to = cloudflare_zero_trust_access_application.fleet_monitor
  id = "accounts/${var.account_id}/37e8df06-3538-4d0f-920d-5d616d117994"
}

resource "cloudflare_zero_trust_access_application" "fleet_metrics" {
  account_id                 = var.account_id
  name                       = "Fleet Metrics Ingest"
  domain                     = "metrics.thedemontuan.dev"
  type                       = "self_hosted"
  app_launcher_visible       = false
  session_duration           = "24h"
  enable_binding_cookie      = false
  http_only_cookie_attribute = true
  options_preflight_bypass   = false
  auto_redirect_to_identity  = false

  destinations = [
    {
      type = "public"
      uri  = "metrics.thedemontuan.dev"
    }
  ]

  policies = [
    {
      id         = "4b6f0797-4f1f-4dae-8a6a-89355be04aab"
      precedence = 1
    }
  ]
}

import {
  to = cloudflare_zero_trust_access_application.fleet_metrics
  id = "accounts/${var.account_id}/9bb7d00c-287d-4067-a8f8-0e7a4cce5caa"
}

resource "cloudflare_zero_trust_access_application" "mc_hub_admin" {
  account_id                 = var.account_id
  name                       = "MC Hub Admin"
  domain                     = "tuannguyenviet.site/admin"
  type                       = "self_hosted"
  app_launcher_visible       = false
  allowed_idps               = ["dc16ea82-1aa4-438a-8778-964be748df75"]
  session_duration           = "24h"
  enable_binding_cookie      = false
  http_only_cookie_attribute = true
  same_site_cookie_attribute = "lax"
  options_preflight_bypass   = false
  auto_redirect_to_identity  = true

  destinations = [
    { type = "public", uri = "tuannguyenviet.site/admin" },
    { type = "public", uri = "tuannguyenviet.site/api/admin" },
    { type = "public", uri = "tuannguyenviet.site/api/auth" },
    { type = "public", uri = "thedemontuan.dev/admin" },
    { type = "public", uri = "thedemontuan.dev/api/admin" },
    { type = "public", uri = "thedemontuan.dev/api/auth" },
  ]

  policies = [
    {
      id         = "ecd28264-68f7-463d-adf8-dff959d6ff88"
      precedence = 1
    }
  ]
}

import {
  to = cloudflare_zero_trust_access_application.mc_hub_admin
  id = "accounts/${var.account_id}/72e0b3e1-e9ff-433c-a4b3-a827ca5470b2"
}

resource "cloudflare_zero_trust_access_application" "omniroute_admin" {
  account_id                 = var.account_id
  name                       = "OmniRoute Admin Dashboard"
  domain                     = "omniroute.tuannguyenviet.site"
  type                       = "self_hosted"
  app_launcher_visible       = true
  allowed_idps               = ["dc16ea82-1aa4-438a-8778-964be748df75"]
  session_duration           = "24h"
  enable_binding_cookie      = false
  http_only_cookie_attribute = true
  options_preflight_bypass   = false
  auto_redirect_to_identity  = false

  destinations = [
    {
      type = "public"
      uri  = "omniroute.tuannguyenviet.site"
    }
  ]

  policies = [
    {
      id         = "6608da0d-74d3-4e08-9b9d-f7bc31fe415b"
      precedence = 1
    }
  ]
}

import {
  to = cloudflare_zero_trust_access_application.omniroute_admin
  id = "accounts/${var.account_id}/8f36d303-f247-40c4-b20e-11bb954e6e2d"
}

resource "cloudflare_zero_trust_access_application" "nine_router_admin" {
  account_id                 = var.account_id
  name                       = "9router Admin Dashboard"
  domain                     = "9router-admin.tuannguyenviet.site"
  type                       = "self_hosted"
  app_launcher_visible       = true
  allowed_idps               = ["dc16ea82-1aa4-438a-8778-964be748df75"]
  session_duration           = "24h"
  enable_binding_cookie      = false
  http_only_cookie_attribute = true
  options_preflight_bypass   = false
  auto_redirect_to_identity  = true

  destinations = [
    {
      type = "public"
      uri  = "9router-admin.tuannguyenviet.site"
    }
  ]

  policies = [
    {
      id         = "07494cea-4083-4df8-978b-cf9f0eb4a2a8"
      precedence = 1
    },
    {
      id         = "6cec55ac-4d13-4643-aac2-d308fdb85683"
      precedence = 2
    }
  ]
}

import {
  to = cloudflare_zero_trust_access_application.nine_router_admin
  id = "accounts/${var.account_id}/cc1dc3d5-cfcc-43bf-a2c5-28d9cfcf9d35"
}

resource "cloudflare_zero_trust_access_application" "bank_event_gateway" {
  account_id                 = var.account_id
  name                       = "Bank Event Gateway Dashboard"
  domain                     = "bank.tuannguyenviet.site"
  type                       = "self_hosted"
  app_launcher_visible       = true
  session_duration           = "24h"
  enable_binding_cookie      = false
  http_only_cookie_attribute = true
  options_preflight_bypass   = false
  auto_redirect_to_identity  = false

  destinations = [
    {
      type = "public"
      uri  = "bank.tuannguyenviet.site"
    }
  ]

  policies = [
    {
      id         = "517925ec-68c9-40b8-af71-778e815734a1"
      precedence = 1
    }
  ]
}

import {
  to = cloudflare_zero_trust_access_application.bank_event_gateway
  id = "accounts/${var.account_id}/ea767285-4995-4562-a9ca-2382ad77ef10"
}
