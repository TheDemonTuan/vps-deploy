variable "cloudflare_api_token" {
  type        = string
  description = "Cloudflare API token with permissions for DNS, Tunnels, Access, and R2"
  sensitive   = true
}

variable "cloudflare_waf_api_token" {
  type        = string
  description = "Cloudflare API token with permissions for Zone WAF (defaults to cloudflare_api_token if null)"
  sensitive   = true
  default     = null
}

variable "tofu_encryption_passphrase" {
  type        = string
  description = "Passphrase for OpenTofu state and plan PBKDF2 encryption"
  sensitive   = true
}

variable "account_id" {
  type        = string
  description = "Cloudflare Account ID"
  default     = "2bd4d7bed700abe668c22946f9f35c9c"
}

variable "zones" {
  type        = map(string)
  description = "Map of domain names to Zone IDs"
  default = {
    "thedemontuan.dev"    = "4bd369e0cbab912271ab31590c506153"
    "tuannguyenviet.site" = "d01c38f57ee75add58e9f54e68611ab5"
  }
}
