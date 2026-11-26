terraform {
  required_version = ">= 1.10.0"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "5.29.0"
    }
  }

  backend "s3" {
    bucket                      = "vps-deploy-tofu"
    key                         = "terraform.tfstate"
    region                      = "auto"
    endpoint                    = "https://2bd4d7bed700abe668c22946f9f35c9c.r2.cloudflarestorage.com"
    use_lockfile                = true
    skip_credentials_validation = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    skip_s3_checksum            = true
  }

  encryption {
    key_provider "pbkdf2" "state_key" {
      passphrase = var.tofu_encryption_passphrase
    }
    method "aes_gcm" "state_cipher" {
      keys = key_provider.pbkdf2.state_key
    }
    state {
      method   = method.aes_gcm.state_cipher
      enforced = true
    }
    plan {
      method   = method.aes_gcm.state_cipher
      enforced = true
    }
  }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

provider "cloudflare" {
  alias     = "waf"
  api_token = coalesce(var.cloudflare_waf_api_token, var.cloudflare_api_token)
}
