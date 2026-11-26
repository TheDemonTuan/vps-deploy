# Cloudflare Infrastructure as Code (OpenTofu)

This directory declares the Cloudflare infrastructure for `vps-deploy` using OpenTofu and the Cloudflare Provider v5.

## What OpenTofu Owns

- **DNS Records**: All 29 authoritative DNS records across `thedemontuan.dev` and `tuannguyenviet.site` (apex CNAMEs, per-node origin CNAMEs `<id>-origin.<zone>`, app CNAMEs, MX email routing, verification TXT, DKIM, SPF, and status AAAA).
- **Zero Trust Cloudflared Tunnels**: Tunnels (`shared-edge-vps` for n1, `shared-edge-vps-n2` for n2, and `shared-edge-<host>` for any new nodes) and their complete ingress configurations.
- **Zero Trust Access Applications**: 6 production Access applications and their attached policies:
  - `Fleet Monitor (Grafana)`
  - `Fleet Metrics Ingest`
  - `MC Hub Admin`
  - `OmniRoute Admin Dashboard`
  - `9router Admin Dashboard`
  - `Bank Event Gateway Dashboard`
- **Zone Rulesets**:
  - `thedemontuan.dev`: Custom WAF (`Edge IP bans`, `edge-probe-paths`), Rate limiting (`Leaked credential check`), Managed WAF (`edge-free-managed`).
  - `tuannguyenviet.site`: Custom WAF (`omniroute_api_paths`, `Edge IP bans`, `edge-probe-paths`), Rate limiting, Managed WAF (`OmniRoute managed WAF`).
- **R2 Storage**: `mc-hub-db` and `mc-hub-media` buckets, protected with `prevent_destroy`.

### What is Left Unmanaged

- **Foreign Resources**: External tunnels (`tern-local-8377`), Warp applications (`Warp Login App`), and desktop session apps (`Tern Remote`, `Messenger AI ...`) belonging to other workstations.
- **Worker Scripts and Dynamic Routes**: Worker source code and bindings for `edge-lb`, `acb-web`, and `uptimeflare` stay managed by their CI deployment scripts (`edge_lb.py`, `deploy.py`, `release-frontend.py`). `edge_lb.py` adds Worker routes dynamically only after origin health responds.
- **Cache Rulesets**: `http_request_cache_settings` phase entrypoints require `Zone -> Cache Rules -> Edit` permission which was not included in the existing local `edge-waf` token.

---

## How to Plan and Apply

### Local Development

1. Export credentials from local token files:
   ```bash
   export TF_VAR_cloudflare_api_token="$(cat ~/.config/cloudflare/mc-hub.token)"
   export TF_VAR_cloudflare_waf_api_token="$(cat ~/.config/cloudflare/edge-waf.token)"
   export TF_VAR_tofu_encryption_passphrase="$(cat ~/.config/vps-deploy/tofu-passphrase)"
   ```

2. State override:
   While R2 S3 access keys are being provisioned by the account owner, state is stored locally and encrypted outside the repo:
   ```bash
   ln -sf ~/.local/state/vps-deploy/tofu/backend_override.tf backend_override.tf
   tofu init
   ```

3. Plan and apply:
   ```bash
   tofu plan
   tofu apply
   ```

### Migrating State to Remote R2 S3 Backend

Once the account owner provisions R2 S3 credentials for bucket `vps-deploy-tofu`:

1. Remove the local backend override:
   ```bash
   rm -f backend_override.tf
   ```

2. Export S3 credentials and passphrase:
   ```bash
   export AWS_ACCESS_KEY_ID="<TOFU_STATE_ACCESS_KEY_ID>"
   export AWS_SECRET_ACCESS_KEY="<TOFU_STATE_SECRET_ACCESS_KEY>"
   export TF_VAR_tofu_encryption_passphrase="$(cat ~/.config/vps-deploy/tofu-passphrase)"
   ```

3. Migrate state:
   ```bash
   tofu init -migrate-state
   ```

---

## Required Permissions for Account Owner

### 1. Cloudflare Central API Token (`CLOUDFLARE_TOFU_TOKEN`)

Create a custom API token with the following permissions:
- **Account Permissions**:
  - `Cloudflare Tunnel`: Edit
  - `Access: Apps and Policies`: Edit
  - `Workers R2 Storage`: Edit
- **Zone Permissions** (Scoped to `thedemontuan.dev` and `tuannguyenviet.site`):
  - `DNS`: Edit
  - `Zone WAF`: Edit
  - `Zone`: Read
  - `Cache Rules`: Edit (grants management of zone cache settings entrypoints)

### 2. R2 S3 Credentials for State Backend (`vps-deploy-tofu`)

Under Cloudflare Dashboard -> **R2** -> **Manage R2 API Tokens**:
1. Create API token with `Object Read & Write` permission scoped to bucket `vps-deploy-tofu`.
2. Save credentials in repository secrets:
   - `TOFU_STATE_ACCESS_KEY_ID`
   - `TOFU_STATE_SECRET_ACCESS_KEY`
   - `TOFU_ENCRYPTION_PASSPHRASE` (32+ character passphrase)
   - `CLOUDFLARE_TOFU_TOKEN`

---

## How a New Node Gets Its Tunnel

1. Create or edit `hosts/<host>.yml` with an `edge` block, specifying node id and weight:
   ```yaml
   edge:
     id: n3
     weight: 50
   ```
   (Note: `tunnel` can be omitted initially; `lib/core.py` supports optional `edge.tunnel`).

2. Run `tofu plan` and `tofu apply`. OpenTofu will automatically:
   - Create `shared-edge-<host>` tunnel.
   - Configure balanced ingress rules for the tunnel.
   - Create the `<id>-origin.thedemontuan.dev` CNAME DNS record.
   - Output the assigned tunnel UUID in `tunnel_ids`.

3. Record the tunnel UUID in `hosts/<host>.yml`:
   ```yaml
   edge:
     id: n3
     tunnel: <tunnel-id-from-output>
     weight: 50
   ```
   Subsequent `tofu plan` runs will bind to the existing tunnel via the import block.
