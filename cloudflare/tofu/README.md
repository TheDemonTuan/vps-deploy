# Cloudflare Infrastructure as Code (OpenTofu)

This directory declares the Cloudflare infrastructure for `vps-deploy` using OpenTofu and the Cloudflare Provider v5.

## What OpenTofu Owns

- **DNS Records**: All 29 authoritative DNS records across `thedemontuan.dev` and `tuannguyenviet.site` (apex CNAMEs, per-node origin CNAMEs `<id>-origin.<zone>`, app CNAMEs, MX email routing, verification TXT, DKIM, SPF, and status AAAA).
- **Zero Trust Cloudflared Tunnels**: Tunnels (`shared-edge-vps` for n1, `shared-edge-vps-n2` for n2, and `shared-edge-<host>` for any new nodes) and their complete ingress configurations.
- **Zero Trust Access Applications**: 5 production Access applications and their attached policies:
  - `Fleet Monitor (Grafana)`
  - `Fleet Metrics Ingest`
  - `MC Hub Admin`
  - `OmniRoute Admin Dashboard`
  - `Bank Event Gateway Dashboard`
- **Zone Rulesets**:
  - `thedemontuan.dev`: Custom WAF (`Edge IP bans`, `edge-probe-paths, foreign-workers`, `mc-hub-api-host`, `mc-hub-methods`, `attack-mode` (off; platform/README "Under attack")), Rate limiting (`mc-hub-api-flood`), Managed WAF (`edge-free-managed`).
  - `tuannguyenviet.site`: Custom WAF (`omniroute_api_paths`, `Edge IP bans`, `foreign-workers`, `edge-probe-paths`, `mc-hub-api-host`), Rate limiting, Managed WAF (`OmniRoute managed WAF`).
- **R2 Storage**: `mc-hub-db` and `mc-hub-media` buckets, protected with `prevent_destroy`; a 30-day lock on `mc-hub-db/backups/` (it cannot be removed from OpenTofu: delete the rule in the dashboard first).
- **Notifications**: none. The `HTTP DDoS Attack Alert` (email) and the account's budget alert (total spend ≥ $10, email) are made in the dashboard (Notifications → Add): the OpenTofu token cannot write notification policies (403).

### What is Left Unmanaged

- **Foreign Resources**: External tunnels (`tern-local-8377`), Warp applications (`Warp Login App`), and desktop session apps (`Tern Remote`, `Messenger AI ...`) belonging to other workstations.
- **Worker Scripts and Dynamic Routes**: Worker source code and bindings for `edge-lb`, `acb-web`, and `uptimeflare` stay managed by their CI deployment scripts (`edge_lb.py`, `deploy.py`, `release-frontend.py`). `edge_lb.py` adds Worker routes dynamically only after origin health responds.
- **Cache Rulesets**: `http_request_cache_settings` phase entrypoints require `Zone -> Cache Rules -> Edit` permission which was not included in the existing local `edge-waf` token.

---

## How to Plan and Apply

### Local Development

1. Export credentials from local files (account tokens `vps-deploy-tofu-ci` and
   `vps-deploy-tofu-state`; the S3 key is the state token's ID, the secret its SHA-256):
   ```bash
   export TF_VAR_cloudflare_api_token="$(cat ~/.config/vps-deploy/vps-deploy-tofu-ci.token)"
   export TF_VAR_tofu_encryption_passphrase="$(cat ~/.config/vps-deploy/tofu-passphrase)"
   export AWS_ACCESS_KEY_ID="$(cat ~/.config/vps-deploy/vps-deploy-tofu-state.id)"
   export AWS_SECRET_ACCESS_KEY="$(cat ~/.config/vps-deploy/vps-deploy-tofu-state.s3-secret)"
   ```

2. Plan and apply (state: R2 bucket `vps-deploy-tofu`, encrypted with the passphrase, locked by
   a lock file there while a run holds it):
   ```bash
   tofu init
   tofu plan
   tofu apply
   ```

CI (`.github/workflows/cloudflare-infra.yml`) plans on pull requests and applies on `main` with
the same credentials, as repository secrets `CLOUDFLARE_TOFU_TOKEN`, `TOFU_STATE_ACCESS_KEY_ID`,
`TOFU_STATE_SECRET_ACCESS_KEY` and `TOFU_ENCRYPTION_PASSPHRASE`.

---

## Tokens

- `vps-deploy-tofu-ci` (account token): DNS Write, Zone WAF Write, Zone Read on the two zones;
  Cloudflare Tunnel Write, Access: Apps and Policies Write, Workers R2 Storage Write, Account
  Settings Read on the account. Not IP-filtered: GitHub's runners have no fixed addresses.
- `vps-deploy-tofu-state` (account token): Workers R2 Storage Bucket Item Write on
  `vps-deploy-tofu` only.

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
