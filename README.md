# Shared VPS Deployment Platform (`vps-deploy`)

Hệ thống CI/CD và deployment engine dùng chung trên VPS cho các dịch vụ local/hardened của `TheDemonTuan`. Kiến trúc tách biệt hoàn toàn giữa CI (chỉ có quyền gửi request triển khai bất biến) và Host Engine (thực thi kiểm tra, Blue/Green cutover nguyên tử, xác thực Traefik route và drain zero-downtime).

---

## 1. Luồng hoạt động khi commit code (Deployment Flow)

Khi developer commit và push code lên nhánh mặc định (`master`) của repository ứng dụng (ví dụ `9router`):

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer
    participant GH as GitHub Actions (App Repo)
    participant GHCR as GitHub Container Registry
    participant SSH as SSH Gateway (VPS)
    participant Engine as deployctl / systemd (VPS)
    participant Docker as Docker Daemon
    participant Traefik as Traefik Dynamic Edge

    Dev->>GH: git push origin master
    activate GH
    Note over GH: Job 1: Verify (bun test, smoke offline)
    Note over GH: Job 2: Build & Push (reusable workflow)
    GH->>GHCR: Buildx native image & push immutable digest
    GH->>GH: Run .deploy/smoke-image.sh on published digest
    Note over GH: Job 3: Deploy (environment: production)
    GH->>SSH: Connect as deploy-<app> with ED25519 key & forced command
    GH->>SSH: Pipe request JSON via stdin (op=deploy, image=<digest>, manifest_sha=...)
    deactivate GH

    activate SSH
    SSH->>Engine: systemd-run detached service (vps-deploy-<app>-<req_id>)
    Engine-->>GH: Receipt {"status": "running", "phase": "dispatched"}
    deactivate SSH

    activate Engine
    Note over Engine: Acquire flock(/run/lock/vps-deploy/<app>.lock)
    Note over Engine: Verify manifest SHA, image prefix & select idle slot
    Engine->>Docker: Pull image directly by sha256 digest
    Engine->>Docker: compose up -d (start candidate container)
    Note over Engine: Direct health check: wget /api/health on container port

    Note over Engine: Acquire Traefik route lock
    Engine->>Traefik: Render dynamic config with new UUID generation
    Engine->>Traefik: Atomic fsync + rename to <app>.yml
    Note over Engine: Public HTTPS probe: verify 2 consecutive ACKs matching generation

    Note over Engine: Atomic commit state.json (active=candidate, draining=old)
    Engine-->>GH: Status {"status": "complete", "healthy": true}
    deactivate Engine

    Note over Docker,Engine: vps-deploy-<app>-drain.timer runs every 60s
    Note over Docker,Engine: Stop old container ONLY when active_requests == 0
```

### Chi tiết các bước thực thi:

1. **Gate 1 - Regression Verification (`verify`)**:
   - Chạy trên runner GitHub.
   - Cài đặt runtime dependencies và chạy `.deploy/verify.sh` (toàn bộ suite offline, syntax, router, persistence, quota/bypass logic).
2. **Gate 2 - Immutable Build & Smoke (`build`)**:
   - Gọi reusable workflow `TheDemonTuan/vps-deploy/.github/workflows/build-docker.yml@<PINNED_SHA>`.
   - Buildx biên dịch native image trên runner ARM64 (`ubuntu-24.04-arm`).
   - Kiểm tra hợp lệ manifest `.deploy/app.yml` trước khi push.
   - Đẩy image lên GHCR với digest cố định: `ghcr.io/<owner>/<app>@sha256:<64hex>`.
   - Chạy `.deploy/smoke-image.sh` kiểm tra container độc lập: endpoint health, header `no-store`, HTTP/2 h2c, background refresh.
3. **Gate 3 - Restricted Transport Cutover (`deploy`)**:
   - Gắn với GitHub Environment `production` (chỉ nhánh `master` mới được cấp secret).
   - Gọi composite action `TheDemonTuan/vps-deploy/.github/actions/deploy@<PINNED_SHA>`.
   - Kết nối SSH tới VPS user riêng `deploy-<app>` với host key ED25519 được pin cứng.
   - User SSH bị giới hạn bằng `forced command`: chỉ có thể đẩy duy nhất payload JSON vào stdin của wrapper, không có quyền mở interactive shell hay chạy bất kỳ lệnh bash nào khác.
4. **Gate 4 - Host Blue/Green Cutover Engine (`deployctl`)**:
   - Tách thành transient unit systemd (`vps-deploy-<app>-<request_id>.service`) giúp tiến trình deploy hoàn toàn độc lập với phiên SSH; mạng chập chờn hay mất kết nối giữa chừng không làm gãy quá trình cutover.
   - Nhận diện slot nhàn rỗi (ví dụ: `blue` đang chạy thì chọn `green` làm candidate).
   - Kéo image trực tiếp bằng immutable digest (`docker compose pull`).
   - Khởi động candidate (`docker compose up -d --no-deps --pull never <app>-<slot>`).
   - Kiểm tra sức khoẻ trực tiếp (`direct_slot_healthy` qua `/api/health`).
   - Giữ khoá an toàn Traefik (`traefik.lock`), sinh mã UUID generation mới cho route.
   - Ghi cấu hình Traefik candidate ra file tạm `.tmp`, `fsync` đĩa rồi `rename` nguyên tử đè lên dynamic route (`/opt/platform/edge/dynamic/<app>.yml`).
   - Probe HTTPS công khai qua Traefik tới khi nhận đủ **2 lần liên tiếp** HTTP 200 khớp generation header và slot candidate.
   - Ghi nhận trạng thái mới vào `/var/lib/vps-deploy/apps/<app>/state.json`. Slot cũ được đánh dấu `draining`.
5. **Gate 5 - Zero-Downtime Drain & Cleanup**:
   - Slot cũ không bị tắt ép buộc để bảo toàn các kết nối dài (như AI streaming SSE).
   - Systemd timer `vps-deploy-<app>-drain.timer` chạy định kỳ mỗi 60 giây, gọi `deployctl cleanup-drains --app <app>`.
   - Chỉ khi nào slot cũ báo `active_requests == 0` thì container mới được `docker stop`. Container dừng này vẫn được giữ lại làm điểm tựa rollback tức thì (instant rollback mà không cần pull hay build lại).

---

## 2. Hướng dẫn đồng bộ thêm một ứng dụng mới (App Onboarding Guide)

Để đưa một ứng dụng mới (ví dụ `my-service`) vào hệ thống triển khai Blue/Green đồng bộ với quy chuẩn của `9router`, thực hiện theo 3 giai đoạn:

```
[Giai đoạn 1: App Repo]      [Giai đoạn 2: Platform Repo]      [Giai đoạn 3: VPS Host]
.deploy/app.yml               apps/<app>/docker-compose...     User deploy-<app> (restricted)
.deploy/verify.sh             apps/<app>/adapter.sh            /etc/vps-deploy/apps/<app>/
.deploy/smoke-image.sh        Core allowlist update            Drain systemd timer
.github/workflows/deploy.yml
```

### Giai đoạn 1: Chuẩn bị tại Repository ứng dụng mới

1. **Tạo manifest `.deploy/app.yml`**:
   Manifest khai báo các thông số cơ bản, tuyệt đối không chứa secret hay đường dẫn máy chủ:
   ```yaml
   version: 1
   app: my-service
   strategy: blue-green
   image: ghcr.io/thedemontuan/my-service
   platform: linux/arm64
   runtime:
     port: 8080
   health:
     path: /api/health
     timeout_seconds: 60
   route:
     timeout_seconds: 30
   ```

2. **Tạo script kiểm tra cổng chất lượng**:
   - `.deploy/verify.sh`: Chạy test suite nội bộ, linter. Kết thúc exit code 0 nếu đạt.
   - `.deploy/smoke-image.sh`: Nhận `$1` là `$IMAGE_REF`, chạy docker run tạm thời trên runner, kiểm tra curl `/api/health` trả HTTP 200, sau đó dọn dẹp container.

3. **Tạo GitHub Workflow `.github/workflows/deploy.yml`**:
   ```yaml
   name: Build and Deploy

   on:
     push:
       branches: [master, main]
     workflow_dispatch:
       inputs:
         skip_deploy:
           description: "Build image only without deploying to VPS"
           type: boolean
           default: false

   concurrency:
     group: my-service-deploy
     cancel-in-progress: false

   permissions:
     contents: read

   jobs:
     verify:
       name: Regression gates
       runs-on: ubuntu-latest
       timeout-minutes: 10
       steps:
        - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
           with:
             persist-credentials: false
         - name: Run verification script
           run: bash .deploy/verify.sh

     build:
       name: Build and smoke immutable image
       needs: verify
       permissions:
         contents: read
         packages: write
       uses: TheDemonTuan/vps-deploy/.github/workflows/build-docker.yml@<PINNED_PLATFORM_SHA>
       with:
         source-sha: ${{ github.sha }}
         platform-ref: <PINNED_PLATFORM_SHA>
         config: .deploy/app.yml

     deploy:
       name: Deploy immutable digest
       needs: build
       if: github.event_name == 'push' || !inputs.skip_deploy
       runs-on: ubuntu-24.04
       environment: production
       timeout-minutes: 17
       steps:
         - uses: TheDemonTuan/vps-deploy/.github/actions/deploy@<PINNED_PLATFORM_SHA>
           with:
             operation: deploy
             component: app
             source-sha: ${{ github.sha }}
             platform-ref: <PINNED_PLATFORM_SHA>
             config: .deploy/app.yml
             image-ref: ${{ needs.build.outputs.image-ref }}
           env:
             DEPLOY_SSH_KEY: ${{ secrets.DEPLOY_SSH_KEY }}
             DEPLOY_HOST: ${{ vars.DEPLOY_HOST }}
             DEPLOY_PORT: ${{ vars.DEPLOY_PORT }}
             DEPLOY_USER: ${{ vars.DEPLOY_USER }}
   ```

4. **Cấu hình GitHub Environment `production` trên App Repo**:
   - Vào **Settings** -> **Environments** -> **New environment**: đặt tên `production`.
   - **Deployment branches**: Chọn *Selected branches* -> thêm nhánh mặc định (`master` hoặc `main`).
   - **Environment secrets**: Thêm `DEPLOY_SSH_KEY` (khóa private OpenSSH ED25519 cho ứng dụng này).
   - **Environment variables**:
     - `DEPLOY_HOST`: Địa chỉ IP hoặc hostname VPS (lưu trong Environment secret/var, không commit public).
     - `DEPLOY_PORT`: Cổng SSH (ví dụ `22`).
     - `DEPLOY_USER`: Tên user riêng của app (`deploy-<app>`).
---

### Giai đoạn 2: Cấu hình trên Platform Repository (`vps-deploy`)

1. **Tạo hồ sơ Compose tại `apps/<app>/docker-compose.prod.yml`**:
   Định nghĩa 2 service `my-service-blue` và `my-service-green`:
   ```yaml
   services:
     my-service-blue:
       image: ${IMAGE_REF}
       container_name: my-service-blue
       restart: unless-stopped
       expose:
         - "8080"
       environment:
         - DEPLOY_SLOT=blue
         - PORT=8080
       networks:
         - edge-my-service
       volumes:
         - my-service-data:/app/data

     my-service-green:
       image: ${IMAGE_REF}
       container_name: my-service-green
       restart: unless-stopped
       expose:
         - "8080"
       environment:
         - DEPLOY_SLOT=green
         - PORT=8080
       networks:
         - edge-my-service
       volumes:
         - my-service-data:/app/data

   networks:
     edge-my-service:
       external: true

   volumes:
     my-service-data:
       name: my-service-data
   ```

2. **Đăng ký ứng dụng trong `registry/<app>.yml`**:
   Tạo file registry định nghĩa caller repo, nhánh cho phép, manifest policy, runtime env và route:
   ```yaml
   version: 1
   app: my-service
   host: oracle-main
   caller:
     repository: TheDemonTuan/my-service
     ref: refs/heads/master
     refs: [refs/heads/master, refs/heads/main]
     config: .deploy/app.yml
     build_workflows: [deploy.yml]
     deploy_workflows: [deploy.yml]
   manifest:
     version: 1
     app: my-service
     strategy: blue-green
     image: ghcr.io/thedemontuan/my-service
     platform: linux/arm64
     runtime: {port: 8080}
     health: {path: /api/health, timeout_seconds: 60}
     route: {timeout_seconds: 30}
   runtime:
     allowed_env: [PORT, DEPLOY_SLOT]
     required_env: []
   route:
     generation_header: X-My-Service-Route-Generation
     required_middlewares: [deny-internal, security-headers]
   ```

3. **Tạo Traefik adapter tại `apps/<app>/adapter.sh`**:
   Script nhận 5 tham số (`slot`, `generation`, `dashboard_host`, `dashboard_alias_host`, `api_host`) và xuất cấu hình YAML hợp lệ ra stdout.

4. **Cập nhật ánh xạ host tại `hosts/<host>.yml`**:
   Thêm `<app>` vào mục `apps:` của host tương ứng (`route_name`, `api_host`, `work_dir`, `edge_network`...).

### Giai đoạn 3: Thiết lập trên máy chủ VPS (Root Operator)

Thực hiện một lần bởi Quản trị viên (Operator) có quyền root:

1. **Tạo cặp khóa SSH và Linux user giới hạn**:
   ```bash
   # Tạo user hệ thống không có mật khẩu, không thuộc nhóm docker
   useradd -r -s /bin/sh -d /var/lib/vps-deploy/home/deploy-my-service -m deploy-my-service
   
   # Sinh khóa ED25519 cho CI (lưu private key để đưa vào GitHub Environment secret)
   ssh-keygen -t ed25519 -N "" -C "deploy-my-service@vps-deploy" -f /root/vps-deploy-my-service
   
   # Cài đặt public key với restriction và forced command
   mkdir -p /var/lib/vps-deploy/home/deploy-my-service/.ssh
   printf 'restrict,command="sudo -n /usr/local/libexec/vps-deploy-my-service" %s\n' \
     "$(cat /root/vps-deploy-my-service.pub)" > /var/lib/vps-deploy/home/deploy-my-service/.ssh/authorized_keys
   chown -R root:root /var/lib/vps-deploy/home/deploy-my-service
   chmod 755 /var/lib/vps-deploy/home/deploy-my-service
   chmod 700 /var/lib/vps-deploy/home/deploy-my-service/.ssh
   chmod 600 /var/lib/vps-deploy/home/deploy-my-service/.ssh/authorized_keys
   ```

2. **Cấu hình sudoers chỉ định đích danh lệnh wrapper**:
   ```bash
   cat <<'EOF' > /etc/sudoers.d/vps-deploy-my-service
   deploy-my-service ALL=(root) NOPASSWD: /usr/local/libexec/vps-deploy-my-service ""
   EOF
   chmod 440 /etc/sudoers.d/vps-deploy-my-service
   visudo -cf /etc/sudoers.d/vps-deploy-my-service
   ```

3. **Cài đặt wrapper thực thi và khởi tạo thư mục state**:
   ```bash
   install -d -m 0755 /usr/local/libexec
   install -m 0755 /opt/vps-deploy/current/install/vps-deploy-my-service /usr/local/libexec/vps-deploy-my-service
   
   install -d -m 0700 /etc/vps-deploy/apps/my-service \
                      /var/lib/vps-deploy/apps/my-service \
                      /var/lib/vps-deploy/apps/my-service/requests
   ```

4. **Tạo runtime env và host configuration**:
   - Tạo `/etc/vps-deploy/apps/my-service/runtime.env` (chứa biến môi trường private, quyền `0600` root:root).
   - Tạo `/etc/vps-deploy/apps/my-service/host.json`:
     ```json
     {
       "platform_ref": "<PINNED_PLATFORM_SHA>",
       "dynamic_dir": "/opt/platform/edge/dynamic",
       "api_host": "my-service.tuannguyenviet.site",
       "compose_project": "my-service",
       "edge_network": "edge-my-service",
       "route_name": "my-service.yml"
     }
     ```

5. **Đăng ký manifest ban đầu & kích hoạt drain timer**:
   ```bash
   # Sao chép manifest từ app commit đã duyệt
   git -C /root/my-service-review show <APP_COMMIT>:.deploy/app.yml > /etc/vps-deploy/apps/my-service/app.yml
   chmod 600 /etc/vps-deploy/apps/my-service/app.yml
   
   # Kích hoạt timer drain tự động
   systemctl enable --now vps-deploy-my-service-drain.timer
   ```

6. **Kiểm tra trạng thái từ xa qua key hạn chế**:
   ```bash
   ssh -i /root/vps-deploy-my-service -o BatchMode=yes -o StrictHostKeyChecking=yes deploy-my-service@127.0.0.1 deployctl
   ```
   Sau khi key hoạt động, đưa private key vào GitHub Environment `production` trên App repo để pipeline tự động triển khai.



### Portfolio (retired)

The portfolio is no longer routed. The apex serves mc-hub; the portfolio source remains in its own repository.

### mc-hub + mc-hub-api: Astro frontend and Go API, separate blue-green apps

`mc-hub` registers `TheDemonTuan/mc-hub` on `main`, image `ghcr.io/thedemontuan/mc-hub`
(Astro SSR on Bun), public host `thedemontuan.dev`. `mc-hub-api` registers
`TheDemonTuan/mc-hub-api`, image `ghcr.io/thedemontuan/mc-hub-api` (Go, SQLite WAL), public
host `api.thedemontuan.dev`. Both expose JSON `/healthz` on port `8080`, run
UID 1000 with a read-only root, and deploy independently.

- Both register `image_access: private`: their repositories and GHCR images are private, so
  the engine skips the anonymous-manifest gate for the app image and `docker compose pull`
  uses root's `docker login ghcr.io` (a classic token with only `read:packages`, stored in
  `/root/.docker/config.json`). An expired token surfaces as `IMAGE_PULL_FAILED`; renew it with
  `sudo docker login ghcr.io -u TheDemonTuan --password-stdin`. Other apps keep the anonymous gate.
- `mc-hub-api` also owns `/api/` and `/media/` on the site host (`mc-hub-api-site-router`,
  priority 200 over the frontend's 100), so admin and uploads stay same-origin.
- `mc-hub-api` blue and green share the named volume `mc-hub-api-data` (SQLite + media +
  backups under `/data/backups`: one per import and a daily `daily-<date>.db` written by
  `platform/peer` on the writer, 14 kept there, all of them in R2); its migrations must stay additive.
  `edge-mc-hub-api` is internal (inbound from Traefik only); outbound goes through
  `mc-hub-api-egress`, used for Cloudflare Turnstile siteverify and the R2 media bucket.
- Both run on every host in `replica_hosts` too, behind the `edge-lb` Worker; the registry
  `host` keeps the SQLite writer. See [platform/README.md](platform/README.md) (routing,
  Litestream, node bootstrap, promotion).
- Frontend SSR reads published content from the same node's mc-hub-api at
  `http://edge-traefik:8082` (`API_URL`, entrypoint `internal`, router `mc-hub-api-internal`).
- Domains live in `hosts/oracle-main.yml`: each app's `api_host` is its domain and
  `dashboard_alias_host` the previous one, kept routed by Traefik as a **fallback**
  (`tuannguyenviet.site`, `minecraft-api.tuannguyenviet.site`). The adapters, the deploy probe
  (`api_host`) and the Cloudflare scripts (`cloudflare/mc_hub_hosts.py`) read them from there;
  `tests/test_mc_hub_api.py` fails until the few literal copies agree (mc-hub-api's site hosts,
  `SITE_URL`, the CrowdSec scope). Cloudflare Single Redirects (dashboard, zone
  `tuannguyenviet.site`) send `tuannguyenviet.site` and `minecraft.tuannguyenviet.site` to
  `https://thedemontuan.dev` with HTTP 301, preserving path and query; keep those hostnames
  proxied in DNS. **Fallback**: disable the apex redirect rule and the old domain serves the
  site again from the same origin (canonical URLs keep naming the new one).
  The Turnstile widget must allow every site domain for login, comments and download unlocks;
  the API checks each token against the host the request was sent to.
- Each zone carries SSL Full (strict), Always HTTPS, TLS ≥ 1.2, Tiered Cache (smart topology),
  the `Edge IP bans` rule (zone listed in the CrowdSec Telegram controller's
  `cloudflare.zone_ids`), Web Analytics and email routing. `thedemontuan.dev` also has Image
  Transformations on (the site serves covers through `/cdn-cgi/image/`) and, for page speed,
  Bot Fight Mode, JS detections, AI Labyrinth and Cloudflare's managed robots.txt / Bot Preference
  Sync off. AI Crawl Control allows Search, Training and Agents and the site's `/robots.txt` blocks
  only `/admin` and `/api/`, so search and AI crawlers read the site freely. Crawler Hints is on: on a
  cache miss Cloudflare sends an IndexNow ping (Bing, Yandex, Seznam, Naver), so new and edited posts
  reach those engines without a sitemap resubmit. CrowdSec, the IP-ban rule and Turnstile remain the
  abuse defences. Traefik serves one Origin CA certificate per zone
  (`/opt/platform/edge/certs/cf-origin-*`, listed in `dynamic/00-tls-origin.yml`).
- `mc-hub-api` requires `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET` in
  `/etc/vps-deploy/apps/mc-hub-api/runtime.env` (root, 0600; widget for the site host).
  Adding a network or env changes Compose parity: recreate the running slot from the new
  release's Compose profile before installing that release (same `docker compose` arguments
  and environment as `install/preflight.py`, `up -d --no-deps --pull never <app>-<slot>`).
  The frontend needs no env.
- Admin auth (argon2id password + TOTP + Turnstile) lives in the API;
  enrollment links come from `docker exec mc-hub-api-<slot> /app/mc-hub-api admin invite --username <u>`.
- Admin is two layers: `mc-hub-access.yml` (survey, then apply) creates the Cloudflare Access
  app "MC Hub Admin" over `/admin`, `/api/admin` and `/api/auth` on every site domain, with its own
  allow policy "MC Hub admins" (exact emails; first copied from the OmniRoute admin app, then
  edited only in the dashboard). The API host routes only SSR reads
  (`/api/posts*`, `/api/pages/*`, `/api/settings`, `/api/stats`, `/api/auth/me`, `/healthz`); everything else
  there hits `deny-internal`.
- Edge cache: `mc-hub-cache.yml` (survey, then apply) keeps one rule
  (`mc-hub-public-edge-cache`) on the cache-settings entrypoint of the site domain's zone.
  It covers the site host except `/api/`, `/admin` and requests with `__Host-mch_session`;
  edge TTL follows origin and bypasses when absent, so only pages the frontend marks
  (`Cloudflare-CDN-Cache-Control`) and the immutable `/media` and `/_astro` files are cached.
- Changing `apps/mc-hub-api/adapter.sh` means the live route no longer matches the next
  release: before installing it, re-render the route with that release's adapter at the
  current slot and generation (`deployctl status`) and replace the route file atomically.
- Routes use app-owned security headers instead of shared `security-headers`: the shared
  CSP blocks AdSense and YouTube embeds. `tunnel-only` and `deny-internal` stay.
- Per-visitor limits key on `CF-Connecting-IP` (safe only because `tunnel-only` admits just
  cloudflared): pages 20 req/s burst 60 and 16 in flight; `/api/` + `/media/` on the site host
  10 req/s burst 30 and 8 in flight; public `POST /api/*` (router `mc-hub-api-site-write`,
  `/api/admin/` excluded) 30/min burst 10 with a 64 KiB body. The API host has none: all of it
  is SSR traffic from the VPS. Both adapters changed, so re-render both live routes first.
- Bot challenge (CrowdSec AppSec, global `crowdsec-ip` bouncer): **off since 2026-11-19** at the
  owner's request; the collection `crowdsecurity/appsec-bot-challenge` (balanced) stays installed,
  and `appsec.yaml.pre-disable-bot-challenge-*` next to `/etc/crowdsec/acquis.d/appsec.yaml` on n1
  holds the config that loaded it. Re-enabling means listing the collection's configs plus
  `security/crowdsec/mc-hub-bot-scope.yaml` (as `local/mc-hub-bot-scope`) in `appsec.yaml` on
  every node and `systemctl reload crowdsec`. Its scoring config challenges every non-exempt
  request on every host, so the scope file must be loaded with it: it exempts every host but the
  two site domains and, there, non-GET, `/api/`, `/media/`, `/_astro/`, `/admin`, `/healthz` and
  crawler files. Googlebot, Bingbot, AdSense, social and monitoring bots pass when UA and
  forward-confirmed rDNS/IP agree (`cscli bot match --ip … --user-agent …`); a spoofed UA is
  challenged. Challenge pages are `no-store` (Cloudflare BYPASS). It only ever sees edge cache misses.
- CRS scope `platform/crowdsec/local-mc-hub-crs-scope.yaml`: rule 930120 (OS file names) is off
  for out-of-band scoring on the site's `/api/`, where it matched readers' Turnstile tokens.
- Enrollment follows the portfolio procedure per app: create `edge-<app>` and attach
  Traefik (live `docker network connect` plus the edge Compose file, no restart), stage
  `<app>-blue` from this release's Compose profile, publish the adapter-rendered route,
  run `mc-hub-ingress.yml` survey then apply (manages both hostnames), installer
  `--check`/apply, `restorecon`, then `deployctl adopt --app <app>`.

#### Moving mc-hub to another domain

The old domain stays a working fallback; nothing is deleted. Change one app's binding per
platform release: the installer refuses a release whose registry differs from another app's
installed binding, so the API side goes first.

1. **New zone** (dashboard): the settings above, apex and `api.` CNAMEs to the tunnel, an Origin
   CA certificate for `<new>` + `*.<new>` from a CSR made on the VPS (`certs/`, `00-tls-origin.yml`),
   the zone id in the CrowdSec Telegram controller, the Turnstile widget domain, a copy of the
   `Edge IP bans` rule, Search Console (DNS TXT) and AdSense site.
2. **Release A, API side**: `mc-hub-api` gets `api_host: api.<new>` and
   `dashboard_alias_host: <its current api_host>`; add `<new>` to mc-hub-api's `site_hosts`
   and the CrowdSec scope; `SITE_URL` names the new site host. After merge, on the VPS:
   publish the mc-hub-api route re-rendered with the new binding at its current slot and
   generation (`lib/route.py publish`), run `mc-hub-ingress.yml` apply, recreate the running
   mc-hub-api slot (Compose parity, see above), installer `--check` then apply, `restorecon -R`
   the release, bump the API repository's pin.
3. **Release B, site side**: `mc-hub` gets `api_host: <new>` and `dashboard_alias_host: <old>`.
   Same VPS steps for mc-hub, reinstall mc-hub-api at B, also run `cloudflare/edge_lb.py` apply,
   then `mc-hub-access.yml` and `mc-hub-cache.yml` apply. In the website set `SITE` in
   `astro.config.mjs` (canonical, sitemap, hreflang, RSS, JSON-LD) and bump its pin.
4. **Cut over**: Single Redirects in the old zone (apex and older hostnames) to `https://<new>`,
   301, path and query kept; purge the new zone's cache; Search Console Change of Address;
   GA4 stream URL; editorial `site_api`; links on YouTube, TikTok, Modrinth, CurseForge, PMC.
   A previous fallback domain only needs its redirect target updated.

### 4. Thành phần Stateful ChatGPT Web Runtime (`cgw`)

**Production 9router đang tạm ngừng CGW (2026-10-16).** Registration không enroll `cgw`, host binding không có `cgw_network`, và caller runtime không còn trong build/security/deploy allowlists. Web app không cần Chrome/runtime để build, healthy hoặc deploy. Source/runtime implementation và account/browser volumes được giữ lại; không tự enroll hay khởi chạy lại.

Khi nâng từ registration có CGW, installer chỉ cho phép so sánh gateway đang chạy với overlay cũ sau khi đã xác minh registration/host cũ. Nó vẫn kiểm tra chính xác network, secret mounts và Compose parity, nhưng không yêu cầu runtime CGW khỏe để bỏ enrollment. Cài platform bằng `install/install.sh --check` rồi cùng lệnh không có `--check`; lần app deploy kế tiếp dùng Compose không CGW. Giữ nguyên `/etc/vps-deploy/apps/9router` secrets và hai volume `9router-cgw-data`, `9router-cgw-browser` để phục hồi có chủ đích; runtime đã dừng phải giữ restart policy `no`.

Đối với các ứng dụng có thành phần runtime trình duyệt hoặc stateful harness (như `9router`):
- Runtime được quản lý dưới Compose project riêng biệt `9router-cgw`, container `9router-cgw-runtime`, volume account `9router-cgw-data` và cache trình duyệt `9router-cgw-browser` riêng biệt.
- Runtime chạy non-root (`10001:10001`), `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges: true`, shm 1GB, giới hạn 1 CPU / 2GB RAM và seccomp profile tương thích user-namespace của Chromium. VNC chỉ bind `127.0.0.1:17842`.
- Giao tiếp giữa gateway và runtime đi qua mạng nội bộ cô lập `9router-cgw` (`internal: true`). Runtime sở hữu mạng egress riêng biệt `9router-cgw-egress` để kết nối ra ngoài, không đi qua Traefik edge.
- Triển khai runtime sử dụng transaction riêng biệt với durable fence, kiểm tra `physicalIdle: true`, tạo private SQLite snapshot, và resume an toàn sau khi commit. Gateway blue/green không can thiệp vòng đời runtime.
- Khi enroll lại CGW có chủ đích, registration phải bổ sung image và caller `chatgpt-web-runtime.yml` trong build/security/deploy allowlists; giữ source gate của `rtk-sidecar.yml`. Caller manifest, mọi `uses` và `platform-ref` phải cutover cùng immutable platform SHA.
- Reusable `build-docker.yml` nhận `component` tùy chọn (`app` mặc định, hoặc `cgw`). `app` giữ Dockerfile, tag/cache và root image smoke hiện tại. `cgw` chỉ dùng `services/chatgpt-web-runtime/Dockerfile`, app-root context, `APP_REVISION=source-sha`, native ARM64 và tag `sha-<source-sha>`; không có input arbitrary Dockerfile/image/component.
- CGW public image không chứa browser. `docker compose up` tự chạy `browser-init` bằng cùng image, non-root, root read-only, 0.5 CPU / 1GB RAM; tải Chrome for Testing `154.0.8037.92` trực tiếp từ Google và xác minh SHA256/provenance trong Docker cache. Không cài Chrome/Python browser installer trên host, không compile/browser builder hoặc COPY payload vào image. Cache mount tại `/opt/cgw-browser`: init RW, runtime RO; executable versioned do từng image sở hữu, giữ các version cũ để rollback. Managed deploy chuẩn bị cache **trước** drain rồi dùng runtime `up --no-deps`; transaction profile/data vẫn giữ nguyên. Build chạy verifier thật trong image sandboxed và COPY duy nhất generated compatibility JSON vào `/opt/cgw/compatibility.json`. Exact published digest phải qua native image/browser smoke và image Trivy gate. `scripts/scan-browser.py` dùng SPDX đọc qua Docker, Grype `0.120.0` theo CPE `google:chrome`, không ignore HIGH/CRITICAL; mỗi lần scan phải chứng minh phát hiện Chrome cũ có lỗ hổng, scanner/database lỗi hoặc thiếu CPE coverage đều fail closed. CI dọn cache/container của chính job, không upload browser/account/runtime state. Offline build evidence không chứng minh account login hay Full readiness. Runbook: [`install/README.md`](install/README.md#first-cgw-enrollment-and-build-proof).
- Gateway CGW env chỉ cho phép URL nội bộ và ba file selectors `CHATGPT_WEB_RUNTIME_TOKEN_FILE`, `CHATGPT_WEB_RUNTIME_ADMIN_TOKEN_FILE`, `CHATGPT_WEB_CLIENT_KEYS_FILE`; không dùng socket env cũ hoặc secrets trực tiếp. `INITIAL_PASSWORD` vẫn bắt buộc; CGW secret-file/native-policy checks chỉ áp dụng khi manifest enroll CGW.


### Lưu ý an toàn cơ sở dữ liệu Blue/Green

Hai slot blue/green dùng chung volume dữ liệu (như SQLite hoặc DB container). Deployment engine hỗ trợ rollback route và container ngay lập tức, nhưng **không rollback dữ liệu đã thay đổi**.

Quy tắc bắt buộc khi có migration DB:
- Mọi thay đổi schema phải backward-compatible (mô hình Expand -> Migrate -> Contract).
- Code phiên bản mới phải chạy được trên schema cũ, hoặc schema mới phải tương thích hoàn toàn với slot phiên bản cũ khi rollback.
- Không chạy migration phá vỡ cấu trúc cũ (destructive migration) trong cùng release chuyển giao.
---

## 3. Các thao tác vận hành khẩn cấp (Operator Runbook)

Khi cần kiểm tra hoặc xử lý trực tiếp trên VPS với quyền root:

- **Kiểm tra trạng thái triển khai**:
  ```bash
  /opt/vps-deploy/current/bin/deployctl status --app 9router --strict
  ```
- **Xử lý sự cố / khôi phục route sau gián đoạn (`reconcile`)**:
  Nếu deploy bị ngắt giữa chừng và báo `recovery_required`, tuyệt đối không khởi động lại script cũ:
  ```bash
  python3 -c '
  import json, subprocess
  payload = dict(version=1, op="reconcile", app="9router", component="app",
                 request_id="manual-reconcile", platform_ref="<PLATFORM_SHA>",
                 manifest_sha256="<MANIFEST_SHA>", source_sha="<SOURCE_SHA>")
  print(subprocess.run(["/opt/vps-deploy/current/bin/deployctl", "submit"], input=json.dumps(payload), text=True, capture_output=True).stdout)
  '
  ```
- **Chủ động dọn dẹp các slot đang drain**:
  ```bash
  /opt/vps-deploy/current/bin/deployctl cleanup-drains --app 9router
  ```

## Cloudflare releases: ACB and uptimeflare

`.github/workflows/cloudflare-deploy.yml` owns Cloudflare deployment. Registered source repositories build and verify immutable artifacts without Cloudflare credentials; this repository verifies successful whole-workflow CI, branch/head eligibility, GitHub ZIP digest, exhaustive SHA256SUMS and manifest identity before executing only platform-owned adapters. No source npm scripts, OpenNext config, Terraform or uploaded deploy scripts run with the token.

Controller verification installs pinned `PyYAML==6.0.3` before its Python suites; the workflow policy checks parse YAML on a clean runner.

- Registry: `cloudflare/registry/{acb,uptimeflare}.json`. Adding an app requires a reviewed registration and trusted adapter, not copying keys into its source repository.
- Central secrets: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`. Existing uptimeflare values were moved as GitHub sealed-box ciphertext; plaintext was not downloaded. `UPTIMEFLARE_D1_ID` is a central variable fixed to `431a0d2e-6413-4e80-9d27-1ee933f14f05`.
- Runtime rotation envelopes are stored centrally as `UPTIMEFLARE_CF_ACCESS_CLIENT_ID`, `UPTIMEFLARE_CF_ACCESS_CLIENT_SECRET`, `UPTIMEFLARE_BESZEL_ACCESS_CLIENT_ID`, `UPTIMEFLARE_BESZEL_ACCESS_CLIENT_SECRET`, `UPTIMEFLARE_TELEGRAM_BOT_TOKEN`, `UPTIMEFLARE_TELEGRAM_CHAT_ID`. Ordinary releases preserve existing Worker secrets without reading or rewriting these GitHub values.
- Token permissions: account Workers Scripts edit, D1 read and Durable Objects read for uptimeflare. ACB additionally requires zone read and Workers Routes access for `tuannguyenviet.site`; a token that previously deployed uptimeflare is not evidence of these zone permissions.
- Jobs use environment `production`, per-app non-cancelling concurrency and full trusted-controller CI. The five-minute schedule selects successful `push`/`main` artifacts; GitHub schedules can be delayed. Repeated current-SHA publication verifies HTTP and does not upload or switch versions.
- Public source artifact access is proven with the central built-in `GITHUB_TOKEN`. Private source onboarding needs a separately scoped artifact-read credential; no per-app Cloudflare token is required.
- ACB automatic publication remains disabled until owner-browser acceptance and its approved VPS/static-hosting cutover. `bootstrap` creates only unexposed static assets: no routes, public preview or backend/VPS state changes.
- ACB `cutover` first bootstraps the exact verified artifact with no routes, then switches and verifies viewer before bank. Any host/publication failure restores this run's owned route snapshots in reverse order; drift is recorded, never overwritten. An already-exposed Worker cannot be re-bootstrapped by cutover. A successful runner receipt is `pending_owner_acceptance`, not permission to migrate VPS metadata or remove frontend containers. The controller never generates owner-browser proof.
- Workers Routes API confirmation is not HTTP edge readiness. Cutover requires three consecutive exact SHA/plain-text/no-store viewer release responses within a bounded readiness window before the full artifact verifier; HTML/challenge, stale SHA and cacheable identities reset convergence and never pass. `readiness.json` retains only status/MIME/body classifications, not response bodies. The full checksum/security/asset checks still run once after convergence and failures restore owned routes.
- The owner explicitly authorized this ACB migration without automated browser checks and will test the UI themselves. A separate private operator authorization receipt records that waiver; HTTP receipts still do not claim authenticated browser success. Route/API/SSE, checksums, locks and rollback remain required. ACB HTML verification excludes at most one empty, exact-URL, SRI-tagged Web Analytics script with tightly allowlisted attributes (optional version `/v` + 32 lowercase hex, optionally followed by a 13-digit timestamp) and at most one exact Cloudflare challenge-platform precursor bootstrap script (`window.__CF$cv$params` and `/cdn-cgi/challenge-platform/scripts/precursor/main.js`). Every other HTML byte and all JS/CSS bytes remain exact artifact comparisons, and the summary reports the exclusions. No security policy is changed.
- Static checksum failures report the artifact path, actual/expected byte counts, whether the one allowed beacon was removable, a whitespace-only mismatch classification and allowlisted beacon type/guard classifications. Guard results contain only booleans and known attribute-name categories, never attribute values. Cloudflare security bootstrap presence is reported, not silently excluded. Diagnostics never print response bodies, beacon payloads, cookies or headers and do not weaken artifact acceptance.
- The ACB adapter preserves the trusted verifier's single-line `FAIL frontend verification:` diagnostic in candidate/rollback receipts. Other subprocess output remains suppressed; HTTP bodies, cookies, provider data and deployment credentials are never copied into diagnostics.
- ACB's approved static CSP includes `media-src 'self' blob: data:` for fetch-owned MP3/MSE and local unlock audio. Gateway JSON retains the exact policy without that directive; credential-page restrictions remain unchanged. The trusted verifier distinguishes these surfaces. A source policy change must update this central verifier before publication.
- `restore-routes` consumes the original central cutover run's immutable receipt artifact, including failed runs. It requires a completed main-branch dispatch from this platform's Cloudflare workflow, checks the server ZIP digest and both snapshot hosts/zones, then uses compare-before-write restoration. Use the original run that created the routes, not a retry whose snapshots contain no changes. Worker versions, VPS metadata and databases are not changed. Verify the original VPS frontend is healthy before restoring traffic.
- uptimeflare publishes `uptimeflare_worker` and `uptimeflare-web` as a checked pair. Existing every-minute Cron, exact RemoteChecker namespace and D1 database are read/verified, never migrated or restored. HTTP checks exercise both SHA markers, actual Next HTML/JS/CSS and D1-backed `/api/data`. Candidate failure restores only owned exact prior versions; deployment drift forbids overwrite. Legacy untagged recovery reports prior SHA as unverified.
- Production uptimeflare verification runs pinned Playwright through a dedicated forced-command VPS probe, using the installed sandboxed Chromium and a fresh anonymous profile. It navigates the real public `https://status.tuannguyenviet.site/` through normal DNS/Cloudflare and fetches compiled `/_next/static/` assets, D1-backed `/api/data` and expected SHA markers in the same browser session. It does not use origin IPs, internal service bindings, browser accounts, Access credentials or browser-identity overrides. Non-200 navigation, wrong MIME/body/SHA, redirects, missing product scripts and invalid API data still fail; no hosted-browser or loose-HTTP fallback exists. The current public baseline must pass before any version upload; candidate and rollback checks use the same public probe.
- Failed uptimeflare Chromium navigation includes only a validated Cloudflare Ray ID, the `challenge`/`none` mitigation classification and an explicitly labelled 1xxx provider error code when available. The sanitized receipt never includes response bodies, cookies, arbitrary headers or credentials. Use that runner Ray ID in Cloudflare Security Events to identify the actual blocking product/rule; a different client's 1010 response does not prove the runner has the same block. A focused `app=uptimeflare, mode=check` dispatch is read-only and retains the production baseline gate. Do not retry `publish`, change browser identity, disable protections or suppress failures to diagnose a blocked baseline.
- The normal production job receives only `UPTIMEFLARE_PROBE_SSH_KEY`, a separate key for `probe-uptimeflare` on the fingerprint-pinned `oracle-main` host. Its forced command accepts only bounded web/monitor SHA JSON, not a shell, arbitrary URL or path. The account has no Docker/group/admin access; a no-argument root-owned launcher creates a serialized, resource-limited, transient systemd unit running the unprivileged probe. Cloudflare/GitHub credentials remain on the hosted controller and are never sent to the probe. Browser sandboxing stays enabled. No persistent GitHub runner/service or global security exemption is installed. Runtime installation and dedicated-key enrollment are separate operator actions documented in [`install/README.md`](install/README.md); platform-admin SSH keys are never added to normal deployment jobs.
- The controller also compares the probe script SHA-256 with its trusted checkout before accepting any captured resources. A stale or mismatched installed probe fails closed; reviewing and enrolling the matching immutable probe runtime is part of changing that script, not an automatic upload through the restricted probe account.

Manual operations run from this repository:

```sh
gh workflow run cloudflare-deploy.yml -R TheDemonTuan/vps-deploy -f app=uptimeflare -f mode=survey
gh workflow run cloudflare-deploy.yml -R TheDemonTuan/vps-deploy -f app=uptimeflare -f mode=check
gh workflow run cloudflare-deploy.yml -R TheDemonTuan/vps-deploy -f app=uptimeflare -f mode=publish -f source_run_id=<successful-source-run>
gh workflow run cloudflare-deploy.yml -R TheDemonTuan/vps-deploy -f app=uptimeflare -f mode=rollback -f sha=<expected-source-sha> -f version_id=<web-uuid> -f monitor_version_id=<monitor-uuid>
gh workflow run cloudflare-deploy.yml -R TheDemonTuan/vps-deploy -f app=acb -f mode=bootstrap -f source_run_id=<successful-source-run>
gh workflow run cloudflare-deploy.yml -R TheDemonTuan/vps-deploy -f app=acb -f mode=cutover -f source_run_id=<successful-source-run>
gh workflow run cloudflare-deploy.yml -R TheDemonTuan/vps-deploy -f app=acb -f mode=restore-routes -f source_run_id=<original-central-cutover-run>
```

Receipts distinguish source validation, upload, active version and public checks; ACB Access redirect checks never claim an authenticated bank-browser SHA. Rollback requires exact registered Worker UUID(s) and matching expected SHA, not latest/list order. Backend rollback never reads or changes these frontend versions.

ACB audio release `bc03bf3d273f65bca38f1165a8eea4093125ae34` passed central publication run `38174236313` (retry after transient release-identity mismatch). Independent public static verification matched decoded HTML/JS/CSS against the pinned source artifact and passed MIME, CSP, cache, ETag, JSON API and SSE heartbeat checks. This HTTP evidence does not certify authenticated browser behavior or human audio listening.

ACB HTML integrity comparison permits only whitespace between tags after tightly allowlisted Cloudflare analytics/security injections are removed. Joining adjacent tags is equivalent to indentation; text, attributes, script bodies and JS/CSS assets remain exact. No scanner or checksum bypass is used.


### Observed acceptance boundary (2026-10-04)

- Central credential-free CI and real source artifact/digest/manifest validation passed. uptimeflare source PR #22 and platform PRs #2–#5 are merged. All eight old source secrets and obsolete source D1/migration variables were removed after central account/infrastructure reads proved the encrypted transfer usable; no live Worker secrets were removed. One-time migration workflows and sealed delivery artifact were removed.
- Read-only central checks confirmed D1 `431a0d2e-6413-4e80-9d27-1ee933f14f05`, namespace `10db02d2c3874aa7b3db1d599cac207c`, every-minute Cron, monitoring version `fd7ce91a-10da-4b85-94ea-fb4e358942f2` and web version `d4eb9307-08ae-4dc1-9d9c-07787a13b9f7`. These legacy versions have no verified source-SHA tag.
- Actual local Chromium HTML, compiled JS/CSS and D1-backed status API passed. Actual central runner Chromium check `37216355307` failed at public navigation with `HTTP_403`. Publication run `37215987679` refused before upload/traffic mutation at its baseline gate. The blocking security rule is not identified; no Cloudflare policy was changed and no response error was suppressed. Actual publish and live rollback remain unaccepted until this runner can pass the public surface.
- Scheduled run [40255899010](https://github.com/TheDemonTuan/vps-deploy/actions/runs/40255899010) (2026-10-26) still refused at baseline Chromium navigation (`HTTP_403`) before any upload or traffic switch. Its receipt retained those same legacy Worker UUIDs. The earlier receipt lacked a Ray ID, so it could not identify the runner's security event. Local default-user-agent HTTP returned Cloudflare error 1010, while both normal Chrome and HeadlessChrome user-agent requests returned application HTML; that local comparison is not evidence of the runner's blocking rule. Keep schedule, baseline checks and rollback protections unchanged while diagnosing the exact runner event.
- Read-only Cloudflare Security Events identified the blocking product for that original failure: at `2026-10-26T01:49:13Z`, status-host requests with Rays `a505cda13df3a63b` and `a505cda11dada63b` received `managed_challenge`, source `botFight`, rule `bot_fight_mode`. Read-only runner check [40258515360](https://github.com/TheDemonTuan/vps-deploy/actions/runs/40258515360) retained Ray `a505fc2fb9100db7-IAD`, `mitigation=challenge`, the same legacy versions and `d1_mutation=false`; it correctly remained failed. The zone uses Free Bot Fight Mode, which [cannot be skipped by host/path WAF custom rules](https://developers.cloudflare.com/bots/get-started/bot-fight-mode/). No registered self-hosted runner or existing uptimeflare VPS browser-probe command was found. A reviewed, owner-authorized trusted execution/security-policy path is required; diagnostics do not repair production access. Do not disable Bot Fight Mode globally or repurpose privileged production SSH/accounts as a workaround.
- `Central Cloudflare deploy` is a finite workflow scheduled by `*/5 * * * *` (GitHub delivery may be delayed), not an infinite deployment-engine loop. `automatic=true` makes each scheduled run resolve eligible source CI again; the blocked baseline prevents the legacy pair from advancing. The recent successful [40159640860](https://github.com/TheDemonTuan/vps-deploy/actions/runs/40159640860) was a manual ACB publication, not successful uptimeflare acceptance. The schedule and production guards remain enabled.
- ACB Workers Routes access subsequently succeeded: run `37218981819` created both route sets, but cutover failed at public verification. Retry `37220020426` failed because it checked the new artifact SHA against the older bootstrap without publishing it. The original run's route snapshots remain the recovery source; retry snapshots have no changes. Owner-browser acceptance is unavailable because the browser relay extension is not connected. ACB PR #113 remains open: no backend-only metadata migration or frontend-container removal is authorized by unauthenticated runner checks.
- Recovery run `37220725551` passed full central CI and restored both original route snapshots from `37218981819`; its receipt confirms no Worker-version or VPS-metadata change. SSH then confirmed release `8a192a44d270c4f0c313ee1eae62c02c7a44ead5`, gateway/frontend `green`, and healthy frontend/gateway/worker. Public transaction API retained its JSON contract; bank retained its approved Access 302. Viewer static requests and a real managed-browser navigation encounter the existing CrowdSec challenge, so restored public UI rendering is not attested. No security rule was disabled. Corrected future cutover ordering is covered by state-transition regressions, not claimed as a completed production migration.

## OmniRoute production

`registry/omniroute.yml` enrolls `TheDemonTuan/OmniRoute`, branch `production`, using the
existing ARM64 build/security/deploy contracts. Images are deployed by digest,
not by `latest`. The source repository owns `.deploy/app.yml` and image smoke.
The image repository is `ghcr.io/thedemontuan/omniroute-vps`; the pre-existing
private `omniroute` package and its historical versions are not modified.

- API: `omniroute-api.tuannguyenviet.site`; dashboard: `omniroute.tuannguyenviet.site`.
- Dedicated resources: `omniroute-{blue,green}`, `edge-omniroute`, `omniroute-data`,
  `/opt/omniroute`, `/etc/vps-deploy/apps/omniroute`, and `deploy-omniroute` SSH identity.
- The API hostname allows inference paths and health only; management paths fall
  through to the existing deny middleware. No host ports or Docker socket mount.
- Cloudflare Access protects the entire dashboard hostname, including login,
  settings and static assets. Its single identity policy copies the exact email
  allowlist, IdP and 24-hour session from `9router-admin.tuannguyenviet.site`;
  9router's monitoring service-token policy is deliberately not copied. Native
  OmniRoute password authentication remains enabled behind Access.
- The first zone custom WAF rule, `omniroute_api_paths`, blocks API-host requests
  outside `/v1/`, `/api/v1/`, `/v1beta/`, `/api/v1beta/` and exact `/api/health`.
  Versioned `management`, `registered-keys`, `agents`, `accounts`, `providers`,
  `issues` and `quotas` prefixes are denied case-insensitively under both `/v1/`
  and `/api/v1/`, at Cloudflare and the origin. The API router strips incoming
  cookies so a dashboard session cannot bypass API-key authentication.
  Review these explicit control-plane prefixes whenever syncing upstream.
  The API hostname has no Access application: CLI clients use API keys, and the
  deploy controller can verify health without a browser session. Origin path
  denial and API rate limiting remain active behind Cloudflare.
- Root-owned mode-0600 `runtime.env` requires `INITIAL_PASSWORD`, `JWT_SECRET`,
  `API_KEY_SECRET`, `PUBLIC_URL` and `PUBLIC_API_URL`. Generate new secrets;
  never reuse 9router's DB.
- `BASE_URL` stays on container loopback for internal sync jobs; only
  `NEXT_PUBLIC_BASE_URL` uses `PUBLIC_URL` for public dashboard/OAuth callbacks.
  `PUBLIC_API_URL=https://omniroute-api.tuannguyenviet.site` supplies the runtime
  `OMNIROUTE_PUBLIC_BASE_URL` override; generated client endpoints and media URLs
  use the API host without changing dashboard login or OAuth callbacks.
- Installer parity is mandatory for runtime/route changes. During initial
  enrollment maintenance, pause only this app's drain timer and serialize its
  submit/operation locks. Stage the already-accepted image in the other slot,
  acknowledge its owned route, wait for real idle before recreating the original
  slot with the reviewed Compose, then restore that slot/generation with the
  reviewed route and drain the temporary slot. Preserve state bytes and sibling
  routes; run installer `--check`, apply and `restorecon`, then restore the timer.
  Do not force parity, edit controller state or use an unscanned image. Ordinary
  application changes subsequently use the normal source Actions cutover.
- Initial enrollment requires a healthy immutable `omniroute-blue` container,
  the app-owned route and network, then the existing installer `--check`, apply,
  and `deployctl adopt`. Install only the app's dedicated forced-command public key.
- On the SELinux-enforcing Oracle host, run
  `sudo restorecon -R /opt/vps-deploy/releases/<reviewed-platform-sha>` after each
  installer apply and before adoption/Actions. A checkout copied from `/root`
  can retain `admin_home_t`; the host's existing policy assigns executable
  `bin_t`. Keep SELinux enforcing; do not change release bytes or disable it.
- Publish both hostnames through the existing Cloudflare tunnel before adoption:
  public health and route-generation acknowledgement are mandatory, not bypassed.
- Both slots share the OmniRoute SQLite volume. Before updating across schema
  changes, take a consistent SQLite backup and verify backward compatibility;
  switching an image does not roll back database migrations. Never attach
  `9router-data` to OmniRoute. Browser/embedded CLI providers are not installed in
  the lean production image; selecting those requires a separately reviewed image.

Local checks: `python3 -m unittest discover -s tests -p test_omniroute.py -v`.

Configure the scoped Access application and API custom WAF rule in the owner
Cloudflare console before publishing DNS. `cloudflare/omniroute_ingress.py`
contains the exact rule expression; keep that rule first so an earlier skip rule
cannot bypass it. No wildcard or secondary dashboard alias is permitted.

Run `omniroute-ingress.yml` with `operation=survey` before enrollment. Its
`operation=apply` requires the protected `platform-admin` environment and an
independently verified healthy origin. It verifies the admin identity policy,
HttpOnly cookie, API's lack of Access, and enabled first-position WAF rule before
adding only the two exact DNS CNAMEs and tunnel routes. Missing or drifted security
fails closed without ingress writes; the workflow never edits Access/WAF policy
or sibling routes. The token needs Access Apps and Policies Read and Zone WAF
Read in addition to its existing zone/DNS/tunnel permissions.
Do not apply another shared-tunnel change concurrently: Cloudflare provides no
conditional configuration PUT; the adapter re-reads immediately before its write.
The API token stays in this platform repository, not the source repo or VPS.

