# Registered app enrollment and 9router engine upgrade

Do not run this procedure until the platform PR's AMD64/ARM64 checks and disposable migration rehearsal pass. The release, app commit, public key, VPS inventory, and caller workflow changes need operator review. This runbook does not authorize a production operation; ACB, Messenger, and the shared Traefik middleware are outside this upgrade. If Oracle host key, network, route, directory, or owner differs from `hosts/oracle-main.yml`, stop; review inventory and publish a corrected platform release rather than overriding policy at runtime.

## Penpot preparation

The old OpenDesign registry, controllers, workflows and recreate engine no longer
ship in new platform releases. Prior versions remain in Git history. This source
change does not remove installed releases, live security configuration, routes,
containers or volumes on the VPS.

Penpot has its own four-image release engine, six-service Compose, offline restore
and daily backup units. `bootstrap-penpot.py --check` validates source/image identity,
volume ownership and edge TLS without creating directories, keys or volumes.
Production activation still fails with `PENPOT_RELEASE_ENGINE_NOT_READY`; only an
authorized `fixture-local` disposable CI profile may pass the preparation fence.
Native recovery evidence, not source-only tests, is required to remove that fence.

Bootstrap uses the host CA `/opt/platform/edge/cloudflare-ca/origin-ca.pem`, mounted
read-only at `/etc/cloudflare-origin-ca` in `edge-cloudflared`. Its origin probe runs
the checked frontend digest in that container's network namespace, with design
Host/SNI and CA verification against `172.31.250.4:8080`. It checks the shared edge
IPs and TLS entrypoint first and needs two matching readiness responses before
enrollment. DNS need not exist yet. Deploy, reconcile and backup retain their public
HTTPS checks; they never fall back to the origin probe.

Apply copies reviewed platform bytes into `/opt/vps-deploy/releases/<platform-sha>`
using the installer's immutable release-copy API. Reuse requires identical bytes.
Enrollment restores the backup timer's prior enabled/active state. A fresh timer
stays disabled/inactive until public readiness, a complete production backup and
a private ARM64 restore rehearsal pass; only then enable the daily timer.

Cloudflare `penpot-ingress.yml` offers manual survey/apply on platform `main`. Apply
uses the protected `platform-admin` identity to prove the exact installed platform,
healthy coherent Penpot state and verified origin TLS before any API write. It
changes only the design hostname and preserves sibling routes and policies. Review
native CI and bootstrap evidence before running it; Access removal is the last
write, followed by public HTTPS readiness.

Survey and apply preflight enumerate every GET inventory page before evaluating
ownership, including Access conflicts found on later pages. Pagination requires
integer `page`, `per_page`, `count` and `total_count`; `total_pages` may be derived
from the counts when absent, but a present value must agree. Empty inventories
accept zero or one total page only with zero counts and page 1. Missing metadata,
short pages, overlapping resource IDs or changing totals fail closed; only the
nonpaginated tunnel-connections endpoint may omit metadata. Ruleset lists use
`per_page=50` and follow `result_info.cursors.after` until no next cursor remains;
missing metadata, repeated cursors and overlapping IDs fail closed.
Inventory reads are bounded to 1,000 pages and 4 MiB total response bytes, keep
filters and block redirects. Writes remain single requests without retries or
pagination. A failed survey does not establish that ownership conflicts are absent.

After a reviewed platform revision reaches `main`, run the read-only smoke with
`gh workflow run penpot-ingress.yml --repo TheDemonTuan/vps-deploy --ref main -f operation=survey`
and inspect that exact run's sanitized summary before considering apply. Local
focused coverage is `python3 -m unittest discover -s cloudflare/tests -p 'test_penpot_ingress.py' -v`.

## Upgrade 9router

1. Pause all caller workflows (`deploy.yml`, `deploy-ops.yml`, `rtk-sidecar.yml`, and `chatgpt-web-runtime.yml` once enrolled). Wait for pending receipts, transient deployments, and old drain service to finish; reconcile any pending intent using the **old** engine. Capture old `status --app 9router --strict`; compare the active/previous image digests, state revision, route generation, route bytes, volumes, environment names, and long-lived connections. Keep existing route and state untouched. Back up selected-app `/etc/vps-deploy/apps/9router/{host.json,app.yml,runtime.env}`, both `/usr/local/libexec/vps-deploy-{9router,drain-9router}`, sudoers, authorized key, legacy service/timer enable state, and owned route **outside** Traefik's watched directory. Never put private env/key contents in logs.
2. Review exact central checkout `<platform-sha>` and immutable app checkout `<app-sha>`. With root privileges run `bash install/install.sh --check --app 9router --host oracle-main --release <platform-sha> --app-source <absolute-9router-checkout> --app-ref <app-sha> --public-key <reviewed-ed25519-key-file>`. Only `CHECK_OK` is approval to run the identical command without `--check`. The check validates registry/manifest policy, public key, collision and trust boundaries, live container/Compose parity, and required runtime names. It neither installs a release nor writes configuration/locks. Missing running route/slot blocks upgrade; do not bootstrap production implicitly.
3. Installer holds shared install lock and selected app submit lock (plus legacy 9router submit lock), pauses only its drain timer and waits until the drain service finishes, then holds selected operation lock (plus legacy operation lock) while replacing its profile/manifest/wrappers. It installs immutable release files, root-owned app key and no-args sudo command, and shared drain templates. It does not change `/opt/vps-deploy/current`, containers, routes, or private app data. Existing state is unchanged except first CGW adoption described below (add runtime digest and advance revision, with exact-byte rollback backup). It checks selected-release `deployctl status --app 9router --strict`; compare pre/post state, route bytes/generation, images, volumes, env names, and connections. A fresh gateway enrollment is **not adopted** and its timer stays disabled; a running healthy slot and separately authorized `deployctl adopt --app <id>` are required.
4. Change all production caller workflows **together**, only after installer success: every composite action call adds `app: 9router`, `host: oracle-main`; reusable build adds `app: 9router`; update all action/reusable workflow `uses` pins and `platform-ref` to the same reviewed release SHA; remove `DEPLOY_HOST`, `DEPLOY_PORT`, `DEPLOY_USER` (host address/port are registered); retain `DEPLOY_SSH_KEY` in the `production` environment and deploy trigger only on `master`. Include `chatgpt-web-runtime.yml` when CGW is enrolled. Do not put a placeholder SHA into executable workflows. Verify status via restricted SSH transport with pinned host key, then perform explicitly authorized same-digest canary, image rollback, and reconcile. Restore reviewed drain-timer enable state; reopen workflows only after proof.
5. On activation error the installer restores selected config/wrappers/timer state. Leave immutable release available for investigation. After power loss or mixed files, pause caller/timer, recover from reviewed selected-app backup under install/submit/operation locks and rerun installer or restore backup; never reset state or blindly copy backed-up route over live route. Unknown drain, route divergence, or an in-flight intent requires reconciliation by its owning engine before retry.

Installer retains root-only per-attempt backup copies under `/var/lib/vps-deploy/apps/<app>/install-backups/activation-*` (SHA-256 path tokens paired with `.json` mode/path metadata); independently reviewed external backups remain necessary before the first upgrade.


## Upgrade 9router ChatGPT Web runtime (`cgw`)

The ChatGPT Web runtime (`ghcr.io/thedemontuan/9router-cgw-runtime`) is a distinct, singleton stateful service on project `9router-cgw` with persistent storage `/data` (`9router-cgw-data`), host-only VNC port `127.0.0.1:17842`, and internal network `9router-cgw`. Normal gateway Blue/Green deployments (`component: app`) NEVER start, restart, or recreate the runtime.

### CGW Lifecycle Contract
1. **Timeout Budgets**: Operation budget is 1800s (`RuntimeMaxSec=1800`), caller polling 1860s. Phase subdeadlines: `prepare` <= 300s, `drain` <= 900s, `quiesce` + `snapshot` + `candidate` <= 300s, `recovery`/`resume` <= 240s, with a 60s termination reserve.
2. **Admission Fence**: A durable fence `{operationId, state: "draining"|"quiesced"}` is persisted in SQLite before starting admission-draining actions. The fence survives process restarts and stops candidate traffic admission during validation.
3. **Physical Quiescence**: Quiescing requires zero active HTTP requests, zero active browser turns, zero pending MCP calls, and physical settlement of all browser tabs and broker activity (`physicalIdle: true`).
4. **Private Snapshot**: After stopping the old runtime, the platform verifies all volume writers have exited, creates a byte-for-byte snapshot of `/data`, runs SQLite `PRAGMA integrity_check`, and writes a manifest containing the SHA256 hashes, user version, and monotonic `acceptedRequestCount`.
5. **Candidate Validation & Commit**: The candidate starts with the durable fence still active. Diagnostics query `/admin/profiles` to verify protocol version 1, schema version 1, and idle status without exposing bearer tokens or credentials. If admission count grew or candidate fails, candidate is stopped and the verified snapshot restored. Once validated, state is committed to `current: <candidate-digest>` and the fence resumed.
6. **Drain Timeout**: If active browser turns or tool executions do not finish within the 900s drain budget, the platform aborts the upgrade, resumes the old runtime without killing turns, and returns typed error `CGW_DRAIN_BUSY`.

### Production Activation Gate
Production registry and workflow pins are immutable. Expanding the registry with `cgw` and updating executable workflow pins to include the `cgw` component requires user authorization, an immutable platform release tag, and simultaneous activation across platform and caller repositories.

### First CGW enrollment and build proof

The production registration now enrolls CGW. Activate the expanded caller manifest and every caller build/security/deploy pin together at the same reviewed immutable platform SHA. `chatgpt-web-runtime.yml` must make actual pinned source-security, `build-docker.yml` (`component: cgw`), image-security, and deploy-action (`app: 9router`, `host: oracle-main`, `component: cgw`) calls; its image comes only from the build digest output.

Before installer `--check`, provision the singleton runtime at the exact scanned digest, its internal/egress networks, read-only secret mounts, native sandbox seccomp, tmpfs and 1GB shm. Config files under the selected app config directory are `cgw-data-token`, `cgw-admin-token`, `cgw-client-keys.json`, `cgw-tunnel-profiles.json` (root-owned mode 0640, group 10001), plus `cgw.env` and `cgw-seccomp.json` (root-owned mode 0600). Data/admin tokens must differ. Existing `INITIAL_PASSWORD` remains required; normalize only the allowed runtime env names after a private operator backup, never log values. An empty operator client/tunnel inventory and no account are valid unconfigured state, not Full readiness. No public viewer/CDP or relaxed sandbox is permitted.

The public runtime image is browserless. Compose's `browser-init` service uses the **same image** to download the pinned official Google Chrome for Testing directly from Google, verifies its SHA256/provenance, and installs it into Docker-owned cache volume `9router-cgw-browser`. No Chrome or browser installer/Python is required on the host; the deployment engine's existing Python dependency is unchanged. Chrome is never compiled, included in the public OCI image/artifacts, or stored in the account volume. First boot needs only the reviewed digest and existing secret configuration:

```bash
: "${CGW_IMAGE:?Export the exact reviewed and scanned runtime digest first}"
export CGW_CONFIG_DIR=/etc/vps-deploy/apps/9router
sudo --preserve-env=CGW_IMAGE,CGW_CONFIG_DIR docker compose -p 9router-cgw \
  -f apps/9router/docker-compose.cgw-runtime.yml up -d --pull always cgw-runtime
```

Compose waits for successful browser initialization before starting the runtime. Init is non-root `10001:10001`, read-only root, no added capabilities, `no-new-privileges`, tmpfs `/tmp` and `/run`, limited to 0.5 CPU / 1GB RAM. It alone mounts the browser cache read-write and never mounts `/data` or credentials. Runtime mounts the cache read-only at `/opt/cgw-browser`, keeps `/data` in separate `9router-cgw-data`, and is limited to 1 CPU / 2GB RAM. The image owns its versioned executable env and manifest, currently `/opt/cgw-browser/154.0.8037.92/chrome`; Compose never overrides an older retained image's pin. Native Chrome sandbox policy is unchanged.

For managed upgrades, the engine pulls the candidate and runs `docker compose run --rm --no-deps browser-init` **before draining or stopping the old runtime**. Init failure leaves the old writer serving. After the existing drain/quiesce/snapshot transaction, managed `up --no-deps` starts only the runtime, avoiding a repeated download. Retained immutable version directories remain available for rollback; recovery can initialize/verify a retained image's own pin through Docker before restarting it. Never delete the production cache with `down --volumes`, overwrite version directories, or mount a host browser directory. Installer preflight proves the canonical named read-only cache mount and the existing sandbox, network, secret, viewer and account-volume policy. Runtime startup still validates its image-bound browser proof. Offline proofs do not assert account login or Full readiness.

For a verified old selected profile whose installed registration has no CGW (or a verified legacy 9router engine/profile without CGW network), first enrollment compares live gateway slots against canonical **base** Compose; it still requires the fully provisioned runtime, authenticated diagnostics, secret policy and native runtime parity. It does not restart the old live gateway to pretend new-overlay parity. Once enrolled, every later installer check requires full CGW overlay parity; a missing network/secret cannot use the transition. The next normal gateway deploy attaches the new overlay.

During activation, under selected and legacy operation locks, first enrollment backs up the selected deployment state along with configuration. If state already exists, it proves current gateway identity/route and runtime digest, unfenced physical idle and strict runtime parity, then adopts only `cgw: {current: <digest>, previous: null}` and advances the state revision before final strict status. Active/previous gateway, route generation, private app data and receipts are preserved. Existing CGW state is never overwritten. Any later activation/key-install failure restores the exact backed-up state bytes and config. `--check` remains read-only; it does not adopt. Unknown pending work or fenced/busy runtime blocks adoption.

The CGW release build uses native ARM64, fixed runtime Dockerfile and `APP_REVISION=source-sha`. It initializes an owned Docker cache with the candidate image and mounts it read-only for `verify-harness-compatibility.ts` and exact published-image smoke; only the actual generated protocol/upstream/boolean evidence is copied to `/opt/cgw/compatibility.json` in a label-preserving derivative. The published `sha-<source-sha>` final digest must pass the existing Trivy image gate and covered Grype `0.120.0` Chrome CPE HIGH/CRITICAL gate without ignore rules. `scripts/scan-browser.py` reads only SPDX metadata obtained through Docker and first requires actual HIGH/CRITICAL matches for a known-vulnerable Chrome version using the same package shape and database; missing CPE coverage or scanner/database failure blocks release. Chrome SPDX stays in the versioned cache at `<installRoot>/browser.spdx.json`. CI removes its owned cache volumes/containers; browser files are never mounted from host paths or uploaded as artifacts. Real-account staging remains separate.

## Image versus engine rollback

Image rollback uses a retained previous container/digest through a new rollback request. It does **not** roll back SQLite schema or app data. Engine rollback is permitted only with no pending intent or unsupported state: pause caller and timer, hold install, selected submit, and selected operation locks (plus legacy locks when reverting 9router), restore selected-app profile/manifest/wrappers/unit and old caller pins, reload systemd, run old strict status, then restore timer. Never overwrite state or dynamic route from backup to conceal divergence. Keep old release, containers, and worktrees available; do not delete shared middleware or another app's files. On SELinux enforcing Oracle Linux, rehearse context-preserving route publication on a disposable enforcing host before any rollout; Ubuntu CI is not SELinux proof.

## Disposable fixture only

`--fixture` is root-only with `/etc/vps-deploy/fixture-ci` owned by root and mode `0600`, host `fixture-local`, assembled release registry/hosts, native localhost images, and a synthetic caller Git commit at `--app-ref`; `--check` still writes nothing. Never create this marker on production. The fixture is not a permission to skip caller manifest policy, release integrity, SSH host-key verification, or per-app isolation.

### GitHub-hosted CGW verification

`.github/workflows/cgw-runtime-ci.yml` builds the exact public app commit from `app_ref` on native `ubuntu-24.04` and `ubuntu-24.04-arm`. The guarded root-only fixture uses an ephemeral loopback OCI registry; it does not publish to GHCR, activate production registrations, use accounts, or upload private state.

Run [37120838018](https://github.com/TheDemonTuan/vps-deploy/actions/runs/37120838018), platform commit `6dfb57053f52c38b9bcdff4c8d4ecf49f2de2ec2`, app commit `b00377d7cbae5516ae7a36020741a4198524df54`, passed both architectures: full 41 Python tests, blue-green shell harness, actual Chromium namespace/renderer sandbox report, authenticated offline browser HTTP fixture, and real Docker/systemd deploy/reconcile with SIGKILL at ten persisted lifecycle phases. Fence admission denial, private snapshot integrity, single writer, commit/resume and rollback assertions passed. No AppArmor teardown, unconfined override, host sysctl change, SYS_ADMIN capability, or browser no-sandbox fallback was used in this run.

The same platform commit passed [Platform verification 37120838027](https://github.com/TheDemonTuan/vps-deploy/actions/runs/37120838027) on both architectures: immutable migration baseline, all 41 current Python tests, adapted blue-green shell harness, actionlint, and disposable Traefik/systemd integration.

The two lifecycle images differ only by OCI labels; this proves stateful switching/recovery, not cross-release schema migration. Renderer process enumeration is unavailable to the unprivileged observer in these sandboxed containers; renderer sandbox evidence comes from `chrome://sandbox` and the actual DOM interaction. Private ChatGPT/Codex, VNC login, authenticated outbound tunnel, and production activation remain separate gates.
