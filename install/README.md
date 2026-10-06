# Registered app enrollment and 9router engine upgrade

Do not run this procedure until the platform PR's AMD64/ARM64 checks and disposable migration rehearsal pass. The release, app commit, public key, VPS inventory, and caller workflow changes need operator review. This runbook does not authorize a production operation; ACB, Messenger, and the shared Traefik middleware are outside this upgrade. If Oracle host key, network, route, directory, or owner differs from `hosts/oracle-main.yml`, stop; review inventory and publish a corrected platform release rather than overriding policy at runtime.

## Reviewed OpenDesign platform activation

OpenDesign upgrades use **Activate OpenDesign platform**, not a workstation
installer invocation or a rewritten release/tag. Dispatch `activate-platform.yml`
on platform `main` with `app_ref` set to the full lowercase 40-character commit
SHA already merged into `TheDemonTuan/open-design/main`. The dispatch's platform
SHA must have completed successful `Platform verification` on both architectures;
PR-only or older successful CI evidence is insufficient.

Configure Environment `platform-admin` with required reviewer `TheDemonTuan`,
only branch `main`, `can_admins_bypass: false`, and `prevent_self_review: false`.
Keep the restricted app deploy key unchanged. Set variable
`OPENDESIGN_DEPLOY_PUBLIC_KEY` to that enrolled Ed25519 public key and provision
secret `VPS_PLATFORM_ADMIN_SSH_KEY` temporarily for this activation only. Approve
the environment deployment manually; never approve it programmatically to bypass
review. The runner removes temporary key files, but the operator must also delete
the environment secret in a `finally` after the run reaches success/failure/cancel
and verify its absence using the secret-name list.

The remote entry requires an idle, already enrolled host. It fetches exact clean
detached commits into private staging, verifies the existing forced-command key,
and invokes the installer first with `--check` then identical apply arguments.
Recreate preflight requires the singleton service while retaining environment,
mount, network and no-published-port parity. A success receipt proves the profile
selected the reviewed platform, strict health passed, and container/image,
route bytes and runtime environment hash/ownership/mode remained unchanged.
The active deployment record may retain the old platform until the next image
deployment; do not edit state to force a match.

Singleton recreate admission and resume wait up to 120 seconds for the internal
deployment API after startup. A monotonic deadline bounds each probe and the
two-second retry interval. Only structured connection refusal and probe timeout
are startup retries; HTTP authentication/non-200 responses, malformed JSON and
other execution failures fail visibly. Readiness does not replace candidate
fencing or SQLite checks. Failed readiness or resume retains the pending operation
for reconciliation; it must not be reported as a healthy completed deployment.

Only after a successful receipt, update all application action refs and
`platform-ref` inputs together to the activated SHA. Preserve Cloudflare Access,
CrowdSec, Traefik and port isolation. On disconnect, inspect profile and strict
status read-only before replaying the same SHAs. `RELEASE_MODIFIED`, key mismatch,
busy state or invariant drift must fail visibly: do not overwrite releases,
patch state, rotate keys, or add another rollback mechanism.

Production proof: [run 37415312347](https://github.com/TheDemonTuan/vps-deploy/actions/runs/37415312347)
activated `840986fe2c98898372ac58de528d1b2606e9c04c` against application
`1bd710a0c41892b276e2f5e51f32e7d19c8d2095`. Its receipt reports healthy,
unchanged container and runtime environment; the temporary admin secret was
deleted and its absence verified after completion. This proof does not claim
that an application image deployment or a provider generation was performed.

### Fixed startup-race recovery

`recover-opendesign.yml` is a protected, main-only recovery entry for the exact
transaction `gh-37424292784-1-app`, not a general recovery command. It requires
successful AMD64/ARM64 CI for the dispatched platform SHA, a reviewed application
main SHA, the enrolled deploy public key and temporary `platform-admin` identity.
It refuses another pending operation, fence, image, snapshot or route identity.
Under the existing submit/operation/Traefik locks, reviewed reconciliation restores
the recorded old image/data, waits for API readiness and resumes the original
operation. Only the engine's proven restored transition permits one bounded
continuation to clear the intent; transport errors never trigger blind replay.
Installed release bytes and enrollment remain unchanged. Use ordinary activation
after successful recovery; do not patch state or bypass environment approval.

[Recovery run 37426963504](https://github.com/TheDemonTuan/vps-deploy/actions/runs/37426963504)
exercised platform `806225b42ac720fb9e1af49beb3b2a073563557c` against application
`bc7372c32407fdf2f13b96edb94e30919d637cac`. Its receipt proves the old digest restored,
healthy, accepting and operation cleared. The temporary admin secret was revoked
and absence verified. This recovery proof is not a new-image deployment proof.


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
