# Registered app enrollment and 9router engine upgrade

Do not run this procedure until the platform PR's AMD64/ARM64 checks and disposable migration rehearsal pass. The release, app commit, public key, VPS inventory, and caller workflow changes need operator review. This runbook does not authorize a production operation; ACB, Messenger, and the shared Traefik middleware are outside this upgrade. If Oracle host key, network, route, directory, or owner differs from `hosts/oracle-main.yml`, stop; review inventory and publish a corrected platform release rather than overriding policy at runtime.

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

The public runtime image is browserless. Official Google Chrome for Testing is downloaded directly from Google into a **private, root-owned, version-bound** host directory, never built from source, redistributed in an image, or stored in `cgw-data`. Before first enrollment or any runtime upgrade, provision the candidate's own manifest pin separately as root. Retain the old image's browser directory for rollback; never replace a shared mutable browser path. Example (review `CGW_IMAGE` as the exact scanned digest and select the installed config directory first):

```bash
: "${CGW_IMAGE:?Export the exact reviewed and scanned runtime digest first}"
export CGW_CONFIG_DIR=/etc/vps-deploy/apps/9router
sudo --preserve-env=CGW_IMAGE,CGW_CONFIG_DIR bash <<'SH'
set -euo pipefail
umask 077
docker pull "$CGW_IMAGE"
private=$(mktemp -d)
cid=$(docker create --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true --entrypoint /bin/true "$CGW_IMAGE")
trap 'docker rm "$cid" >/dev/null 2>&1 || true; rm -rf "$private"' EXIT
docker cp "$cid:/opt/cgw/image-build-manifest.json" "$private/manifest.json"
docker cp "$cid:/opt/cgw/scripts/install-browser.py" "$private/install-browser.py"
install -d -m 0755 "$CGW_CONFIG_DIR/cgw-browsers"
python3 - "$private" "$CGW_CONFIG_DIR" <<'PY'
import json, platform, subprocess, sys
from pathlib import Path
private, config = map(Path, sys.argv[1:])
arch = {'aarch64': 'arm64', 'x86_64': 'amd64'}[platform.machine()]
pin = json.loads((private / 'manifest.json').read_text())['browser']['platforms'][arch]
assert len(pin['sha256']) == 64 and all(c in '0123456789abcdef' for c in pin['sha256'])
subprocess.run(['python3', str(private / 'install-browser.py'), '--manifest', str(private / 'manifest.json'),
                '--arch', arch, '--output', str(config / 'cgw-browsers' / pin['sha256'])], check=True)
print('CGW_BROWSER_DIR=' + str(config / 'cgw-browsers' / pin['sha256']))
PY
SH
```

Set `CGW_BROWSER_DIR` to that printed archive-SHA directory for the first manual Compose `up`. Compose requires it and binds it read-only at `/opt/cgw-browser`, with `CGW_CHROMIUM_EXECUTABLE=/opt/cgw-browser/chrome`; a missing source cannot be auto-created. Installer preflight/adoption proves live bind identity and sandbox parity. Managed lifecycle resolves each candidate/retained image's manifest in its own account-free, network-disabled container, validates root ownership, non-writable/non-symlink paths, proof and every payload hash **before draining/stopping the old writer**, and supplies the matching bind to Compose. Missing, unsafe or mismatched bundles fail closed; deploy/reconcile never download a browser. Startup additionally validates the image-bound Chrome binary; exact-image smoke validates the complete bundle. These offline proofs do not assert login or Full readiness.

For a verified old selected profile whose installed registration has no CGW (or a verified legacy 9router engine/profile without CGW network), first enrollment compares live gateway slots against canonical **base** Compose; it still requires the fully provisioned runtime, authenticated diagnostics, secret policy and native runtime parity. It does not restart the old live gateway to pretend new-overlay parity. Once enrolled, every later installer check requires full CGW overlay parity; a missing network/secret cannot use the transition. The next normal gateway deploy attaches the new overlay.

During activation, under selected and legacy operation locks, first enrollment backs up the selected deployment state along with configuration. If state already exists, it proves current gateway identity/route and runtime digest, unfenced physical idle and strict runtime parity, then adopts only `cgw: {current: <digest>, previous: null}` and advances the state revision before final strict status. Active/previous gateway, route generation, private app data and receipts are preserved. Existing CGW state is never overwritten. Any later activation/key-install failure restores the exact backed-up state bytes and config. `--check` remains read-only; it does not adopt. Unknown pending work or fenced/busy runtime blocks adoption.

The CGW release build uses native ARM64, fixed runtime Dockerfile and `APP_REVISION=source-sha`. It downloads the pinned official browser privately with the app installer and mounts it read-only for `verify-harness-compatibility.ts` and exact published-image smoke; only the actual generated protocol/upstream/boolean evidence is copied to `/opt/cgw/compatibility.json` in a label-preserving derivative. The published `sha-<source-sha>` final digest must pass the existing Trivy image gate, private-bundle secret/misconfig gate, and Grype `0.120.0` Chrome CPE HIGH/CRITICAL gate without ignore rules. `scripts/scan-private-browser.py` first requires actual HIGH/CRITICAL matches for a known-vulnerable Chrome version using the same SPDX package shape and database; missing CPE coverage, failed database refresh or scan errors fail closed. Trivy does not support this generic Chrome CPE: an empty Trivy SBOM/filesystem vulnerability report is not browser security evidence. Reports contain metadata only; Chrome payload, licenses, account and runtime state are never uploaded or included in public images. This establishes offline build compatibility only: real ChatGPT/Codex login, outbound connector readiness and per-profile Full smoke remain separate operator gates.

## Image versus engine rollback

Image rollback uses a retained previous container/digest through a new rollback request. It does **not** roll back SQLite schema or app data. Engine rollback is permitted only with no pending intent or unsupported state: pause caller and timer, hold install, selected submit, and selected operation locks (plus legacy locks when reverting 9router), restore selected-app profile/manifest/wrappers/unit and old caller pins, reload systemd, run old strict status, then restore timer. Never overwrite state or dynamic route from backup to conceal divergence. Keep old release, containers, and worktrees available; do not delete shared middleware or another app's files. On SELinux enforcing Oracle Linux, rehearse context-preserving route publication on a disposable enforcing host before any rollout; Ubuntu CI is not SELinux proof.

## Disposable fixture only

`--fixture` is root-only with `/etc/vps-deploy/fixture-ci` owned by root and mode `0600`, host `fixture-local`, assembled release registry/hosts, native localhost images, and a synthetic caller Git commit at `--app-ref`; `--check` still writes nothing. Never create this marker on production. The fixture is not a permission to skip caller manifest policy, release integrity, SSH host-key verification, or per-app isolation.

### GitHub-hosted CGW verification

`.github/workflows/cgw-runtime-ci.yml` builds the exact public app commit from `app_ref` on native `ubuntu-24.04` and `ubuntu-24.04-arm`. The guarded root-only fixture uses an ephemeral loopback OCI registry; it does not publish to GHCR, activate production registrations, use accounts, or upload private state.

Run [37120838018](https://github.com/TheDemonTuan/vps-deploy/actions/runs/37120838018), platform commit `6dfb57053f52c38b9bcdff4c8d4ecf49f2de2ec2`, app commit `b00377d7cbae5516ae7a36020741a4198524df54`, passed both architectures: full 41 Python tests, blue-green shell harness, actual Chromium namespace/renderer sandbox report, authenticated offline browser HTTP fixture, and real Docker/systemd deploy/reconcile with SIGKILL at ten persisted lifecycle phases. Fence admission denial, private snapshot integrity, single writer, commit/resume and rollback assertions passed. No AppArmor teardown, unconfined override, host sysctl change, SYS_ADMIN capability, or browser no-sandbox fallback was used in this run.

The same platform commit passed [Platform verification 37120838027](https://github.com/TheDemonTuan/vps-deploy/actions/runs/37120838027) on both architectures: immutable migration baseline, all 41 current Python tests, adapted blue-green shell harness, actionlint, and disposable Traefik/systemd integration.

The two lifecycle images differ only by OCI labels; this proves stateful switching/recovery, not cross-release schema migration. Renderer process enumeration is unavailable to the unprivileged observer in these sandboxed containers; renderer sandbox evidence comes from `chrome://sandbox` and the actual DOM interaction. Private ChatGPT/Codex, VNC login, authenticated outbound tunnel, and production activation remain separate gates.
