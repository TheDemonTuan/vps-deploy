# Registered app enrollment and platform engine upgrade

Do not run this procedure until the platform PR's AMD64/ARM64 checks and disposable migration rehearsal pass. The release, app commit, public key, VPS inventory, and caller workflow changes need operator review. This runbook does not authorize a production operation; ACB and the shared Traefik middleware are outside this upgrade. If Oracle host key, network, route, directory, or owner differs from `hosts/oracle-main.yml`, stop; review inventory and publish a corrected platform release rather than overriding policy at runtime.

## Dedicated Uptimeflare browser probe enrollment

`install-uptimeflare-probe.py` is an **offline, root-only** enrollment and
upgrade installer. It does not enroll an application, change a route, disable Cloudflare
Bot Fight Mode, create a persistent runner/service, or touch deployment state.
The normal deploy identity receives no additional privilege: use a separate
Ed25519 key solely for `probe-uptimeflare` and pin the VPS SSH host key separately.
Install the host's Chromium browser at `/usr/bin/chromium-browser` beforehand;
the probe retains Chromium's sandbox. Browser/package installation is not part
of this root installer.

### Stage reviewed inputs without root network access

Run the following on a trusted **non-root operator workstation**, from a clean
checkout after the reviewed installer and browser probe have been committed.
Set the full reviewed platform commit, dedicated public key, and operator SSH
destination. An ARM64 VPS uses `ARCH=arm64`; an x86-64 VPS uses `ARCH=x64`.
The private probe key must never be copied to the staging directory or VPS.

```sh
RELEASE=<full-reviewed-40-character-platform-commit>
ARCH=arm64
PROBE_PUBLIC_KEY="$HOME/.ssh/uptimeflare-probe.pub"
OPERATOR=vps  # existing pinned operator SSH alias, or operator@host
STAGE="$PWD/uptimeflare-probe-stage-$RELEASE"
test "$(id -u)" -ne 0
test ! -e "$STAGE"
mkdir -p "$STAGE/source"
git archive "$RELEASE" | tar -x -C "$STAGE/source"
printf '%s\n' "$RELEASE" > "$STAGE/source/.probe-source-sha"
cp "$PROBE_PUBLIC_KEY" "$STAGE/probe.pub"
python3 - "$STAGE" "$ARCH" <<'PY'
from pathlib import Path
import sys
import importlib.util
import urllib.request
stage, arch = Path(sys.argv[1]), sys.argv[2]
assert arch in ('arm64', 'x64')
spec = importlib.util.spec_from_file_location('probe', stage / 'source/install/install-uptimeflare-probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
records = probe.lock_records((stage / 'source/cloudflare/bun.lock').read_bytes())
zip_name = probe.BUN_ARCHIVE_NAMES[arch] + '.zip'
urls = {'bun.zip': f'https://github.com/oven-sh/bun/releases/download/bun-v{probe.BUN_VERSION}/{zip_name}'}
for name in ('playwright', 'playwright-core'):
    urls[name + '.tgz'] = f"https://registry.npmjs.org/{name}/-/{name}-{records[name]['version']}.tgz"
for name, url in urls.items():
    with urllib.request.urlopen(url, timeout=120) as response:
        (stage / name).write_bytes(response.read())
PY
scp -r "$STAGE" "$OPERATOR:uptimeflare-probe-stage-$RELEASE"
```

`git archive` exports exactly the operator-selected commit; the marker records
that reviewed selection. The installer deliberately does not run Git as root
or claim that a marker alone cryptographically attests source provenance. The
operator must review/select the commit and protect the SSH staging transfer.
Archive authenticity is independently enforced at enrollment: Bun 1.4.5 has
hard-coded architecture-specific SHA-256 pins, and both npm registry tarballs must match
the SHA-512 integrity entries in that commit's `cloudflare/bun.lock`. No package
manager command, lifecycle script, browser download, or network fetch runs as root.

On the VPS, as the existing operator identity, freeze a private root-owned copy
before executing any staged code. `INCOMING` is relative to that operator's home,
matching the upload destination above.
The root destination must not already exist; do not reuse an incoming directory
while another process is modifying it.

```sh
RELEASE=<same-full-reviewed-platform-commit>
INCOMING="$HOME/uptimeflare-probe-stage-$RELEASE"
ROOT_STAGE="/root/uptimeflare-probe-stage-$RELEASE"
sudo test ! -e "$ROOT_STAGE"
sudo cp -a -- "$INCOMING" "$ROOT_STAGE"
sudo chown -hR root:root "$ROOT_STAGE"
sudo chmod -R u=rwX,go=rX "$ROOT_STAGE"
sudo chmod 0700 "$ROOT_STAGE"
sudo /usr/bin/python3 -B "$ROOT_STAGE/source/install/install-uptimeflare-probe.py" \
  --source "$ROOT_STAGE/source" --release "$RELEASE" \
  --public-key "$ROOT_STAGE/probe.pub" --bun-archive "$ROOT_STAGE/bun.zip" \
  --playwright-archive "$ROOT_STAGE/playwright.tgz" \
  --playwright-core-archive "$ROOT_STAGE/playwright-core.tgz" --check
```

Inspect the JSON `status: checked`, release, `manifest_sha256` and
`reused_release` before enrollment. `--check` validates inputs, account policy,
host prerequisites and all existing managed bytes/modes **without creating a
directory, lock, account, file, unit, or process**. To enroll, repeat the exact
last command with only `--check` removed. Save its manifest digest with the
operator change record. The complete digest manifest is installed at
`/opt/vps-deploy-probe/releases/<SHA>/manifest.json`: it records source hashes,
Bun pin, package integrity strings, and every runtime file's hash/mode.

### Upgrade an existing enrollment

Stage the new reviewed commit exactly as above with the **same** probe public
key, then run the installer command with `--check --upgrade`, and after
inspecting the JSON, with only `--check` removed (`status: upgraded`). An upgrade
requires the existing account, `authorized_keys`, forced entry and sudoers rule to
match byte for byte; it publishes the new immutable release directory and then
atomically replaces only the root wrapper (same-directory temporary file, fsync,
rename) so the next probe run uses the new release. Earlier release directories
stay in place for investigation and rollback. Verify with the public probe
command below before closing the change record.

### Resources and immutable retry policy

The installer owns only:

- the password-disabled system account/group `probe-uptimeflare` (shadow password
  `*`, allowing public-key authentication), with no supplementary groups,
  root-owned `/home/probe-uptimeflare` and its restricted SSH key;
  `.ssh` is root-owned mode 0755 and its public `authorized_keys` is root-owned
  mode 0644 so sshd can open it as the login UID; neither is writable by that UID.
  No private key is installed on the VPS.
- `/opt/vps-deploy-probe/releases/<SHA>` containing the probe, pinned Bun binary,
  `playwright`, `playwright-core`, and digest manifest;
- `/usr/local/libexec/vps-deploy-uptimeflare-probe-entry`, the fixed root wrapper
  `/usr/local/libexec/vps-deploy-uptimeflare-probe`, and the dedicated no-argument
  sudoers rule `/etc/sudoers.d/vps-deploy-uptimeflare-probe`;
- `/run/vps-deploy-probe-install.lock` and the root wrapper's transient
  `/run/vps-deploy-uptimeflare-probe.lock`.

When `/usr/sbin/restorecon` is installed, enrollment restores SELinux labels only
on the dedicated probe home, including `.ssh/authorized_keys`. It does not relabel
other homes or change SELinux policy.

Every staged input/resource and ancestor must be root-owned, non-symlink, and not
group/other writable. Host executable paths alone may use root-owned symlinks:
their parent directories and every resolved target/ancestor must pass the same
ownership/write policy; a symlink's normal 0777 mode is not treated as a write
grant. Package extraction accepts only regular files/directories within the
package prefix: no links, devices, traversal, duplicate names or privileged
modes. Existing runtime trees must contain exactly the expected files,
directories, bytes and modes. Differing release content, keys, wrappers, account
policy or home content fails closed, never overwrites; the only exception is
`--upgrade` repointing the root wrapper to a new release. Repeating enrollment with
identical inputs reuses the exact runtime (`reused_release: true`) and leaves
existing runtime/key/wrapper inodes and timestamps unchanged. This is not a key
rotation interface; a different key needs separate operator
review, not deletion of conflict checks. Root-owned partial enrollment may be
resumed only where every already-published managed resource still matches.

The SSH key has `restrict` and a forced entry command. That entry accepts only
the literal SSH command `probe`, no arguments, then permits `sudo -n` for one
fixed no-argument root wrapper. The wrapper clears the environment and runs a
serialized transient systemd unit as the unprivileged probe account with a
90-second deadline, 768 MiB memory limit, 100% CPU quota, 256-task limit,
`PrivateTmp`, private devices, strict system/home protection, read-only probe
runtime, no new privileges and empty capability sets. App/private paths
`/etc/vps-deploy`, `/var/lib/vps-deploy`, `/opt/platform`,
`/opt/tuan-portfolio` are inaccessible. The Docker socket remains
root:docker mode 0660 and the probe belongs only to its own group, so it has no
Docker access; masking that SELinux-labelled socket is not required or permitted.
Chromium's temporary profile lives in that unit's private
temporary directory and is removed with it; no persistent browser profile is
created. The unit is collected after completion. Wrapper stderr is preserved for
the controller's allowlisted diagnostic extraction; the controller must never
print raw SSH stderr or response bodies. The only public protocol is bounded
JSON stdin and the probe's JSON stdout:

```sh
printf '{"web_sha":"","monitor_sha":""}\n' | ssh \
  -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -i "$HOME/.ssh/uptimeflare-probe" probe-uptimeflare@<vps-host> probe
```

The controller supplies the expected nonempty source SHAs during deploys. The
empty values above are the operator's fresh-browser public reachability probe;
they do not change expected deployment revisions or bypass Cloudflare policy.

## Upgrade registered app

1. Pause caller workflows (`deploy.yml`, `deploy-ops.yml`). Wait for pending receipts, transient deployments, and old drain service to finish; reconcile any pending intent using the **old** engine. Capture old `status --app <app> --strict`; compare the active/previous image digests, state revision, route generation, route bytes, volumes, environment names, and long-lived connections. Keep existing route and state untouched. Back up selected-app `/etc/vps-deploy/apps/<app>/{host.json,app.yml,runtime.env}`, both `/usr/local/libexec/vps-deploy-{<app>,drain-<app>}`, sudoers, authorized key, service/timer enable state, and owned route **outside** Traefik's watched directory. Never put private env/key contents in logs.
2. Review exact central checkout `<platform-sha>` and immutable app checkout `<app-sha>`. With root privileges run `bash install/install.sh --check --app <app> --host oracle-main --release <platform-sha> --app-source <absolute-app-checkout> --app-ref <app-sha> --public-key <reviewed-ed25519-key-file>`. Only `CHECK_OK` is approval to run the identical command without `--check`. The check validates registry/manifest policy, public key, collision and trust boundaries, live container/Compose parity, and required runtime names. It neither installs a release nor writes configuration/locks. Missing running route/slot blocks upgrade; do not bootstrap production implicitly.
3. Installer holds shared install lock and selected app submit lock, pauses only its drain timer and waits until the drain service finishes, then holds selected operation lock while replacing its profile/manifest/wrappers. It installs immutable release files, root-owned app key and no-args sudo command, and shared drain templates. It does not change `/opt/vps-deploy/current`, containers, routes, or private app data. It checks selected-release `deployctl status --app <app> --strict`; compare pre/post state, route bytes/generation, images, volumes, env names, and connections. A fresh gateway enrollment is **not adopted** and its timer stays disabled; a running healthy slot and separately authorized `deployctl adopt --app <id>` are required.
4. Change production caller workflows **together**, only after installer success: composite action calls use `app: <app>`, `host: oracle-main`; reusable build uses `app: <app>`; update all action/reusable workflow `uses` pins and `platform-ref` to the same reviewed release SHA; remove `DEPLOY_HOST`, `DEPLOY_PORT`, `DEPLOY_USER` (host address/port are registered); retain `DEPLOY_SSH_KEY` in the `production` environment. Do not put a placeholder SHA into executable workflows. Verify status via restricted SSH transport with pinned host key, then perform explicitly authorized same-digest canary, image rollback, and reconcile. Restore reviewed drain-timer enable state; reopen workflows only after proof.
5. On activation error the installer restores selected config/wrappers/timer state. Leave immutable release available for investigation. After power loss or mixed files, pause caller/timer, recover from reviewed selected-app backup under install/submit/operation locks and rerun installer or restore backup; never reset state or blindly copy backed-up route over live route. Unknown drain, route divergence, or an in-flight intent requires reconciliation by its owning engine before retry.

Installer retains root-only per-attempt backup copies under `/var/lib/vps-deploy/apps/<app>/install-backups/activation-*` (SHA-256 path tokens paired with `.json` mode/path metadata); independently reviewed external backups remain necessary before the first upgrade.
## Image versus engine rollback

Image rollback uses a retained previous container/digest through a new rollback request. It does **not** roll back SQLite schema or app data. Engine rollback is permitted only with no pending intent or unsupported state: pause caller and timer, hold install, selected submit, and selected operation locks, restore selected-app profile/manifest/wrappers/unit and old caller pins, reload systemd, run old strict status, then restore timer. Never overwrite state or dynamic route from backup to conceal divergence. Keep old release, containers, and worktrees available; do not delete shared middleware or another app's files. On SELinux enforcing Oracle Linux, rehearse context-preserving route publication on a disposable enforcing host before any rollout; Ubuntu CI is not SELinux proof.

## Disposable fixture only

`--fixture` is root-only with `/etc/vps-deploy/fixture-ci` owned by root and mode `0600`, host `fixture-local`, assembled release registry/hosts, native localhost images, and a synthetic caller Git commit at `--app-ref`; `--check` still writes nothing. Never create this marker on production. The fixture is not a permission to skip caller manifest policy, release integrity, SSH host-key verification, or per-app isolation.

