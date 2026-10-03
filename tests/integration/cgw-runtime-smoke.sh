#!/usr/bin/env bash
# Destructive fixture ONLY: fresh disposable native Linux VM with Docker+systemd.
set -euo pipefail
umask 077
[[ ${CGW_DISPOSABLE_VM:-} == 1 && $EUID == 0 ]]
[[ $(uname -s) == Linux ]]
: "${CGW_SMOKE_OLD_IMAGE:?Reviewed runtime digest required}"
: "${CGW_SMOKE_NEW_IMAGE:?Second compatible runtime digest required}"
: "${CGW_SMOKE_SECCOMP_FILE:?Reviewed Chromium user-namespace seccomp JSON required}"
if [[ ${CGW_CI_LOOPBACK:-} == 1 ]]; then
  [[ ${CI:-} == true && ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]]
  [[ ${CGW_CI_REPOSITORY:-} =~ ^127\.0\.0\.1:([0-9]{1,5})/cgw-fixture/[0-9a-f]{40}$ ]]
  [[ ${BASH_REMATCH[1]} -ge 1024 && ${BASH_REMATCH[1]} -le 65535 ]]
  case "${CGW_CI_ARCH:-}:$(uname -m)" in amd64:x86_64|arm64:aarch64) ;; *) exit 1;; esac
  for image in "$CGW_SMOKE_OLD_IMAGE" "$CGW_SMOKE_NEW_IMAGE"; do
    [[ $image == "$CGW_CI_REPOSITORY"@* && ${image#"$CGW_CI_REPOSITORY"@} =~ ^sha256:[0-9a-f]{64}$ ]]
  done
else
  [[ $(uname -m) == aarch64 && -z ${CGW_CI_REPOSITORY:-} ]]
  for image in "$CGW_SMOKE_OLD_IMAGE" "$CGW_SMOKE_NEW_IMAGE"; do
    [[ $image =~ ^ghcr\.io/thedemontuan/9router-cgw-runtime@sha256:[0-9a-f]{64}$ ]]
  done
fi
[[ $CGW_SMOKE_OLD_IMAGE != "$CGW_SMOKE_NEW_IMAGE" ]]
command -v docker
command -v systemd-run
systemctl show-environment >/dev/null || { echo 'Systemd manager unavailable; lifecycle gate blocked' >&2; exit 1; }
root=$(realpath "$(dirname "$0")/../..")
[[ ! -e /etc/vps-deploy/fixture-ci && ! -e /etc/vps-deploy/apps/9router && ! -e /var/lib/vps-deploy/apps/9router ]]
[[ -z $(docker ps -aq --filter name=9router) ]]
for network in 9router-cgw 9router-cgw-egress; do
  if docker network inspect "$network" >/dev/null 2>&1; then exit 1; fi
done
if docker volume inspect 9router-cgw-data >/dev/null 2>&1; then exit 1; fi
mkdir -p /etc/vps-deploy
printf 'disposable cgw fixture\n' > /etc/vps-deploy/fixture-ci
chmod 600 /etc/vps-deploy/fixture-ci
work=$(mktemp -d /opt/cgw-platform-smoke.XXXXXX)
chmod 700 "$work"
mkdir -m 700 "$work/config" "$work/state"
config=$work/config
export CGW_CONFIG_DIR=$config
export CGW_IMAGE=$CGW_SMOKE_OLD_IMAGE
units=()
cleanup() {
  set +e
  for unit in "${units[@]}"; do systemctl stop "$unit" >/dev/null 2>&1; systemctl reset-failed "$unit" >/dev/null 2>&1; done
  docker compose -p 9router-cgw -f "$root/apps/9router/docker-compose.cgw-runtime.yml" down --volumes || true
  rm -f /etc/vps-deploy/fixture-ci
  rm -rf "$work"
}
trap cleanup EXIT
if [[ ${CGW_CI_LOOPBACK:-} == 1 ]]; then
  python3 - "$work/loopback-fixture.json" "$CGW_CI_REPOSITORY" <<'PY'
import json, sys
from pathlib import Path
p=Path(sys.argv[1])
p.write_text(json.dumps({'repository':sys.argv[2],'disposable':True}))
p.chmod(0o600)
PY
fi
python3 - "$config" "$CGW_SMOKE_SECCOMP_FILE" <<'PY'
import json, os, secrets, shutil, sys
from pathlib import Path
p = Path(sys.argv[1])
for name in ('cgw-data-token', 'cgw-admin-token'):
    (p / name).write_text(secrets.token_urlsafe(48))
(p / 'cgw-client-keys.json').write_text(json.dumps({'version':1,'clients':[]}))
(p / 'cgw-tunnel-profiles.json').write_text('{}')
for name in ('cgw-data-token','cgw-admin-token','cgw-client-keys.json','cgw-tunnel-profiles.json'):
    os.chown(p / name, 0, 10001)
    (p / name).chmod(0o640)
(p / 'cgw.env').write_text('')
(p / 'cgw.env').chmod(0o600)
shutil.copyfile(sys.argv[2], p / 'cgw-seccomp.json')
(p / 'cgw-seccomp.json').chmod(0o600)
(p / 'cgw-tunnel-keys').mkdir(mode=0o750)
os.chown(p / 'cgw-tunnel-keys',0,10001)
policy=json.loads((p / 'cgw-seccomp.json').read_bytes())
assert policy['defaultAction'] in ('SCMP_ACT_ERRNO','SCMP_ACT_KILL','SCMP_ACT_KILL_PROCESS')
PY
# No public publication or production registry/profile changes in this fixture.
docker pull "$CGW_SMOKE_OLD_IMAGE"
docker pull "$CGW_SMOKE_NEW_IMAGE"
docker compose -p 9router-cgw -f "$root/apps/9router/docker-compose.cgw-runtime.yml" up -d --pull never cgw-runtime
python3 "$root/tests/integration/cgw-runtime-driver.py" adopt --directory "$work" --image "$CGW_SMOKE_OLD_IMAGE"
# Bundled browser/MCP/HTTP fixture is run in separate isolated containers by CI,
# never concurrently with the runtime's /data writer here.
if [[ ${CGW_CI_LOOPBACK:-} != 1 ]]; then
  hardening=(--rm --read-only --network none --cap-drop ALL --security-opt no-new-privileges:true
    --security-opt "seccomp=$CGW_SMOKE_SECCOMP_FILE" --shm-size 1g
    --tmpfs /tmp:rw,nosuid,nodev,size=512m,mode=1777
    --tmpfs /run:rw,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=0700
    --tmpfs /data:rw,nosuid,nodev,size=512m,uid=10001,gid=10001,mode=0700)
  docker run "${hardening[@]}" "$CGW_SMOKE_OLD_IMAGE" bun scripts/image-smoke.ts --arch arm64
  docker run "${hardening[@]}" "$CGW_SMOKE_OLD_IMAGE" bun scripts/smoke-offline.ts
fi
sequence=0
run_unit() {
  local action=$1 image=$2 phase=${3:-}
  sequence=$((sequence+1))
  local unit="cgw-fixture-${sequence}-$$"
  units+=("$unit")
  local environment=()
  if [[ ${CGW_CI_LOOPBACK:-} == 1 ]]; then
    environment=(--setenv=CI=true --setenv=GITHUB_ACTIONS=true --setenv=RUNNER_ENVIRONMENT=github-hosted
      --setenv=CGW_CI_LOOPBACK=1 "--setenv=CGW_CI_REPOSITORY=$CGW_CI_REPOSITORY")
  fi
  local args=("$root/tests/integration/cgw-runtime-driver.py" "$action" --directory "$work" --image "$image" --operation-id "fixture-${sequence}")
  if [[ -n $phase ]]; then args+=(--crash-phase "$phase"); fi
  if systemd-run "${environment[@]}" --unit="$unit" --property=Type=exec --property=RuntimeMaxSec=1800 --property=TimeoutStopSec=60 --property=KillMode=mixed --wait /usr/bin/python3 "${args[@]}"; then
    [[ -z $phase ]]
  else
    journalctl -u "$unit" --no-pager || true
    [[ -n $phase ]]
    [[ $(systemctl show "$unit" -p ExecMainStatus --value) == 9 ]]
  fi
  systemctl reset-failed "$unit" || true
}
run_unit deploy "$CGW_SMOKE_NEW_IMAGE"
current=$CGW_SMOKE_NEW_IMAGE
python3 "$root/tests/integration/cgw-runtime-driver.py" assert --directory "$work" --image "$current"
for phase in cgw_prepared cgw_draining cgw_quiescing cgw_quiesced cgw_stopped cgw_snapshot_verified cgw_switching cgw_candidate cgw_committed cgw_resumed; do
  target=$CGW_SMOKE_OLD_IMAGE
  if [[ $current == "$CGW_SMOKE_OLD_IMAGE" ]]; then target=$CGW_SMOKE_NEW_IMAGE; fi
  run_unit deploy "$target" "$phase"
  run_unit reconcile "$target"
  if [[ $phase == cgw_committed || $phase == cgw_resumed ]]; then current=$target; fi
  python3 "$root/tests/integration/cgw-runtime-driver.py" assert --directory "$work" --image "$current"
done
printf '%s\n' 'CGW native disposable lifecycle smoke passed (offline only; not live Full Harness).'
