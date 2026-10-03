#!/usr/bin/env bash
# GitHub-hosted fresh VM only. Never publish outside this job's loopback registry.
set -euo pipefail
umask 077
[[ $EUID == 0 && ${CI:-} == true && ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted && ${CGW_DISPOSABLE_VM:-} == 1 ]] || { echo 'Requires sudo on a fresh GitHub-hosted disposable job VM' >&2; exit 1; }
[[ ${CGW_APP_REF:-} =~ ^[0-9a-f]{40}$ && ${GITHUB_RUN_ID:-} =~ ^[0-9]+$ ]]
: "${CGW_CI_APP_DIR:?Immutable sibling app checkout required}"
case "${CGW_CI_ARCH:-}:$(uname -m)" in amd64:x86_64|arm64:aarch64) ;; *) echo 'Native Linux amd64/ARM64 required; emulation forbidden' >&2; exit 1;; esac
[[ $(uname -s) == Linux && $(cat /proc/1/comm) == systemd ]] || { echo 'Hosted runner lacks systemd PID 1; lifecycle gate cannot run safely' >&2; exit 1; }
systemctl show-environment >/dev/null || { echo 'Hosted runner systemd manager unavailable; lifecycle gate blocked' >&2; exit 1; }
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
export NO_PROXY=127.0.0.1,localhost
app=$(realpath "$CGW_CI_APP_DIR")
root=$(realpath "$(dirname "$0")/../..")
[[ $(git -c safe.directory="$app" -C "$app" rev-parse HEAD) == "$CGW_APP_REF" ]]
[[ $app != "$root" && $app != "$root/"* ]]
[[ ! -e /etc/vps-deploy/fixture-ci && ! -e /etc/vps-deploy/apps/9router && ! -e /var/lib/vps-deploy/apps/9router ]]
[[ -z $(docker ps -aq --filter name=9router) ]]
for network in 9router-cgw 9router-cgw-egress; do
  ! docker network inspect "$network" >/dev/null 2>&1 || { echo "Occupied network: $network" >&2; exit 1; }
done
! docker volume inspect 9router-cgw-data >/dev/null 2>&1 || { echo 'Occupied runtime volume' >&2; exit 1; }
work=$(mktemp -d /opt/cgw-native-ci.XXXXXX)
registry="cgw-ci-registry-${GITHUB_RUN_ID}-$$"
probe="cgw-ci-systemd-${GITHUB_RUN_ID}-$$"
images=()
cleanup() {
  set +e
  systemctl stop "$probe" >/dev/null 2>&1
  systemctl reset-failed "$probe" >/dev/null 2>&1
  docker rm -f "$registry" >/dev/null 2>&1
  for image in "${images[@]}"; do docker image rm "$image" >/dev/null 2>&1; done
  rm -rf -- "$work"
}
trap cleanup EXIT
systemd-run --unit="$probe" --property=Type=exec --property=RuntimeMaxSec=10 --wait /usr/bin/true || { echo 'Transient systemd services are unavailable; CGW crash gate blocked (not skipped)' >&2; exit 1; }
# Freeze a root-owned test release: production trusted_path checks remain unchanged.
mkdir -m 700 "$work/release"
for area in lib apps install tests; do cp -a "$root/$area" "$work/release/$area"; done
chown -R root:root "$work/release"
chmod -R go-w "$work/release"
package="$app/services/chatgpt-web-runtime"
python3 - "$package" <<'PY'
import hashlib, json, sys
from pathlib import Path
p=Path(sys.argv[1])
m=json.loads((p/'image-build-manifest.json').read_bytes())
assert m['schemaVersion'] == 1 and m['image'] == 'ghcr.io/thedemontuan/9router-cgw-runtime'
assert m['upstream']['revision'] == 'fa2d2c6c24926078b46eedb2186f69f2e8d548d7'
assert m['bun']['version'] == '1.4.0' and m['tunnel']['version'] == '0.0.12'
assert hashlib.sha256((p/'security/seccomp.json').read_bytes()).hexdigest() == m['seccomp']['packagedSha256']
policy=json.loads((p/'security/seccomp.json').read_bytes())
assert policy['defaultAction'] in ('SCMP_ACT_ERRNO','SCMP_ACT_KILL','SCMP_ACT_KILL_PROCESS')
PY
base="cgw-ci-base:${CGW_APP_REF}-${CGW_CI_ARCH}"
images+=("$base")
docker buildx build --builder default --load --platform "linux/$CGW_CI_ARCH" \
  --build-arg "APP_REVISION=$CGW_APP_REF" -f "$package/Dockerfile" -t "$base" "$app"
sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 || true
hardening=(--rm --read-only --network none --cap-drop ALL --security-opt no-new-privileges:true
  --security-opt apparmor=unconfined
  --security-opt "seccomp=$package/security/seccomp.json" --shm-size 1g
  --tmpfs /tmp:rw,nosuid,nodev,size=512m,mode=1777
  --tmpfs /run:rw,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=0700
  --tmpfs /data:rw,nosuid,nodev,size=512m,uid=10001,gid=10001,mode=0700)
# Must prove actual UID, ELF/CPU architecture, namespace + renderer seccomp.
# Unsupported hosted kernel/AppArmor must fail here; do not weaken sandbox.
docker run "${hardening[@]}" "$base" bun scripts/image-smoke.ts --arch "$CGW_CI_ARCH"
docker run "${hardening[@]}" "$base" bun scripts/smoke-offline.ts
# Immutable official multiarch registry index, resolved from Docker Hub tag metadata:
# https://hub.docker.com/v2/repositories/library/registry/tags/2
# Random Docker-assigned loopback port; no public binding, login or public push.
docker run -d --name "$registry" -p 127.0.0.1::5000 \
  registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373
port=$(docker inspect --format '{{(index (index .NetworkSettings.Ports "5000/tcp") 0).HostPort}}' "$registry")
[[ $port =~ ^[0-9]+$ && $port -ge 1024 && $port -le 65535 ]]
repository="127.0.0.1:${port}/cgw-fixture/${CGW_APP_REF}"
ready=0
for _ in {1..60}; do
  if curl --noproxy '*' -fsS "http://127.0.0.1:${port}/v2/" >/dev/null; then ready=1; break; fi
  sleep 1
done
[[ $ready == 1 ]] || { echo 'Ephemeral loopback registry did not become healthy' >&2; exit 1; }
# Identical real runtime closure, different OCI configs/digests; labels only.
# This exercises upgrade/rollback, not cross-version schema compatibility.
printf 'ARG BASE\nFROM ${BASE}\nARG VARIANT\nLABEL cgw.fixture.variant="${VARIANT}"\n' > "$work/Dockerfile"
for variant in old new; do
  tag="$repository:$variant"
  images+=("$tag")
  docker buildx build --builder default --load --platform "linux/$CGW_CI_ARCH" \
    --build-arg "BASE=$base" --build-arg "VARIANT=$variant" -f "$work/Dockerfile" -t "$tag" "$work"
  docker push "$tag"
  docker pull "$tag"
  ref=$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$tag")
  [[ $ref == "$repository"@* && ${ref#"$repository"@} =~ ^sha256:[0-9a-f]{64}$ ]]
  if [[ $variant == old ]]; then old=$ref; else new=$ref; fi
done
[[ $old != "$new" ]]
export CGW_CI_LOOPBACK=1 CGW_CI_REPOSITORY="$repository"
export CGW_SMOKE_OLD_IMAGE="$old" CGW_SMOKE_NEW_IMAGE="$new"
export CGW_SMOKE_SECCOMP_FILE="$package/security/seccomp.json"
bash "$work/release/tests/integration/cgw-runtime-smoke.sh"
printf '%s\n' "Native offline lifecycle complete: app=$CGW_APP_REF arch=$CGW_CI_ARCH; public publication and live staging not performed."
