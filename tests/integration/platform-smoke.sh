#!/usr/bin/env bash
set -euo pipefail
set -E
# shellcheck disable=SC2154 # rc is assigned when ERR trap executes.
trap 'rc=$?; printf "platform-smoke failed line=%s exit=%s\n" "$LINENO" "$rc" >&2; if [[ -f ${fixture:-/nonexistent}/sshd.log ]]; then cat "$fixture/sshd.log" >&2; fi' ERR
[[ $(id -u) == 0 && $(uname -s) == Linux && -n ${RUNNER_TEMP:-} ]] || { echo 'Requires sudo on disposable Ubuntu runner with RUNNER_TEMP' >&2; exit 1; }
export NO_PROXY='localhost,127.0.0.1,.platform-smoke.test,.fixture.test'
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
[[ $# == 2 && $1 == --migration-base && -d $2 && ! -L $2 ]] || { echo 'Usage: platform-smoke.sh --migration-base <baseline-checkout>' >&2; exit 2; }
new_root=$root
root=$(cd -- "$2" && pwd -P)
[[ $(git -C "$root" rev-parse HEAD) == 4e9674ad29112a02d2384f6542cc64644da33dea ]] || { echo INVALID_BASELINE >&2; exit 2; }
new_sha=$(git -C "$new_root" rev-parse HEAD)
[[ $new_sha =~ ^[0-9a-f]{40}$ ]] || exit 2
new_release=/opt/vps-deploy/releases/$new_sha
[[ $RUNNER_TEMP == /tmp/* || $RUNNER_TEMP == /home/runner/work/* ]] || { echo 'Unexpected runner temp' >&2; exit 1; }
[[ ${GITHUB_RUN_ID:-0} =~ ^[0-9]+$ ]] || exit 1
fixture=/tmp/vps-deploy-smoke-${GITHUB_RUN_ID:-0}
[[ ! -e $fixture ]] || { echo "Fixture already exists: $fixture" >&2; exit 1; }
release_sha=$(git -C "$root" rev-parse HEAD)
[[ $release_sha =~ ^[0-9a-f]{40}$ ]] || exit 1
release=/opt/vps-deploy/releases/$release_sha
baseline_release=$release
profile=/etc/vps-deploy/apps/9router
state=/var/lib/vps-deploy/apps/9router
locks=/run/lock/vps-deploy
api=api.platform-smoke.test
cert=$fixture/server.crt
ca=$fixture/ca.crt
registry=localhost:5000
ssh_port=22222
cleanup() {
  set +e
  trap - ERR
  [[ -z ${tls_pid:-} ]] || { kill "$tls_pid"; wait "$tls_pid" 2>/dev/null; }
  [[ -z ${sshd_pid:-} ]] || { kill "$sshd_pid"; wait "$sshd_pid" 2>/dev/null; }
  if [[ -n ${stream_pid:-} ]]; then kill "$stream_pid" 2>/dev/null; wait "$stream_pid" 2>/dev/null; fi
  if [[ -n ${unit_ids:-} ]]; then
    for id in $unit_ids; do systemctl stop "vps-deploy-9router@$id.service" 2>/dev/null; done
  fi
  systemctl stop 'vps-deploy-demo@demo-deploy.service' 'vps-deploy-demo@demo-rollback.service' 'vps-deploy-demo@demo-reconcile.service' 'vps-deploy-demo@demo-parallel.service' 'vps-deploy-demo@demo-shared-lock.service' 2>/dev/null || true
  systemctl disable --now 'vps-deploy-drain@9router.timer' 'vps-deploy-drain@demo.timer' 2>/dev/null || true
  rm -f /etc/systemd/system/vps-deploy-drain@.service /etc/systemd/system/vps-deploy-drain@.timer
  systemctl daemon-reload 2>/dev/null || true
  for name in edge-traefik 9router-blue 9router-green 9router-rtk-rtk-1 demo-blue demo-green fixture-registry; do docker rm -f "$name" >/dev/null 2>&1; done
  for name in edge-9router edge-demo 9router-rtk 9router_internal; do docker network rm "$name" >/dev/null 2>&1; done
  docker volume rm 9router-data demo-data >/dev/null 2>&1
  for tagged in localhost:5000/9router:first localhost:5000/9router:second localhost:5000/rtk-sidecar:rtk localhost:5000/rtk-sidecar:rtk-bad localhost:5000/demo:first localhost:5000/demo:second; do docker image rm "$tagged" >/dev/null 2>&1; done
  if [[ ${hosts_written:-} == 1 ]]; then sed -i '/# vps-deploy-smoke$/d' /etc/hosts; fi
  rm -f /etc/vps-deploy/fixture-ci /opt/vps-deploy/current /usr/local/libexec/vps-deploy-9router /usr/local/libexec/vps-deploy-drain-9router /usr/local/libexec/vps-deploy-demo /usr/local/libexec/vps-deploy-drain-demo /etc/sudoers.d/vps-deploy-9router /etc/sudoers.d/vps-deploy-demo
  [[ -z ${user_created:-} ]] || userdel -r deploy-9router >/dev/null 2>&1
  [[ -z ${demo_user_created:-} ]] || userdel -r deploy-demo >/dev/null 2>&1
  rm -rf -- "$baseline_release" "$new_release" "$profile" "$state" /etc/vps-deploy/apps/demo /var/lib/vps-deploy/apps/demo "$fixture"
  if [[ ${sshd_directory_created:-} == 1 ]]; then rmdir /run/sshd 2>/dev/null || true; fi
  [[ -z ${opt_mode:-} ]] || chmod "$opt_mode" /opt
}
for path in /etc/vps-deploy/fixture-ci "$profile" "$state" "$release" "$new_release" /etc/vps-deploy/apps/demo /var/lib/vps-deploy/apps/demo /opt/vps-deploy/current /usr/local/libexec/vps-deploy-9router /usr/local/libexec/vps-deploy-demo /usr/local/libexec/vps-deploy-drain-9router /usr/local/libexec/vps-deploy-drain-demo /etc/sudoers.d/vps-deploy-9router /etc/sudoers.d/vps-deploy-demo /etc/systemd/system/vps-deploy-drain@.service /etc/systemd/system/vps-deploy-drain@.timer; do
  [[ ! -e $path && ! -L $path ]] || { echo "Refusing occupied fixture path $path" >&2; exit 1; }
done
for name in edge-traefik 9router-blue 9router-green 9router-rtk-rtk-1 demo-blue demo-green fixture-registry; do
  ! docker container inspect "$name" >/dev/null 2>&1 || { echo "Container occupied: $name" >&2; exit 1; }
done
for name in edge-9router edge-demo 9router-rtk; do
  ! docker network inspect "$name" >/dev/null 2>&1 || { echo "Network occupied: $name" >&2; exit 1; }
done
! docker volume inspect 9router-data >/dev/null 2>&1 && ! docker volume inspect demo-data >/dev/null 2>&1 || { echo 'Volume occupied' >&2; exit 1; }
for tagged in localhost:5000/9router:first localhost:5000/9router:second localhost:5000/rtk-sidecar:rtk localhost:5000/rtk-sidecar:rtk-bad localhost:5000/demo:first localhost:5000/demo:second; do
  ! docker image inspect "$tagged" >/dev/null 2>&1 || { echo "Image tag occupied: $tagged" >&2; exit 1; }
done
! id deploy-demo >/dev/null 2>&1 || { echo 'User occupied: deploy-demo' >&2; exit 1; }
[[ $(stat -c %u /opt) == 0 && ! -L /opt ]] || { echo 'Untrusted runner /opt' >&2; exit 1; }
opt_mode=$(stat -c %a /opt)
trap cleanup EXIT
chmod 0755 /opt
mkdir -m 0755 "$fixture"
mkdir -p "$fixture/dynamic" "$fixture/work" /opt/vps-deploy/releases /etc/vps-deploy/apps "$profile" /var/lib/vps-deploy/apps "$state/requests" "$locks"
install -d -m 0755 /opt/vps-deploy /opt/vps-deploy/releases
chmod 0700 /etc/vps-deploy /etc/vps-deploy/apps "$profile" /var/lib/vps-deploy /var/lib/vps-deploy/apps "$state" "$state/requests" "$locks" "$fixture/work"
install -d -m 0755 "$release"
for area in bin lib apps schema install; do cp -a "$root/$area" "$release/$area"; done
chown -R root:root "$release"; chmod -R go-w "$release"
ln -s "$release" /opt/vps-deploy/current
install -m 0600 /dev/null /etc/vps-deploy/fixture-ci
printf '%s\n' "127.0.0.1 $api dashboard.platform-smoke.test legacy.platform-smoke.test sentinel.platform-smoke.test demo.fixture.test # vps-deploy-smoke" >> /etc/hosts
hosts_written=1
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=platform-smoke.test' -addext 'subjectAltName=DNS:api.platform-smoke.test,DNS:dashboard.platform-smoke.test,DNS:legacy.platform-smoke.test,DNS:sentinel.platform-smoke.test,DNS:demo.fixture.test' -keyout "$fixture/server.key" -out "$cert" >/dev/null 2>&1
install -m 0644 "$cert" "$ca"
python3 "$root/tests/integration/server.py" tls "$cert" "$fixture/server.key" 18080 "$fixture" & tls_pid=$!
cat > "$profile/app.yml" <<'YAML'
version: 1
app: 9router
strategy: blue-green
image: ghcr.io/thedemontuan/9router
platform: linux/arm64
runtime: {port: 20128}
health: {path: /api/health, timeout_seconds: 60}
route: {timeout_seconds: 30}
rtk: {image: ghcr.io/thedemontuan/rtk-sidecar}
YAML
printf 'INITIAL_PASSWORD=fixture-not-a-secret\n' > "$profile/runtime.env"
chmod 0600 "$profile/app.yml" "$profile/runtime.env"
arch=$(docker info --format '{{.Architecture}}')
case "$arch" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo "Unsupported $arch" >&2; exit 1;; esac
python3 - "$profile/host.json" "$release_sha" "$fixture" "$api" "$arch" "$ca" <<'PY'
import json,sys
p,sha,work,api,arch,ca=sys.argv[1:]
value=dict(platform_ref=sha,dynamic_dir=work+'/dynamic',api_host=api,dashboard_host='dashboard.platform-smoke.test',dashboard_alias_host='legacy.platform-smoke.test',work_dir=work+'/work',compose_project='9router',edge_network='edge-9router',rtk_network='9router-rtk',route_name='9router.yml',fixture_ci=True,image_repository='localhost:5000/9router',rtk_image_repository='localhost:5000/rtk-sidecar',architecture=arch,ca_bundle=ca,fault_file=work+'/work/fault')
with open(p,'w') as output: json.dump(value,output)
PY
chmod 0600 "$profile/host.json"
ssh-keygen -q -t ed25519 -N '' -f "$fixture/key"
useradd --create-home --shell /bin/sh --user-group deploy-9router
user_created=1
bash "$release/install/install-key.sh" "$fixture/key.pub"
install -d -m 0755 /usr/local/libexec
install -m 0755 "$release/install/vps-deploy-9router" /usr/local/libexec/vps-deploy-9router
printf 'deploy-9router ALL=(root) NOPASSWD: /usr/local/libexec/vps-deploy-9router ""\n' > /etc/sudoers.d/vps-deploy-9router
chmod 0440 /etc/sudoers.d/vps-deploy-9router
visudo -cf /etc/sudoers.d/vps-deploy-9router >/dev/null
ssh-keygen -q -t ed25519 -N '' -f "$fixture/hostkey"
cat > "$fixture/sshd_config" <<EOF
Port $ssh_port
ListenAddress 127.0.0.1
HostKey $fixture/hostkey
PidFile $fixture/sshd.pid
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers deploy-9router deploy-demo
AllowTcpForwarding no
X11Forwarding no
Subsystem sftp internal-sftp
LogLevel ERROR
EOF
if [[ ! -d /run/sshd ]]; then install -d -m 0755 /run/sshd; sshd_directory_created=1; fi
/usr/sbin/sshd -f "$fixture/sshd_config" -E "$fixture/sshd.log"; sshd_pid=$(cat "$fixture/sshd.pid")
printf '[127.0.0.1]:%s %s\n' "$ssh_port" "$(cat "$fixture/hostkey.pub")" > "$fixture/known_hosts"
ssh_args=(-i "$fixture/key" -p "$ssh_port" -o UserKnownHostsFile="$fixture/known_hosts" -o StrictHostKeyChecking=yes -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=5)
ssh_request() { ssh "${ssh_args[@]}" deploy-9router@127.0.0.1 deployctl; }
assert_json() { python3 -c 'import json,sys; v=json.load(sys.stdin); assert all(v.get(k)==expected for k,expected in json.loads(sys.argv[1]).items()), v' "$1"; }
make_request() { python3 - "$1" "$2" "$3" "$4" "$release_sha" "$(sha256sum "$profile/app.yml" | cut -d' ' -f1)" <<'PY'
import json,sys
op,component,ident,image,ref,manifest=sys.argv[1:]
v=dict(version=1,op=op,app='9router',request_id=ident,component=component,platform_ref=ref,manifest_sha256=manifest,source_sha='a'*40)
if op=='deploy': v['image']=image
print(json.dumps(v,separators=(',',':')))
PY
}
fault() { printf '%s\n' "$1" > "$fixture/work/fault"; chmod 0600 "$fixture/work/fault"; }
interrupted_status() { local id=$1 expected=${2:-recovery_required} outcome
  for _ in {1..90}; do
    outcome=$(printf '{"version":1,"op":"status","app":"9router","request_id":"%s"}' "$id" | ssh_request)
    if [[ $(python3 -c 'import json,sys;print(json.load(sys.stdin)["status"])' <<< "$outcome") == "$expected" ]]; then printf '%s\n' "$outcome"; return 0; fi
    sleep .2
  done
  echo "No $expected status: $id" >&2; printf '%s\n' "$outcome" >&2; journalctl -u "vps-deploy-9router@$id.service" --no-pager -n 25 >&2; return 1
}
poll() { local id=$1 outcome
  for _ in {1..90}; do
    outcome=$(printf '{"version":1,"op":"status","app":"9router","request_id":"%s"}' "$id" | ssh_request)
    case "$(python3 -c 'import json,sys;print(json.load(sys.stdin)["status"])' <<< "$outcome")" in
      complete) printf '%s\n' "$outcome"; return 0 ;;
      failed|recovery_required) echo "$outcome" >&2; journalctl -u "vps-deploy-9router@$id.service" --no-pager -n 25 >&2; return 1 ;;
    esac
    sleep 1
  done
  echo "Timeout waiting for $id" >&2; return 1
}
unit_ids='fixture-bad-route fixture-receipt fixture-started fixture-crash fixture-reconcile fixture-crash-reconcile fixture-after-rename fixture-after-reconcile fixture-after-rollback fixture-ack-before fixture-ack-reconcile fixture-ack-rollback fixture-committed fixture-commit-reconcile fixture-commit-rollback fixture-stale-ack fixture-deploy fixture-rollback fixture-rtk fixture-rtk-bad fixture-rtk-started fixture-rtk-reconcile fixture-busy fixture-parallel fixture-shared-lock'
mkdir -m 0700 "$fixture/registry"
docker run -d --name fixture-registry -p 127.0.0.1:5000:5000 -v "$fixture/registry:/var/lib/registry" registry:2 >/dev/null
for _ in {1..30}; do curl -fsS http://127.0.0.1:5000/v2/ >/dev/null 2>&1 && break; sleep .2; done
for name in first second rtk rtk-bad; do
  mode=app; repo=9router
  if [[ $name == rtk || $name == rtk-bad ]]; then repo="rtk-sidecar"; fi
  [[ $name != rtk ]] || mode=rtk
  docker build -q --build-arg FIXTURE_MODE="$mode" --label "fixture.revision=$name" -t "$registry/$repo:$name" "$root/tests/integration" >/dev/null
  docker push "$registry/$repo:$name" >/dev/null
  docker pull "$registry/$repo:$name" >/dev/null
  docker image inspect "$registry/$repo:$name" --format '{{index .RepoDigests 0}}' > "$fixture/$name.ref"
done
first=$(cat "$fixture/first.ref"); second=$(cat "$fixture/second.ref"); rtk=$(cat "$fixture/rtk.ref"); rtk_bad=$(cat "$fixture/rtk-bad.ref")
docker network create edge-9router >/dev/null
export RTK_IMAGE=$rtk RTK_NETWORK=9router-rtk RTK_PROJECT=9router-rtk
/usr/bin/docker compose -f "$release/apps/9router/docker-compose.rtk.yml" up -d rtk >/dev/null
docker network inspect 9router-rtk | python3 -c 'import json,sys; net=json.load(sys.stdin)[0]; assert net["Internal"] is True and net["Driver"]=="bridge"'
docker inspect 9router-rtk-rtk-1 | python3 -c 'import json,sys; c=json.load(sys.stdin)[0]; assert not (c["NetworkSettings"]["Ports"] or {}).get("8080/tcp") and set(c["NetworkSettings"]["Networks"])=={"9router-rtk"}'
export IMAGE_REF=$first INITIAL_PASSWORD=fixture-not-a-secret DASHBOARD_HOST=dashboard.platform-smoke.test API_HOST=$api EDGE_NETWORK=edge-9router
/usr/bin/docker compose --env-file "$profile/runtime.env" -p 9router -f "$release/apps/9router/docker-compose.prod.yml" up -d 9router-blue >/dev/null
cat > "$fixture/dynamic/shared.yml" <<'YAML'
http:
  middlewares:
    deny-internal:
      ipAllowList: {sourceRange: ["192.0.2.0/24"]}
    tunnel-only:
      headers: {customRequestHeaders: {X-Fixture: "trusted"}}
    public-api-rate-limit:
      rateLimit: {average: 1000, burst: 1000}
    security-headers:
      headers: {frameDeny: true}
  routers:
    fixture-sentinel:
      rule: "Host(`sentinel.platform-smoke.test`)"
      entryPoints: [web]
      service: sentinel
  services:
    sentinel:
      loadBalancer:
        servers: [{url: "http://9router-blue:20128"}]
YAML
# Middleware definitions are intentionally independent; the sentinel is byte-for-byte invariant.
bash "$release/apps/9router/adapter.sh" blue 11111111111111111111111111111111 dashboard.platform-smoke.test legacy.platform-smoke.test "$api" > "$fixture/dynamic/9router.yml"
chmod 0644 "$fixture/dynamic/"*.yml
sha256sum "$fixture/dynamic/shared.yml" > "$fixture/sentinel.sha"
cat > "$fixture/traefik.yml" <<'YAML'
entryPoints:
  web:
    address: ":80"
providers:
  file:
    directory: /etc/traefik/dynamic
    watch: true
log:
  level: ERROR
YAML
docker run -d --name edge-traefik --network edge-9router -p 127.0.0.1:18080:80 -v "$fixture/dynamic:/etc/traefik/dynamic:ro" -v "$fixture/traefik.yml:/etc/traefik/traefik.yml:ro" traefik:v3.7.13 >/dev/null
for _ in {1..40}; do if curl -fsS --cacert "$ca" "https://$api/api/health" | python3 -c 'import json,sys;assert json.load(sys.stdin)["deployment_slot"]=="blue"' 2>/dev/null; then break; fi; sleep .5; done
curl -fsS --cacert "$ca" "https://$api/api/health" | assert_json '{"deployment_slot":"blue"}'
"$release/bin/deployctl" adopt --app 9router --strict | assert_json '{"healthy":true}'
# Existing state and route come from the immutable baseline, before any new enrollment.
install -d -m 0755 "$new_release"
for area in bin lib apps schema install registry hosts; do cp -a "$new_root/$area" "$new_release/$area"; done
install -d -m 0755 "$new_release/apps/demo"
cp "$new_root/tests/integration/fixtures/demo/registry.yml" "$new_release/registry/demo.yml"
cp "$new_root/tests/integration/fixtures/demo/adapter.sh" "$new_root/tests/integration/fixtures/demo/docker-compose.prod.yml" "$new_release/apps/demo/"
python3 - "$new_release" "$fixture" "$api" "$ssh_port" <<'PY'
import pathlib, sys, yaml
release, work, api, port = sys.argv[1:]
release = pathlib.Path(release)
reg = release/'registry/9router.yml'
value = yaml.safe_load(reg.read_text())
value['host'] = 'fixture-local'
reg.write_text(yaml.safe_dump(value, sort_keys=False))
host = yaml.safe_load((release/'hosts/oracle-main.yml').read_text())
host['host'] = 'fixture-local'
host['ssh'].update(address='127.0.0.1', port=int(port))
host['traefik']['dynamic_dir'] = work+'/dynamic'
host['apps']['9router'].update(api_host=api, dashboard_host='dashboard.platform-smoke.test', dashboard_alias_host='legacy.platform-smoke.test', work_dir=work+'/work')
host['apps']['demo'] = dict(api_host='demo.fixture.test', dashboard_host='', dashboard_alias_host='', work_dir=work+'/demo', compose_project='demo', edge_network='edge-demo', route_name='demo.yml')
(release/'hosts/fixture-local.yml').write_text(yaml.safe_dump(host, sort_keys=False))
PY
host_fingerprint=$(ssh-keygen -lf "$fixture/hostkey.pub" | cut -d' ' -f2)
python3 - "$new_release/hosts/fixture-local.yml" "$fixture/hostkey.pub" "$host_fingerprint" <<'PY'
import pathlib, sys, yaml
path = pathlib.Path(sys.argv[1]); host = yaml.safe_load(path.read_text())
host['ssh']['host_key'] = ' '.join(pathlib.Path(sys.argv[2]).read_text().split()[:2])
host['ssh']['fingerprint'] = sys.argv[3]
path.write_text(yaml.safe_dump(host, sort_keys=False))
PY
chown -R root:root "$new_release"
chmod -R go-w "$new_release"
install -d -m 0700 "$fixture/source/.deploy"
cp "$profile/app.yml" "$fixture/source/.deploy/app.yml"
git -C "$fixture/source" init -q
git -C "$fixture/source" add .deploy/app.yml
git -C "$fixture/source" -c user.name=Fixture -c user.email=fixture@example.invalid commit -qm 'test: fixture caller manifest'
app_sha=$(git -C "$fixture/source" rev-parse HEAD)
state_before=$(sha256sum "$state/state.json" | cut -d' ' -f1)
route_before=$(sha256sum "$fixture/dynamic/9router.yml" | cut -d' ' -f1)
bash "$new_release/install/install.sh" --fixture --check --app 9router --host fixture-local --release "$new_sha" --app-source "$fixture/source" --app-ref "$app_sha" --public-key "$fixture/key.pub"
[[ $(sha256sum "$state/state.json" | cut -d' ' -f1) == "$state_before" && $(sha256sum "$fixture/dynamic/9router.yml" | cut -d' ' -f1) == "$route_before" ]]
bash "$new_release/install/install.sh" --fixture --app 9router --host fixture-local --release "$new_sha" --app-source "$fixture/source" --app-ref "$app_sha" --public-key "$fixture/key.pub"
[[ $(sha256sum "$state/state.json" | cut -d' ' -f1) == "$state_before" && $(sha256sum "$fixture/dynamic/9router.yml" | cut -d' ' -f1) == "$route_before" ]]
release=$new_release release_sha=$new_sha root=$new_root
"$release/bin/deployctl" status --app 9router --strict | assert_json '{"healthy":true}'
printf 'BASELINE_9ROUTER_MIGRATION_OK\n'
demo_profile=/etc/vps-deploy/apps/demo
demo_state=/var/lib/vps-deploy/apps/demo
install -d -m 0700 "$fixture/demo" "$demo_profile" "$demo_state" "$demo_state/requests"
python3 - "$new_release/registry/demo.yml" "$demo_profile/app.yml" <<'PY'
import pathlib,sys,yaml
source = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text())
pathlib.Path(sys.argv[2]).write_text(yaml.safe_dump(source['manifest'], sort_keys=False))
PY
install -m 0600 /dev/null "$demo_profile/runtime.env"
python3 - "$demo_profile/host.json" "$new_sha" "$fixture" "$arch" "$ca" <<'PY'
import json,sys
path,sha,work,arch,ca=sys.argv[1:]
value=dict(platform_ref=sha,dynamic_dir=work+'/dynamic',api_host='demo.fixture.test',dashboard_host='',dashboard_alias_host='',work_dir=work+'/demo',compose_project='demo',edge_network='edge-demo',route_name='demo.yml',fixture_ci=True,image_repository='localhost:5000/demo',architecture=arch,ca_bundle=ca)
with open(path,'w') as output: json.dump(value,output)
PY
chmod 0600 "$demo_profile/app.yml" "$demo_profile/host.json"
for tag in first second; do
  docker build -q --build-arg FIXTURE_MODE=app --label "fixture.demo=$tag" -t "$registry/demo:$tag" "$root/tests/integration" >/dev/null
  docker push "$registry/demo:$tag" >/dev/null
  docker pull "$registry/demo:$tag" >/dev/null
  docker image inspect "$registry/demo:$tag" --format '{{index .RepoDigests 0}}' > "$fixture/demo/$tag.ref"
done
demo_first=$(cat "$fixture/demo/first.ref"); demo_second=$(cat "$fixture/demo/second.ref")
docker network create edge-demo >/dev/null
docker network connect edge-demo edge-traefik
IMAGE_REF=$demo_first EDGE_NETWORK=edge-demo docker compose --env-file "$demo_profile/runtime.env" -p demo -f "$new_release/apps/demo/docker-compose.prod.yml" up -d demo-blue >/dev/null
bash "$new_release/apps/demo/adapter.sh" blue 22222222222222222222222222222222 '' '' demo.fixture.test > "$fixture/dynamic/demo.yml"
chmod 0644 "$fixture/dynamic/demo.yml"
for _ in {1..40}; do if curl -fsS --cacert "$ca" 'https://demo.fixture.test/healthz' | assert_json '{"deployment_slot":"blue"}' 2>/dev/null; then break; fi; sleep .5; done
curl -fsS --cacert "$ca" 'https://demo.fixture.test/healthz' | assert_json '{"deployment_slot":"blue"}'
ssh-keygen -q -t ed25519 -N '' -f "$fixture/demo-key"
bash "$new_release/install/install.sh" --fixture --check --app demo --host fixture-local --release "$new_sha" --app-source "$fixture/source" --app-ref "$app_sha" --public-key "$fixture/demo-key.pub" || demo_check_failed=1
[[ ${demo_check_failed:-} == 1 ]] # A 9router manifest cannot enroll demo.
cp "$demo_profile/app.yml" "$fixture/source/.deploy/app.yml"
git -C "$fixture/source" add .deploy/app.yml
git -C "$fixture/source" -c user.name=Fixture -c user.email=fixture@example.invalid commit -qm 'test: fixture demo manifest'
demo_sha=$(git -C "$fixture/source" rev-parse HEAD)
bash "$new_release/install/install.sh" --fixture --check --app demo --host fixture-local --release "$new_sha" --app-source "$fixture/source" --app-ref "$demo_sha" --public-key "$fixture/demo-key.pub"
demo_user_created=1
bash "$new_release/install/install.sh" --fixture --app demo --host fixture-local --release "$new_sha" --app-source "$fixture/source" --app-ref "$demo_sha" --public-key "$fixture/demo-key.pub"
"$new_release/bin/deployctl" adopt --app demo --strict | assert_json '{"healthy":true,"rtk_healthy":null}'
[[ $(sha256sum "$state/state.json" | cut -d' ' -f1) == "$state_before" && $(sha256sum "$fixture/dynamic/9router.yml" | cut -d' ' -f1) == "$route_before" ]]
printf 'SECOND_APP_ADOPT_OK\n'
demo_ssh() { ssh -i "$fixture/demo-key" -p "$ssh_port" -o UserKnownHostsFile="$fixture/known_hosts" -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes -o IdentitiesOnly=yes deploy-demo@127.0.0.1 deployctl; }
demo_request() { python3 - "$1" "$2" "$3" "$demo_sha" "$new_sha" "$(sha256sum "$demo_profile/app.yml" | cut -d' ' -f1)" <<'PY'
import json,sys
op,ident,image,source,platform,manifest=sys.argv[1:]
value=dict(version=1,op=op,app='demo',request_id=ident,component='app',platform_ref=platform,manifest_sha256=manifest,source_sha=source)
if op=='deploy': value['image']=image
print(json.dumps(value,separators=(',',':')))
PY
}
demo_poll() { local id=$1 answer
  for _ in {1..90}; do
    answer=$(printf '{"version":1,"op":"status","app":"demo","request_id":"%s"}' "$id" | demo_ssh)
    case "$(python3 -c 'import json,sys;print(json.load(sys.stdin)["status"])' <<< "$answer")" in
      complete) printf '%s\n' "$answer"; return 0 ;;
      failed|recovery_required) printf '%s\n' "$answer" >&2; return 1 ;;
    esac
    sleep 1
  done
  echo DEMO_TIMEOUT >&2; return 1
}
cross=$(printf '{"version":1,"op":"status","app":"9router"}' | demo_ssh || true)
printf '%s' "$cross" | assert_json '{"status":"failed","error_code":"APP_BINDING_MISMATCH"}'
cross=$(printf '{"version":1,"op":"status","app":"demo"}' | ssh_request || true)
printf '%s' "$cross" | assert_json '{"status":"failed","error_code":"APP_BINDING_MISMATCH"}'
(cd "$fixture/source" && DEPLOY_KEY_FILE="$fixture/demo-key" GITHUB_STEP_SUMMARY="$fixture/demo-summary" python3 "$new_root/scripts/ssh-request.py" --fixture --platform-root "$new_release" --app demo --host fixture-local --operation deploy --component app --source-sha "$demo_sha" --platform-ref "$new_sha" --config .deploy/app.yml --request-id demo-deploy --image "$demo_second")
demo_poll demo-deploy | assert_json '{"status":"complete","healthy":true,"rtk_healthy":null}'
curl -fsS --cacert "$ca" 'https://demo.fixture.test/healthz' | assert_json '{"deployment_slot":"green"}'
printf '%s' "$(demo_request rollback demo-rollback '')" | demo_ssh | assert_json '{"status":"running"}'
demo_poll demo-rollback | assert_json '{"status":"complete","healthy":true}'
printf '%s' "$(demo_request reconcile demo-reconcile '')" | demo_ssh | assert_json '{"status":"running"}'
demo_poll demo-reconcile | assert_json '{"status":"complete","healthy":true}'
[[ $(sha256sum "$state/state.json" | cut -d' ' -f1) == "$state_before" && $(sha256sum "$fixture/dynamic/9router.yml" | cut -d' ' -f1) == "$route_before" ]]
printf 'DEMO_DEPLOY_ROLLBACK_RECONCILE_OK\n'



foreign=$(printf '{"version":1,"op":"status","app":"acb"}' | ssh_request || true)
printf '%s' "$foreign" | assert_json '{"status":"failed","error_code":"APP_BINDING_MISMATCH"}'
for bad in 'id' 'sudo -n id'; do
  # shellcheck disable=SC2029 # Deliberately send these literal commands to the forced SSH endpoint.
  if ssh "${ssh_args[@]}" deploy-9router@127.0.0.1 "$bad" </dev/null >/dev/null 2>&1; then echo "Arbitrary command accepted: $bad" >&2; exit 1; fi
done
if printf 'ls\n' | sftp -b - -i "$fixture/key" -P "$ssh_port" -o UserKnownHostsFile="$fixture/known_hosts" -o StrictHostKeyChecking=yes -o BatchMode=yes -o IdentitiesOnly=yes deploy-9router@127.0.0.1 >/dev/null 2>&1; then echo 'SFTP accepted' >&2; exit 1; fi
if scp -O -P "$ssh_port" -i "$fixture/key" -o UserKnownHostsFile="$fixture/known_hosts" -o StrictHostKeyChecking=yes -o BatchMode=yes -o IdentitiesOnly=yes "$fixture/sentinel.sha" deploy-9router@127.0.0.1:/tmp/platform-smoke-injection >/dev/null 2>&1; then echo 'SCP accepted' >&2; exit 1; fi
[[ ! -e /tmp/platform-smoke-injection ]]
if ssh -W 127.0.0.1:5000 "${ssh_args[@]}" deploy-9router@127.0.0.1 </dev/null >/dev/null 2>&1; then echo 'Forwarding accepted' >&2; exit 1; fi
ssh-keygen -q -t ed25519 -N '' -f "$fixture/wrong-host"
printf '[127.0.0.1]:%s %s\n' "$ssh_port" "$(cat "$fixture/wrong-host.pub")" > "$fixture/wrong-known"
if printf '{"version":1,"op":"status","app":"9router"}' | ssh -i "$fixture/key" -p "$ssh_port" -o UserKnownHostsFile="$fixture/wrong-known" -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes -o IdentitiesOnly=yes deploy-9router@127.0.0.1 deployctl >/dev/null 2>&1; then echo 'Wrong host key accepted' >&2; exit 1; fi
printf '{"version":1,"op":"status","app":"9router"}' | ssh_request | assert_json '{"healthy":true}'
[[ $(curl --silent --output /dev/null --write-out '%{http_code}' --cacert "$ca" "https://$api/internal") == 403 ]]
[[ $(curl --silent --output /dev/null --write-out '%{http_code}' --cacert "$ca" "https://$api/api/settings") == 403 ]]
curl -fsS --cacert "$ca" 'https://sentinel.platform-smoke.test/api/health' | assert_json '{"deployment_slot":"blue"}'
# Malformed shared YAML fails before Docker; restore the fixture's own sentinel bytes.
cp "$fixture/dynamic/shared.yml" "$fixture/shared.saved"
printf 'http: {routers: {fixture-sentinel: 1, fixture-sentinel: 2}}\n' > "$fixture/dynamic/shared.yml"
printf '%s' "$(make_request deploy app fixture-bad-route "$second")" | ssh_request | assert_json '{"status":"running"}'
if poll fixture-bad-route 2> "$fixture/bad-route.log"; then echo 'Malformed shared YAML accepted' >&2; exit 1; fi
[[ $(docker inspect -f '{{.State.Running}}' 9router-blue) == true ]]
if docker container inspect 9router-green >/dev/null 2>&1; then echo 'Candidate started before preflight' >&2; exit 1; fi
cp "$fixture/shared.saved" "$fixture/dynamic/shared.yml"
sha256sum -c "$fixture/sentinel.sha" >/dev/null
printf '{"version":1,"op":"deploy","app":"9router","component":"app","request_id":"invalid-image","platform_ref":"%s","source_sha":"%040d","manifest_sha256":"%s","image":"localhost:5000/9router:latest"}' "$release_sha" 0 "$(sha256sum "$profile/app.yml" | cut -d' ' -f1)" | ssh_request > "$fixture/rejected.json" || true
assert_json '{"status":"failed","error_code":"INVALID_IMAGE"}' < "$fixture/rejected.json"
fault receipt_saved
receipt_req=$(make_request reconcile app fixture-receipt '')
printf '%s' "$receipt_req" | ssh_request > "$fixture/receipt.out" 2>&1 || true
[[ -f $state/requests/fixture-receipt/request.json && ! -e $state/requests/fixture-receipt/started ]]
rm "$fixture/work/fault"
printf '%s' "$receipt_req" | ssh_request | assert_json '{"status":"running"}'
poll fixture-receipt | assert_json '{"status":"complete","healthy":true}'
fault started
printf '%s' "$(make_request reconcile app fixture-started '')" | ssh_request | assert_json '{"status":"running"}'
interrupted_status fixture-started | assert_json '{"status":"recovery_required"}'
[[ -f $state/requests/fixture-started/started && ! -e $state/requests/fixture-started/result.json ]]
rm "$fixture/work/fault"
printf '%s' "$(make_request reconcile app fixture-reconcile '')" | ssh_request | assert_json '{"status":"running"}'
poll fixture-reconcile | assert_json '{"status":"complete","healthy":true}'
# Kill after durable publish intent, before the route rename; reconcile must retain blue.
fault publishing
printf '%s' "$(make_request deploy app fixture-crash "$second")" | ssh_request | assert_json '{"status":"running"}'
interrupted_status fixture-crash | assert_json '{"status":"recovery_required"}'
rm "$fixture/work/fault"
printf '%s' "$(make_request reconcile app fixture-crash-reconcile '')" | ssh_request | assert_json '{"status":"running"}'
poll fixture-crash-reconcile | assert_json '{"status":"complete","healthy":true}'
curl -fsS --cacert "$ca" "https://$api/api/health" | assert_json '{"deployment_slot":"blue"}'
sha256sum -c "$fixture/sentinel.sha" >/dev/null
fault after_rename
printf '%s' "$(make_request deploy app fixture-after-rename "$second")" | ssh_request | assert_json '{"status":"running"}'
interrupted_status fixture-after-rename | assert_json '{"status":"recovery_required"}'
rm "$fixture/work/fault"
python3 - "$fixture/dynamic/9router.yml" "$state/state.json" <<'PY'
import json,sys,yaml
route=yaml.safe_load(open(sys.argv[1]))['http']; state=json.load(open(sys.argv[2])); assert state['active']['slot']=='blue' and state['operation']['phase']=='publishing'; assert route['services']['9router-service']['loadBalancer']['servers']==[{'url':'http://9router-green:20128'}]
PY
printf '%s' "$(make_request reconcile app fixture-after-reconcile '')" | ssh_request | assert_json '{"status":"running"}'
poll fixture-after-reconcile | assert_json '{"status":"complete","healthy":true}'
curl -fsS --cacert "$ca" "https://$api/api/health" | assert_json '{"deployment_slot":"green"}'
printf '%s' "$(make_request rollback app fixture-after-rollback '')" | ssh_request | assert_json '{"status":"running"}'
poll fixture-after-rollback | assert_json '{"status":"complete","healthy":true}'
curl -fsS --cacert "$ca" "https://$api/api/health" | assert_json '{"deployment_slot":"blue"}'
fault ack_before_commit
printf '%s' "$(make_request deploy app fixture-ack-before "$second")" | ssh_request | assert_json '{"status":"running"}'
interrupted_status fixture-ack-before | assert_json '{"status":"recovery_required"}'
rm "$fixture/work/fault"
python3 - "$state/state.json" <<'PY'
import json,sys
state=json.load(open(sys.argv[1])); assert state['active']['slot']=='blue' and state['operation']['phase']=='publishing'
PY
printf '%s' "$(make_request reconcile app fixture-ack-reconcile '')" | ssh_request | assert_json '{"status":"running"}'
poll fixture-ack-reconcile | assert_json '{"status":"complete","healthy":true}'
curl -fsS --cacert "$ca" "https://$api/api/health" | assert_json '{"deployment_slot":"green"}'
printf '%s' "$(make_request rollback app fixture-ack-rollback '')" | ssh_request | assert_json '{"status":"running"}'
poll fixture-ack-rollback | assert_json '{"status":"complete","healthy":true}'
fault committed
printf '%s' "$(make_request deploy app fixture-committed "$second")" | ssh_request | assert_json '{"status":"running"}'
interrupted_status fixture-committed | assert_json '{"status":"recovery_required"}'
rm "$fixture/work/fault"
python3 - "$state/state.json" <<'PY'
import json,sys
state=json.load(open(sys.argv[1])); assert state['active']['slot']=='green' and state['operation']['phase']=='committed'
PY
printf '%s' "$(make_request reconcile app fixture-commit-reconcile '')" | ssh_request | assert_json '{"status":"running"}'
poll fixture-commit-reconcile | assert_json '{"status":"complete","healthy":true}'
printf '%s' "$(make_request rollback app fixture-commit-rollback '')" | ssh_request | assert_json '{"status":"running"}'
poll fixture-commit-rollback | assert_json '{"status":"complete","healthy":true}'
# The TLS front supplies old valid identity after Traefik's rename. CAS restore must ACK old.
cp "$fixture/dynamic/9router.yml" "$fixture/route-before-ack"
touch "$fixture/stale-public-ack"
printf '%s' "$(make_request deploy app fixture-stale-ack "$second")" | ssh_request | assert_json '{"status":"running"}'
if poll fixture-stale-ack 2> "$fixture/stale-ack.log"; then echo 'Stale public generation committed' >&2; exit 1; fi
rm "$fixture/stale-public-ack"
cmp "$fixture/route-before-ack" "$fixture/dynamic/9router.yml"
for _ in {1..30}; do
  if "$release/bin/deployctl" status --app 9router --strict | assert_json '{"healthy":true}' 2>/dev/null; then break; fi
  sleep 1
done
"$release/bin/deployctl" status --app 9router --strict | assert_json '{"healthy":true}'
[[ $(docker inspect -f '{{.State.Running}}' 9router-blue) == true ]]
# SSE begins through HTTPS before route publication; the old Docker slot must survive.
curl --silent --show-error --no-buffer --cacert "$ca" "https://dashboard.platform-smoke.test/stream" > "$fixture/stream.out" & stream_pid=$!
for _ in {1..30}; do
  n=$(docker exec 9router-blue wget -qO- http://127.0.0.1:20128/api/health | python3 -c 'import json,sys;print(json.load(sys.stdin)["active_requests"])')
  [[ $n == 0 ]] || break
  sleep .2
done
[[ $n == 1 ]] || { echo 'SSE counter did not start' >&2; exit 1; }
req=$(make_request deploy app fixture-deploy "$second")
printf '%s' "$req" | ssh_request | assert_json '{"status":"running"}'
printf '%s' "$req" | ssh_request | python3 -c 'import json,sys; r=json.load(sys.stdin); assert r["request_id"]=="fixture-deploy" and r["status"] in ("running","complete"),r'
poll fixture-deploy | assert_json '{"status":"complete","healthy":true,"draining":"blue"}'
python3 - "$fixture/dynamic/9router.yml" "$state/state.json" "$second" <<'PY'
import json,sys,yaml
route=yaml.safe_load(open(sys.argv[1]))['http']; state=json.load(open(sys.argv[2])); assert state['active']['slot']=='green' and state['active']['image']==sys.argv[3]; assert route['services']['9router-service']['loadBalancer']['servers']==[{'url':'http://9router-green:20128'}]
PY
[[ $(docker inspect -f '{{.Image}}' 9router-green) == "$(docker image inspect -f '{{.Id}}' "$second")" ]]
docker image inspect "$second" | python3 -c 'import json,sys; image=json.load(sys.stdin)[0]; assert image["Os"]=="linux" and image["Architecture"]==sys.argv[1] and sys.argv[2] in image["RepoDigests"]' "$arch" "$second"
[[ $(stat -c %a "$fixture/dynamic/9router.yml") == 644 ]]
sha256sum -c "$fixture/sentinel.sha" >/dev/null
[[ $(docker inspect -f '{{.State.Running}}' 9router-blue) == true ]]
"$release/bin/deployctl" cleanup-drains --app 9router >/dev/null
[[ $(docker inspect -f '{{.State.Running}}' 9router-blue) == true ]]
conflict=$(printf '%s' "$(make_request deploy app fixture-deploy "$first")" | ssh_request || true)
printf '%s' "$conflict" | assert_json '{"status":"failed","error_code":"REQUEST_CONFLICT"}'
# Stream release is signaled inside its persistent Docker volume; retained container stops only after zero.
docker exec 9router-blue touch /app/data/release-stream
wait "$stream_pid"; stream_pid=
python3 - "$fixture/stream.out" <<'PY'
import sys
assert open(sys.argv[1]).read().count('data:')==2
PY
for unsafe in unknown negative boolean; do
  docker exec 9router-blue sh -c "printf '%s' '$unsafe' > /app/data/health-override"
  "$release/bin/deployctl" cleanup-drains --app 9router >/dev/null
  [[ $(docker inspect -f '{{.State.Running}}' 9router-blue) == true ]]
done
docker exec 9router-blue rm /app/data/health-override
"$release/bin/deployctl" cleanup-drains --app 9router >/dev/null
[[ $(docker inspect -f '{{.State.Running}}' 9router-blue) == false ]]
printf '%s' "$(make_request rollback app fixture-rollback '')" | ssh_request | assert_json '{"status":"running"}'
poll fixture-rollback | assert_json '{"status":"complete","healthy":true}'
[[ $(docker inspect -f '{{.State.Running}}' 9router-blue) == true ]]
printf '%s' "$(make_request deploy rtk fixture-rtk "$rtk")" | ssh_request | assert_json '{"status":"running"}'
poll fixture-rtk | assert_json '{"status":"complete","rtk_healthy":true}'
sha256sum -c "$fixture/sentinel.sha" >/dev/null
before_route=$(sha256sum "$fixture/dynamic/9router.yml" | cut -d' ' -f1)
printf '%s' "$(make_request deploy rtk fixture-rtk-bad "$rtk_bad")" | ssh_request | assert_json '{"status":"running"}'
if poll fixture-rtk-bad 2> "$fixture/rtk-bad.log"; then echo 'Unhealthy sidecar accepted' >&2; exit 1; fi
python3 - "$state/state.json" "$state/requests/fixture-rtk-bad/result.json" "$rtk" <<'PY'
import json,sys
state=json.load(open(sys.argv[1])); result=json.load(open(sys.argv[2])); assert state['rtk']['current']==sys.argv[3] and result['error_code']=='RTK_UPGRADE_FAILED'
PY
fault rtk_started
printf '%s' "$(make_request deploy rtk fixture-rtk-started "$rtk_bad")" | ssh_request | assert_json '{"status":"running"}'
interrupted_status fixture-rtk-started | assert_json '{"status":"recovery_required"}'
rm "$fixture/work/fault"
python3 - "$state/state.json" "$rtk" <<'PY'
import json,sys
state=json.load(open(sys.argv[1])); assert state['rtk']['current']==sys.argv[2] and state['operation']['phase']=='rtk_started'
PY
printf '%s' "$(make_request reconcile rtk fixture-rtk-reconcile '')" | ssh_request | assert_json '{"status":"running"}'
poll fixture-rtk-reconcile | assert_json '{"status":"complete","rtk_healthy":true}'
[[ $(sha256sum "$fixture/dynamic/9router.yml" | cut -d' ' -f1) == "$before_route" ]]
# A held app lock makes concurrent systemd worker return APP_BUSY without touching route.
flock -x "$locks/9router@operation.lock" -c "touch '$fixture/lock-held'; sleep 8" & locker=$!
for _ in {1..30}; do [[ ! -e $fixture/lock-held ]] || break; sleep .1; done
[[ -e $fixture/lock-held ]]
printf '%s' "$(make_request reconcile app fixture-busy '')" | ssh_request >/dev/null
if poll fixture-busy 2> "$fixture/busy.log"; then echo 'Concurrent worker escaped lock' >&2; exit 1; fi
python3 - "$state/requests/fixture-busy/result.json" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))['error_code']=='APP_BUSY'
PY
wait "$locker"
sha256sum -c "$fixture/sentinel.sha" >/dev/null
# One app waits on candidate health while the other finishes an actual cutover.
docker exec demo-blue touch /app/data/health-gate-green
demo_route_before=$(sha256sum "$fixture/dynamic/demo.yml" | cut -d' ' -f1)
printf '%s' "$(demo_request deploy demo-parallel "$demo_second")" | demo_ssh | assert_json '{"status":"running"}'
for _ in {1..60}; do
  [[ -f $demo_state/state.json ]] && phase=$(python3 - "$demo_state/state.json" <<'PY'
import json,sys
value=json.load(open(sys.argv[1])); print((value['operation'] or {}).get('phase', ''))
PY
  )
  [[ ${phase:-} == prepared ]] && break
  sleep .2
done
[[ ${phase:-} == prepared ]]
printf '%s' "$(make_request deploy app fixture-parallel "$second")" | ssh_request | assert_json '{"status":"running"}'
poll fixture-parallel | assert_json '{"status":"complete","healthy":true}'
[[ $(sha256sum "$fixture/dynamic/demo.yml" | cut -d' ' -f1) == "$demo_route_before" ]]
[[ ! -f $demo_state/requests/demo-parallel/result.json ]]
docker exec demo-blue rm /app/data/health-gate-green
demo_poll demo-parallel | assert_json '{"status":"complete","healthy":true}'
sha256sum -c "$fixture/sentinel.sha" >/dev/null
printf 'PARALLEL_CANDIDATES_ISOLATED_OK\n'
wait_phase() { local file=$1 expected=$2 actual
  for _ in {1..90}; do
    actual=$(python3 - "$file" <<'PY'
import json,sys
try:
    value=json.load(open(sys.argv[1]))
    print((value['operation'] or {}).get('phase', ''))
except (OSError, ValueError):
    print('')
PY
    )
    [[ $actual == "$expected" ]] && return 0
    sleep .2
  done
  printf 'PHASE_TIMEOUT %s %s %s\n' "$file" "$expected" "$actual" >&2; return 1
}
docker exec 9router-green touch /app/data/health-gate-blue
docker exec demo-green touch /app/data/health-gate-blue
router_route_before=$(sha256sum "$fixture/dynamic/9router.yml" | cut -d' ' -f1)
demo_route_before=$(sha256sum "$fixture/dynamic/demo.yml" | cut -d' ' -f1)
printf '%s' "$(make_request deploy app fixture-shared-lock "$first")" | ssh_request | assert_json '{"status":"running"}'
printf '%s' "$(demo_request deploy demo-shared-lock "$demo_first")" | demo_ssh | assert_json '{"status":"running"}'
wait_phase "$state/state.json" prepared
wait_phase "$demo_state/state.json" prepared
exec {publish_fd}> "$locks/traefik.lock"
flock -x "$publish_fd"
docker exec 9router-green rm /app/data/health-gate-blue
docker exec demo-green rm /app/data/health-gate-blue
wait_phase "$state/state.json" candidate_ready
wait_phase "$demo_state/state.json" candidate_ready
[[ $(sha256sum "$fixture/dynamic/9router.yml" | cut -d' ' -f1) == "$router_route_before" && $(sha256sum "$fixture/dynamic/demo.yml" | cut -d' ' -f1) == "$demo_route_before" ]]
flock -u "$publish_fd"
exec {publish_fd}>&-
poll fixture-shared-lock | assert_json '{"status":"complete","healthy":true}'
demo_poll demo-shared-lock | assert_json '{"status":"complete","healthy":true}'
sha256sum -c "$fixture/sentinel.sha" >/dev/null
printf 'SHARED_PUBLISH_LOCK_OK\n'
shared_id=fixture-deploy
demo_reconcile=$(demo_request reconcile "$shared_id" '')
printf '%s' "$demo_reconcile" | demo_ssh | assert_json '{"status":"running"}'
demo_poll "$shared_id" | assert_json '{"status":"complete","healthy":true}'
[[ -f $state/requests/$shared_id/result.json && -f $demo_state/requests/$shared_id/result.json ]]
printf '%s' "$demo_reconcile" | demo_ssh | assert_json '{"status":"complete"}'
demo_conflict=$(printf '%s' "$(demo_request deploy "$shared_id" "$demo_second")" | demo_ssh || true)
printf '%s' "$demo_conflict" | assert_json '{"status":"failed","error_code":"REQUEST_CONFLICT"}'
printf 'APP_RECEIPT_ISOLATION_OK\n'



printf 'Real Docker/Traefik v3.7.13, TLS CA, forced SSH/systemd, identity, SSE drain, rollback, RTK, busy passed\n'
