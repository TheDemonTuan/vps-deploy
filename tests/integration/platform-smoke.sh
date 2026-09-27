#!/usr/bin/env bash
set -euo pipefail
set -E
# shellcheck disable=SC2154 # rc is assigned when ERR trap executes.
trap 'rc=$?; printf "platform-smoke failed line=%s exit=%s\n" "$LINENO" "$rc" >&2; if [[ -f ${fixture:-/nonexistent}/sshd.log ]]; then cat "$fixture/sshd.log" >&2; fi' ERR
[[ $(id -u) == 0 && $(uname -s) == Linux && -n ${RUNNER_TEMP:-} ]] || { echo 'Requires sudo on disposable Ubuntu runner with RUNNER_TEMP' >&2; exit 1; }
export NO_PROXY='localhost,127.0.0.1,.platform-smoke.test'
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
fixture=$RUNNER_TEMP/vps-deploy-smoke
[[ $fixture == /tmp/* || $fixture == /home/runner/work/* ]] || { echo "RUNNER_TEMP outside fixture policy: $fixture" >&2; exit 1; }
[[ ! -e $fixture ]] || { echo "Fixture already exists: $fixture" >&2; exit 1; }
release_sha=$(git -C "$root" rev-parse HEAD)
[[ $release_sha =~ ^[0-9a-f]{40}$ ]] || exit 1
release=/opt/vps-deploy/releases/$release_sha
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
  if [[ -n ${publisher:-} ]]; then touch "$fixture/publisher-release"; wait "$publisher" 2>/dev/null; fi
  [[ -z ${tls_pid:-} ]] || { kill "$tls_pid"; wait "$tls_pid" 2>/dev/null; }
  [[ -z ${sshd_pid:-} ]] || { kill "$sshd_pid"; wait "$sshd_pid" 2>/dev/null; }
  if [[ -n ${stream_pid:-} ]]; then kill "$stream_pid" 2>/dev/null; wait "$stream_pid" 2>/dev/null; fi
  if [[ -n ${unit_ids:-} ]]; then
    for id in $unit_ids; do systemctl stop "vps-deploy-9router-$id" 2>/dev/null; done
  fi
  for name in edge-traefik 9router-blue 9router-green 9router-rtk-rtk-1 fixture-registry; do docker rm -f "$name" >/dev/null 2>&1; done
  for name in edge-9router 9router-rtk 9router_internal; do docker network rm "$name" >/dev/null 2>&1; done
  docker volume rm 9router-data >/dev/null 2>&1
  for tagged in localhost:5000/9router:first localhost:5000/9router:second localhost:5000/rtk-sidecar:rtk localhost:5000/rtk-sidecar:rtk-bad; do docker image rm "$tagged" >/dev/null 2>&1; done
  if [[ ${hosts_written:-} == 1 ]]; then sed -i '/# vps-deploy-smoke$/d' /etc/hosts; fi
  rm -f /etc/vps-deploy/fixture-ci /opt/vps-deploy/current /usr/local/libexec/vps-deploy-9router /etc/sudoers.d/vps-deploy-9router
  [[ -z ${user_created:-} ]] || userdel -r deploy-9router >/dev/null 2>&1
  rm -rf -- "$release" "$profile" "$state" "$fixture"
  if [[ ${sshd_directory_created:-} == 1 ]]; then rmdir /run/sshd 2>/dev/null || true; fi
}
for path in /etc/vps-deploy/fixture-ci "$profile" "$state" "$release" /opt/vps-deploy/current /usr/local/libexec/vps-deploy-9router /etc/sudoers.d/vps-deploy-9router; do
  [[ ! -e $path && ! -L $path ]] || { echo "Refusing occupied fixture path $path" >&2; exit 1; }
done
for name in edge-traefik 9router-blue 9router-green 9router-rtk-rtk-1 fixture-registry; do
  ! docker container inspect "$name" >/dev/null 2>&1 || { echo "Container occupied: $name" >&2; exit 1; }
done
for name in edge-9router 9router-rtk; do
  ! docker network inspect "$name" >/dev/null 2>&1 || { echo "Network occupied: $name" >&2; exit 1; }
done
! docker volume inspect 9router-data >/dev/null 2>&1 || { echo 'Volume occupied: 9router-data' >&2; exit 1; }
for tagged in localhost:5000/9router:first localhost:5000/9router:second localhost:5000/rtk-sidecar:rtk localhost:5000/rtk-sidecar:rtk-bad; do
  ! docker image inspect "$tagged" >/dev/null 2>&1 || { echo "Image tag occupied: $tagged" >&2; exit 1; }
done
trap cleanup EXIT
mkdir -m 0755 "$fixture"
mkdir -p "$fixture/dynamic" "$fixture/work" /opt/vps-deploy/releases /etc/vps-deploy/apps "$profile" /var/lib/vps-deploy/apps "$state/requests" "$locks"
chmod 0700 /etc/vps-deploy /etc/vps-deploy/apps "$profile" /var/lib/vps-deploy /var/lib/vps-deploy/apps "$state" "$state/requests" "$locks" "$fixture/work"
install -d -m 0755 "$release"
for area in bin lib apps schema install; do cp -a "$root/$area" "$release/$area"; done
chown -R root:root "$release"; chmod -R go-w "$release"
chmod 0755 "$release/bin/deployctl"
ln -s "$release" /opt/vps-deploy/current
install -m 0600 /dev/null /etc/vps-deploy/fixture-ci
printf '%s\n' "127.0.0.1 $api dashboard.platform-smoke.test legacy.platform-smoke.test sentinel.platform-smoke.test # vps-deploy-smoke" >> /etc/hosts
hosts_written=1
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=platform-smoke.test' -addext 'subjectAltName=DNS:api.platform-smoke.test,DNS:dashboard.platform-smoke.test,DNS:legacy.platform-smoke.test,DNS:sentinel.platform-smoke.test' -keyout "$fixture/server.key" -out "$cert" >/dev/null 2>&1
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
AllowUsers deploy-9router
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
  echo "No $expected status: $id" >&2; return 1
}
poll() { local id=$1 outcome
  for _ in {1..90}; do
    outcome=$(printf '{"version":1,"op":"status","app":"9router","request_id":"%s"}' "$id" | ssh_request)
    case "$(python3 -c 'import json,sys;print(json.load(sys.stdin)["status"])' <<< "$outcome")" in
      complete) printf '%s\n' "$outcome"; return 0 ;;
      failed|recovery_required) echo "$outcome" >&2; return 1 ;;
    esac
    sleep 1
  done
  echo "Timeout waiting for $id" >&2; return 1
}
unit_ids='fixture-bad-route fixture-receipt fixture-started fixture-crash fixture-reconcile fixture-after-rename fixture-after-reconcile fixture-after-rollback fixture-ack-before fixture-ack-reconcile fixture-ack-rollback fixture-committed fixture-commit-reconcile fixture-commit-rollback fixture-stale-ack fixture-deploy fixture-rollback fixture-rtk fixture-rtk-bad fixture-rtk-started fixture-rtk-reconcile fixture-busy'
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
CURL_CA_BUNDLE="$ca" bash "$release/lib/traefik.sh" probe "$api" || { curl -fsS --cacert "$ca" -D - "https://$api/api/health?deploy_probe=fixture" >&2; exit 1; }
"$release/bin/deployctl" adopt --app 9router --strict | assert_json '{"healthy":true}'
foreign=$(printf '{"version":1,"op":"status","app":"acb"}' | ssh_request || true)
printf '%s' "$foreign" | assert_json '{"status":"failed","error_code":"INVALID_APP"}'
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
if printf '{"version":1,"op":"status","app":"9router"}' | ssh "${ssh_args[@]}" -o UserKnownHostsFile="$fixture/wrong-known" deploy-9router@127.0.0.1 deployctl >/dev/null 2>&1; then echo 'Wrong host key accepted' >&2; exit 1; fi
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
# Hold the cooperative publisher lock, SIGKILL the real systemd worker after durable intent,
# then reconcile old route without replaying its request or stopping the serving blue slot.
flock -x "$locks/traefik.lock" -c "touch '$fixture/publisher-held'; while test ! -f '$fixture/publisher-release'; do sleep .1; done" & publisher=$!
for _ in {1..30}; do [[ ! -e $fixture/publisher-held ]] || break; sleep .1; done
[[ -e $fixture/publisher-held ]]
printf '%s' "$(make_request deploy app fixture-crash "$second")" | ssh_request | assert_json '{"status":"running"}'
for _ in {1..90}; do
  phase=$(python3 - "$state/state.json" <<'PY'
import json,sys
print((json.load(open(sys.argv[1])).get('operation') or {}).get('phase','waiting'))
PY
  )
  [[ $phase != publishing ]] || break
  sleep .3
done
[[ $phase == publishing ]] || { echo 'Candidate never reached publisher lock' >&2; exit 1; }
systemctl kill --kill-whom=main --signal=SIGKILL vps-deploy-9router-fixture-crash
touch "$fixture/publisher-release"; wait "$publisher"; publisher=
for _ in {1..20}; do
  interrupted=$(printf '{"version":1,"op":"status","app":"9router","request_id":"fixture-crash"}' | ssh_request)
  [[ $(python3 -c 'import json,sys;print(json.load(sys.stdin)["status"])' <<< "$interrupted") == running ]] || break
  sleep .2
done
printf '%s' "$interrupted" | assert_json '{"status":"recovery_required"}'
printf '%s' "$(make_request reconcile app fixture-reconcile '')" | ssh_request | assert_json '{"status":"running"}'
poll fixture-reconcile | assert_json '{"status":"complete","healthy":true}'
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
[[ $(docker inspect -f '{{.State.Running}}' 9router-green) == true ]]
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
poll fixture-rollback | assert_json '{"status":"complete","healthy":true,"draining":"green"}'
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
flock -x "$locks/9router.lock" -c "touch '$fixture/lock-held'; sleep 8" & locker=$!
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
printf 'Real Docker/Traefik v3.7.13, TLS CA, forced SSH/systemd, identity, SSE drain, rollback, RTK, busy passed\n'
