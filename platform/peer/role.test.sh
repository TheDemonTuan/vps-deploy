#!/usr/bin/env bash
# Self-check for role.sh (bash platform/peer/role.test.sh): a copy with its paths moved into a
# temporary directory, docker stubbed (the restore "finishes" unless $t/stuck exists), no sleeps.
# shellcheck disable=SC2034 # rc is read inside check's eval
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
mkdir -p "$t/bin" "$t/vol" "$t/peer" "$t/sync/crowdsec" "$t/etc"
cp write-position.sh "$t/"
sed -e "s#/etc/platform#$t/etc#g; s#/run/platform-role.lock#$t/lock#; s#/var/lib/docker/volumes/mc-hub-api-data/_data#$t/vol#;
  s#/var/lib/platform-peer#$t/peer#g; s#/srv/platform-sync/litestream#$t/sync#; s#sleep [0-9]*#:#g;
  s#chown 1000:1000#chown $(id -u):$(id -g)#; s#-o 1000 -g 1000#-o $(id -u) -g $(id -g)#" role.sh >"$t/role.sh"
printf 'NODE=n2\nROLE=replica\nLEASE_URL=http://lease.invalid\n' >"$t/etc/peer.env"
printf '# id ip host key\nn1 10.0.0.1 ecdsa-sha2-nistp256 AAAAone\nn2 10.0.0.2 ecdsa-sha2-nistp256 AAAAtwo\nn3 10.0.0.3 ecdsa-sha2-nistp256 AAAAthree\n' >"$t/etc/nodes"
cat >"$t/bin/docker" <<EOF
#!/usr/bin/env bash
echo "docker \$*" >>"$t/log"
case "\$1" in
  ps) cat "$t/running" 2>/dev/null ;;
  stop) : >"$t/running" ;;
  start|restart)
    if [ -e "$t/restart-fails" ]; then : >"$t/running"; exit 1; fi
    shift; printf '%s\n' "\$@" >"$t/running" ;;
  compose)
    if [[ "\$*" == *'--profile replica up'* ]] && [ ! -e "$t/stuck" ]; then
      echo restored >"$t/vol/mc-hub.db"; echo 00000000000000c0 >"$t/vol/mc-hub.db-txid"
    elif [[ "\$*" == *'--profile primary up'* ]] && [ -e "$t/primary-fails" ]; then exit 1; fi ;;
esac
EOF
cat >"$t/bin/sftp" <<EOF
#!/usr/bin/env bash
read -r op src dest
[ "\$op" = get ] && cp "$t/remote\$src" "\$dest"
EOF
chmod +x "$t/bin/"*
fail=0
run() {
  : >"$t/log"; echo "$1" >"$t/peer/writer"
  printf '{"writer":"%s","epoch":%s,"floor":%s}\n' "$1" "${2:-0}" "${3:-null}" >"$t/peer/lease"
  PATH="$t/bin:$PATH" bash "$t/role.sh" "${4:-reconcile}" >"$t/output" 2>&1; echo $?
}
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; sed 's/^/     /' "$t/output" "$t/log"; fail=1; fi; }
follows() { sed -n 's/^PRIMARY_SSH=//p' "$t/etc/litestream-primary.env" 2>/dev/null; }

echo replica >"$t/vol/role"; touch "$t/vol/mc-hub.db"; echo mc-hub-api-blue >"$t/running"
printf 'PRIMARY_SSH=10.0.0.1:22\nPRIMARY_HOST_KEY=ecdsa-sha2-nistp256 AAAAone\n' >"$t/etc/litestream-primary.env"
rc=$(run n1)
check "a replica already following the writer does nothing" '[ "$rc" = 0 ] && [ ! -s "$t/log" ]'

rc=$(run n3)
check "a new writer is followed from a fresh restore" '[ "$rc" = 0 ] && [ "$(follows)" = 10.0.0.3:22 ] &&
  grep -q "PRIMARY_HOST_KEY=ecdsa-sha2-nistp256 AAAAthree" "$t/etc/litestream-primary.env" && ls "$t"/vol/fenced-*/mc-hub.db >/dev/null 2>&1'
check "the apps stopped for it start again" 'grep -qx "docker start mc-hub-api-blue" "$t/log" && [ ! -e "$t/peer/stopped-apps" ]'

rc=$(run n9)
check "a writer missing from the nodes file is refused" '[ "$rc" = 1 ] && [ "$(follows)" = 10.0.0.3:22 ] && [ ! -s "$t/log" ]'

touch "$t/stuck"; rc=$(run n1)
check "an unfinished restore keeps the apps stopped and fails" '[ "$rc" = 1 ] && grep -qx mc-hub-api-blue "$t/peer/stopped-apps"'
rm "$t/stuck"; rc=$(run n1)
check "the next run finishes it" '[ "$rc" = 0 ] && grep -qx "docker start mc-hub-api-blue" "$t/log" && [ ! -e "$t/peer/stopped-apps" ]'

mkdir -p "$t/sync/mc-hub-api/ltx/9" "$t/vol/.mc-hub.db-litestream/ltx"; rc=$(run n2)
check "the writer's own node becomes primary with a new lineage" '[ "$rc" = 0 ] && [ "$(cat "$t/vol/role")" = primary ] &&
  [ ! -e "$t/sync/mc-hub-api" ] && [ -d "$t/sync/crowdsec" ] && [ ! -e "$t/vol/.mc-hub.db-litestream" ] && [ ! -e "$t/etc/litestream-primary.env" ] && grep -qx "docker restart mc-hub-api-blue" "$t/log"'
rc=$(run n2)
check "a settled primary does nothing" '[ "$rc" = 0 ] && [ ! -s "$t/log" ]'

mkdir -p "$t/sync/mc-hub-api/ltx/9" "$t/vol/.mc-hub.db-litestream/ltx"; rc=$(run n1)
check "a primary that lost the lease follows the new writer" '[ "$rc" = 0 ] && [ "$(cat "$t/vol/role")" = replica ] && [ "$(follows)" = 10.0.0.1:22 ]'
check "and stops serving its old lineage (but not the LAPI's copy)" '[ ! -e "$t/sync/mc-hub-api" ] && [ -d "$t/sync/crowdsec" ] && [ ! -e "$t/vol/.mc-hub.db-litestream" ]'

# Activate as a real shell invocation; only the node's external services and OS paths are replaced.
mkdir -p "$t/remote/litestream/mc-hub-api-7"; echo 7 >"$t/remote/litestream/mc-hub-api-7/epoch"
echo test-key >"$t/etc/edge-node-key"
rc=$(umask 077; run n1 7 null enable-quorum)
check 'activation keeps the key private and publishes a readable follower epoch' '[ "$rc" = 0 ] &&
  [ "$(stat -c %a "$t/vol/write-quorum.json")" = 600 ] && [ "$(stat -c %a "$t/vol/follower-epoch")" = 644 ] &&
  [ "$(cat "$t/vol/follower-epoch")" = 7 ] && grep -qx mc-hub-api-blue "$t/running"'
floor='{"epoch":7,"txid":"00000000000000c0"}'
rc=$(run n2 8 '{"epoch":7,"txid":"00000000000000c1"}')
check 'a database below the floor never becomes writable' '[ "$rc" != 0 ] && [ "$(cat "$t/vol/role")" = replica ] && [ ! -e "$t/peer/promoting" ]'
touch "$t/primary-fails"; rc=$(run n2 8 "$floor")
check 'failure to start replication does not publish primary' '[ "$rc" != 0 ] && [ "$(cat "$t/vol/role")" = replica ] && [ ! -e "$t/vol/writer-epoch" ]'
mkdir -p "$t/vol/.mc-hub.db-litestream"; echo retain >"$t/vol/.mc-hub.db-litestream/state"; echo retain >"$t/sync/mc-hub-api-8/ltx-sentinel"
rm "$t/primary-fails"; rc=$(run n2 9 "$floor")
check 'another epoch cannot resume the interrupted promotion' '[ "$rc" != 0 ] && [ ! -e "$t/sync/mc-hub-api-9" ] && [ "$(cat "$t/vol/role")" = replica ]'
touch "$t/restart-fails"; rc=$(run n2 8 "$floor")
check 'API restart failure leaves the promotion unfinished' '[ "$rc" != 0 ] && [ "$(cat "$t/vol/role")" = primary ] && [ -e "$t/peer/promoting" ] && [ ! -s "$t/running" ]'
rm "$t/restart-fails"; rc=$(run n2 8 "$floor")
check 'retry restores the stopped API without deleting data or restarting the lineage' '[ "$rc" = 0 ] &&
  grep -qx mc-hub-api-blue "$t/running" && [ "$(cat "$t/vol/mc-hub.db")" = restored ] &&
  [ "$(cat "$t/vol/.mc-hub.db-litestream/state")" = retain ] && [ "$(cat "$t/sync/mc-hub-api-8/ltx-sentinel")" = retain ] &&
  [ "$(cat "$t/vol/writer-epoch")" = 8 ] && [ ! -e "$t/peer/promoting" ] && [ ! -e "$t/peer/stopped-apps" ]'
exit $fail
