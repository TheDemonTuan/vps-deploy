#!/usr/bin/env bash
# Self-check for role.sh (bash platform/peer/role.test.sh): a copy with its paths moved into a
# temporary directory, docker stubbed (the restore "finishes" unless $t/stuck exists), no sleeps.
# shellcheck disable=SC2034 # rc is read inside check's eval
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
mkdir -p "$t/bin" "$t/vol" "$t/peer" "$t/sync/x" "$t/etc"
sed -e "s#/etc/platform#$t/etc#g; s#/run/platform-role.lock#$t/lock#; s#/var/lib/docker/volumes/mc-hub-api-data/_data#$t/vol#;
  s#/var/lib/platform-peer#$t/peer#g; s#/srv/platform-sync/litestream#$t/sync#; s#sleep [0-9]*#:#g" role.sh >"$t/role.sh"
printf 'NODE=n2\nROLE=replica\nLEASE_URL=http://lease.invalid\n' >"$t/etc/peer.env"
printf '# id ip host key\nn1 10.0.0.1 ecdsa-sha2-nistp256 AAAAone\nn2 10.0.0.2 ecdsa-sha2-nistp256 AAAAtwo\nn3 10.0.0.3 ecdsa-sha2-nistp256 AAAAthree\n' >"$t/etc/nodes"
cat >"$t/bin/docker" <<EOF
#!/usr/bin/env bash
echo "docker \$*" >>"$t/log"
case "\$1" in
  ps) cat "$t/running" 2>/dev/null ;;
  stop) : >"$t/running" ;;
  start|restart) shift; printf '%s\n' "\$@" >"$t/running" ;;
  compose) [[ "\$*" == *"--profile replica up"* ]] && [ ! -e "$t/stuck" ] && echo 00000000000000c0 >"$t/vol/mc-hub.db-txid"; true ;;
esac
EOF
chmod +x "$t/bin/docker"
fail=0
run() { : >"$t/log"; echo "$1" >"$t/peer/writer"; PATH="$t/bin:$PATH" bash "$t/role.sh" reconcile >/dev/null 2>&1; echo $?; }
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; sed 's/^/     /' "$t/log"; fail=1; fi; }
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

rc=$(run n2)
check "the writer's own node becomes primary with a new lineage" '[ "$rc" = 0 ] && [ "$(cat "$t/vol/role")" = primary ] &&
  [ -z "$(ls -A "$t/sync")" ] && [ ! -e "$t/etc/litestream-primary.env" ] && grep -qx "docker restart mc-hub-api-blue" "$t/log"'
rc=$(run n2)
check "a settled primary does nothing" '[ "$rc" = 0 ] && [ ! -s "$t/log" ]'

rc=$(run n1)
check "a primary that lost the lease follows the new writer" '[ "$rc" = 0 ] && [ "$(cat "$t/vol/role")" = replica ] && [ "$(follows)" = 10.0.0.1:22 ]'
exit $fail
