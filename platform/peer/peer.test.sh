#!/usr/bin/env bash
# Self-check for peer.sh's follower checks and alerts (bash platform/peer/peer.test.sh): a copy
# with its paths moved into a temporary directory, as replica n2 following n1 (writer and LAPI).
# The sftp stub lists the writer's newest transaction, then the writer commits one more and the
# followers apply it at once, before peer.sh goes on: the race that alerted every few hours.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
mkdir -p "$t/bin" "$t/vol" "$t/peer" "$t/run" "$t/sync" "$t/follow" "$t/metrics" "$t/etc"
cp write-position.sh "$t/"
sed -e "s#/etc/platform#$t/etc#g; s#/var/lib/platform-peer#$t/peer#g; s#/var/lib/docker/volumes/mc-hub-api-data/_data#$t/vol#;
  s#/run/platform-peer#$t/run#g; s#/srv/platform-sync/litestream#$t/sync#g; s#/var/lib/crowdsec/follow#$t/follow#g;
  s#/var/lib/node-exporter#$t/metrics#" peer.sh >"$t/peer.sh"
printf 'NODE=n2\nNODE_IP=10.0.0.2\nROLE=replica\nLEASE_URL=http://lease.invalid\nTELEGRAM_CHAT_ID=1\n' >"$t/etc/peer.env"
printf 'n1 10.0.0.1 ecdsa-sha2-nistp256 AAAAone\nn2 10.0.0.2 ecdsa-sha2-nistp256 AAAAtwo\n' >"$t/etc/nodes"
printf 'PRIMARY_SSH=10.0.0.1:22\n' >"$t/etc/litestream-primary.env"
echo token >"$t/etc/telegram-token"; echo key >"$t/etc/edge-node-key"
echo replica >"$t/vol/role"; echo n1 >"$t/peer/lapi"
echo 5000 >"$t/at"; printf '%016x\n' 5000 | tee "$t/vol/mc-hub.db-txid" >"$t/follow/crowdsec.db-txid"
cat >"$t/bin/curl" <<EOF
#!/usr/bin/env bash
cat >/dev/null
if [[ "\$*" == *lease.invalid* ]]; then echo '{"writer":"n1","epoch":0,"lapiGrant":false}'; exit; fi
n=\$((\$(cat "$t/sent" 2>/dev/null || echo 0) + 1)); echo "\$n" >"$t/sent"
{ echo "--- message \$n"; printf '%s\n' "\$@"; } >>"$t/telegram"
echo "{\"ok\":true,\"result\":{\"message_id\":\$n}}"
EOF
cat >"$t/bin/sftp" <<EOF
#!/usr/bin/env bash
cat >/dev/null
at=\$(cat "$t/at")
printf '/litestream/crowdsec/ltx/0/0000000000000001-%016x.ltx\n/litestream/mc-hub-api/ltx/0/0000000000000001-%016x.ltx\n' "\$at" "\$at"
echo \$((at + 1)) >"$t/at"
[ -e "$t/stuck" ] || printf '%016x\n' \$((at + 1)) | tee "$t/vol/mc-hub.db-txid" >"$t/follow/crowdsec.db-txid"
EOF
printf '#!/bin/sh\nexit 0\n' | tee "$t/bin/systemctl" >"$t/bin/docker"
chmod +x "$t/bin/"*
fail=0
run() { PATH="$t/bin:$PATH" bash "$t/peer.sh" >"$t/output" 2>&1; }
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; sed 's/^/     /' "$t/output" "$t/telegram" 2>/dev/null; fail=1; fi; }

run; run; run
check "a copy one transaction past the writer's listing is no problem" '[ ! -e "$t/telegram" ] &&
  [ "$(cat "$t/peer/crowdsec_follower.fails")" = 0 ] && [ "$(cat "$t/peer/litestream_follower.fails")" = 0 ]'

touch "$t/stuck"; for _ in 1 2 3 4; do run; done
check "a stuck copy alerts once, in plain words with where to start" '[ "$(grep -c "^--- message" "$t/telegram")" = 2 ] &&
  grep -qx "parse_mode=HTML" "$t/telegram" && grep -q "n2: CrowdSec ban database copy is behind" "$t/telegram" &&
  grep -q "litestream-crowdsec</code> on n2" "$t/telegram" && grep -q "ours is stuck at #5003" "$t/telegram" &&
  grep -q "n2: mc-hub database copy is behind" "$t/telegram"'

rm "$t/stuck"; run; run
check "its recovery replies to that alert" '[ "$(grep -c "n2: resolved after" "$t/telegram")" = 2 ] &&
  grep -qF "\"message_id\":1," "$t/telegram" && grep -qF "\"message_id\":2," "$t/telegram" &&
  [ ! -e "$t/peer/crowdsec_follower.alerted" ] && [ "$(grep -c "^--- message" "$t/telegram")" = 4 ]'
exit $fail
