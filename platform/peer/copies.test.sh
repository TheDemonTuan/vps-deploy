#!/usr/bin/env bash
# Self-check for copies.jq (run on a node or locally: bash platform/peer/copies.test.sh).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fail=0

# plan <peer export> <copies state> <tombstones> <this node's cscli copies>
plan() {
  echo "$1" >"$t/peer"; echo "$2" >"$t/copies"; echo "$3" >"$t/tomb"
  jq -r --arg tag peer/n2: --arg skip "10.0.0.1 10.0.0.2" --slurpfile peer "$t/peer" \
    --slurpfile copies "$t/copies" --slurpfile tomb "$t/tomb" -f copies.jq <<<"$4" | sort | paste -sd'|'
}
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got '$2', want '$3'"; fail=1; fi; }

x='[{"id":5,"value":"192.0.2.7","scenario":"crowdsecurity/http-probing","duration":"3h0m0s"}]'
copy='[{"decisions":[{"id":40,"value":"192.0.2.7","scenario":"peer/n2:crowdsecurity/http-probing"}]}]'
held='[{"ids":[5],"value":"192.0.2.7","scenario":"peer/n2:crowdsecurity/http-probing"}]'

check "new peer ban is copied" "$(plan "$x" '[]' '[]' null)" \
  "add 5 192.0.2.7 3h0m0s peer/n2:crowdsecurity/http-probing"
check "present copy is kept" "$(plan "$x" "$held" '[]' "$copy")" \
  "keep 5 192.0.2.7 peer/n2:crowdsecurity/http-probing"
check "copy removed by an operator is tombstoned, not re-added" "$(plan "$x" "$held" '[]' null)" "tomb 5"
check "tombstone holds while the peer still bans it" "$(plan "$x" '[]' '[5]' null)" "tomb 5"
check "tombstone ends with the peer's ban; a new ban is copied" \
  "$(plan '[{"id":9,"value":"192.0.2.7","scenario":"crowdsecurity/http-probing","duration":"1h"}]' '[]' '[5]' null)" \
  "add 9 192.0.2.7 1h peer/n2:crowdsecurity/http-probing"
check "copy expiring with the peer's ban is not an unban" \
  "$(plan '[{"id":5,"value":"192.0.2.7","scenario":"crowdsecurity/http-probing","duration":"2m10s"}]' "$held" '[]' null)" \
  "add 5 192.0.2.7 2m10s peer/n2:crowdsecurity/http-probing"
check "copy of a ban the peer dropped is deleted" "$(plan '[]' "$held" '[]' "$copy")" "del 40"
check "nodes and ranges are never copied" \
  "$(plan '[{"id":1,"value":"10.0.0.1","scenario":"a","duration":"1h"},{"id":2,"value":"192.0.2.0/24","scenario":"a","duration":"1h"}]' '[]' '[]' null)" ""
check "an export without ids (older peer.sh) is still copied" \
  "$(plan '[{"value":"192.0.2.8","scenario":"a","duration":"1h"}]' '[]' '[]' null)" "add - 192.0.2.8 1h peer/n2:a"
exit $fail
