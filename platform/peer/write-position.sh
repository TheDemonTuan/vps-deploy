# Sourced by peer.sh and role.sh. Litestream advances its sidecar only after syncing the pages.
position() {
  local epoch txid
  epoch=$(cat "$volume/follower-epoch" 2>/dev/null) || return 1
  txid=$(cat "$volume/mc-hub.db-txid" 2>/dev/null) || return 1
  [[ $epoch =~ ^[0-9]{1,15}$ && $txid =~ ^[0-9a-f]{16}$ && -s "$volume/mc-hub.db" ]] || return 1
  [[ $(cat "$volume/follower-epoch" 2>/dev/null) == "$epoch" ]] || return 1
  printf '{"epoch":%s,"txid":"%s"}' "$epoch" "$txid"
}
