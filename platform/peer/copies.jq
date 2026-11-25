# Plans this node's copies of the peer's bans (peer.sh, section 1). Input: `cscli decisions list
# -o json --origin cscli`. $peer: the peer's decisions.json; $copies: the copies this node held after
# its last run ([{ids, value, scenario}]); $tomb: peer decision ids this node no longer copies.
# Prints one line per action:
#   tomb <peer id>                                an operator removed it here: keep it removed
#   keep <peer ids|-> <ip> <scenario>             copy present and still wanted
#   add <peer ids|-> <ip> <duration> <scenario>   copy to create
#   del <decision id>                             copy of a ban the peer no longer has
def secs: [scan("([0-9]+)([hms])") | (.[0] | tonumber) * {"h": 3600, "m": 60, "s": 1}[.[1]]] | add // 0;
def key: .value + " " + .scenario;
($skip | split(" ")) as $skip
# The other node is trusted for bans, not for their shape: plain IPs only (no ranges), never a node.
| [$peer[0][]? | select((.id == null or (.id | type == "number"))
    and (.value | type == "string" and test("^[0-9a-fA-F.:]{2,45}$")) and (.value | IN($skip[]) | not)
    and (.scenario | type == "string" and test("^[A-Za-z0-9_./-]{1,100}$"))
    and (.duration | type == "string" and test("^([0-9]+h)?([0-9]+m)?([0-9]+s)?$")))
    | .scenario = $tag + .scenario] as $exported
| [.[]?.decisions[]? | select(.scenario | startswith($tag))] as $mine
| ($mine | map({(key): true}) | add // {}) as $have
| ($exported | map(select(.id != null) | {(.id | tostring): .}) | add // {}) as $byid
# A copy held last run that is gone while the peer still bans it for over 3 minutes (more than its
# export can lag) was removed here by an operator: cscli or the Telegram controller. Tombstones last
# until the peer, told through unbans.json, drops the ban.
| ([$tomb[0][]? | numbers]
   + [$copies[0][]? | select($have[key] | not) | .ids[]? | numbers
      | select(($byid[tostring] // {duration: ""}).duration | secs > 180)]
   | unique | map(select($byid[tostring] != null))) as $tombs
| ($tombs | map({(tostring): true}) | add // {}) as $dead
| ($exported | map(select(.id == null or ($dead[.id | tostring] | not))) | group_by(key)
   | map({value: .[0].value, scenario: .[0].scenario, duration: (max_by(.duration | secs).duration),
          ids: ([.[].id | numbers | tostring] | if length == 0 then "-" else join(",") end)})) as $want
| ($want | map({(key): true}) | add // {}) as $wanted
| ($tombs[] | "tomb \(.)"),
  ($want[] | if $have[key] then "keep \(.ids) \(.value) \(.scenario)" else "add \(.ids) \(.value) \(.duration) \(.scenario)" end),
  ($mine[] | select($wanted[key] | not) | "del \(.id)")
