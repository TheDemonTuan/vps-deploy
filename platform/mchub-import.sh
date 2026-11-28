#!/usr/bin/env bash
# mchub-import.sh BUNDLE_DIR: run `mc-hub-api import` for BUNDLE_DIR (content.json + the files it
# names) once, on the node that holds the edge lease (the writer), from the operator's machine.
# The other nodes need nothing: Litestream copies the database to them within about a second and
# the files go to R2, which they read; the script waits until every replica has the import.
# Then it clears each node's page cache (mc-hub's POST /internal/revalidate, from inside the
# container), so pages show the import at once and Cloudflare's edge copy within about 2 minutes.
# MCHUB_NODES: ssh aliases of every node (default: the host ids, hosts/*.yml).
set -euo pipefail
bundle=${1:?usage: mchub-import.sh BUNDLE_DIR}
[ -f "$bundle/content.json" ] || { echo "no $bundle/content.json" >&2; exit 2; }
nodes=${MCHUB_NODES:-n1-oci-sin1-arm-4c24g n2-oci-sin2-arm-4c24g n3-vhs-buf-x86-4c16g}
volume=/var/lib/docker/volumes/mc-hub-api-data/_data
# Replication position: on the writer the highest LTX end txid it published, on a replica the
# follower's -txid file (16 hex digits each, so they compare as strings).
position='ls /srv/platform-sync/litestream/mc-hub-api/ltx/*/ | sed -n "s/.*-\([0-9a-f]\{16\}\)\.ltx$/\1/p" | sort | tail -1'

writer="" target="" writers="" reachable=""
for host in $nodes; do
  # node id, lease writer as last renewed (every minute), database role, running mc-hub-api slot
  info=$(ssh -o ConnectTimeout=10 "$host" "sudo sh -c '. /etc/platform/peer.env; echo \$NODE \
    \$(cat /var/lib/platform-peer/writer 2>/dev/null || echo -) \$(cat $volume/role 2>/dev/null || echo \$ROLE) \
    \$(docker ps --format {{.Names}} | grep -E \"^mc-hub-api-(blue|green)\$\" | head -1)'") ||
    { echo "$host: unreachable, skipped (it catches up from the writer when back)"; continue; }
  read -r id lease role app <<<"$info"
  echo "$host: node $id, role $role, lease writer $lease, app ${app:-none}"
  reachable="$reachable $host" writers="$writers $lease"
  if [ "$id" = "$lease" ] && [ "$role" = primary ]; then
    [ -z "$target" ] || { echo "two nodes claim the writer; resolve the failover first" >&2; exit 1; }
    target=$host writer=$id container=$app
  fi
done
[ "$(tr ' ' '\n' <<<"$writers" | sort -u | grep -c .)" = 1 ] || { echo "nodes disagree on the writer (failover in progress?); retry in a minute" >&2; exit 1; }
[ -n "$target" ] && [ -n "$container" ] || { echo "no reachable node is both the lease writer and a running primary" >&2; exit 1; }

dir=/data/tmp/import-$(date +%s)-$$
echo "importing on $target ($writer, $container)"
tar -C "$bundle" -cf - . | ssh "$target" "sudo docker exec -i $container sh -c 'mkdir -p $dir && tar x -C $dir' &&
  { sudo docker exec $container /app/mc-hub-api import $dir; rc=\$?; sudo docker exec $container rm -rf $dir; exit \$rc; }"

sleep 3 # Litestream ships a change within about a second
want=$(ssh "$target" "sudo sh -c '$position'")
for host in $reachable; do
  [ "$host" = "$target" ] && continue
  for i in $(seq 60); do
    have=$(ssh "$host" "sudo cat $volume/mc-hub.db-txid 2>/dev/null" || true)
    [ -n "$have" ] && [[ ! $have < $want ]] && break
    [ "$i" = 60 ] && { echo "$host: replica at ${have:-none}, writer at $want after 60 s; check platform-peer/litestream" >&2; exit 1; }
    sleep 1
  done
  echo "$host: replica has it (txid $have)"
done
echo "done: every node serves the import"

# shortcut: a node unreachable now keeps its old pages until they expire (up to an hour); rerun then.
revalidate='const r = await fetch("http://127.0.0.1:8080/internal/revalidate", { method: "POST" }); if (r.status !== 204) { console.error(`HTTP ${r.status}`); process.exit(1); }'
for host in $reachable; do
  for c in $(ssh "$host" "sudo docker ps --format {{.Names}}" | grep -E '^mc-hub-(blue|green)$'); do
    if ssh "$host" "sudo docker exec $c bun -e '$revalidate'"; then echo "$host: $c page cache cleared"
    else echo "$host: $c page cache NOT cleared; POST /admin/revalidate from a signed-in admin tab" >&2; fi
  done
done
