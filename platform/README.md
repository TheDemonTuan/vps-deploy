# Multi-node platform: edge load balancer, replicas, node bootstrap

Balanced apps (`replica_hosts` in `registry/<app>.yml`) run on several Oracle nodes; everything
else stays on its registry `host`. Only Cloudflare sits in between:

```mermaid
flowchart LR
  C[Client] --> W[Worker edge-lb<br/>route host/*]
  W -- "resolveOverride n1-origin" --> T1[Tunnel A] --> N1[n1 Traefik<br/>primary]
  W -- "resolveOverride n2-origin" --> T2[Tunnel B] --> N2[n2 Traefik<br/>replica]
  W -- "/media/*.jpg" --> R2M[(R2 mc-hub-media)]
  N1 -- "Litestream file replica" --> F[n1 /srv/platform-sync]
  F -- "read-only SFTP, follow ~1 s" --> N2
  F -- "rclone hourly" --> R2D[(R2 mc-hub-db)]
  N1 -- "uploads (S3 API)" --> R2M
```

- **Routing** (`cloudflare/edge-lb/index.mjs`, rules from `registry/<app>.yml` `balance`):
  reads go to a node chosen by weighted rendezvous hashing of the client IP
  (`hosts/<node>.yml` `edge.weight`; lower on a node that also runs unbalanced services), so a
  client always lands on the same node and nodes share clients by weight. A 5xx (a read's 500
  too), a connect failure or no response headers within 10 s is retried once on the next node
  and (except a 500) marks the failed node last for 30 s. The cron's checks (every minute) put a
  node last for everyone while its last check failed, and a replica whose follower has not
  confirmed for 3 minutes that it is current (`peer.sh` sends `synced` with each renewal) while
  the writer renews; down nodes still serve when nothing else does. Writes (non-GET), `primary_paths`, `primary_cookies` and, for
  `sticky_seconds` after a write that returns content (not a 204 such as a view count), the same
  client go to the writer: the registry `host`, or with `lease` the node its Durable Object names
  (re-read every 30 s; see Failover). Reads among them (a signed-in admin's pages, a sticky
  client's) fail over like any read while the writer fails, never through the edge cache; writes
  do not (queued or an error).
  `fanout` repeats a request (the admin cache purge) on the other nodes after a delay.
  `X-Edge-Node: <id>` pins a read to one node, honoured only from a node's own IP (its
  `ssh.address`): the deploy probe (`lib/route.py`) uses it.
- **Edge features of leased sites** (mc-hub only):
  - `queue_paths` (views, comments, compat and feedback votes, feedback): while the writer
    answers 5xx or not at all, the write goes to Queue `edge-lb-writes` and the reader gets
    202 `{"queued": true}`; the consumer replays it to the writer with backoff (30 s up to an
    hour, 100 tries), signing the reader's address in `X-Edge-Replay` (Worker `REPLAY_KEY` =
    `edge-replay-key` in the mc-hub-api volume). Comments and feedback carry a Turnstile token
    that expires after 5 minutes: those are dropped (a 4xx) if the writer stays down longer.
  - `edge_cache`: GETs of the listed paths without the session cookie stay in the Cache API
    for `ttl_seconds` and are served stale for `stale_seconds` when every node fails; only
    responses marked `public` or `no-cache`. The key carries the lease's version, bumped after
    each `fanout` reached every node, so an admin's purge reaches every colo.
  - `immutable_paths` (`/_astro/`): served by the edge cache; a miss that a node answers 404
    (a deploy reaches the nodes one after another) is tried on the next node, and only 2xx
    is cached.
  - Cron every minute: `/healthz` of every site on every node, and whether the writer renewed
    the lease in the last 3 minutes; Telegram (Worker secrets `TELEGRAM_TOKEN`,
    `TELEGRAM_CHAT_ID`) after two failures in a row and on recovery.
  - `WRITE_LIMIT` (Workers rate limit, every site): a reader address gets 60 writes a minute per
    Cloudflare location, then 429 `RATE_LIMITED` with `Retry-After: 60` from the edge (readers
    peaked at 28). Node addresses are not limited; the API's per-endpoint throttles stay the
    real limits. Approximate, and addresses behind one carrier NAT share it.
  - Workers Analytics Engine dataset `edge_lb`, a point per request: node, method, outcome
    (origin, hit, stale, queued, bucket, limited), status, milliseconds.
    `edge_lb.py --operation stats` sums the last hour (token: Account Analytics Read).
- **Edge WAF & Rulesets** (`cloudflare/tofu/rulesets.tf`): `edge-probe-paths` on both zones
  blocks dotfiles (not `/.well-known/`), `*.php` and WordPress paths before the tunnel; on
  thedemontuan.dev `edge-free-managed` runs Cloudflare's Free Managed Ruleset except on
  monitor./metrics. tuannguyenviet.site keeps its Free ruleset rule (OmniRoute hosts only)
  and API path rules. Managed declaratively via OpenTofu in `cloudflare/tofu/`. Blocks show in
  Security → Events.
- **Data**: SQLite stays single-writer on the primary. Litestream (`litestream/`) writes its WAL
  changes to a local directory; each replica follows it over read-only SFTP (`sync/`) into its
  own file, and mc-hub-api opens that read-only (`DB_ROLE` = engine `NODE_ROLE`, or the volume's
  `role` file after a failover; writes there return 503 `READ_ONLY`, but the Worker never sends
  them). The primary mirrors that directory
  and `/data/backups` to R2 hourly; the mirror container never restarts by itself: `peer/` starts
  it only while the lease confirms the node as writer and stops it after three failed renewals,
  so an old primary back from a reboot cannot replace the new primary's R2 copy. `peer/` also
  writes `/data/backups/daily-<UTC date>.db` on the confirmed writer (VACUUM INTO, 14 kept on the
  node, every one in R2). Replication makes no R2 requests: following R2 directly
  listed ~480 objects a minute (Class A, beyond the free tier). Uploads are written locally and
  to R2; a node missing a file fetches it from R2.
- **SSR** stays on the node: mc-hub calls `http://edge-traefik:8082` (entrypoint `internal`,
  router `mc-hub-api-internal`).
- **Per-node limits**: Traefik rate limits run per node; with client affinity a visitor's
  requests (except writes, which go to the primary) are seen by one node. `peer/`
  (`platform-peer.timer`, every minute) renews the node's lease first (Telegram after two failed
  renewals). On a replica it checks that
  the follower keeps up, including when the writer's SFTP cannot be read at all (the follower
  uses the same link), and restarts the follower on the lease writer when it follows another
  node; Telegram after two bad runs and on recovery. The fleet is `/etc/platform/nodes`
  (`<id> <ip> <ECDSA host key>`, written by `ansible/`).
- **One CrowdSec LAPI** (`crowdsec_lapi_host`, n1; CrowdSec's multi-server setup): every node
  runs the agent (its own logs, AppSec on `172.31.254.1:7422`), the nftables bouncer and
  Traefik's bouncer; their alerts become decisions on n1, so a ban detected anywhere blocks
  everywhere, and the CrowdSec → Cloudflare controller on n1 is the only writer of the edge
  list. The other nodes reach n1's `172.31.254.1:8080` through `crowdsec-lapi.service`, an SSH
  forward as `crowdsec-lapi` (key per node, `from=` its address, `permitopen` that port only):
  no new open port. Agents (machine `n2`) and bouncers (`traefik-n2`, `cs-firewall-bouncer-n2`)
  are registered on n1 by `ansible/`. With n1 down, the other nodes keep serving with the
  decisions they hold (Traefik's bouncer is fail-open, `updateMaxFailure: -1`) but add no ban.
- **Unban once**: `cscli decisions delete -i <ip>` on n1, or the Telegram bot's unban; every
  node drops it within a minute and the controller takes the IP off Cloudflare.
- **No self-renewing bans**: the LAPI's first profile (`crowdsec/config/profiles.yaml`,
  `already_banned`) gives an IP that already has a ban no new one; the bouncer's own 403s used
  to re-ban it through `http-generic-403-bf`.
- **No ban for a missing User-Agent**: `crowdsec/config/appsec-configs/local-no-ua-scope.yaml` (AppSec config, listed in
  `acquis.d/appsec.yaml`) drops the hub's out-of-band `crowdsecurity/experimental-no-user-agent`:
  six header-less API reads banned the owner's network for 16 h. That network leaves through
  three ISPs, each address banned on its own, so the site failed for some connections only.
- **Controller** (`/opt/crowdsec-telegram-controller` on n1, no source repository: its releases
  are the source; change one with `deploy/install.py --check/--install --source <copy>`): it
  tracks LAPI decisions by id, so it pulls the stream with `dedup=false` (release
  `574071fe425d99ee`). LAPI's default deduplication hides a deleted ban while another ban on the
  same IP outlives it, and that ban then stayed on Cloudflare until it would have expired.

## Change weights, rules or nodes

Edit `hosts/*.yml` / `registry/*.yml`, then:

```sh
python3 cloudflare/edge_lb.py --operation render   # rewrites edge-lb/config.mjs; commit it
CLOUDFLARE_API_TOKEN=… CLOUDFLARE_ACCOUNT_ID=… python3 cloudflare/edge_lb.py --operation survey
CLOUDFLARE_API_TOKEN=… CLOUDFLARE_ACCOUNT_ID=… python3 cloudflare/edge_lb.py --operation apply
```

`apply` creates the queue, uploads the Worker with its bindings (R2, Durable Object, queue,
Analytics Engine; secrets are kept), its queue consumer and cron, and only then sets the routes
(fail-open, Workers Paid); DNS and tunnels are OpenTofu's (`cloudflare/tofu`). Token: Workers
Scripts Edit, Workers Routes Edit, Queues Edit, Zone Read. Worker secrets, once: `NODE_KEY` (also each node's `/etc/platform/edge-node-key`),
`REPLAY_KEY` (also `edge-replay-key` in each node's mc-hub-api volume, owner 1000, 0600: a
runtime.env key would change the containers' environment, which a release upgrade refuses),
`TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID` (`PUT .../workers/scripts/edge-lb/secrets`). Drain a node
with `weight: 0` (it still takes retries and pinned probes).

## Balance another app

1. Its routes must work on every node (same Traefik bindings in each `hosts/<node>.yml`).
2. State must be shared: a database writer only on `host` (read-only replica elsewhere, as
   mc-hub-api), files in R2; anything else in memory or on disk is per node.
3. Add `replica_hosts` and `balance` to `registry/<app>.yml`, render, release, install the app
   on the new hosts (below), point its caller workflow at every host (`host` first), apply.

## Add a node

`hosts/<host>.yml` is the inventory; `ansible/` gives every node the same platform layer
(packages, CrowdSec, networks, edge stack, sync, Litestream, peer, monitoring agent, deploy
engine prerequisites) from this repository. Run it from the operator workstation (ssh-agent with
the nodes' `opc` keys); CI only lints it.

1. **Instance**: Oracle Linux 9 or 10 (ARM), ingress only SSH 22 (security list and firewalld).
   Grow the boot volume (`oci-growfs -y`). Record the ed25519 host key from the OCI console
   serial log, not from a first connection. Oracle reclaims idle Always Free instances (over 7
   days, 95th-percentile CPU, network and A1 memory all under 20 %), which a lightly loaded
   replica is: `keepalive: true` in `ansible/host_vars/<host>.yml` on a node under 20 % memory, or
   upgrade its tenancy to Pay As You Go (Always Free resources stay free).
2. **Cloudflare** (dashboard): the node's IP in the IP filter of the R2 token in
   `litestream.env` (else the mirror and uploads fail there), and a tunnel
   `shared-edge-<host>` (remotely managed).
3. **Registry**: `hosts/<host>.yml` with `ssh` (address, port, fingerprint and `host_key`),
   `traefik`, `edge` (`id`, `tunnel`, `weight: 0`) and the balanced apps' bindings as on the
   other nodes; the host in each balanced app's `replica_hosts`; render.
4. **Platform**, from `ansible/` (the API token reads the new tunnel's token: Cloudflare Tunnel
   Read):

   ```sh
   export CLOUDFLARE_API_TOKEN=… CLOUDFLARE_ACCOUNT_ID=…
   ansible-playbook site.yml --check --diff   # every node: the new one appears in their fleet files
   ansible-playbook site.yml
   ```

   Shared secrets (alert bot, the Worker's `NODE_KEY`, R2 keys, origin certificates, the
   monitoring service token, GHCR login, app runtime env) are copied from `secrets_source`
   (`group_vars/edge.yml`) to a node that lacks them, never overwritten and never on the
   workstation; the sync and LAPI tunnel keys are generated on the node, its CrowdSec agent and
   bouncer keys on the LAPI node. Within a
   minute `peer.sh` starts `platform-role.service`, which follows the lease writer: the first
   `docker logs litestream` line is `entering follow mode`.
5. **Apps**: start `<app>-blue` from the release's Compose profile with the primary's current
   image and `NODE_ROLE=replica`, publish the adapter-rendered route (slot `blue`, a new
   generation). Installer `--check`, then apply, with `--host <host>` and the same deploy public
   key (`install/README.md`); `restorecon -R` the release.
6. `cloudflare/edge_lb.py --operation apply` with the new node's weight at 0 first (pinned probes
   only), then `deployctl adopt --app <app>` on the node,
   `systemctl enable --now vps-deploy-drain@<app>.timer`, and apply again with the real weight.
   Add the host to the app's caller workflow (after the primary host).

The monitoring hub (`monitor_hub: true`, n2) keeps its own `/etc/platform/monitor.env` (below);
Ansible writes only the agents'. Changing any node's platform files: edit them here, then the
same two commands (`--limit <host>` for one node). App routes in `/opt/platform/edge/dynamic`
belong to the deploy engine and are never touched.

## Fleet monitoring (replaced Beszel)

<https://monitor.thedemontuan.dev> (Cloudflare Access email login; Grafana trusts the Access JWT,
no second password), dashboard **Fleet**:

- **Edge routing**: requests, p95 and errors per node from edge-lb's Analytics Engine dataset,
  and a node × outcome × host table (`origin`, `hit`, `stale`, `queued`, `bucket`).
- **Lease and roles**: the lease writer as each node last saw it, primary/replica per node,
  whether the last lease renewal worked, replica lag in transactions (from `peer.sh`).
- **Nodes**: CPU, memory, disk, network, load, which scrape targets are up.
- **Containers**: memory and CPU per container (cAdvisor).
- **Traefik**: requests, 5xx and p95 per service on each node: what actually reached the node.

How it fits together (`platform/monitor/compose.yml`):

- Every node runs the `agent` profile: node-exporter, cAdvisor and vmagent, which scrapes them
  and Traefik every 30 s, labels everything `node=<NODE>` and pushes it to the hub, buffering up
  to 1 GB on disk while the hub is unreachable.
- The hub (n2) also runs `hub`: VictoriaMetrics (90 days) and Grafana. Its own vmagent writes to
  `127.0.0.1:8428`; the others push to `metrics.thedemontuan.dev` (tunnel B, Access app
  "Fleet Metrics Ingest": service token `monitor-vmagent` only, expires 2027-11-25), whose
  Traefik route only accepts `POST /api/v1/write`. The hub's `/etc/platform/monitor.env` (root
  0600, written by hand before `ansible/` runs there: it stops otherwise) is `NODE`,
  `METRICS_URL=http://127.0.0.1:8428/api/v1/write`, `CF_ACCOUNT_ID`, `CF_ANALYTICS_TOKEN` (user
  token `grafana-analytics-read`: Account Analytics Read, IP-filtered to the hub) and
  `ACCESS_AUD` (the Grafana Access app's AUD). The hub is one node: while it is down Grafana is
  down and the other agents buffer; its VictoriaMetrics data lives only on its disk (lost with
  n2's boot volume on 2026-11-26).
- Traefik on each node: a `metrics` entrypoint `:8899` with `metrics.prometheus` (entryPoint
  `metrics`, `addServicesLabels`), published only on `127.0.0.1:18082`. On the hub Traefik also
  joins `edge-monitor`, and `platform/monitor/traefik-monitor.yml` is
  `/opt/platform/edge/dynamic/monitor.yml`. Drain the node (weight 0) before recreating Traefik.
- CrowdSec: `dynamic/crowdsec.yml` on every node has `excludedHosts: [monitor.thedemontuan.dev,
  metrics.thedemontuan.dev]`. AppSec reads Grafana's query bodies (Analytics Engine SQL) and
  vmagent's binary remote-write bodies as SQL injection / HTTP violations and banned the owner's
  IP; both hosts only take requests Access already let through.
- Another node: `ansible/` (agent); it shows up in every panel by its `NODE`. Moving the hub: a new
  `grafana-analytics-read` token for the new hub's IP, tunnel ingress for both hostnames on the
  new hub's tunnel, the other nodes' `METRICS_URL` unchanged.

Not covered: logs (still `docker logs` on each node) and alert rules (alerts stay with the edge
cron, `peer.sh` and CrowdSec on Telegram; UptimeFlare checks Grafana's `/api/health`).

## Publish content (mc-hub `import`)

From the operator's machine, with the `vps-node-*` ssh aliases:

```sh
platform/mchub-import.sh path/to/bundle   # content.json + the files it names
```

It imports once, on the node that is both the lease writer and a running primary (refusing
while nodes disagree, mid-failover), then waits until every reachable replica's Litestream copy
has it. Nothing else is copied by hand: the files go to R2 during the import and the other nodes
read them from there. A replica refuses `import` by itself (read-only database). Pages show the
change within about 5 minutes (each node's page cache).

## Failover (the writer is down)

Reads keep working without action (the Worker retries the other nodes), readers' writes are
queued at the edge, everything else that writes fails for a few minutes. Once the writer has
failed 3 cron checks in a row (both its sites count), the edge gives the lease to the
highest-weight replica that passes its checks, renewed within 3 minutes and whose follower last
confirmed it current at most 2 minutes before the writer's last good check (when none
qualifies nothing changes; the PROBLEM alerts stand). That node's next `peer/` run promotes it as below. By hand,
on a replica:

```sh
sudo /opt/platform/peer/role.sh promote          # refused while the writer still renews
sudo /opt/platform/peer/role.sh promote --force  # the writer is up but must stop writing
```

The lease names this node; every colo sends writes here within 30 s, and the node keeps following
the old primary for 35 s first, so writes a still-running old writer accepted in that window are
kept (writes here return 503 `READ_ONLY` meanwhile; readers' writes are queued). The node then
starts Litestream as primary with a new lineage from its copy (writes the old primary had not
replicated, normally about a second, are lost), writes `role` into the mc-hub-api volume and
restarts mc-hub-api, which then opens the database writable. The mirror replaces the R2 copy with
the new lineage within the hour. The old primary, once it renews again, sees it lost the lease:
`platform-role.service` stops its Litestream, mirror and mc-hub-api, moves its database to
`fenced-<time>/` in the volume, follows the new primary and starts mc-hub-api read-only. If that
restore does not finish within 5 minutes, mc-hub-api stays stopped and the next `peer/` run tries
again (`/var/lib/platform-peer/stopped-apps` lists what to start). Switches never overlap
(`/run/platform-role.lock`). Promote it back the same way.

The deploy engine still follows the registry: until `host` and `replica_hosts` are swapped in
the balanced apps' registries (render, release, `edge_lb.py --operation apply`), mc-hub-api's
pre-release backup on the old `host` fails and stops its deploys; the `role` file keeps each
node's role across deploys either way.

## Restore from R2 (every node lost)

The mirror is a plain Litestream S3 replica. With the R2 token (IP-filtered to the nodes: add a
new node's IP first), a config `{dbs: [{path: /out/mc-hub.db, replica: {type: s3, bucket:
mc-hub-db, path: litestream/mc-hub-api, endpoint: https://<account>.r2.cloudflarestorage.com,
region: auto}}]}` and `litestream restore -config … /out/mc-hub.db` rebuild the database as of
the last hourly mirror; `r2:mc-hub-db/backups` holds `/data/backups` (the pre-release
`VACUUM INTO` snapshots).
