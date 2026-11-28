#!/usr/bin/env python3
"""Edge load balancer for apps that run on several nodes (registry `replica_hosts`).

Source of truth: hosts/<node>.yml `edge` (id, tunnel, weight) and registry/<app>.yml `balance`.
`--operation render` writes edge-lb/config.mjs (committed; a test keeps it equal to the
registry). `survey` reports and `apply` makes Cloudflare match it:
- per node and zone, a proxied CNAME <id>-origin.<zone> to the node's tunnel, and the tunnel's
  ingress for every balanced hostname the node serves;
- the Worker `edge-lb` with its R2 bindings, routed on <hostname>/* for each balanced hostname
  (Workers Paid). Routes fail open: if the Worker cannot run, the hostname's own DNS record (the
  primary node's tunnel) serves everything, as before balancing. Other routes of those hostnames
  that run no Worker or this one are removed;
- with a `lease`: the Durable Object class Lease, the queue `edge-lb-writes` and its consumer,
  and a cron trigger every minute; Analytics Engine dataset `edge_lb` always, and the rate limit
  WRITE_LIMIT (every write from one address: 60 a minute per Cloudflare location).
Worker secrets (set once, kept across uploads): NODE_KEY, REPLAY_KEY, TELEGRAM_TOKEN,
TELEGRAM_CHAT_ID; `survey` lists missing ones. `stats` sums the last hour per node.
Adding a node: hosts/<node>.yml with `edge` and the apps it runs, the host in each app's
`replica_hosts`, node bootstrap (platform/README.md); then render, commit, apply.
"""
import argparse
import json
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
from core import Failure as CoreFailure, app_hosts, app_registration, host_registration  # noqa: E402
from tunnel_api import Client, Failure, inventory_list  # noqa: E402

WORKER = Path(__file__).with_name('edge-lb')
SCRIPT = 'edge-lb'
COMPATIBILITY_DATE = '2025-09-01'
QUEUE = 'edge-lb-writes'
DATASET = 'edge_lb'
MIGRATION = 'v1'
SECRETS = ('NODE_KEY', 'REPLAY_KEY', 'TELEGRAM_TOKEN', 'TELEGRAM_CHAT_ID')
CRON = '* * * * *'
# Namespace ids are account-wide integers; readers' writes peaked at 28 a minute per address.
WRITE_LIMIT = {'type': 'ratelimit', 'name': 'WRITE_LIMIT', 'namespace_id': '1101', 'simple': {'limit': 60, 'period': 60}}


def plan(root=ROOT):
    hosts = {path.stem: host_registration(root, path.stem) for path in sorted((root / 'hosts').glob('*.yml'))}
    nodes, sites, rules, buckets, tunnels = {}, {}, {}, {}, {}
    for path in sorted((root / 'registry').glob('*.yml')):
        registration = app_registration(root, path.stem)
        if 'balance' not in registration:
            continue
        app, balance, ids, bindings = path.stem, registration['balance'], [], []
        for name in app_hosts(registration):
            record = hosts.get(name)
            if not record or 'edge' not in record or app not in record['apps']:
                raise Failure('EDGE_NODE_REQUIRED:' + app + '@' + name)
            # shortcut: the node's egress address is its ssh.address (true for Oracle public IPs); the
            # Worker accepts X-Edge-Node only from it. Give hosts an explicit egress IP if that changes.
            edge = dict(record['edge'], ip=record['ssh']['address'], name=record['host'])
            if nodes.setdefault(edge['id'], edge) != edge:
                raise Failure('EDGE_NODE_ID_REUSED:' + edge['id'])
            ids.append(edge['id'])
            bindings.append(record['apps'][app]['api_host'])
        site = bindings[0]
        if len(set(bindings)) != 1 or site in sites:
            raise Failure('EDGE_SITE_POLICY:' + app)
        # shortcut: zone = last two labels (thedemontuan.dev); apply checks it against the account's zones.
        zone = '.'.join(site.split('.')[-2:])
        sites[site] = {'zone': zone, 'primary': ids[0], 'nodes': ids, 'rules': app, 'lease': balance.get('lease')}
        rules[app] = {'primary_paths': balance['primary_paths'], 'primary_cookies': balance.get('primary_cookies', []),
                      'sticky_seconds': balance.get('sticky_seconds', 0), 'fanout': balance.get('fanout', []),
                      'public_bucket': balance.get('public_bucket'), 'queue_paths': balance.get('queue_paths', []),
                      'immutable_paths': balance.get('immutable_paths', []), 'edge_cache': balance.get('edge_cache')}
        bucket = balance.get('public_bucket')
        if bucket and buckets.setdefault(bucket['binding'], bucket['bucket']) != bucket['bucket']:
            raise Failure('EDGE_BUCKET_BINDING_REUSED:' + bucket['binding'])
        for node in ids:
            tunnels.setdefault(node, set()).add(site)
    worker = {'nodes': {node: {key: nodes[node][key] for key in ('weight', 'ip', 'name')} for node in sorted(tunnels)}, 'sites': sites, 'rules': rules}
    return {'worker': worker, 'buckets': buckets, 'leased': any(site['lease'] for site in sites.values()),
            'tunnels': {node: (nodes[node]['tunnel'], sorted(hostnames)) for node, hostnames in tunnels.items()}}


def module(worker):
    # A JS module: the Workers upload API takes no JSON modules.
    return 'export default ' + json.dumps(worker, indent=2, sort_keys=True) + ';\n'


def rendered(root=ROOT):
    return module(plan(root)['worker'])


def zones(client, wanted):
    found = {zone['name']: zone['id'] for zone in inventory_list(client.get('/zones?per_page=50'))
             if zone.get('account', {}).get('id') == client.account and zone.get('name') in wanted}
    if set(found) != set(wanted):
        raise Failure('EDGE_ZONE_NOT_IN_ACCOUNT:' + ','.join(sorted(set(wanted) - set(found))))
    return found



def route_changes(client, zone_ids, wanted):
    changes = []
    for zone, patterns in wanted.items():
        path = '/zones/' + zone_ids[zone] + '/workers/routes'
        existing = {route['pattern']: route for route in inventory_list(client.get(path))}
        for pattern, script in patterns.items():
            route = existing.get(pattern)
            if route and route.get('script') not in (None, '', SCRIPT):
                raise Failure('ROUTE_OWNERSHIP_CONFLICT:' + pattern)
            body = {'pattern': pattern, 'request_limit_fail_open': True, 'script': script}
            if not route:
                changes.append(('POST', path, body))
            elif (route.get('script'), route.get('request_limit_fail_open')) != (script, True):
                changes.append(('PUT', path + '/' + route['id'], body))
        # A narrower route on a balanced hostname would take its paths away from the Worker.
        hosts = tuple(pattern[:-1] for pattern in patterns)
        for pattern, route in existing.items():
            if pattern not in patterns and pattern.startswith(hosts) and route.get('script') in (None, '', SCRIPT):
                changes.append(('DELETE', path + '/' + route['id'], {'pattern': pattern}))
    return changes


def result(client, method, path, body=None):
    """Whole `result` of endpoints outside tunnel_api's pagination policy (one page each)."""
    return client._response(method, path, body)[0]['result']


def bindings(edge, migration_tag):
    metadata = {'main_module': 'index.mjs', 'compatibility_date': COMPATIBILITY_DATE, 'keep_bindings': ['secret_text'],
                'bindings': [{'type': 'r2_bucket', 'name': name, 'bucket_name': bucket} for name, bucket in sorted(edge['buckets'].items())] +
                [{'type': 'analytics_engine', 'name': 'METRICS', 'dataset': DATASET}, WRITE_LIMIT]}
    if edge['leased']:
        metadata['bindings'] += [{'type': 'durable_object_namespace', 'name': 'LEASE', 'class_name': 'Lease'},
                                 {'type': 'queue', 'name': 'WRITES', 'queue_name': QUEUE}]
        if migration_tag != MIGRATION:
            metadata['migrations'] = {'new_tag': MIGRATION, 'new_sqlite_classes': ['Lease']}
    return metadata


def upload(client, edge, metadata):
    """Multipart script upload (Workers API); routes stay as they are."""
    parts = [('metadata', 'metadata.json', 'application/json', json.dumps(metadata).encode()),
             ('index.mjs', 'index.mjs', 'application/javascript+module', (WORKER / 'index.mjs').read_bytes()),
             ('config.mjs', 'config.mjs', 'application/javascript+module', module(edge['worker']).encode())]
    boundary = uuid.uuid4().hex
    body = b''.join(b'--%s\r\nContent-Disposition: form-data; name="%s"; filename="%s"\r\nContent-Type: %s\r\n\r\n%s\r\n'
                    % (boundary.encode(), name.encode(), filename.encode(), kind.encode(), data)
                    for name, filename, kind, data in parts) + b'--%s--\r\n' % boundary.encode()
    request = urllib.request.Request(
        'https://api.cloudflare.com/client/v4/accounts/' + client.account + '/workers/scripts/' + SCRIPT, data=body, method='PUT',
        headers={'Authorization': 'Bearer ' + client.token, 'Content-Type': 'multipart/form-data; boundary=' + boundary})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            if json.loads(response.read(1 << 20)).get('success') is not True:
                raise Failure('WORKER_UPLOAD_FAILED')
    except urllib.error.HTTPError as error:
        codes = [item.get('code') for item in json.loads(error.read(1 << 20) or b'{}').get('errors', [])][:8]
        raise Failure('WORKER_UPLOAD_FAILED: HTTP ' + str(error.code) + ' error_codes=' + json.dumps(codes)) from None


def run(client, operation):
    edge = plan()
    if (WORKER / 'config.mjs').read_text() != rendered():
        raise Failure('EDGE_CONFIG_STALE: run --operation render and commit')
    sites = edge['worker']['sites']
    zone_ids = zones(client, {site['zone'] for site in sites.values()})
    for host, site in sites.items():
        if not (host == site['zone'] or host.endswith('.' + site['zone'])):
            raise Failure('EDGE_ZONE_POLICY:' + host)
    routes = {}
    for host, site in sites.items():
        routes.setdefault(site['zone'], {})[host + '/*'] = SCRIPT
    route_plan = route_changes(client, zone_ids, routes)
    account = '/accounts/' + client.account
    script = account + '/workers/scripts/' + SCRIPT
    deployed = next((s for s in result(client, 'GET', account + '/workers/scripts') if s.get('id') == SCRIPT), {})
    queue = next((q for q in result(client, 'GET', account + '/queues') if q.get('queue_name') == QUEUE), None)
    schedules = [s['cron'] for s in result(client, 'GET', script + '/schedules')['schedules']] if deployed else []
    secrets = {s['name'] for s in result(client, 'GET', script + '/secrets')} if deployed else set()
    summary = {'operation': operation, 'nodes': edge['worker']['nodes'], 'sites': sorted(sites), 'missing_dns': [],
               'tunnel_changes': [],
               'route_changes': [(method, body['pattern']) for method, _, body in route_plan],
               'missing_secrets': sorted(set(SECRETS) - secrets) if edge['leased'] else [],
               'queue': bool(queue), 'schedules': schedules}
    if operation == 'apply':
        if edge['leased'] and not queue:
            queue = result(client, 'POST', account + '/queues', {'queue_name': QUEUE})
        upload(client, edge, bindings(edge, deployed.get('migration_tag')))
        if edge['leased']:
            consumers = result(client, 'GET', account + '/queues/' + queue['queue_id'] + '/consumers')
            if not any(c.get('script') == SCRIPT or c.get('script_name') == SCRIPT for c in consumers):
                result(client, 'POST', account + '/queues/' + queue['queue_id'] + '/consumers',
                       {'script_name': SCRIPT, 'type': 'worker', 'settings': {'batch_size': 10, 'max_retries': 100, 'max_wait_time_ms': 5000}})
        if schedules != ([CRON] if edge['leased'] else []):
            result(client, 'PUT', script + '/schedules', [{'cron': CRON}] if edge['leased'] else [])
        # Routes last: traffic reaches the Worker only once every origin answers.
        for method, path, body in route_plan:
            client.request(method, path, None if method == 'DELETE' else body)
        if route_changes(client, zone_ids, routes):
            raise Failure('EDGE_VERIFY_FAILED')
    return summary


def stats(client):
    """Last hour per node and outcome from Analytics Engine (needs Account Analytics Read)."""
    query = ('SELECT blob2 AS node, blob4 AS outcome, SUM(_sample_interval) AS requests, '
             'SUM(IF(double1 >= 500 OR double1 = 0, _sample_interval, 0)) AS errors, '
             'quantileExactWeighted(0.95)(double2, _sample_interval) AS p95_ms '
             "FROM " + DATASET + " WHERE timestamp > NOW() - INTERVAL '1' HOUR GROUP BY node, outcome ORDER BY node, outcome FORMAT JSON")
    request = urllib.request.Request('https://api.cloudflare.com/client/v4/accounts/' + client.account + '/analytics_engine/sql',
                                     data=query.encode(), method='POST', headers={'Authorization': 'Bearer ' + client.token})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read(1 << 20))['data']
    except urllib.error.HTTPError as error:
        raise Failure('EDGE_STATS_FAILED: HTTP ' + str(error.code)) from None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--operation', choices=('render', 'survey', 'apply', 'stats'), required=True)
    args = parser.parse_args()
    if args.operation == 'render':
        (WORKER / 'config.mjs').write_text(rendered())
        return
    print(json.dumps(stats(Client()) if args.operation == 'stats' else run(Client(), args.operation), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (Failure, CoreFailure, KeyError, TypeError, AttributeError) as error:
        print(str(error) if isinstance(error, (Failure, CoreFailure)) else 'CLOUDFLARE_INVENTORY_POLICY', file=sys.stderr)
        sys.exit(1)
