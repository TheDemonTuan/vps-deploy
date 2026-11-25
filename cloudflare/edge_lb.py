#!/usr/bin/env python3
"""Edge load balancer for apps that run on several nodes (registry `replica_hosts`).

Source of truth: hosts/<node>.yml `edge` (id, tunnel, weight) and registry/<app>.yml `balance`.
`--operation render` writes edge-lb/config.json (committed; a test keeps it equal to the
registry). `survey` reports and `apply` makes Cloudflare match it:
- per node and zone, a proxied CNAME <id>-origin.<zone> to the node's tunnel, and the tunnel's
  ingress for every balanced hostname the node serves;
- the Worker `edge-lb` with its R2 bindings, routed on <hostname>/* for each balanced hostname
  (Workers Paid). Routes fail open: if the Worker cannot run, the hostname's own DNS record (the
  primary node's tunnel) serves everything, as before balancing;
- routes without a Worker for `bypass_paths` (immutable assets the edge cache already serves).
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
from mc_hub_ingress import origin  # noqa: E402
from tunnel_api import Client, Failure, active_connectors, inventory_list  # noqa: E402

WORKER = Path(__file__).with_name('edge-lb')
SCRIPT = 'edge-lb'
COMPATIBILITY_DATE = '2025-09-01'


def plan(root=ROOT):
    hosts = {path.stem: host_registration(root, path.stem) for path in sorted((root / 'hosts').glob('*.yml'))}
    nodes, sites, rules, buckets, tunnels, bypass = {}, {}, {}, {}, {}, []
    for path in sorted((root / 'registry').glob('*.yml')):
        registration = app_registration(root, path.stem)
        if 'balance' not in registration:
            continue
        app, balance, ids, bindings = path.stem, registration['balance'], [], []
        for name in app_hosts(registration):
            record = hosts.get(name)
            if not record or 'edge' not in record or app not in record['apps']:
                raise Failure('EDGE_NODE_REQUIRED:' + app + '@' + name)
            edge = record['edge']
            if nodes.setdefault(edge['id'], edge) != edge:
                raise Failure('EDGE_NODE_ID_REUSED:' + edge['id'])
            ids.append(edge['id'])
            bindings.append(record['apps'][app]['api_host'])
        site = bindings[0]
        if len(set(bindings)) != 1 or site in sites:
            raise Failure('EDGE_SITE_POLICY:' + app)
        # shortcut: zone = last two labels (thedemontuan.dev); apply checks it against the account's zones.
        zone = '.'.join(site.split('.')[-2:])
        sites[site] = {'zone': zone, 'primary': ids[0], 'nodes': ids, 'rules': app}
        rules[app] = {'primary_paths': balance['primary_paths'], 'primary_cookies': balance.get('primary_cookies', []),
                      'sticky_seconds': balance.get('sticky_seconds', 0), 'fanout': balance.get('fanout', []),
                      'public_bucket': balance.get('public_bucket')}
        bucket = balance.get('public_bucket')
        if bucket and buckets.setdefault(bucket['binding'], bucket['bucket']) != bucket['bucket']:
            raise Failure('EDGE_BUCKET_BINDING_REUSED:' + bucket['binding'])
        bypass += [site + pattern for pattern in balance.get('bypass_paths', [])]
        for node in ids:
            tunnels.setdefault(node, set()).add(site)
    worker = {'nodes': {node: {'weight': nodes[node]['weight']} for node in sorted(tunnels)}, 'sites': sites, 'rules': rules}
    return {'worker': worker, 'buckets': buckets, 'bypass': bypass,
            'tunnels': {node: (nodes[node]['tunnel'], sorted(hostnames)) for node, hostnames in tunnels.items()}}


def rendered(root=ROOT):
    return json.dumps(plan(root)['worker'], indent=2, sort_keys=True) + '\n'


def zones(client, wanted):
    found = {zone['name']: zone['id'] for zone in inventory_list(client.get('/zones?per_page=50'))
             if zone.get('account', {}).get('id') == client.account and zone.get('name') in wanted}
    if set(found) != set(wanted):
        raise Failure('EDGE_ZONE_NOT_IN_ACCOUNT:' + ','.join(sorted(set(wanted) - set(found))))
    return found


def ingress_changes(client, tunnel, hostnames):
    path = '/accounts/' + client.account + '/cfd_tunnel/' + tunnel + '/configurations'
    current = client.get(path)
    config = json.loads(json.dumps(current.get('config')))
    ingress = inventory_list(config.get('ingress') if type(config) is dict else None)
    if not ingress or ingress[-1].get('hostname') or ingress[-1].get('service') != 'http_status:404':
        raise Failure('TUNNEL_CATCHALL_POLICY:' + tunnel)
    if active_connectors(client.get('/accounts/' + client.account + '/cfd_tunnel/' + tunnel + '/connections')) < 1:
        raise Failure('ACTIVE_CONNECTOR_REQUIRED:' + tunnel)
    for host in hostnames:
        selected = [rule for rule in ingress if rule.get('hostname') == host]
        if len(selected) > 1 or selected and selected[0] != origin(host):
            raise Failure('TUNNEL_SCOPE_CONFLICT:' + host)
        if not selected:
            ingress.insert(len(ingress) - 1, origin(host))
    return path, current, config


def dns_changes(client, zone_ids, records):
    missing = []
    for name, (zone, target) in records.items():
        found = [r for r in inventory_list(client.get('/zones/' + zone_ids[zone] + '/dns_records?name=' + name + '&per_page=100'))
                 if r.get('type') in ('A', 'AAAA', 'CNAME')]
        if found and (len(found) > 1 or found[0].get('type') != 'CNAME' or found[0].get('proxied') is not True or
                      found[0].get('content', '').rstrip('.') != target):
            raise Failure('DNS_OWNERSHIP_CONFLICT:' + name)
        if not found:
            missing.append(name)
    return missing


def route_changes(client, zone_ids, wanted):
    changes = []
    for zone, patterns in wanted.items():
        path = '/zones/' + zone_ids[zone] + '/workers/routes'
        existing = {route['pattern']: route for route in inventory_list(client.get(path))}
        for pattern, script in patterns.items():
            route = existing.get(pattern)
            if route and route.get('script') not in (None, '', SCRIPT):
                raise Failure('ROUTE_OWNERSHIP_CONFLICT:' + pattern)
            body = {'pattern': pattern, 'request_limit_fail_open': True, **({'script': script} if script else {})}
            if not route:
                changes.append(('POST', path, body))
            elif (route.get('script') or None, route.get('request_limit_fail_open')) != (script, True):
                changes.append(('PUT', path + '/' + route['id'], body))
    return changes


def upload(client, worker, buckets):
    """Multipart script upload (Workers API); routes stay as they are."""
    metadata = {'main_module': 'index.mjs', 'compatibility_date': COMPATIBILITY_DATE,
                'bindings': [{'type': 'r2_bucket', 'name': name, 'bucket_name': bucket} for name, bucket in sorted(buckets.items())]}
    parts = [('metadata', 'metadata.json', 'application/json', json.dumps(metadata).encode()),
             ('index.mjs', 'index.mjs', 'application/javascript+module', (WORKER / 'index.mjs').read_bytes()),
             ('config.json', 'config.json', 'application/json', json.dumps(worker).encode())]
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
    if (WORKER / 'config.json').read_text() != rendered():
        raise Failure('EDGE_CONFIG_STALE: run --operation render and commit')
    sites = edge['worker']['sites']
    zone_ids = zones(client, {site['zone'] for site in sites.values()})
    for host, site in sites.items():
        if not (host == site['zone'] or host.endswith('.' + site['zone'])):
            raise Failure('EDGE_ZONE_POLICY:' + host)
    records = {node + '-origin.' + sites[host]['zone']: (sites[host]['zone'], tunnel + '.cfargotunnel.com')
               for node, (tunnel, hostnames) in edge['tunnels'].items() for host in hostnames}
    tunnels = {node: ingress_changes(client, tunnel, hostnames) for node, (tunnel, hostnames) in edge['tunnels'].items()}
    routes = {}
    for host, site in sites.items():
        routes.setdefault(site['zone'], {})[host + '/*'] = SCRIPT
    for pattern in edge['bypass']:
        routes.setdefault(next(s['zone'] for h, s in sites.items() if pattern.startswith(h + '/')), {})[pattern] = None
    missing = dns_changes(client, zone_ids, records)
    route_plan = route_changes(client, zone_ids, routes)
    summary = {'operation': operation, 'nodes': edge['worker']['nodes'], 'sites': sorted(sites), 'missing_dns': missing,
               'tunnel_changes': sorted(node for node, (_, current, wanted) in tunnels.items() if current['config'] != wanted),
               'route_changes': [(method, body['pattern']) for method, _, body in route_plan]}
    if operation == 'apply':
        for node, (path, current, wanted) in tunnels.items():
            if current['config'] != wanted:
                if client.get(path) != current:
                    raise Failure('TUNNEL_VERSION_DRIFT:' + node)
                client.request('PUT', path, {'config': wanted})
        for name in missing:
            zone, target = records[name]
            client.request('POST', '/zones/' + zone_ids[zone] + '/dns_records',
                           {'type': 'CNAME', 'name': name, 'content': target, 'proxied': True, 'ttl': 1})
        upload(client, edge['worker'], edge['buckets'])
        # Routes last: traffic reaches the Worker only once every origin answers.
        for method, path, body in route_plan:
            client.request(method, path, body)
        if dns_changes(client, zone_ids, records) or route_changes(client, zone_ids, routes) or any(
                client.get(path)['config'] != wanted for path, _, wanted in tunnels.values()):
            raise Failure('EDGE_VERIFY_FAILED')
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--operation', choices=('render', 'survey', 'apply'), required=True)
    args = parser.parse_args()
    if args.operation == 'render':
        (WORKER / 'config.json').write_text(rendered())
        return
    print(json.dumps(run(Client(), args.operation), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (Failure, CoreFailure, KeyError, TypeError, AttributeError) as error:
        print(str(error) if isinstance(error, (Failure, CoreFailure)) else 'CLOUDFLARE_INVENTORY_POLICY', file=sys.stderr)
        sys.exit(1)
