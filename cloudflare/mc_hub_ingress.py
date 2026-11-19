#!/usr/bin/env python3
"""Enroll only mc-hub's public hostnames on the shared tunnel; preserve sibling state.

The hostnames come from hosts/oracle-main.yml (mc_hub_hosts): the site (mc-hub, which also
serves mc-hub-api under /api/ and /media/ via Traefik) and the SSR API host (mc-hub-api), each
with its fallback alias. Every hostname gets a tunnel ingress rule and a proxied CNAME in the
zone that owns it. Public content needs no WAF rule; the admin paths are covered by the
"MC Hub Admin" Access app (mc_hub_access.py), and admin authentication (password + TOTP)
still lives in mc-hub-api.
"""
import argparse
import copy
import fnmatch
import json
import sys
from mc_hub_hosts import hosts, zone_id
from tunnel_api import Client, Failure, TUNNEL, active_connectors, inventory_list

HOSTS = tuple(hosts('mc-hub') + hosts('mc-hub-api'))


def origin(host):
    return {'hostname': host, 'service': 'https://172.31.250.4:8080',
            'originRequest': {'originServerName': host,
                              'caPool': '/etc/cloudflare-origin-ca/origin-ca.pem',
                              'noTLSVerify': False}}


def prepare(client):
    zones = {host: zone_id(client, host) for host in HOSTS}
    base = '/accounts/' + client.account
    tunnel_path = base + '/cfd_tunnel/' + TUNNEL + '/configurations'
    tunnel = client.get(tunnel_path)
    config = copy.deepcopy(tunnel.get('config'))
    if type(config) is not dict:
        raise Failure('TUNNEL_CONFIG_POLICY')
    ingress = inventory_list(config.get('ingress'))
    if not ingress or ingress[-1].get('hostname') or ingress[-1].get('service') != 'http_status:404' or any(not item.get('hostname') for item in ingress[:-1]):
        raise Failure('TUNNEL_CATCHALL_POLICY')
    if active_connectors(client.get(base + '/cfd_tunnel/' + TUNNEL + '/connections')) < 1:
        raise Failure('ACTIVE_CONNECTOR_REQUIRED')
    for host in HOSTS:
        selected = [rule for rule in ingress if rule.get('hostname') == host]
        if len(selected) > 1 or selected and selected[0] != origin(host) or any(
                '*' in rule.get('hostname', '') and fnmatch.fnmatchcase(host, rule['hostname']) for rule in ingress):
            raise Failure('TUNNEL_SCOPE_CONFLICT')
        if not selected:
            config['ingress'].insert(len(config['ingress']) - 1, origin(host))
    records = {}
    for host in HOSTS:
        path = '/zones/' + zones[host] + '/dns_records'
        # An apex also carries MX and TXT (mail routing, Search Console); only address records route.
        found = [record for record in inventory_list(client.get(path + '?name=' + host + '&per_page=100'))
                 if record.get('type') in ('A', 'AAAA', 'CNAME')]
        if len(found) > 1 or any(record.get('name') != host or record.get('type') != 'CNAME' or
                record.get('proxied') is not True or record.get('content', '').rstrip('.') != TUNNEL + '.cfargotunnel.com' for record in found):
            raise Failure('DNS_OWNERSHIP_CONFLICT')
        records[host] = path, found
    return tunnel_path, tunnel, config, records


def run(client, operation):
    tunnel_path, before, wanted, records = prepare(client)
    if operation == 'apply':
        # Cloudflare has no conditional PUT here; re-read immediately before writing.
        if client.get(tunnel_path) != before:
            raise Failure('TUNNEL_VERSION_DRIFT')
        if before['config'] != wanted:
            client.request('PUT', tunnel_path, {'config': wanted})
        if client.get(tunnel_path).get('config') != wanted:
            raise Failure('TUNNEL_VERIFY_FAILED')
        for host in HOSTS:
            path, found = records[host]
            if not found:
                client.request('POST', path, {'type': 'CNAME', 'name': host,
                    'content': TUNNEL + '.cfargotunnel.com', 'proxied': True, 'ttl': 1})
        _, after, _, final_records = prepare(client)
        if after['config'] != wanted or not all(found for _, found in final_records.values()):
            raise Failure('INGRESS_VERIFY_FAILED')
    return {'operation': operation, 'hosts': list(HOSTS), 'missing_dns': [host for host in HOSTS if not records[host][1]],
            'tunnel_change_needed': before['config'] != wanted, 'sibling_routes_preserved': True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--operation', choices=('survey', 'apply'), required=True)
    args = parser.parse_args()
    print(json.dumps(run(Client(), args.operation), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (Failure, KeyError, TypeError, AttributeError) as error:
        print(str(error) if isinstance(error, Failure) else 'CLOUDFLARE_INVENTORY_POLICY', file=sys.stderr)
        sys.exit(1)
