#!/usr/bin/env python3
"""Enroll only mc-hub's public hostname on the shared tunnel; preserve sibling state.

mc-hub is a public site: no Access application or WAF rule is required. Its
admin (/keystatic) authenticates through GitHub OAuth in the application.
"""
import argparse
import copy
import fnmatch
import json
import sys
from penpot_ingress import Client, Failure, TUNNEL, ZONE, active_connectors, inventory_list

HOST = 'minecraft.tuannguyenviet.site'
ORIGIN = {'hostname': HOST, 'service': 'https://172.31.250.4:8080',
          'originRequest': {'originServerName': HOST,
                            'caPool': '/etc/cloudflare-origin-ca/origin-ca.pem',
                            'noTLSVerify': False}}


def prepare(client):
    zones = inventory_list(client.get('/zones?name=' + ZONE + '&per_page=50'))
    matches = [zone for zone in zones if zone.get('name') == ZONE and zone.get('account', {}).get('id') == client.account]
    if len(matches) != 1:
        raise Failure('EXACT_ACCOUNT_ZONE_REQUIRED')
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
    selected = [rule for rule in ingress if rule.get('hostname') == HOST]
    if len(selected) > 1 or selected and selected[0] != ORIGIN or any(
            '*' in rule.get('hostname', '') and fnmatch.fnmatchcase(HOST, rule['hostname']) for rule in ingress):
        raise Failure('TUNNEL_SCOPE_CONFLICT')
    if not selected:
        config['ingress'].insert(len(config['ingress']) - 1, ORIGIN)
    path = '/zones/' + matches[0]['id'] + '/dns_records'
    records = inventory_list(client.get(path + '?name=' + HOST + '&per_page=100'))
    if len(records) > 1 or any(record.get('name') != HOST or record.get('type') != 'CNAME' or
            record.get('proxied') is not True or record.get('content', '').rstrip('.') != TUNNEL + '.cfargotunnel.com' for record in records):
        raise Failure('DNS_OWNERSHIP_CONFLICT')
    return tunnel_path, tunnel, config, path, records


def run(client, operation):
    tunnel_path, before, wanted, dns_path, records = prepare(client)
    if operation == 'apply':
        # Cloudflare has no conditional PUT here; re-read immediately before writing.
        if client.get(tunnel_path) != before:
            raise Failure('TUNNEL_VERSION_DRIFT')
        if before['config'] != wanted:
            client.request('PUT', tunnel_path, {'config': wanted})
        if client.get(tunnel_path).get('config') != wanted:
            raise Failure('TUNNEL_VERIFY_FAILED')
        if not records:
            client.request('POST', dns_path, {'type': 'CNAME', 'name': HOST,
                'content': TUNNEL + '.cfargotunnel.com', 'proxied': True, 'ttl': 1})
        _, after, _, _, final_records = prepare(client)
        if after['config'] != wanted or not final_records:
            raise Failure('INGRESS_VERIFY_FAILED')
    return {'operation': operation, 'host': HOST, 'existing_dns': bool(records),
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
