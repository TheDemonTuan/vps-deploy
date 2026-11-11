#!/usr/bin/env python3
"""Enroll only OmniRoute's two new hostnames; preserve sibling Cloudflare state."""
import argparse
import copy
import fnmatch
import json
import sys
from penpot_ingress import Client, Failure, TUNNEL, ZONE, active_connectors, inventory_list
from penpot_apply import domains, identity

HOSTS = ('omniroute-api.tuannguyenviet.site', 'omniroute.tuannguyenviet.site')
ADMIN_NAME = 'OmniRoute Admin Dashboard'
API_PATH_REF = 'omniroute_api_paths'
API_PATH_EXPRESSION = (
    '(http.host eq "' + HOSTS[0] + '") and (not ('
    'starts_with(http.request.uri.path, "/v1/") or '
    'starts_with(http.request.uri.path, "/api/v1/") or '
    'starts_with(http.request.uri.path, "/v1beta/") or '
    'starts_with(http.request.uri.path, "/api/v1beta/") or '
    'http.request.uri.path eq "/api/health") or '
    'starts_with(lower(http.request.uri.path), "/v1/management") or '
    'starts_with(lower(http.request.uri.path), "/api/v1/management") or '
    'starts_with(lower(http.request.uri.path), "/v1/registered-keys") or '
    'starts_with(lower(http.request.uri.path), "/api/v1/registered-keys") or '
    'starts_with(lower(http.request.uri.path), "/v1/agents") or '
    'starts_with(lower(http.request.uri.path), "/api/v1/agents") or '
    'starts_with(lower(http.request.uri.path), "/v1/accounts") or '
    'starts_with(lower(http.request.uri.path), "/api/v1/accounts") or '
    'starts_with(lower(http.request.uri.path), "/v1/providers") or '
    'starts_with(lower(http.request.uri.path), "/api/v1/providers") or '
    'starts_with(lower(http.request.uri.path), "/v1/issues") or '
    'starts_with(lower(http.request.uri.path), "/api/v1/issues") or '
    'starts_with(lower(http.request.uri.path), "/v1/quotas") or '
    'starts_with(lower(http.request.uri.path), "/api/v1/quotas"))')


def verify_security(client, zone, apps):
    own = [app for app in apps if app.get('name') == ADMIN_NAME and domains(app) == [HOSTS[1]]]
    for app in apps:
        for host in HOSTS:
            if any(fnmatch.fnmatchcase(host, value.split('/', 1)[0]) for value in domains(app)) and (
                    host == HOSTS[0] or app not in own):
                raise Failure('ACCESS_SCOPE_CONFLICT')
    if len(own) != 1:
        counts = {'apps': len(apps), 'owned': len(own),
                  'owned_name': sum(app.get('name') == ADMIN_NAME for app in apps),
                  'domain_field': sum('domain' in app for app in apps),
                  'destinations_field': sum('destinations' in app for app in apps)}
        raise Failure('ADMIN_ACCESS_REQUIRED; inventory_counts=' + json.dumps(counts, sort_keys=True))
    admin = client.get('/accounts/' + client.account + '/access/apps/' + identity(own[0].get('id')))
    policies = inventory_list(admin.get('policies'))
    # The admin app is its own policy source: one allow policy over exact email addresses only.
    includes = inventory_list(policies[0].get('include')) if len(policies) == 1 else []
    if (admin.get('id') != own[0].get('id') or admin.get('type') != 'self_hosted' or
            admin.get('name') != ADMIN_NAME or domains(admin) != [HOSTS[1]] or
            admin.get('http_only_cookie_attribute') is not True or not admin.get('allowed_idps') or
            len(policies) != 1 or policies[0].get('decision') != 'allow' or not includes or
            policies[0].get('exclude', []) or policies[0].get('require', []) or
            any(set(rule) != {'email'} or type(rule['email'].get('email')) is not str or
                '@' not in rule['email']['email'] or '*' in rule['email']['email'] for rule in includes)):
        raise Failure('ADMIN_ACCESS_POLICY_DRIFT')
    waf = client.get('/zones/' + zone + '/rulesets/phases/http_request_firewall_custom/entrypoint')
    rules = inventory_list(waf.get('rules'))
    selected = [rule for rule in rules if rule.get('ref') == API_PATH_REF]
    if (waf.get('kind') != 'zone' or waf.get('phase') != 'http_request_firewall_custom' or
            len(selected) != 1 or rules[0] != selected[0] or selected[0].get('action') != 'block' or
            selected[0].get('enabled') is not True or selected[0].get('expression') != API_PATH_EXPRESSION):
        raise Failure('API_PATH_WAF_POLICY_DRIFT')


def origin(host):
    return {'hostname': host, 'service': 'https://172.31.250.4:8080',
            'originRequest': {'originServerName': host,
                              'caPool': '/etc/cloudflare-origin-ca/origin-ca.pem',
                              'noTLSVerify': False}}


def prepare(client):
    zones = inventory_list(client.get('/zones?name=' + ZONE + '&per_page=50'))
    matches = [zone for zone in zones if zone.get('name') == ZONE and zone.get('account', {}).get('id') == client.account]
    if len(matches) != 1:
        raise Failure('EXACT_ACCOUNT_ZONE_REQUIRED')
    zone = matches[0]['id']
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
    apps = inventory_list(client.get(base + '/access/apps?per_page=100'))
    verify_security(client, zone, apps)
    dns = {}
    for host in HOSTS:
        selected = [rule for rule in ingress if rule.get('hostname') == host]
        if len(selected) > 1 or selected and selected[0] != origin(host) or any(
                '*' in rule.get('hostname', '') and fnmatch.fnmatchcase(host, rule['hostname']) for rule in ingress):
            raise Failure('TUNNEL_SCOPE_CONFLICT')
        if not selected:
            config['ingress'].insert(len(config['ingress']) - 1, origin(host))
        path = '/zones/' + zone + '/dns_records'
        records = inventory_list(client.get(path + '?name=' + host + '&per_page=100'))
        if len(records) > 1 or any(record.get('name') != host or record.get('type') != 'CNAME' or
                record.get('proxied') is not True or record.get('content', '').rstrip('.') != TUNNEL + '.cfargotunnel.com' for record in records):
            raise Failure('DNS_OWNERSHIP_CONFLICT')
        dns[host] = (path, records)
    return tunnel_path, tunnel, config, dns


def run(client, operation):
    tunnel_path, before, wanted, dns = prepare(client)
    if operation == 'apply':
        # Cloudflare has no conditional PUT here; re-read immediately before writing.
        if client.get(tunnel_path) != before:
            raise Failure('TUNNEL_VERSION_DRIFT')
        if before['config'] != wanted:
            client.request('PUT', tunnel_path, {'config': wanted})
        if client.get(tunnel_path).get('config') != wanted:
            raise Failure('TUNNEL_VERIFY_FAILED')
        for host, (path, records) in dns.items():
            if not records:
                client.request('POST', path, {'type': 'CNAME', 'name': host,
                    'content': TUNNEL + '.cfargotunnel.com', 'proxied': True, 'ttl': 1})
        _, after, _, final_dns = prepare(client)
        if after['config'] != wanted or any(not records for _, records in final_dns.values()):
            raise Failure('INGRESS_VERIFY_FAILED')
    return {'operation': operation, 'hosts': list(HOSTS),
            'existing_dns': {host: bool(records) for host, (_, records) in dns.items()},
            'tunnel_change_needed': before['config'] != wanted,
            'sibling_routes_preserved': True, 'access_policies_modified': False,
            'admin_access_verified': True, 'api_path_waf_verified': True}


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
