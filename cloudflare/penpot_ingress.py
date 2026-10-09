#!/usr/bin/env python3
"""Scoped Penpot ingress inventory and guarded apply. No credentials in receipts."""
import argparse
import fnmatch
import json
import os
import re
import sys
import urllib.error
import urllib.request

HOST = 'design.tuannguyenviet.site'
ZONE = 'tuannguyenviet.site'
TUNNEL = '09575df7-5465-4201-94c0-130e16472dce'


class Failure(Exception):
    pass


def permission(path, method='GET'):
    if '/dns_records' in path:
        return 'DNS: Read' if method == 'GET' else 'DNS: Edit'
    if '/access/apps' in path:
        return 'Access: Apps and Policies: Read' if method == 'GET' else 'Access: Apps and Policies: Edit'
    if '/cfd_tunnel/' in path:
        return 'Cloudflare Tunnel: Read' if method == 'GET' else 'Cloudflare Tunnel: Edit'
    if '/rulesets' in path:
        return 'Cache Rules: Read' if method == 'GET' else 'Cache Rules: Edit'
    return 'Zone: Read'


class NoApiRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        raise Failure('CLOUDFLARE_REDIRECT_FORBIDDEN')


class Client:
    def __init__(self):
        self.token = os.environ.get('CLOUDFLARE_API_TOKEN', '')
        self.account = os.environ.get('CLOUDFLARE_ACCOUNT_ID', '')
        if not self.token or not re.fullmatch('[0-9a-f]{32}', self.account):
            raise Failure('CENTRAL_CLOUDFLARE_CREDENTIALS_REQUIRED')

    def get(self, path):
        return self.request('GET', path)

    def request(self, method, path, body=None):
        if method not in ('GET', 'PUT', 'POST', 'PATCH', 'DELETE') or not path.startswith(('/zones', '/accounts/')) or '#' in path:
            raise Failure('API_PATH_POLICY')
        request = urllib.request.Request('https://api.cloudflare.com/client/v4' + path,
                                         headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'},
                                         method=method, data=None if body is None else json.dumps(body).encode())
        try:
            with urllib.request.build_opener(NoApiRedirect()).open(request, timeout=30) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
                if len(raw) > 4 * 1024 * 1024:
                    raise Failure('CLOUDFLARE_RESPONSE_TOO_LARGE')
                data = json.loads(raw)
        except urllib.error.HTTPError as error:
            raise Failure('Cloudflare ' + method + ' ' + path.split('?')[0] + ' HTTP ' + str(error.code) +
                          '; required permission: ' + permission(path, method)) from None
        except (urllib.error.URLError, ValueError):
            raise Failure('CLOUDFLARE_READ_FAILED') from None
        if type(data) is not dict or data.get('success') is not True or 'result' not in data:
            raise Failure('CLOUDFLARE_RESPONSE_POLICY')
        # Fail closed rather than omit apps/rules on an incomplete inventory.
        pages = data.get('result_info', {}).get('total_pages', 1)
        if type(pages) is not int or pages != 1:
            raise Failure('CLOUDFLARE_PAGINATION_REQUIRED:' + path.split('?')[0])
        return data['result']


def wildcard_matches(pattern):
    return type(pattern) is str and '*' in pattern and fnmatch.fnmatchcase(HOST, pattern.split('/', 1)[0])


def inventory_list(value):
    if type(value) is not list or any(type(item) is not dict for item in value):
        raise Failure('CLOUDFLARE_INVENTORY_POLICY')
    return value


def survey(api, account):
    if type(account) is not str or not re.fullmatch('[0-9a-f]{32}', account):
        raise Failure('EXACT_ACCOUNT_REQUIRED')
    zones = api('/zones?name=' + ZONE + '&per_page=50')
    matches = [item for item in inventory_list(zones) if item.get('name') == ZONE and item.get('account', {}).get('id') == account]
    if len(matches) != 1 or not re.fullmatch('[0-9a-f]{32}', matches[0].get('id', '')):
        raise Failure('EXACT_ACCOUNT_ZONE_REQUIRED')
    zone = matches[0]['id']
    base = '/accounts/' + account
    records = api('/zones/' + zone + '/dns_records?name=' + HOST + '&per_page=100')
    connections = api(base + '/cfd_tunnel/' + TUNNEL + '/connections')
    config = api(base + '/cfd_tunnel/' + TUNNEL + '/configurations')
    apps = api(base + '/access/apps?per_page=100')
    rulesets = api('/zones/' + zone + '/rulesets?per_page=100')
    for value in (records, connections, apps, rulesets):
        inventory_list(value)
    if type(config) is not dict or type(config.get('version')) is not int:
        raise Failure('CLOUDFLARE_INVENTORY_POLICY')
    conflicts = []
    if len(records) > 1 or any(item.get('name') != HOST or item.get('type') != 'CNAME' or
                              item.get('content', '').rstrip('.') != TUNNEL + '.cfargotunnel.com' or
                              item.get('proxied') is not True for item in records):
        conflicts.append('DNS_OWNERSHIP_CONFLICT')
    if not any(item.get('is_pending_reconnect') is False for item in connections):
        conflicts.append('ACTIVE_CONNECTOR_REQUIRED')
    ingress = config.get('config', {}).get('ingress', [])
    inventory_list(ingress)
    selected = [item for item in ingress if item.get('hostname') == HOST]
    if len(selected) > 1 or any(wildcard_matches(item.get('hostname', '')) for item in ingress):
        conflicts.append('TUNNEL_SCOPE_CONFLICT')
    access = []
    for app in apps:
        extra = app.get('self_hosted_domains', [])
        if type(extra) is not list:
            raise Failure('CLOUDFLARE_INVENTORY_POLICY')
        domains = [app.get('domain', '')] + extra
        if any(type(domain) is not str for domain in domains):
            raise Failure('CLOUDFLARE_INVENTORY_POLICY')
        if any(wildcard_matches(domain) or domain.split('/', 1)[0].lower().rstrip('.') == HOST and domain != HOST for domain in domains):
            conflicts.append('ACCESS_SCOPE_CONFLICT')
        if HOST in domains:
            access.append({'id': app.get('id'), 'dedicated': all(domain in ('', HOST) for domain in domains)})
    cache = []
    for item in rulesets:
        if item.get('phase') == 'http_request_cache_settings':
            detail = api('/zones/' + zone + '/rulesets/' + item['id'])
            cache.append({'id': item['id'], 'version': detail.get('version'),
                          'penpot_rule_ids': [rule.get('id') for rule in detail.get('rules', [])
                                              if rule.get('description') == 'penpot-bypass-cache']})
    return {'status': 'read_only', 'host': HOST, 'zone_id': zone, 'tunnel_id': TUNNEL,
            'tunnel_version': config.get('version'), 'active_connector_count': sum(
                item.get('is_pending_reconnect') is False for item in connections),
            'dns_record_ids': [item.get('id') for item in records], 'exact_ingress_count': len(selected),
            'access_apps': access, 'cache_rulesets': cache, 'conflicts': sorted(set(conflicts)),
            'note': 'No DNS, tunnel, Access, cache rules, certificates or VPS state modified'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--operation', choices=['survey', 'apply'], required=True)
    args = parser.parse_args()
    client = Client()
    if args.operation == 'apply':
        from penpot_apply import apply, public_ready
        from penpot_origin import verifier
        value = apply(client, client.account, verifier())
        public_ready()
        value['public_ready'] = True
    else:
        value = survey(client.get, client.account)
    print(json.dumps(value, sort_keys=True, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (Failure, KeyError, TypeError, AttributeError) as error:
        print(str(error) if isinstance(error, Failure) else 'CLOUDFLARE_INVENTORY_POLICY', file=sys.stderr)
        sys.exit(1)
