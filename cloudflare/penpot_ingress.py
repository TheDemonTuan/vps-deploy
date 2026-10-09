#!/usr/bin/env python3
"""Scoped Penpot ingress inventory and guarded apply. No credentials in receipts."""
import argparse
import fnmatch
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

HOST = 'design.tuannguyenviet.site'
ZONE = 'tuannguyenviet.site'
TUNNEL = '09575df7-5465-4201-94c0-130e16472dce'
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_INVENTORY_PAGES = 1000


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
        data, size = self._response(method, path, body)
        if method != 'GET' or type(data['result']) is not list:
            info = data.get('result_info', {})
            if type(info) is not dict or type(info.get('total_pages', 1)) is not int or info.get('total_pages', 1) != 1:
                raise Failure('CLOUDFLARE_PAGINATION_REQUIRED:' + path.split('?')[0])
            return data['result']

        endpoint, separator, query = path.partition('?')
        parameters = urllib.parse.parse_qsl(query, keep_blank_values=True)
        if re.fullmatch(r'/zones/[0-9a-f]{32}/rulesets', endpoint):
            return self._cursor_inventory(endpoint, parameters, data, size)
        pages = [value for key, value in parameters if key == 'page']
        per_pages = [value for key, value in parameters if key == 'per_page']
        if pages not in ([], ['1']) or len(per_pages) > 1:
            raise Failure('CLOUDFLARE_PAGINATION_REQUIRED:' + endpoint)
        if 'result_info' not in data:
            # These endpoints return all objects without pagination. Paginated
            # inventories (notably Access apps) must supply complete metadata.
            if re.fullmatch(r'/accounts/[0-9a-f]{32}/cfd_tunnel/[^/]+/connections', endpoint):
                return data['result']
            raise Failure('CLOUDFLARE_PAGINATION_REQUIRED:' + endpoint)

        total_pages, per_page, total_count = self._pagination(data, 1, endpoint)
        result = data['result']
        seen_ids = set()
        for page in range(1, max(1, total_pages) + 1):
            if page > 1:
                parameters = [(key, value) for key, value in parameters if key not in ('page', 'per_page')]
                next_path = endpoint + '?' + urllib.parse.urlencode(parameters + [('page', page), ('per_page', per_page)])
                data, page_size = self._response('GET', next_path, None)
                size += page_size
                if size > MAX_RESPONSE_BYTES:
                    raise Failure('CLOUDFLARE_RESPONSE_TOO_LARGE')
                if self._pagination(data, page, endpoint) != (total_pages, per_page, total_count):
                    raise Failure('CLOUDFLARE_PAGINATION_REQUIRED:' + endpoint)
                result.extend(data['result'])
            # Overlapping resource IDs can hide an omitted ownership conflict.
            for item in data['result']:
                if type(item) is dict and type(item.get('id')) is str:
                    if item['id'] in seen_ids:
                        raise Failure('CLOUDFLARE_PAGINATION_REQUIRED:' + endpoint)
                    seen_ids.add(item['id'])
        return result

    def _cursor_inventory(self, endpoint, parameters, data, size):
        if any(key in ('page', 'cursor') for key, value in parameters):
            raise Failure('CLOUDFLARE_PAGINATION_REQUIRED:' + endpoint)
        result, cursors, ids = [], set(), set()
        for number in range(MAX_INVENTORY_PAGES):
            items = inventory_list(data.get('result'))
            for item in items:
                identity = item.get('id')
                if type(identity) is not str or not identity or identity in ids:
                    raise Failure('CLOUDFLARE_PAGINATION_REQUIRED:' + endpoint)
                ids.add(identity)
            result.extend(items)
            info = data.get('result_info')
            if type(info) is not dict or type(info.get('cursors')) is not dict:
                # Only fixed field names and JSON types: never response values,
                # cursor bytes, resource IDs or credentials in diagnostics.
                fields = ('page', 'per_page', 'count', 'total_count', 'total_pages', 'cursors')
                shape = {key: type(info[key]).__name__ for key in fields if type(info) is dict and key in info}
                diagnostic = {'result_info_type': type(info).__name__, 'fields': shape,
                              'items': len(items), 'page': number + 1}
                raise Failure('CLOUDFLARE_PAGINATION_REQUIRED:' + endpoint +
                              '; metadata_shape=' + json.dumps(diagnostic, sort_keys=True))
            after = info['cursors'].get('after')
            if after is None:
                return result
            if type(after) is not str or not after or after in cursors or not items:
                raise Failure('CLOUDFLARE_PAGINATION_REQUIRED:' + endpoint)
            cursors.add(after)
            next_path = endpoint + '?' + urllib.parse.urlencode(parameters + [('cursor', after)])
            data, page_size = self._response('GET', next_path, None)
            size += page_size
            if size > MAX_RESPONSE_BYTES:
                raise Failure('CLOUDFLARE_RESPONSE_TOO_LARGE')
        raise Failure('CLOUDFLARE_PAGINATION_REQUIRED:' + endpoint)

    def _pagination(self, data, page, endpoint):
        info = data.get('result_info')
        fields = ('page', 'per_page', 'count', 'total_count')
        if type(data.get('result')) is not list or type(info) is not dict or any(
                type(info.get(field)) is not int for field in fields):
            raise Failure('CLOUDFLARE_PAGINATION_REQUIRED:' + endpoint)
        per_page, total_count = info['per_page'], info['total_count']
        if info['page'] != page or per_page < 1 or total_count < 0:
            raise Failure('CLOUDFLARE_PAGINATION_REQUIRED:' + endpoint)
        expected_pages = (total_count + per_page - 1) // per_page
        total_pages = info.get('total_pages', expected_pages)
        if type(total_pages) is not int or total_pages not in ((0, 1) if total_count == 0 else (expected_pages,)) or (
                total_pages > MAX_INVENTORY_PAGES or page > max(1, total_pages)):
            raise Failure('CLOUDFLARE_PAGINATION_REQUIRED:' + endpoint)
        expected_count = min(per_page, max(0, total_count - (page - 1) * per_page))
        if info['count'] != expected_count or len(data['result']) != expected_count:
            raise Failure('CLOUDFLARE_PAGINATION_REQUIRED:' + endpoint)
        return total_pages, per_page, total_count

    def _response(self, method, path, body):
        request = urllib.request.Request('https://api.cloudflare.com/client/v4' + path,
                                         headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'},
                                         method=method, data=None if body is None else json.dumps(body).encode())
        try:
            with urllib.request.build_opener(NoApiRedirect()).open(request, timeout=30) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise Failure('CLOUDFLARE_RESPONSE_TOO_LARGE')
                data = json.loads(raw)
        except urllib.error.HTTPError as error:
            raise Failure('Cloudflare ' + method + ' ' + path.split('?')[0] + ' HTTP ' + str(error.code) +
                          '; required permission: ' + permission(path, method)) from None
        except (urllib.error.URLError, ValueError):
            raise Failure('CLOUDFLARE_READ_FAILED') from None
        if type(data) is not dict or data.get('success') is not True or 'result' not in data:
            raise Failure('CLOUDFLARE_RESPONSE_POLICY')
        return data, len(raw)


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
    rulesets = api('/zones/' + zone + '/rulesets?per_page=50')
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
