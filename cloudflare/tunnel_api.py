#!/usr/bin/env python3
"""Shared Cloudflare API client and helper routines for tunnel and zone management."""
import fnmatch
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

ZONE = 'tuannguyenviet.site'
TUNNEL = '09575df7-5465-4201-94c0-130e16472dce'
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_INVENTORY_PAGES = 1000
READ_ONLY = {'id', 'version', 'last_updated', 'created_at', 'updated_at', 'aud'}


class Failure(Exception):
    pass


def permission(path, method='GET'):
    if '/dns_records' in path:
        return 'DNS: Read' if method == 'GET' else 'DNS: Edit'
    if '/access/apps' in path:
        return 'Access: Apps and Policies: Read' if method == 'GET' else 'Access: Apps and Policies: Edit'
    if '/cfd_tunnel/' in path:
        return 'Cloudflare Tunnel: Read' if method == 'GET' else 'Cloudflare Tunnel: Edit'
    if '/rulesets/phases/http_request_firewall_custom/' in path:
        return 'Zone WAF: Read'
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
            # Both endpoints return their complete list without pagination metadata.
            if re.fullmatch(r'/accounts/[0-9a-f]{32}/cfd_tunnel/[^/]+/connections|/zones/[0-9a-f]{32}/workers/routes', endpoint):
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
            for item in data['result']:
                if type(item) is dict and type(item.get('id')) is str:
                    if item['id'] in seen_ids:
                        raise Failure('CLOUDFLARE_PAGINATION_REQUIRED:' + endpoint)
                    seen_ids.add(item['id'])
        return result

    def _cursor_inventory(self, endpoint, parameters, data, size):
        if any(key in ('page', 'cursor') for key, value in parameters) or [
                value for key, value in parameters if key == 'per_page'] != ['50']:
            raise Failure('CLOUDFLARE_PAGINATION_REQUIRED:' + endpoint)
        result, cursors, ids = [], set(), set()
        for number in range(MAX_INVENTORY_PAGES):
            items = inventory_list(data.get('result'))
            for item in items:
                identity_val = item.get('id')
                if type(identity_val) is not str or not identity_val or identity_val in ids:
                    raise Failure('CLOUDFLARE_PAGINATION_REQUIRED:' + endpoint)
                ids.add(identity_val)
            result.extend(items)
            info = data.get('result_info')
            if info is None and number == 0 and len(items) < 50:
                return result
            if type(info) is not dict or type(info.get('cursors')) is not dict:
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
            codes = []
            try:
                raw = error.read(MAX_RESPONSE_BYTES + 1)
                data = json.loads(raw) if len(raw) <= MAX_RESPONSE_BYTES else None
                errors = data.get('errors') if type(data) is dict else None
                if type(errors) is list:
                    codes = [item['code'] for item in errors[:16] if type(item) is dict and
                             type(item.get('code')) is int and 0 <= item['code'] <= 999999999]
            except (OSError, ValueError):
                pass
            detail = '; required permission: ' + permission(path, method) if error.code in (401, 403) else ''
            raise Failure('Cloudflare ' + method + ' ' + path.split('?')[0] + ' HTTP ' + str(error.code) +
                          '; error_codes=' + json.dumps(codes) + detail) from None
        except (urllib.error.URLError, ValueError):
            raise Failure('CLOUDFLARE_READ_FAILED') from None
        if type(data) is not dict or data.get('success') is not True or 'result' not in data:
            raise Failure('CLOUDFLARE_RESPONSE_POLICY')
        return data, len(raw)


def inventory_list(value):
    if type(value) is not list or any(type(item) is not dict for item in value):
        raise Failure('CLOUDFLARE_INVENTORY_POLICY')
    return value


def active_connectors(value):
    """Count Client objects, not their individual Cloudflare edge connections."""
    clients, connections, count = set(), set(), 0
    uuid = r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'
    for client in inventory_list(value):
        client_id = client.get('id')
        if type(client_id) is not str or not re.fullmatch(uuid, client_id) or client_id.lower() in clients:
            raise Failure('CLOUDFLARE_INVENTORY_POLICY')
        clients.add(client_id.lower())
        active = False
        for connection in inventory_list(client.get('conns')):
            connection_id, conn_client_id = connection.get('id'), connection.get('client_id')
            pending = connection.get('is_pending_reconnect')
            if (type(connection_id) is not str or not re.fullmatch(uuid, connection_id) or
                    connection_id.lower() in connections or type(conn_client_id) is not str or
                    conn_client_id.lower() != client_id.lower() or type(pending) is not bool):
                raise Failure('CLOUDFLARE_INVENTORY_POLICY')
            if 'uuid' in connection and (type(connection['uuid']) is not str or
                                         connection['uuid'].lower() != connection_id.lower()):
                raise Failure('CLOUDFLARE_INVENTORY_POLICY')
            connections.add(connection_id.lower())
            active = active or pending is False
        count += active
    return count


def identity(value):
    if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value):
        raise Failure('CLOUDFLARE_RESOURCE_ID_POLICY')
    return value


def domains(app):
    extra = app.get('self_hosted_domains', [])
    if type(extra) is not list or any(type(value) is not str for value in extra):
        raise Failure('ACCESS_DOMAIN_POLICY')
    primary = app.get('domain', '')
    if type(primary) is not str:
        raise Failure('ACCESS_DOMAIN_POLICY')
    return list(dict.fromkeys([value for value in [primary] + extra if value]))
