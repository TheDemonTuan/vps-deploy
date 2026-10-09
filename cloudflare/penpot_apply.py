"""Scoped, repeatable ingress writes; never restore whole shared configurations."""
import copy
import re
import time
import urllib.error
import urllib.request
from penpot_ingress import Failure, HOST, TUNNEL, inventory_list, survey

ORIGIN = {'hostname': HOST, 'service': 'https://172.31.250.4:8080',
          'originRequest': {'originServerName': HOST,
                            'caPool': '/etc/cloudflare-origin-ca/origin-ca.pem', 'noTLSVerify': False}}
CACHE = {'description': 'penpot-bypass-cache', 'expression': '(http.host eq "' + HOST + '")',
         'action': 'set_cache_settings', 'action_parameters': {'cache': False}, 'enabled': True}
READ_ONLY = {'id', 'version', 'last_updated', 'created_at', 'updated_at', 'aud'}


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


def dns_allowed(api, account, records):
    if len(records) > 1:
        return False
    for record in records:
        if record.get('name') != HOST or record.get('type') != 'CNAME' or record.get('proxied') is not True:
            return False
        content = record.get('content', '').rstrip('.')
        if content == TUNNEL + '.cfargotunnel.com':
            continue
        match = re.fullmatch(r'([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})\.cfargotunnel\.com', content)
        if not match:
            return False
        base = '/accounts/' + account + '/cfd_tunnel/' + match[1]
        old = api.get(base)
        if old.get('id') != match[1] or old.get('name') != 'opendesign' or inventory_list(api.get(base + '/connections')):
            return False
    return True


def prepare(api, account):
    receipt = survey(api.get, account)
    zone = receipt['zone_id']
    base = '/accounts/' + account
    dns_path = '/zones/' + zone + '/dns_records?name=' + HOST + '&per_page=100'
    dns = inventory_list(api.get(dns_path))
    conflicts = set(receipt['conflicts'])
    if 'DNS_OWNERSHIP_CONFLICT' in conflicts and dns_allowed(api, account, dns):
        conflicts.remove('DNS_OWNERSHIP_CONFLICT')
    if conflicts:
        raise Failure('PENPOT_INGRESS_CONFLICT:' + ','.join(sorted(conflicts)))
    tunnel_path = base + '/cfd_tunnel/' + TUNNEL + '/configurations'
    tunnel = api.get(tunnel_path)
    if tunnel.get('version') != receipt['tunnel_version']:
        raise Failure('TUNNEL_VERSION_DRIFT')
    config = copy.deepcopy(tunnel.get('config'))
    if type(config) is not dict:
        raise Failure('TUNNEL_CONFIG_POLICY')
    ingress = inventory_list(config.get('ingress'))
    if not ingress or ingress[-1].get('hostname') or ingress[-1].get('service') != 'http_status:404' or any(
            not item.get('hostname') for item in ingress[:-1]):
        raise Failure('TUNNEL_CATCHALL_POLICY')
    selected = [item for item in ingress if item.get('hostname') == HOST]
    if len(selected) > 1 or any('path' in item for item in selected):
        raise Failure('TUNNEL_SCOPE_CONFLICT')
    target = copy.deepcopy(selected[0]) if selected else {'hostname': HOST}
    target['service'] = ORIGIN['service']
    if type(target.get('originRequest', {})) is not dict:
        raise Failure('TUNNEL_CONFIG_POLICY')
    target.setdefault('originRequest', {}).update(ORIGIN['originRequest'])
    config['ingress'] = [target if item.get('hostname') == HOST else item for item in ingress]
    if not selected:
        config['ingress'].insert(len(ingress) - 1, target)
    apps_path = base + '/access/apps?per_page=100'
    apps = inventory_list(api.get(apps_path))
    access = []
    for app in apps:
        values = domains(app)
        if HOST not in values:
            continue
        if app.get('type') != 'self_hosted':
            raise Failure('ACCESS_APPLICATION_TYPE_CONFLICT')
        path = base + '/access/apps/' + identity(app.get('id'))
        before = api.get(path)
        if before.get('id') != app.get('id') or before.get('type') != app.get('type') or domains(before) != values:
            raise Failure('ACCESS_APPLICATION_DRIFT')
        remaining = [value for value in values if value != HOST]
        body = {key: copy.deepcopy(value) for key, value in before.items() if key not in READ_ONLY}
        if remaining:
            body['domain'] = remaining[0]
            body['self_hosted_domains'] = remaining
        access.append((path, before, body if remaining else None))
    sets_path = '/zones/' + zone + '/rulesets?per_page=100'
    sets = inventory_list(api.get(sets_path))
    entrypoints = [item for item in sets if item.get('phase') == 'http_request_cache_settings' and item.get('kind') == 'zone']
    if len(entrypoints) > 1:
        raise Failure('CACHE_ENTRYPOINT_CONFLICT')
    if entrypoints:
        cache_path = '/zones/' + zone + '/rulesets/' + identity(entrypoints[0].get('id'))
        cache = api.get(cache_path)
        if cache.get('kind') != 'zone' or cache.get('phase') != 'http_request_cache_settings':
            raise Failure('CACHE_ENTRYPOINT_CONFLICT')
        rules = inventory_list(cache.get('rules'))
        body = {key: copy.deepcopy(cache[key]) for key in ('name', 'description', 'kind', 'phase') if key in cache}
    else:
        cache_path = '/zones/' + zone + '/rulesets/phases/http_request_cache_settings/entrypoint'
        cache = None
        rules = []
        body = {'name': 'Penpot cache settings', 'kind': 'zone', 'phase': 'http_request_cache_settings'}
    managed = [rule for rule in rules if rule.get('description') == CACHE['description']]
    if len(managed) > 1 or any(rule.get('expression') != CACHE['expression'] or rule.get('action') != CACHE['action'] for rule in managed):
        raise Failure('CACHE_RULE_OWNERSHIP_CONFLICT')
    body['rules'] = [{key: copy.deepcopy(value) for key, value in rule.items() if key not in {'version', 'last_updated'}} for rule in rules]
    if managed:
        for rule in body['rules']:
            if rule.get('description') == CACHE['description']:
                rule.update(CACHE)
    else:
        body['rules'].append(copy.deepcopy(CACHE))
    return dict(receipt=receipt, tunnel_path=tunnel_path, tunnel=tunnel, config=config,
                dns_path=dns_path, dns=dns, apps_path=apps_path, apps=apps, access=access,
                sets_path=sets_path, sets=sets, cache_path=cache_path, cache=cache, cache_body=body)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        return None


def public_ready(timeout=90):
    """Require HTTPS 200/OK, never an Access redirect or Cloudflare error page."""
    deadline = time.monotonic() + timeout
    opener = urllib.request.build_opener(NoRedirect())
    while True:
        try:
            with opener.open('https://' + HOST + '/readyz', timeout=10) as response:
                if response.status == 200 and response.read(257) == b'OK':
                    return
        except (urllib.error.URLError, OSError):
            pass
        if time.monotonic() >= deadline:
            raise Failure('PENPOT_PUBLIC_READINESS_FAILED')
        time.sleep(2)


def unchanged(api, path, before):
    if api.get(path) != before:
        raise Failure('CLOUDFLARE_RESOURCE_DRIFT:' + path.split('?')[0])


def apply(api, account, check_origin):
    # Finish the entire conflict/permission inventory before the first mutation.
    plan = prepare(api, account)
    check_origin()
    writes = []
    if plan['tunnel']['config'] != plan['config']:
        unchanged(api, plan['tunnel_path'], plan['tunnel'])
        after = api.request('PUT', plan['tunnel_path'], {'config': plan['config']})
        if after.get('config') != plan['config']:
            raise Failure('TUNNEL_WRITE_MISMATCH')
        writes.append('tunnel')
    zone = plan['receipt']['zone_id']
    records = plan['dns']
    desired = {'type': 'CNAME', 'name': HOST, 'content': TUNNEL + '.cfargotunnel.com', 'proxied': True}
    if not records or any(records[0].get(key) != value for key, value in desired.items()):
        unchanged(api, plan['dns_path'], records)
        path = '/zones/' + zone + '/dns_records'
        method = 'POST'
        if records:
            path += '/' + identity(records[0].get('id'))
            method = 'PATCH'
        after = api.request(method, path, desired)
        if any(after.get(key) != value for key, value in desired.items()):
            raise Failure('DNS_WRITE_MISMATCH')
        writes.append('dns')
    before_rules = [{key: value for key, value in rule.items() if key not in {'version', 'last_updated'}}
                    for rule in (plan['cache'] or {}).get('rules', [])]
    if before_rules != plan['cache_body']['rules']:
        if plan['cache'] is None:
            unchanged(api, plan['sets_path'], plan['sets'])
        else:
            unchanged(api, plan['cache_path'], plan['cache'])
        after = api.request('PUT', plan['cache_path'], plan['cache_body'])
        actual = [{key: value for key, value in rule.items() if key not in {'version', 'last_updated'}}
                  for rule in inventory_list(after.get('rules'))]
        # Cloudflare assigns an ID/ref to a newly appended rule.
        for actual_rule, expected_rule in zip(actual, plan['cache_body']['rules']):
            for key in ('id', 'ref'):
                if key not in expected_rule:
                    actual_rule.pop(key, None)
        if actual != plan['cache_body']['rules']:
            raise Failure('CACHE_WRITE_MISMATCH')
        writes.append('cache')
    # Remove Access last, after origin/DNS/cache are configured and rechecked.
    for path, before, body in plan['access']:
        check_origin()
        unchanged(api, path, before)
        after = api.request('DELETE' if body is None else 'PUT', path, body)
        if body is not None and any(after.get(key) != value for key, value in body.items()):
            raise Failure('ACCESS_WRITE_MISMATCH')
        writes.append('access')
    final = prepare(api, account)
    if final['access'] or final['dns'] == [] or final['tunnel']['config'] != final['config']:
        raise Failure('PENPOT_INGRESS_POSTCHECK_FAILED')
    return {'status': 'applied', 'host': HOST, 'tunnel_id': TUNNEL, 'zone_id': zone,
            'tunnel_version': final['receipt']['tunnel_version'], 'changes': writes,
            'note': 'Scoped writes only; public readiness must still be verified'}
