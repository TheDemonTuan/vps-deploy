"""One-time, exact-host teardown; never print API bodies or credentials."""
import copy
import json
import re
import sys
from urllib.parse import urlsplit
from penpot_ingress import Client, Failure, HOST, ZONE, TUNNEL, inventory_list, active_connectors
from penpot_apply import READ_ONLY, domains


def require(value, label):
    if not value:
        raise Failure(label)


def host(value):
    if not isinstance(value, str):
        return ''
    return urlsplit(value if '://' in value else 'https://' + value).hostname or ''


def clean(value):
    if isinstance(value, dict):
        return {key: clean(item) for key, item in value.items() if key not in ('version', 'last_updated', 'updated_at')}
    if isinstance(value, list):
        return [clean(item) for item in value]
    return value


def plain_list(api, path):
    data, _ = api._response('GET', path, None)
    info = data.get('result_info', {})
    require(not info.get('total_pages') or info['total_pages'] <= 1, 'OPTIONAL_INVENTORY_PAGINATION')
    return inventory_list(data['result'])


def run(receipt):
    api = Client()
    zones = inventory_list(api.get('/zones?name=' + ZONE + '&per_page=50'))
    matches = [zone for zone in zones if zone.get('name') == ZONE and zone.get('account', {}).get('id') == api.account]
    require(len(matches) == 1, 'EXACT_ZONE_REQUIRED')
    base = '/zones/' + matches[0]['id']
    account = '/accounts/' + api.account
    tunnel_path = account + '/cfd_tunnel/' + TUNNEL + '/configurations'
    before_tunnel = api.get(tunnel_path)
    config = copy.deepcopy(before_tunnel['config'])
    ingress = inventory_list(config['ingress'])
    require(not any('*' in item.get('hostname', '') and HOST.endswith(item['hostname'].lstrip('*')) for item in ingress), 'WILDCARD_TUNNEL_REQUIRES_REVIEW')
    selected = [item for item in ingress if item.get('hostname') == HOST]
    config['ingress'] = [item for item in ingress if item.get('hostname') != HOST]
    require(config['ingress'] and 'hostname' not in config['ingress'][-1], 'SHARED_CATCHALL_REQUIRED')
    dns_path = base + '/dns_records?per_page=100'
    before_dns = inventory_list(api.get(dns_path))
    selected_dns = [item for item in before_dns if item.get('name') == HOST]
    apps_path = account + '/access/apps?per_page=100'
    before_apps = inventory_list(api.get(apps_path))
    app_changes = []
    for app in before_apps:
        values = domains(app)
        selected_domains = [value for value in values if host(value) == HOST]
        if not selected_domains:
            continue
        require(app.get('type') == 'self_hosted', 'ACCESS_TYPE_REQUIRES_REVIEW')
        path = account + '/access/apps/' + app['id']
        detail = api.get(path)
        require(domains(detail) == values, 'ACCESS_DRIFT')
        remaining = [value for value in values if host(value) != HOST]
        body = {key: copy.deepcopy(value) for key, value in detail.items() if key not in READ_ONLY}
        if remaining:
            body['domain'] = remaining[0]
            body['self_hosted_domains'] = remaining
        app_changes.append((path, app['id'], body if remaining else None, remaining))
    rule_changes = []
    rule_snapshots = []
    for ruleset in inventory_list(api.get(base + '/rulesets?per_page=50')):
        if ruleset.get('kind') == 'managed':
            continue
        path = base + '/rulesets/' + ruleset['id']
        try:
            detail = api.get(path)
        except Failure as error:
            receipt['blockers'].append('ruleset_phase=' + ruleset.get('phase', 'unknown') + ':' + str(error))
            continue
        rules = inventory_list(detail.get('rules', []))
        selected_rules = []
        for rule in rules:
            expression = rule.get('expression', '')
            if HOST not in expression and 'penpot' not in rule.get('description', '').lower():
                continue
            exact = re.sub(r'[\s()]', '', expression) == 'http.hosteq"' + HOST + '"'
            if not exact:
                receipt['blockers'].append('REVIEW_RULE_SCOPE:' + ruleset['id'] + ':' + rule['id'])
                continue
            selected_rules.append(rule)
            rule_changes.append((path + '/rules/' + rule['id'], ruleset['id'], rule['id']))
        rule_snapshots.append((path, [rule for rule in rules if rule not in selected_rules]))
    extras = []
    for label, path, selector, pagination in (
        ('workers_routes', base + '/workers/routes', lambda item: host(item.get('pattern', '')) == HOST, False),
        ('page_rules', base + '/pagerules?per_page=100', lambda item: bool(item.get('targets')) and all(target.get('target') == 'url' and host(target.get('constraint', {}).get('value', '')) == HOST for target in item['targets']), False),
        ('custom_hostnames', base + '/custom_hostnames?per_page=50', lambda item: item.get('hostname') == HOST, True),
    ):
        try:
            items = inventory_list(api.get(path)) if pagination else plain_list(api, path)
            extras.append((label, path, items, selector))
        except Failure as error:
            receipt['blockers'].append(label + ':' + str(error))
    receipt['before'] = {'dns_records': [item['id'] for item in selected_dns], 'ingress_rules': len(selected),
                         'access_apps': [item[1] for item in app_changes],
                         'rules': [{'ruleset': item[1], 'rule': item[2]} for item in rule_changes],
                         'unrelated_ingress_count': len(config['ingress'])}
    if selected:
        require(api.get(tunnel_path) == before_tunnel, 'TUNNEL_CONFIG_DRIFT')
        api.request('PUT', tunnel_path, {'config': config})
        receipt['removed']['ingress_rules'] = len(selected)
    for item in selected_dns:
        api.request('DELETE', base + '/dns_records/' + item['id'])
        receipt['removed']['dns_records'].append(item['id'])
    for path, identity, body, remaining in app_changes:
        api.request('DELETE' if body is None else 'PUT', path, body)
        receipt['removed']['access_apps' if body is None else 'shared_access_domains'].append(identity)
    for path, ruleset, identity in rule_changes:
        api.request('DELETE', path)
        receipt['removed']['rules'].append({'ruleset': ruleset, 'rule': identity})
    for label, path, items, selector in extras:
        for item in items:
            if selector(item):
                api.request('DELETE', path.split('?', 1)[0] + '/' + item['id'])
                receipt['removed'].setdefault(label, []).append(item['id'])
    after_tunnel = api.get(tunnel_path)
    require(after_tunnel['config'] == config, 'SHARED_TUNNEL_CONFIG_CHANGED')
    after_dns = inventory_list(api.get(dns_path))
    require(not any(item.get('name') == HOST for item in after_dns), 'DNS_REMAINS')
    require(clean(after_dns) == clean([item for item in before_dns if item.get('name') != HOST]), 'UNRELATED_DNS_CHANGED')
    after_apps = inventory_list(api.get(apps_path))
    require(not any(host(value) == HOST for app in after_apps for value in domains(app)), 'ACCESS_REMAINS')
    changed_app_ids = {item[1] for item in app_changes}
    require(clean([item for item in before_apps if item['id'] not in changed_app_ids]) == clean([item for item in after_apps if item['id'] not in changed_app_ids]), 'UNRELATED_ACCESS_CHANGED')
    for path, identity, body, remaining in app_changes:
        if body is not None:
            require(domains(api.get(path)) == remaining, 'SHARED_ACCESS_DOMAIN_CHANGED')
    for path, expected in rule_snapshots:
        require(clean(api.get(path).get('rules', [])) == clean(expected), 'UNRELATED_RULES_CHANGED')
    for label, path, items, selector in extras:
        current = inventory_list(api.get(path)) if label == 'custom_hostnames' else plain_list(api, path)
        require(not any(selector(item) for item in current), 'EXTRA_HOST_RESOURCE_REMAINS')
        require(clean(current) == clean([item for item in items if not selector(item)]), 'UNRELATED_EXTRA_RESOURCE_CHANGED')
        receipt['verified'][label + '_remaining'] = 0
    connectors = active_connectors(api.get(account + '/cfd_tunnel/' + TUNNEL + '/connections'))
    require(connectors > 0, 'SHARED_CONNECTOR_INACTIVE')
    receipt['verified'].update({'dns_remaining': 0, 'ingress_remaining': 0, 'access_remaining': 0,
                               'shared_tunnel_unchanged_except_penpot': True, 'unrelated_dns_unchanged': True,
                               'unrelated_access_unchanged': True, 'unrelated_rules_unchanged': True,
                               'active_shared_connectors': connectors,
                               'preserved_ingress_hostnames': [item.get('hostname', '<catchall>') for item in config['ingress']],
                               'shared_origin_certificate_preserved': True})
    receipt['status'] = 'verified' if not receipt['blockers'] else 'verified_core_with_blockers'


receipt = {'host': HOST, 'tunnel_id': TUNNEL, 'removed': {'dns_records': [], 'ingress_rules': 0, 'access_apps': [], 'shared_access_domains': [], 'rules': []}, 'verified': {}, 'blockers': []}
try:
    run(receipt)
except (Failure, KeyError, TypeError, ValueError) as error:
    receipt['status'] = 'failed'
    receipt['blockers'].append(str(error) if isinstance(error, Failure) else 'TEARDOWN_RESPONSE_POLICY')
print(json.dumps(receipt, sort_keys=True, indent=2))
sys.exit(1 if receipt['status'] == 'failed' else 0)
