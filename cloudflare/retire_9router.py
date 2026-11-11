#!/usr/bin/env python3
"""One-time 9router Cloudflare teardown: exact hosts only; never print API bodies or credentials."""
import argparse
import copy
import json
import re
import sys
from urllib.parse import urlsplit
from penpot_ingress import Client, Failure, ZONE, TUNNEL, inventory_list, active_connectors
from penpot_apply import READ_ONLY, domains

HOSTS = ('9router-api.tuannguyenviet.site', '9router.tuannguyenviet.site', '9router-admin.tuannguyenviet.site')
MARKER = '9router'


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


def host_only_rule(expression):
    """True when the expression matches nothing but 9router hosts."""
    compact = re.sub(r'\s+', ' ', expression.strip())
    while compact.startswith('(') and compact.endswith(')'):
        compact = compact[1:-1].strip()
    single = re.fullmatch(r'http\.host eq "([^"]+)"', compact)
    if single:
        return single.group(1) in HOSTS
    listed = re.fullmatch(r'http\.host in \{((?:\s*"[^"]+")+\s*)\}', compact)
    return bool(listed) and set(re.findall(r'"([^"]+)"', listed.group(1))) <= set(HOSTS)


def run(api, operation, receipt):
    zones = inventory_list(api.get('/zones?name=' + ZONE + '&per_page=50'))
    matches = [zone for zone in zones if zone.get('name') == ZONE and zone.get('account', {}).get('id') == api.account]
    require(len(matches) == 1, 'EXACT_ZONE_REQUIRED')
    base = '/zones/' + matches[0]['id']
    account = '/accounts/' + api.account
    tunnel_path = account + '/cfd_tunnel/' + TUNNEL + '/configurations'
    before_tunnel = api.get(tunnel_path)
    config = copy.deepcopy(before_tunnel['config'])
    ingress = inventory_list(config['ingress'])
    require(not any('*' in item.get('hostname', '') for item in ingress if any(h.endswith(item['hostname'].lstrip('*')) for h in HOSTS)), 'WILDCARD_TUNNEL_REQUIRES_REVIEW')
    selected_ingress = [item for item in ingress if item.get('hostname') in HOSTS]
    config['ingress'] = [item for item in ingress if item.get('hostname') not in HOSTS]
    require(config['ingress'] and 'hostname' not in config['ingress'][-1], 'SHARED_CATCHALL_REQUIRED')

    dns_path = base + '/dns_records?per_page=100'
    before_dns = inventory_list(api.get(dns_path))
    selected_dns = [item for item in before_dns if item.get('name') in HOSTS]

    apps_path = account + '/access/apps?per_page=100'
    before_apps = inventory_list(api.get(apps_path))
    app_changes = []
    for app in before_apps:
        values = domains(app)
        if not any(host(value) in HOSTS for value in values):
            continue
        require(app.get('type') == 'self_hosted', 'ACCESS_TYPE_REQUIRES_REVIEW')
        path = account + '/access/apps/' + app['id']
        detail = api.get(path)
        require(domains(detail) == values, 'ACCESS_DRIFT')
        remaining = [value for value in values if host(value) not in HOSTS]
        body = {key: copy.deepcopy(value) for key, value in detail.items() if key not in READ_ONLY}
        if remaining:
            body['domain'] = remaining[0]
            body['self_hosted_domains'] = remaining
        app_changes.append((path, app['id'], app.get('name', ''), body if remaining else None, remaining))

    rule_changes, rule_snapshots, review = [], [], []
    for ruleset in inventory_list(api.get(base + '/rulesets?per_page=50')):
        if ruleset.get('kind') != 'zone':
            continue
        path = base + '/rulesets/' + ruleset['id']
        rules = inventory_list(api.get(path).get('rules', []))
        kept = []
        for rule in rules:
            expression = rule.get('expression', '')
            if MARKER not in expression and MARKER not in rule.get('description', '').lower():
                kept.append(rule)
                continue
            if host_only_rule(expression):
                rule_changes.append((path + '/rules/' + rule['id'], ruleset['id'], rule['id'], rule.get('description', '')))
                continue
            kept.append(rule)
            review.append({'ruleset': ruleset['id'], 'phase': ruleset.get('phase'), 'rule': rule['id'],
                           'description': rule.get('description', ''), 'expression': expression})
        rule_snapshots.append((path, kept))

    extras = []
    for label, path, selector in (
        ('workers_routes', base + '/workers/routes', lambda item: host(item.get('pattern', '')) in HOSTS),
        ('page_rules', base + '/pagerules?per_page=100', lambda item: bool(item.get('targets')) and all(
            host(target.get('constraint', {}).get('value', '')) in HOSTS for target in item['targets'])),
    ):
        try:
            items = inventory_list(api.get(path))
            extras.append((label, path, items, selector))
        except Failure as error:
            receipt['blockers'].append(label + ':' + str(error))

    # Anything else carrying the 9router name is reported, never touched.
    receipt['other_named'] = {
        'dns': [item.get('name') for item in before_dns if MARKER in item.get('name', '') and item.get('name') not in HOSTS],
        'ingress': [item.get('hostname') for item in ingress if MARKER in item.get('hostname', '') and item.get('hostname') not in HOSTS],
        'access_apps': [app.get('name') for app in before_apps if MARKER in app.get('name', '').lower() and app['id'] not in {c[1] for c in app_changes}],
        'rules_for_review': review,
    }
    receipt['selected'] = {
        'dns_records': [{'id': item['id'], 'name': item['name'], 'type': item.get('type')} for item in selected_dns],
        'ingress_hostnames': [item['hostname'] for item in selected_ingress],
        'access_apps': [{'id': c[1], 'name': c[2], 'action': 'delete' if c[3] is None else 'trim', 'remaining': c[4]} for c in app_changes],
        'rules': [{'ruleset': c[1], 'rule': c[2], 'description': c[3]} for c in rule_changes],
        'extras': {label: [item['id'] for item in items if selector(item)] for label, _, items, selector in extras},
    }
    if operation == 'survey':
        receipt['status'] = 'surveyed'
        return

    if selected_ingress:
        require(api.get(tunnel_path) == before_tunnel, 'TUNNEL_CONFIG_DRIFT')
        api.request('PUT', tunnel_path, {'config': config})
    for item in selected_dns:
        api.request('DELETE', base + '/dns_records/' + item['id'])
    for path, _, _, body, _ in app_changes:
        api.request('DELETE' if body is None else 'PUT', path, body)
    for path, *_ in rule_changes:
        api.request('DELETE', path)
    for label, path, items, selector in extras:
        for item in items:
            if selector(item):
                api.request('DELETE', path.split('?', 1)[0] + '/' + item['id'])

    require(api.get(tunnel_path)['config'] == config, 'SHARED_TUNNEL_CONFIG_CHANGED')
    after_dns = inventory_list(api.get(dns_path))
    require(clean(after_dns) == clean([item for item in before_dns if item.get('name') not in HOSTS]), 'UNRELATED_DNS_CHANGED')
    after_apps = inventory_list(api.get(apps_path))
    require(not any(host(value) in HOSTS for app in after_apps for value in domains(app)), 'ACCESS_REMAINS')
    changed = {c[1] for c in app_changes}
    require(clean([a for a in before_apps if a['id'] not in changed]) == clean([a for a in after_apps if a['id'] not in changed]), 'UNRELATED_ACCESS_CHANGED')
    for path, kept in rule_snapshots:
        require(clean(api.get(path).get('rules', [])) == clean(kept), 'UNRELATED_RULES_CHANGED')
    for label, path, items, selector in extras:
        current = inventory_list(api.get(path))
        require(clean(current) == clean([item for item in items if not selector(item)]), 'UNRELATED_EXTRA_RESOURCE_CHANGED')
    require(active_connectors(api.get(account + '/cfd_tunnel/' + TUNNEL + '/connections')) > 0, 'SHARED_CONNECTOR_INACTIVE')
    receipt['verified'] = {'preserved_ingress_hostnames': [item.get('hostname', '<catchall>') for item in config['ingress']]}
    receipt['status'] = 'removed' if not review and not receipt['blockers'] else 'removed_with_review_items'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--operation', choices=('survey', 'apply'), required=True)
    operation = parser.parse_args().operation
    receipt = {'hosts': list(HOSTS), 'operation': operation, 'blockers': []}
    try:
        run(Client(), operation, receipt)
    except (Failure, KeyError, TypeError, ValueError) as error:
        receipt['status'] = 'failed'
        receipt['blockers'].append(str(error) if isinstance(error, Failure) else 'TEARDOWN_RESPONSE_POLICY:' + type(error).__name__)
    print(json.dumps(receipt, sort_keys=True, indent=2))
    sys.exit(1 if receipt['status'] == 'failed' else 0)


if __name__ == '__main__':
    main()
