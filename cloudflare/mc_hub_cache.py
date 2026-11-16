#!/usr/bin/env python3
"""Let Cloudflare's edge cache mc-hub's public pages; touch no sibling cache rule.

One rule on the zone's cache-settings entrypoint makes the site host eligible for the edge
cache, except the API, the admin pages and requests carrying the admin session cookie (so the
creator always sees an edit at once). Edge TTL follows the origin and bypasses responses
without cache headers: the site marks only its route-cached public pages
(Cloudflare-CDN-Cache-Control), /media keeps its immutable headers, and redirects, errors and
/healthz stay uncached. The API host is not matched at all.
Output is counts and booleans only: this repository's Actions logs are public.
"""
import argparse
import copy
import json
import sys
from tunnel_api import Client, Failure, ZONE, identity, inventory_list

SITE = 'minecraft.tuannguyenviet.site'
PHASE = 'http_request_cache_settings'
RULE = {
    'description': 'mc-hub-public-edge-cache',
    'expression': ('(http.host eq "' + SITE + '" and not starts_with(http.request.uri.path, "/api/")'
                   ' and not starts_with(http.request.uri.path, "/admin")'
                   ' and not http.cookie contains "__Host-mch_session=")'),
    'action': 'set_cache_settings',
    'action_parameters': {'cache': True, 'edge_ttl': {'mode': 'bypass_by_default'},
                          'browser_ttl': {'mode': 'respect_origin'}},
    'enabled': True,
}
SHAPE = ('description', 'expression', 'action', 'action_parameters', 'enabled')
READ_ONLY = {'version', 'last_updated'}


def zone_id(client):
    zones = inventory_list(client.get('/zones?name=' + ZONE + '&per_page=50'))
    matches = [zone for zone in zones if zone.get('name') == ZONE and zone.get('account', {}).get('id') == client.account]
    if len(matches) != 1:
        raise Failure('EXACT_ACCOUNT_ZONE_REQUIRED')
    return identity(matches[0].get('id'))


def shape(rule):
    return {key: rule.get(key) for key in SHAPE}


def plan(client):
    zone = zone_id(client)
    sets_path = '/zones/' + zone + '/rulesets?per_page=50'
    sets = inventory_list(client.get(sets_path))
    entrypoints = [item for item in sets if item.get('phase') == PHASE and item.get('kind') == 'zone']
    if len(entrypoints) > 1:
        raise Failure('CACHE_ENTRYPOINT_CONFLICT')
    if entrypoints:
        path = '/zones/' + zone + '/rulesets/' + identity(entrypoints[0].get('id'))
        before = client.get(path)
        if before.get('kind') != 'zone' or before.get('phase') != PHASE:
            raise Failure('CACHE_ENTRYPOINT_CONFLICT')
        rules = inventory_list(before.get('rules', []))
        body = {key: copy.deepcopy(before[key]) for key in ('name', 'description', 'kind', 'phase') if key in before}
    else:
        path, before, rules = '/zones/' + zone + '/rulesets', None, []
        body = {'name': 'Zone cache settings', 'kind': 'zone', 'phase': PHASE}
    own = [rule for rule in rules if rule.get('description') == RULE['description']]
    if len(own) > 1:
        raise Failure('CACHE_RULE_DUPLICATE')
    # Another rule naming the site would silently override or be overridden by ours.
    if any(rule not in own and SITE in str(rule.get('expression', '')) for rule in rules):
        raise Failure('CACHE_SCOPE_CONFLICT')
    body['rules'] = [{key: copy.deepcopy(value) for key, value in rule.items() if key not in READ_ONLY} for rule in rules]
    if own:
        for rule in body['rules']:
            if rule.get('description') == RULE['description']:
                rule.update(copy.deepcopy(RULE))
    else:
        body['rules'].append(copy.deepcopy(RULE))
    return {'sets_path': sets_path, 'sets': sets, 'path': path, 'before': before, 'body': body,
            'present': bool(own), 'current': bool(own) and shape(own[0]) == RULE, 'siblings': len(rules) - len(own)}


def run(client, operation):
    state = plan(client)
    changed = False
    if operation == 'apply' and not state['current']:
        # Cloudflare has no conditional write here; re-read immediately before writing.
        if (client.get(state['sets_path']) if state['before'] is None else client.get(state['path'])) != (
                state['sets'] if state['before'] is None else state['before']):
            raise Failure('CACHE_RULESET_DRIFT')
        after = client.request('POST' if state['before'] is None else 'PUT', state['path'], state['body'])
        actual = [shape(rule) for rule in inventory_list(after.get('rules'))]
        if actual != [shape(rule) for rule in state['body']['rules']]:
            raise Failure('CACHE_WRITE_MISMATCH')
        changed = True
        state = plan(client)
        if not state['current']:
            raise Failure('CACHE_VERIFY_FAILED')
    return {'operation': operation, 'host': SITE, 'rule_present': state['present'], 'rule_current': state['current'],
            'changed': changed, 'sibling_rules_preserved': state['siblings']}


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
