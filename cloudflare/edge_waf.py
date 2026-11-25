#!/usr/bin/env python3
"""Edge WAF rules this repository owns, added beside the rules it does not own on each zone.

- `edge-probe-paths` (both zones, custom rules): block what scanners ask for and no site serves:
  dotfiles and dot-directories (`/.env`, `/.git/config`, `/.aws/credentials`; not `/.well-known/`),
  `*.php` and WordPress paths. In 11 days of Traefik logs these were most of what CrowdSec
  AppSec caught; Cloudflare now stops them before the tunnel.
- `edge-free-managed` (thedemontuan.dev, managed rules): Cloudflare's Free Managed Ruleset, except
  on monitor. and metrics. (Access-gated; Grafana's queries and vmagent's bodies). On
  tuannguyenviet.site the Free ruleset stays as deployed by hand for the OmniRoute hosts only: a
  zone runs it once, and the Free plan cannot log-test it first against that zone's payment
  webhooks.
Others' rules (the CrowdSec controller's `Edge IP bans`; omniroute_ingress.py's API path rule,
which must stay first) are never rewritten: ours go through the per-rule endpoints, appended.
Token: Zone Read and Zone WAF Edit (`edge-waf`). Output is counts and booleans only.
"""
import argparse
import json
import sys
from mc_hub_hosts import zone_id
from tunnel_api import Client, Failure, identity, inventory_list

FREE_MANAGED_RULESET = '77454fe2d30c4220b5701f6fdfb893ba'
PATH = 'lower(http.request.uri.path)'
PROBE = {
    'description': 'edge-probe-paths',
    'expression': ('(http.request.uri.path contains "/." and not starts_with(http.request.uri.path, "/.well-known/"))'
                   ' or ends_with(' + PATH + ', ".php") or ' + PATH + ' contains "/wp-admin"'
                   ' or ' + PATH + ' contains "/wp-includes" or ' + PATH + ' contains "/wp-content"'),
    'action': 'block',
    'enabled': True,
}
MANAGED = {
    'description': 'edge-free-managed',
    'expression': 'not http.host in {"monitor.thedemontuan.dev" "metrics.thedemontuan.dev"}',
    'action': 'execute',
    'action_parameters': {'id': FREE_MANAGED_RULESET, 'version': 'latest'},
    'enabled': True,
}
WANT = {
    'thedemontuan.dev': {'http_request_firewall_custom': PROBE, 'http_request_firewall_managed': MANAGED},
    'tuannguyenviet.site': {'http_request_firewall_custom': PROBE},
}
SHAPE = ('description', 'expression', 'action', 'action_parameters', 'enabled')


def shape(rule):
    return {key: rule.get(key) for key in SHAPE}


def plan(client, zone, phase, rule):
    sets = inventory_list(client.get('/zones/' + zone + '/rulesets?per_page=50'))
    entry = [item for item in sets if item.get('kind') == 'zone' and item.get('phase') == phase]
    if len(entry) > 1:
        raise Failure('WAF_ENTRYPOINT_CONFLICT')
    if not entry:
        return {'present': False, 'current': False, 'siblings': 0, 'method': 'POST', 'path': '/zones/' + zone + '/rulesets',
                'body': {'name': 'zone ' + phase, 'kind': 'zone', 'phase': phase, 'rules': [rule]}}
    path = '/zones/' + zone + '/rulesets/' + identity(entry[0].get('id'))
    rules = inventory_list(client.get(path).get('rules', []))
    own = [item for item in rules if item.get('description') == rule['description']]
    if len(own) > 1:
        raise Failure('WAF_RULE_DUPLICATE')
    # A zone runs a managed ruleset once; one deployed under another rule is not ours to change.
    if rule['action'] == 'execute' and any(item not in own and (item.get('action_parameters') or {}).get('id') ==
                                           rule['action_parameters']['id'] for item in rules):
        raise Failure('WAF_MANAGED_RULESET_DEPLOYED_ELSEWHERE')
    return {'present': bool(own), 'current': bool(own) and shape(own[0]) == shape(rule), 'siblings': len(rules) - len(own),
            'method': 'PATCH' if own else 'POST', 'body': rule,
            'path': path + '/rules' + ('/' + identity(own[0].get('id')) if own else '')}


def run(client, operation):
    report, changed = [], 0
    for name, phases in WANT.items():
        zone = zone_id(client, name)
        for phase, rule in phases.items():
            state = plan(client, zone, phase, rule)
            if operation == 'apply' and not state['current']:
                client.request(state['method'], state['path'], state['body'])
                changed += 1
                state = plan(client, zone, phase, rule)
                if not state['current']:
                    raise Failure('WAF_VERIFY_FAILED:' + name + ':' + phase)
            report.append({'zone': name, 'phase': phase, 'rule': rule['description'], 'present': state['present'],
                           'current': state['current'], 'sibling_rules': state['siblings']})
    return {'operation': operation, 'changed': changed, 'rules': report}


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
