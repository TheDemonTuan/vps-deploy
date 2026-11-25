import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from edge_waf import MANAGED, PROBE, Failure, run

DEV, SITE = 'd' * 32, 's' * 32
BANS = {'id': 'b', 'ref': 'crowdsec_edge_block', 'description': 'Edge IP bans', 'expression': 'ip.src in $edge_bans',
        'action': 'block', 'enabled': True}
API_PATHS = {'id': 'o', 'ref': 'omniroute_api_paths', 'description': 'omniroute_api_paths', 'expression': '(http.host eq "x")',
             'action': 'block', 'enabled': True}


class Client:
    """Zones with their phase entrypoints, as the rulesets API serves them."""
    account = 'a' * 32

    def __init__(self, sets):
        self.sets, self.writes, self.ids = copy.deepcopy(sets), [], 0

    def get(self, path):
        if path == '/zones?per_page=50':
            return [{'id': DEV, 'name': 'thedemontuan.dev', 'account': {'id': self.account}},
                    {'id': SITE, 'name': 'tuannguyenviet.site', 'account': {'id': self.account}}]
        zone, _, rest = path[len('/zones/'):].partition('/rulesets')
        if rest == '?per_page=50':
            return [{'id': ruleset['id'], 'kind': 'zone', 'phase': phase} for phase, ruleset in self.sets[zone].items()]
        return copy.deepcopy(next(r for r in self.sets[zone].values() if r['id'] == rest[1:]))

    def request(self, method, path, body):
        self.writes.append((method, path))
        zone, _, rest = path[len('/zones/'):].partition('/rulesets')
        self.ids += 1
        if rest == '':
            self.sets[zone][body['phase']] = dict(copy.deepcopy(body), id='new%d' % self.ids,
                                                  rules=[dict(rule, id='r%d' % self.ids) for rule in body['rules']])
            return
        ruleset_id, _, rule_id = rest[1:].partition('/rules')
        ruleset = next(r for r in self.sets[zone].values() if r['id'] == ruleset_id)
        if method == 'POST':
            ruleset['rules'].append(dict(copy.deepcopy(body), id='r%d' % self.ids))
        else:
            rule = next(r for r in ruleset['rules'] if r['id'] == rule_id[1:])
            rule.update(copy.deepcopy(body))


def zones():
    return {DEV: {'http_request_firewall_custom': {'id': 'dc', 'rules': [BANS]}},
            SITE: {'http_request_firewall_custom': {'id': 'sc', 'rules': [API_PATHS, BANS]}},
            }


class EdgeWaf(unittest.TestCase):
    def test_rules_are_appended_beside_others_and_a_second_apply_writes_nothing(self):
        client = Client(zones())
        self.assertEqual(run(client, 'apply')['changed'], 3)
        self.assertEqual(client.writes, [('POST', '/zones/' + DEV + '/rulesets/dc/rules'), ('POST', '/zones/' + DEV + '/rulesets'),
                                         ('POST', '/zones/' + SITE + '/rulesets/sc/rules')])
        # The controller's rule and omniroute's (which must stay first) are untouched.
        self.assertEqual([r['description'] for r in client.sets[SITE]['http_request_firewall_custom']['rules']],
                         ['omniroute_api_paths', 'Edge IP bans', 'edge-probe-paths'])
        self.assertEqual(client.sets[DEV]['http_request_firewall_managed']['rules'][0]['action_parameters'],
                         MANAGED['action_parameters'])
        client.writes = []
        self.assertEqual(run(client, 'apply')['changed'], 0)
        self.assertEqual(client.writes, [])

    def test_a_drifted_rule_of_ours_is_patched_in_place(self):
        sets = zones()
        sets[DEV]['http_request_firewall_custom']['rules'].append(dict(PROBE, id='p', expression='false'))
        sets[DEV]['http_request_firewall_managed'] = {'id': 'dm', 'rules': [dict(MANAGED, id='m')]}
        client = Client(sets)
        run(client, 'apply')
        self.assertIn(('PATCH', '/zones/' + DEV + '/rulesets/dc/rules/p'), client.writes)
        self.assertNotIn('POST', [method for method, path in client.writes if DEV in path])

    def test_survey_writes_nothing(self):
        client = Client(zones())
        self.assertFalse(any(rule['current'] for rule in run(client, 'survey')['rules']))
        self.assertEqual(client.writes, [])

    def test_the_free_ruleset_deployed_by_another_rule_is_refused(self):
        sets = zones()
        sets[DEV]['http_request_firewall_managed'] = {'id': 'dm', 'rules': [dict(MANAGED, id='m', description='by hand')]}
        with self.assertRaisesRegex(Failure, 'WAF_MANAGED_RULESET_DEPLOYED_ELSEWHERE'):
            run(Client(sets), 'apply')


if __name__ == '__main__':
    unittest.main()
