import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mc_hub_cache import RULE, Failure, run

ZONE_ID = 'z' * 32
SIBLING = {'id': 'r1', 'ref': 'r1', 'version': '3', 'description': 'sibling-bypass-cache',
          'expression': '(http.host eq "sibling.tuannguyenviet.site")', 'action': 'set_cache_settings',
          'action_parameters': {'cache': False}, 'enabled': True}


class Client:
    account = 'a' * 32

    def __init__(self, rules=None):
        self.ruleset = None if rules is None else {'id': 'cache', 'kind': 'zone', 'phase': 'http_request_cache_settings',
                                                    'name': 'Zone cache settings', 'version': '7', 'rules': rules}
        self.writes = []

    def get(self, path):
        if path.startswith('/zones?name='):
            return [{'id': ZONE_ID, 'name': 'tuannguyenviet.site', 'account': {'id': self.account}}]
        if path == '/zones/' + ZONE_ID + '/rulesets?per_page=50':
            sets = [{'id': 'waf', 'kind': 'zone', 'phase': 'http_request_firewall_custom'}]
            return sets + ([{'id': 'cache', 'kind': 'zone', 'phase': 'http_request_cache_settings'}] if self.ruleset else [])
        assert path == '/zones/' + ZONE_ID + '/rulesets/cache', path
        return copy.deepcopy(self.ruleset)

    def request(self, method, path, body):
        assert (method, path) in (('PUT', '/zones/' + ZONE_ID + '/rulesets/cache'), ('POST', '/zones/' + ZONE_ID + '/rulesets')), (method, path)
        self.writes.append((method, copy.deepcopy(body)))
        rules = [dict(rule, id=rule.get('id', 'new'), version='1') for rule in copy.deepcopy(body['rules'])]
        self.ruleset = dict(copy.deepcopy(body), id='cache', version='8', rules=rules)
        return copy.deepcopy(self.ruleset)


class Cache(unittest.TestCase):
    def test_appends_one_rule_keeps_siblings_and_is_repeatable(self):
        client = Client([copy.deepcopy(SIBLING)])
        self.assertEqual(run(client, 'survey')['rule_present'], False)
        self.assertEqual(client.writes, [])
        result = run(client, 'apply')
        self.assertEqual((result['changed'], result['rule_current'], result['sibling_rules_preserved']), (True, True, 1))
        ((method, body),) = client.writes
        self.assertEqual(method, 'PUT')
        sibling, own = body['rules']
        self.assertEqual(sibling, {k: v for k, v in SIBLING.items() if k != 'version'})
        self.assertEqual(own, RULE)
        self.assertIn('not http.cookie contains "__Host-mch_session="', own['expression'])
        self.assertEqual(run(client, 'apply')['changed'], False)
        self.assertEqual(len(client.writes), 1)

    def test_creates_entrypoint_when_zone_has_none(self):
        client = Client()
        self.assertTrue(run(client, 'apply')['rule_current'])
        ((method, body),) = client.writes
        self.assertEqual((method, body['phase'], body['rules']), ('POST', 'http_request_cache_settings', [RULE]))

    def test_repairs_drifted_own_rule_in_place(self):
        client = Client([copy.deepcopy(SIBLING), dict(copy.deepcopy(RULE), id='own', expression='(http.host eq "minecraft.tuannguyenviet.site")')])
        self.assertTrue(run(client, 'apply')['changed'])
        self.assertEqual(client.ruleset['rules'][1]['id'], 'own')
        self.assertEqual(client.ruleset['rules'][1]['expression'], RULE['expression'])

    def test_unsafe_state_never_writes(self):
        other = dict(copy.deepcopy(SIBLING), id='x', description='someone else', expression='(http.host eq "tuannguyenviet.site")')
        for rules in ([copy.deepcopy(SIBLING), other], [dict(RULE, id='a'), dict(RULE, id='b')]):
            client = Client(rules)
            with self.subTest(rules=len(rules)), self.assertRaises(Failure):
                run(client, 'apply')
            self.assertEqual(client.writes, [])


if __name__ == '__main__':
    unittest.main()
