import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from omniroute_ingress import ADMIN_NAME, API_PATH_EXPRESSION, API_PATH_REF, HOSTS, Failure, TUNNEL, run


class Client:
    account = 'a' * 32

    def __init__(self):
        self.config = {'version': 7, 'config': {'originRequest': {'connectTimeout': 30},
            'ingress': [{'hostname': 'sibling.tuannguyenviet.site', 'service': 'https://old-origin'},
                        {'service': 'http_status:404'}]}}
        self.dns = {host: [] for host in HOSTS}
        allow = {'decision': 'allow', 'include': [{'email': {'email': 'owner@example.invalid'}}],
                 'exclude': [], 'require': []}
        self.apps = [
            {'id': 'sibling', 'domain': 'sibling-admin.tuannguyenviet.site', 'type': 'self_hosted',
             'policies': [{'decision': 'non_identity', 'include': [{'service_token': {'token_id': 'monitor'}}]}]},
            {'id': 'omniroute-admin', 'name': ADMIN_NAME, 'domain': HOSTS[1],
             'self_hosted_domains': [HOSTS[1]], 'type': 'self_hosted',
             'allowed_idps': ['email-otp'], 'session_duration': '24h',
             'http_only_cookie_attribute': True, 'policies': [copy.deepcopy(allow)]}]
        self.waf = {'kind': 'zone', 'phase': 'http_request_firewall_custom', 'rules': [
            {'ref': API_PATH_REF, 'action': 'block', 'enabled': True, 'expression': API_PATH_EXPRESSION},
            {'ref': 'existing-ip-bans', 'action': 'block', 'expression': 'ip.src in $banned'}]}
        self.writes = []
        self.drift = False
        self.config_reads = 0

    def get(self, path):
        if path.startswith('/zones?'):
            return [{'id': 'b' * 32, 'name': 'tuannguyenviet.site', 'account': {'id': self.account}}]
        if '/dns_records?' in path:
            return copy.deepcopy(self.dns[path.split('name=')[1].split('&')[0]])
        if path.endswith('/connections'):
            client = '11111111-1111-1111-1111-111111111111'
            return [{'id': client, 'conns': [{'id': '22222222-2222-2222-2222-222222222222',
                    'client_id': client, 'is_pending_reconnect': False}]}]
        if '/access/apps?' in path:
            return copy.deepcopy(self.apps)
        if '/access/apps/' in path:
            return copy.deepcopy(next(app for app in self.apps if app['id'] == path.rsplit('/', 1)[1]))
        if '/rulesets/phases/http_request_firewall_custom/' in path:
            return copy.deepcopy(self.waf)
        if path.endswith('/configurations'):
            self.config_reads += 1
            value = copy.deepcopy(self.config)
            if self.drift and self.config_reads > 1:
                value['version'] += 1
            return value
        raise AssertionError(path)

    def request(self, method, path, body):
        self.writes.append((method, path, body))
        if method == 'PUT':
            self.config['config'] = copy.deepcopy(body['config'])
            self.config['version'] += 1
        elif method == 'POST':
            self.dns[body['name']] = [copy.deepcopy(body)]
        else:
            raise AssertionError(method)


class Ingress(unittest.TestCase):
    def test_add_preserves_siblings_and_is_repeatable(self):
        client = Client()
        original = copy.deepcopy(client.config['config'])
        security = copy.deepcopy((client.apps, client.waf))
        run(client, 'survey')
        self.assertEqual(client.writes, [])
        run(client, 'apply')
        config = client.config['config']
        self.assertEqual(config['originRequest'], original['originRequest'])
        self.assertEqual(config['ingress'][0], original['ingress'][0])
        self.assertEqual(config['ingress'][-1], original['ingress'][-1])
        self.assertEqual([rule['hostname'] for rule in config['ingress'][1:-1]], list(HOSTS))
        self.assertTrue(all(rule['originRequest']['noTLSVerify'] is False for rule in config['ingress'][1:-1]))
        writes = len(client.writes)
        run(client, 'apply')
        self.assertEqual(len(client.writes), writes)
        self.assertEqual((client.apps, client.waf), security)

    def test_dns_or_access_conflict_never_writes(self):
        for conflict in ('dns', 'access', 'wildcard'):
            client = Client()
            if conflict == 'dns':
                client.dns[HOSTS[1]] = [{'name': HOSTS[1], 'type': 'A', 'content': '192.0.2.1'}]
            elif conflict == 'access':
                client.apps = [{'domain': '*.tuannguyenviet.site'}]
            else:
                client.config['config']['ingress'].insert(0, {'hostname': '*.tuannguyenviet.site', 'service': 'http://foreign'})
            with self.subTest(conflict=conflict), self.assertRaises(Failure):
                run(client, 'apply')
            self.assertEqual(client.writes, [])

    def test_access_exposure_or_identity_drift_never_writes(self):
        for change in ('missing', 'bypass', 'service-auth', 'wildcard-email', 'everyone', 'no-idp', 'exclude', 'alias', 'cookie', 'api-access'):
            client = Client()
            admin = client.apps[1]
            if change == 'missing':
                client.apps.pop()
            elif change == 'bypass':
                admin['policies'][0]['decision'] = 'bypass'
            elif change == 'service-auth':
                admin['policies'].append(copy.deepcopy(client.apps[0]['policies'][0]))
            elif change == 'wildcard-email':
                admin['policies'][0]['include'] = [{'email': {'email': '*@example.invalid'}}]
            elif change == 'everyone':
                admin['policies'][0]['include'] = [{'everyone': {}}]
            elif change == 'no-idp':
                admin['allowed_idps'] = []
            elif change == 'exclude':
                admin['policies'][0]['exclude'] = [{'email': {'email': 'owner@example.invalid'}}]
            elif change == 'alias':
                admin['self_hosted_domains'].append('unprotected-alias.example.invalid')
            elif change == 'cookie':
                admin['http_only_cookie_attribute'] = False
            else:
                client.apps.append({'domain': HOSTS[0]})
            with self.subTest(change=change), self.assertRaises(Failure):
                run(client, 'apply')
            self.assertEqual(client.writes, [])

    def test_api_waf_cannot_be_removed_weakened_or_skipped(self):
        for change in ('missing', 'disabled', 'wrong-expression', 'earlier-skip'):
            client = Client()
            if change == 'missing':
                client.waf['rules'].pop(0)
            elif change == 'disabled':
                client.waf['rules'][0]['enabled'] = False
            elif change == 'wrong-expression':
                client.waf['rules'][0]['expression'] = 'http.host eq "other.example.invalid"'
            else:
                client.waf['rules'].insert(0, {'action': 'skip', 'action_parameters': {'ruleset': 'current'}})
            with self.subTest(change=change), self.assertRaisesRegex(Failure, 'API_PATH_WAF_POLICY_DRIFT'):
                run(client, 'apply')
            self.assertEqual(client.writes, [])

    def test_tunnel_drift_refuses_shared_write(self):
        client = Client()
        client.drift = True
        with self.assertRaisesRegex(Failure, 'TUNNEL_VERSION_DRIFT'):
            run(client, 'apply')
        self.assertEqual(client.writes, [])


if __name__ == '__main__':
    unittest.main()
