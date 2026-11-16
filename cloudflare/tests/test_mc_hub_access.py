import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mc_hub_access import NAME, PATHS, POLICY, SOURCE, Failure, run

ADMIN = {'email': {'email': 'owner@example.test'}}


class Client:
    account = 'a' * 32

    def __init__(self):
        self.apps = {'src': {'id': 'src', 'name': SOURCE, 'type': 'self_hosted', 'domain': 'omniroute.tuannguyenviet.site',
                             'allowed_idps': ['idp-1'], 'http_only_cookie_attribute': True,
                             'policies': [{'id': 'p0', 'decision': 'allow', 'include': [ADMIN], 'exclude': [], 'require': []}]}}
        self.policies = {}
        self.writes = []

    def get(self, path):
        base = '/accounts/' + self.account + '/access/'
        assert path.startswith(base), path
        kind, _, rest = path[len(base):].partition('/')
        if kind.startswith('apps?'):
            return copy.deepcopy(list(self.apps.values()))
        if kind.startswith('policies?'):
            return copy.deepcopy(list(self.policies.values()))
        return copy.deepcopy({'apps': self.apps, 'policies': self.policies}[kind][rest])

    def request(self, method, path, body):
        assert method == 'POST', method
        self.writes.append((path.rsplit('/', 1)[1], body))
        created = dict(copy.deepcopy(body), id='id%d' % len(self.writes))
        if path.endswith('/policies'):
            self.policies[created['id']] = created
        else:
            created['policies'] = [{'id': link['id'], 'precedence': 1} for link in body['policies']]
            self.apps[created['id']] = created
        return created


class Access(unittest.TestCase):
    def test_creates_policy_then_app_and_is_repeatable(self):
        client = Client()
        result = run(client, 'survey')
        self.assertEqual(client.writes, [])
        self.assertFalse(result['protected'])
        self.assertEqual(result['allowed_emails'], 1)
        run(client, 'apply')
        (kind, policy), (_, app) = client.writes
        self.assertEqual((kind, policy['name'], policy['decision'], policy['include']), ('policies', POLICY, 'allow', [ADMIN]))
        self.assertEqual([d['uri'] for d in app['destinations']], list(PATHS))
        self.assertEqual(app['policies'], [{'id': 'id1', 'precedence': 1}])
        self.assertTrue(app['http_only_cookie_attribute'] and app['auto_redirect_to_identity'])
        self.assertEqual(app['allowed_idps'], ['idp-1'])
        self.assertTrue(run(client, 'apply')['protected'])
        self.assertEqual(len(client.writes), 2)

    def test_unsafe_state_never_writes(self):
        def wildcard(c):
            c.apps['x'] = {'id': 'x', 'name': 'Other', 'domain': '*.tuannguyenviet.site'}
        def api_path(c):
            c.apps['x'] = {'id': 'x', 'name': 'Other', 'destinations': [{'type': 'public', 'uri': 'minecraft-api.tuannguyenviet.site/x'}]}
        def wildcard_email(c):
            c.apps['src']['policies'][0]['include'] = [{'email_domain': {'domain': 'example.test'}}]
        def excluded(c):
            c.apps['src']['policies'][0]['exclude'] = [ADMIN]
        def no_source(c):
            del c.apps['src']
        def drifted(c):
            run(c, 'apply')
            c.apps['id2']['destinations'].pop()
            c.writes.clear()
        for mutate in (wildcard, api_path, wildcard_email, excluded, no_source, drifted):
            client = Client()
            mutate(client)
            with self.subTest(mutate.__name__), self.assertRaises(Failure):
                run(client, 'apply')
            self.assertEqual(client.writes, [])

    def test_existing_policy_is_linked_not_duplicated(self):
        client = Client()
        client.policies['keep'] = {'id': 'keep', 'name': POLICY, 'decision': 'allow', 'include': [ADMIN, {'email': {'email': 'b@example.test'}}]}
        self.assertEqual(run(client, 'apply')['allowed_emails'], 2)
        self.assertEqual([(kind, body['policies']) for kind, body in client.writes], [('apps', [{'id': 'keep', 'precedence': 1}])])


if __name__ == '__main__':
    unittest.main()
