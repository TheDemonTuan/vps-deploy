import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mc_hub_access import PATHS, POLICY, SOURCE, Failure, run

ADMIN = {'email': {'email': 'owner@example.test'}}


class Client:
    account = 'a' * 32

    def __init__(self):
        self.apps = {'src': {'id': 'src', 'name': SOURCE, 'type': 'self_hosted', 'domain': 'omniroute.tuannguyenviet.site',
                             'allowed_idps': ['idp-1'], 'http_only_cookie_attribute': True,
                             'policies': [{'id': 'p0', 'decision': 'allow', 'include': [ADMIN], 'exclude': [], 'require': []}]}}
        self.writes = []

    def get(self, path):
        base = '/accounts/' + self.account + '/access/apps'
        assert path.startswith(base), path
        if path.startswith(base + '?'):
            return copy.deepcopy(list(self.apps.values()))
        return copy.deepcopy(self.apps[path[len(base) + 1:]])

    def request(self, method, path, body):
        assert (method, path) == ('POST', '/accounts/' + self.account + '/access/apps'), (method, path)
        self.writes.append(body)
        created = dict(copy.deepcopy(body), id='new')
        self.apps['new'] = created
        return created


class Access(unittest.TestCase):
    def test_creates_app_with_own_email_policy_and_is_repeatable(self):
        client = Client()
        result = run(client, 'survey')
        self.assertEqual(client.writes, [])
        self.assertEqual((result['protected'], result['allowed_emails']), (False, 1))
        self.assertTrue(run(client, 'apply')['protected'])
        (app,) = client.writes
        self.assertEqual([d['uri'] for d in app['destinations']], list(PATHS))
        (policy,) = app['policies']
        self.assertEqual((policy['name'], policy['decision'], policy['include']), (POLICY, 'allow', [ADMIN]))
        self.assertTrue(app['http_only_cookie_attribute'] and app['auto_redirect_to_identity'])
        self.assertEqual(app['allowed_idps'], ['idp-1'])
        self.assertTrue(run(client, 'apply')['app_present'])
        self.assertEqual(len(client.writes), 1)

    def test_unsafe_state_never_writes(self):
        def wildcard(c):
            c.apps['x'] = {'id': 'x', 'name': 'Other', 'domain': '*.tuannguyenviet.site'}
        def api_path(c):
            c.apps['x'] = {'id': 'x', 'name': 'Other', 'destinations': [{'type': 'public', 'uri': 'minecraft-api.tuannguyenviet.site/x'}]}
        def email_domain(c):
            c.apps['src']['policies'][0]['include'] = [{'email_domain': {'domain': 'example.test'}}]
        def excluded(c):
            c.apps['src']['policies'][0]['exclude'] = [ADMIN]
        def no_source(c):
            del c.apps['src']
        def drifted(c):
            run(c, 'apply')
            c.apps['new']['destinations'].pop()
            c.writes.clear()
        def widened(c):
            run(c, 'apply')
            c.apps['new']['policies'][0]['include'].append({'everyone': {}})
            c.writes.clear()
        for mutate in (wildcard, api_path, email_domain, excluded, no_source, drifted, widened):
            client = Client()
            mutate(client)
            with self.subTest(mutate.__name__), self.assertRaises(Failure):
                run(client, 'apply')
            self.assertEqual(client.writes, [])


if __name__ == '__main__':
    unittest.main()
