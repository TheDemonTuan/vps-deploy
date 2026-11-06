import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from omniroute_ingress import HOSTS, Failure, TUNNEL, run


class Client:
    account = 'a' * 32

    def __init__(self):
        self.config = {'version': 7, 'config': {'originRequest': {'connectTimeout': 30},
            'ingress': [{'hostname': '9router-api.tuannguyenviet.site', 'service': 'https://old-origin'},
                        {'service': 'http_status:404'}]}}
        self.dns = {host: [] for host in HOSTS}
        self.apps = []
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

    def test_tunnel_drift_refuses_shared_write(self):
        client = Client()
        client.drift = True
        with self.assertRaisesRegex(Failure, 'TUNNEL_VERSION_DRIFT'):
            run(client, 'apply')
        self.assertEqual(client.writes, [])


if __name__ == '__main__':
    unittest.main()
