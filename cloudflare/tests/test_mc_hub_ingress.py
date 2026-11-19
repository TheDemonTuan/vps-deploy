import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mc_hub_ingress import HOSTS, Failure, TUNNEL, origin, run

ZONES = ('tuannguyenviet.site', 'thedemontuan.dev')


class Client:
    account = 'a' * 32

    def __init__(self):
        self.config = {'version': 7, 'config': {'originRequest': {'connectTimeout': 30},
            'ingress': [{'hostname': 'sibling.tuannguyenviet.site', 'service': 'https://old-origin'},
                        {'service': 'http_status:404'}]}}
        self.dns = {host: [] for host in HOSTS}
        self.writes = []
        self.drift = False
        self.config_reads = 0

    def get(self, path):
        if path.startswith('/zones?'):
            return [{'id': str(i) * 32, 'name': name, 'account': {'id': self.account}} for i, name in enumerate(ZONES)]
        if '/dns_records?' in path:
            return copy.deepcopy(self.dns[path.split('name=')[1].split('&')[0]])
        if path.endswith('/connections'):
            client = '11111111-1111-1111-1111-111111111111'
            return [{'id': client, 'conns': [{'id': '22222222-2222-2222-2222-222222222222',
                    'client_id': client, 'is_pending_reconnect': False}]}]
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


def enrolled_but(missing):
    # Production state before a hostname is added: every other one is routed.
    client = Client()
    for host in HOSTS:
        if host != missing:
            client.config['config']['ingress'].insert(len(client.config['config']['ingress']) - 1, origin(host))
            client.dns[host] = [{'name': host, 'type': 'CNAME', 'proxied': True, 'content': TUNNEL + '.cfargotunnel.com'}]
    return client


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
        self.assertTrue(all(self.dns_ok(client, host) for host in HOSTS))
        writes = len(client.writes)
        run(client, 'apply')
        self.assertEqual(len(client.writes), writes)

    def test_adds_only_the_missing_host_in_its_own_zone(self):
        for missing in HOSTS:
            with self.subTest(missing):
                client = enrolled_but(missing)
                before = copy.deepcopy(client.config['config']['ingress'])
                self.assertEqual(run(client, 'survey')['missing_dns'], [missing])
                run(client, 'apply')
                ingress = client.config['config']['ingress']
                self.assertEqual(ingress[:-2], before[:-1])
                self.assertEqual(ingress[-2], origin(missing))
                posts = [(path, body['name']) for method, path, body in client.writes if method == 'POST']
                zone = next(str(i) * 32 for i, name in enumerate(ZONES) if missing == name or missing.endswith('.' + name))
                self.assertEqual(posts, [('/zones/' + zone + '/dns_records', missing)])

    def test_conflicts_never_write(self):
        for host in HOSTS:
            for conflict in ('dns', 'wildcard', 'foreign-rule'):
                client = Client()
                if conflict == 'dns':
                    client.dns[host] = [{'name': host, 'type': 'A', 'content': '192.0.2.1'}]
                elif conflict == 'wildcard':
                    client.config['config']['ingress'].insert(0, {'hostname': '*.' + host.split('.', 1)[1], 'service': 'http://foreign'})
                else:
                    client.config['config']['ingress'].insert(0, {'hostname': host, 'service': 'http://foreign'})
                with self.subTest(host=host, conflict=conflict), self.assertRaises(Failure):
                    run(client, 'apply')
                self.assertEqual(client.writes, [])

    def test_mail_and_verification_records_coexist(self):
        missing = HOSTS[0]
        client = enrolled_but(missing)
        client.dns[missing] = [{'name': missing, 'type': 'MX', 'content': 'route1.mx.cloudflare.net'},
                               {'name': missing, 'type': 'TXT', 'content': '"google-site-verification=x"'}]
        self.assertEqual(run(client, 'survey')['missing_dns'], [missing])
        run(client, 'apply')
        posts = [body['name'] for method, path, body in client.writes if method == 'POST']
        self.assertEqual(posts, [missing])

    def test_tunnel_drift_refuses_shared_write(self):
        client = Client()
        client.drift = True
        with self.assertRaisesRegex(Failure, 'TUNNEL_VERSION_DRIFT'):
            run(client, 'apply')
        self.assertEqual(client.writes, [])

    @staticmethod
    def dns_ok(client, host):
        return [record['content'] for record in client.dns[host]] == [TUNNEL + '.cfargotunnel.com']


if __name__ == '__main__':
    unittest.main()
