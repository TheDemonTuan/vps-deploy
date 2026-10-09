import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import yaml

from test_penpot_contract import ROOT, profile
import core
import penpot
import route

GENERATION = '0123456789abcdef0123456789abcdef'


def route_profile():
    value = profile()
    value.update(route_name='penpot.yml', platform_ref='a' * 40,
                 api_host='design.tuannguyenviet.site', dashboard_host='', dashboard_alias_host='',
                 host_registration={'traefik': {'container': 'edge-traefik', 'mount': '/etc/traefik/dynamic'}})
    return value


def rendered():
    return subprocess.check_output(['bash', str(ROOT / 'apps/penpot/adapter.sh'), 'single', GENERATION,
                                    '', '', 'design.tuannguyenviet.site'])


class PenpotRoutes(unittest.TestCase):
    def test_normal_route_is_frontend_only_and_generation_aware(self):
        raw = rendered()
        self.assertEqual(route.route_state(raw, route_profile()), ('single', GENERATION))
        document = yaml.safe_load(raw)['http']
        self.assertEqual(set(document['routers']), {'penpot-public-router', 'penpot-internal-health'})
        public = document['routers']['penpot-public-router']
        self.assertEqual(public['rule'], 'Host(`design.tuannguyenviet.site`)')
        self.assertEqual(public['entryPoints'], ['web'])
        self.assertEqual(public['middlewares'], ['penpot-route-generation', 'tunnel-only', 'crowdsec-ip'])
        internal = document['routers']['penpot-internal-health']
        self.assertEqual(internal['entryPoints'], ['slot-probe'])
        self.assertIn('Path(`/readyz`)', internal['rule'])
        service = document['services']['penpot-service']['loadBalancer']
        self.assertEqual(service['servers'], [{'url': 'http://penpot-frontend:8080'}])
        self.assertEqual(service['responseForwarding']['flushInterval'], '-1ms')

    def test_adapter_rejects_invalid_identity_before_rendering(self):
        for args in [('blue', GENERATION, '', '', 'design.tuannguyenviet.site'),
                     ('single', GENERATION, 'foreign.test', '', 'design.tuannguyenviet.site'),
                     ('single', GENERATION, '', '', 'evil` ) || Host(`other.test'),
                     ('single', 'bad', '', '', 'design.tuannguyenviet.site')]:
            result = subprocess.run(['bash', str(ROOT / 'apps/penpot/adapter.sh'), *args], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'')

    def test_wrong_backend_port_header_and_extra_url_rejected(self):
        raw = rendered()
        for bad in (raw.replace(b'penpot-frontend:8080', b'penpot-backend:6060'),
                    raw.replace(b'8080', b'9001'),
                    raw.replace(b'X-Penpot-Route-Generation', b'X-Foreign-Generation'),
                    raw.replace(b'http://penpot-frontend:8080', b'http://penpot-frontend:8080/readyz')):
            with self.subTest(bad=bad), self.assertRaises(core.Failure):
                route.route_state(bad, route_profile())

    def test_maintenance_removes_only_public_router_and_keeps_internal_probe(self):
        normal = rendered()
        closed = penpot.maintenance_route(normal, route_profile())
        expected = yaml.safe_load(normal)
        del expected['http']['routers']['penpot-public-router']
        self.assertEqual(yaml.safe_load(closed), expected)
        self.assertEqual(route.route_state(closed, route_profile()), ('single', GENERATION))
        with self.assertRaises(core.Failure):
            penpot.maintenance_route(closed, route_profile())

    def test_internal_probe_requires_exact_ok_generation_and_single_200(self):
        good = SimpleNamespace(returncode=0, stdout=b'OK', stderr=('  HTTP/1.1 200 OK\n  X-Penpot-Route-Generation: ' + GENERATION + '\n').encode())
        with mock.patch.object(route.subprocess, 'run', return_value=good):
            self.assertEqual(route.probe(route_profile()), ('single', GENERATION))
        for bad in (SimpleNamespace(returncode=0, stdout=b'{"ok":true}', stderr=good.stderr),
                    SimpleNamespace(returncode=1, stdout=b'OK', stderr=good.stderr),
                    SimpleNamespace(returncode=0, stdout=b'OK', stderr=good.stderr + good.stderr),
                    SimpleNamespace(returncode=0, stdout=b'OK', stderr=good.stderr + b'  Age: 1\n'),
                    SimpleNamespace(returncode=0, stdout=b'OK', stderr=b' HTTP/1.1 200 OK\n'),
                    SimpleNamespace(returncode=0, stdout=b'OK', stderr=good.stderr.replace(b'200 OK', b'302 Found'))):
            with self.subTest(bad=bad), mock.patch.object(route.subprocess, 'run', return_value=bad), self.assertRaises(core.Failure):
                route.probe(route_profile())

    def test_public_probe_proves_normal_or_closed_route_without_redirect_or_cache(self):
        def responder(status, headers, body):
            def run(argv, **kwargs):
                Path(argv[argv.index('--dump-header') + 1]).write_bytes(headers)
                Path(argv[argv.index('--output') + 1]).write_bytes(body)
                return SimpleNamespace(returncode=0, stdout=status.encode())
            return run
        good = ('HTTP/2 200\r\nX-Penpot-Route-Generation: ' + GENERATION + '\r\n\r\n').encode()
        with mock.patch.object(penpot.subprocess, 'run', side_effect=responder('200', good, b'OK')):
            penpot.public_health(route_profile(), GENERATION)
        closed = b'HTTP/2 404\r\n\r\n'
        with mock.patch.object(penpot.subprocess, 'run', side_effect=responder('404', closed, b'404 page not found')):
            penpot.public_health(route_profile(), maintenance=True)
        for status, headers, body, maintenance in [('302', b'HTTP/2 302\r\nLocation: /login\r\n\r\n', b'', False),
                                                  ('200', good, b'OK', True), ('404', good, b'not found', True),
                                                  ('200', good + b'Age: 1\r\n', b'OK', False),
                                                  ('200', good + good, b'OK', False),
                                                  ('200', good, b'{"ok":true}', False),
                                                  ('200', good + b'Location: /login\r\n', b'OK', False),
                                                  ('200', good + b'Age: 0\r\nAge: 0\r\n', b'OK', False),
                                                  ('200', good + ('X-Penpot-Route-Generation: ' + GENERATION + '\r\n').encode(), b'OK', False),
                                                  ('200', good, b'OK' + b' ' * 63, False),
                                                  ('404', closed, b'x' * 65537, True)]:
            with self.subTest(status=status, maintenance=maintenance), mock.patch.object(penpot.subprocess, 'run', side_effect=responder(status, headers, body)), self.assertRaises(core.Failure):
                penpot.public_health(route_profile(), GENERATION, maintenance=maintenance)

    def test_maintenance_ack_requires_two_consecutive_closed_proofs(self):
        with mock.patch.object(penpot, 'public_health', side_effect=[None, core.Failure('PENPOT_PUBLIC_HEALTH'), None, None]) as probe, mock.patch.object(penpot.time, 'sleep'):
            penpot.public_ack(route_profile(), maintenance=True)
            self.assertEqual(probe.call_count, 4)

    def test_recorded_routes_reject_foreign_bytes_and_shared_file_drift(self):
        forms = {'old': rendered(), 'target': rendered().replace(GENERATION.encode(), b'f' * 32)}
        forms['maintenance'] = penpot.maintenance_route(forms['target'], route_profile())
        for name, raw in forms.items():
            self.assertEqual(penpot.recorded_route(raw, forms), name)
        for foreign in (forms['target'] + b'\n# foreign writer\n', b'foreign', forms['target'].replace(b'crowdsec-ip', b'foreign')):
            with self.assertRaisesRegex(core.Failure, 'PENPOT_ROUTE_DRIFT'):
                penpot.recorded_route(foreign, forms)
        with self.assertRaises(core.Failure):
            penpot.recorded_route(forms['old'], {'old': forms['old']})


if __name__ == '__main__':
    unittest.main()
