import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from core import Failure, app_registration, exact, host_registration, parse_yaml, resource_collisions

ROOT = Path(__file__).resolve().parents[1]


class Registration(unittest.TestCase):
    def test_production_records(self):
        app = app_registration(ROOT, '9router')
        host = host_registration(ROOT, app['host'])
        self.assertEqual(host['apps']['9router']['route_name'], '9router.yml')
        self.assertEqual(app['manifest']['runtime']['port'], 20128)
        from test_core import GOOD
        exact(parse_yaml(GOOD), app['manifest'])

    def test_unknown_and_unsafe_identifiers(self):
        for app in ('../9router', '9router/', '%i', 'not-enrolled', 'a' * 25):
            with self.subTest(app=app), self.assertRaises(Failure):
                app_registration(ROOT, app)
        with self.assertRaisesRegex(Failure, 'HOST_NOT_REGISTERED'):
            host_registration(ROOT, 'not-enrolled')

    def test_manifest_bool_does_not_equal_integer(self):
        with self.assertRaisesRegex(Failure, 'MANIFEST_POLICY'):
            exact({'version': True}, {'version': 1})

    def test_registry_rejects_duplicate_alias_and_bad_port(self):
        raw = (ROOT / 'registry/9router.yml').read_bytes()
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name) / 'registry'
            directory.mkdir()
            for mutated in (raw + b'app: 9router\n', raw.replace(b'port: 20128', b'port: true'), raw.replace(b'port: 20128', b'port: &port 20128')):
                (directory / '9router.yml').write_bytes(mutated)
                with self.assertRaises(Failure):
                    app_registration(directory.parent, '9router')

    def test_drain_wrapper_namespace(self):
        host = host_registration(ROOT, 'oracle-main')
        host['apps']['drain-9router'] = {
            'api_host': 'demo.fixture.test', 'dashboard_host': '', 'dashboard_alias_host': '',
            'work_dir': '/opt/demo', 'compose_project': 'drain-9router',
            'edge_network': 'edge-drain-9router', 'route_name': 'drain-9router.yml',
        }
        with self.assertRaisesRegex(Failure, 'RESOURCE_COLLISION'):
            resource_collisions(host)



if __name__ == '__main__':
    unittest.main()
