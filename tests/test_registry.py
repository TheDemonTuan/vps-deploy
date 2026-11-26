import sys
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import core
from core import Failure, app_registration, exact, host_registration, parse_yaml, resource_collisions, trusted_path

ROOT = Path(__file__).resolve().parents[1]


class Registration(unittest.TestCase):

    def test_unknown_and_unsafe_identifiers(self):
        for app in ('../omniroute', 'omniroute/', '%i', 'not-enrolled', 'a' * 25):
            with self.subTest(app=app), self.assertRaises(Failure):
                app_registration(ROOT, app)
        with self.assertRaisesRegex(Failure, 'HOST_NOT_REGISTERED'):
            host_registration(ROOT, 'not-enrolled')

    def test_host_registration_allows_omitted_edge_tunnel(self):
        raw = (ROOT / 'hosts/oracle-main.yml').read_text()
        mutated = raw.replace('  tunnel: 09575df7-5465-4201-94c0-130e16472dce\n', '')
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name) / 'hosts'
            directory.mkdir()
            (directory / 'oracle-main.yml').write_text(mutated)
            host = host_registration(directory.parent, 'oracle-main')
            self.assertNotIn('tunnel', host['edge'])
            self.assertEqual(host['edge']['id'], 'n1')

    def test_registration_of_a_release_with_the_dropped_bypass_paths_still_loads(self):
        raw = (ROOT / 'registry/mc-hub.yml').read_text()
        mutated = raw.replace('  lease: mc-hub-api\n', "  lease: mc-hub-api\n  bypass_paths: ['/_astro/*']\n")
        self.assertNotEqual(raw, mutated)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for directory in ('registry', 'hosts'):
                (root / directory).mkdir()
            (root / 'registry/mc-hub.yml').write_text(mutated)
            self.assertEqual(app_registration(root, 'mc-hub')['host'], 'oracle-main')

    def test_manifest_bool_does_not_equal_integer(self):
        with self.assertRaisesRegex(Failure, 'MANIFEST_POLICY'):
            exact({'version': True}, {'version': 1})

    def test_registry_rejects_duplicate_alias_and_bad_port(self):
        raw = (ROOT / 'registry/omniroute.yml').read_bytes()
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name) / 'registry'
            directory.mkdir()
            for mutated in (raw + b'app: omniroute\n', raw.replace(b'port: 20128', b'port: true'), raw.replace(b'port: 20128', b'port: &port 20128')):
                (directory / 'omniroute.yml').write_bytes(mutated)
                with self.assertRaises(Failure):
                    app_registration(directory.parent, 'omniroute')

    def test_drain_wrapper_namespace(self):
        host = host_registration(ROOT, 'oracle-main')
        host['apps']['drain-omniroute'] = {
            'api_host': 'demo.fixture.test', 'dashboard_host': '', 'dashboard_alias_host': '',
            'work_dir': '/opt/demo', 'compose_project': 'drain-omniroute',
            'edge_network': 'edge-drain-omniroute', 'route_name': 'drain-omniroute.yml',
        }
        with self.assertRaisesRegex(Failure, 'RESOURCE_COLLISION'):
            resource_collisions(host)

    def test_production_host_profile_loads_single_image_app(self):
        # #81 left a dangling multi_image reference: every real host load raised NameError.
        registration = app_registration(ROOT, 'omniroute')
        host_record = host_registration(ROOT, 'oracle-main')
        profile = dict(host_record['apps']['omniroute'], platform_ref='a' * 40,
                       dynamic_dir=host_record['traefik']['dynamic_dir'])
        with mock.patch('core.trusted_path'), mock.patch('core.load', return_value=dict(profile)), \
                mock.patch('core.app_registration', return_value=registration), \
                mock.patch('core.host_registration', return_value=host_record), \
                mock.patch('core.fixture_authorized', return_value=False), \
                mock.patch.object(Path, 'stat', return_value=SimpleNamespace(st_mode=0o100600)):
            value = core.host(Path('/etc/vps-deploy/apps/omniroute'), registration, host_record)
        self.assertEqual(value['image_repository'], 'ghcr.io/thedemontuan/omniroute-vps')
        self.assertEqual(value['architecture'], 'arm64')


    def test_root_owned_sticky_lock_ancestor_only(self):
        modes = {'/run/lock': stat.S_IFDIR | 0o1777, '/etc': stat.S_IFDIR | 0o1777}
        def metadata(path):
            return SimpleNamespace(st_uid=0, st_mode=modes.get(str(path), stat.S_IFDIR | 0o755))
        with mock.patch.object(Path, 'lstat', metadata), mock.patch('core.fixture_authorized', return_value=False):
            self.assertEqual(trusted_path('/run/lock/vps-deploy', directory=True), Path('/run/lock/vps-deploy'))
            with self.assertRaisesRegex(Failure, 'UNTRUSTED_PATH'):
                trusted_path('/etc/vps-deploy', directory=True)
            modes['/run/lock'] = stat.S_IFDIR | 0o777
            with self.assertRaisesRegex(Failure, 'UNTRUSTED_PATH'):
                trusted_path('/run/lock/vps-deploy', directory=True)

    def test_image_access_is_public_unless_registry_opts_in(self):
        self.assertEqual(app_registration(ROOT, 'mc-hub-api')['image_access'], 'private')
        self.assertNotIn('image_access', app_registration(ROOT, 'omniroute'))
        raw = (ROOT / 'registry/mc-hub-api.yml').read_bytes()
        with tempfile.TemporaryDirectory() as name:
            (Path(name) / 'registry').mkdir()
            (Path(name) / 'registry/mc-hub-api.yml').write_bytes(raw.replace(b'image_access: private', b'image_access: anyone'))
            with self.assertRaisesRegex(Failure, 'REGISTRY_POLICY'):
                app_registration(Path(name), 'mc-hub-api')

    def test_only_private_app_images_skip_the_anonymous_pull_check(self):
        import operations
        for access, checked in (('public', True), ('private', False)):
            profile = {'registration': {'image_access': access}, 'image_repository': 'ghcr.io/x/app'}
            ref = 'ghcr.io/x/app@sha256:' + 'a' * 64
            with self.subTest(access=access), mock.patch('operations.image_id', side_effect=[Failure('MISSING'), 'id']), \
                    mock.patch('operations.anonymous_image') as anonymous, mock.patch('operations.command'), mock.patch('operations.compose'), \
                    mock.patch('operations.environment', return_value={}):
                operations.pull(Path('/release'), profile, Path('/cfg'), ref, 'blue')
                self.assertEqual(anonymous.called, checked)


if __name__ == '__main__':
    unittest.main()
