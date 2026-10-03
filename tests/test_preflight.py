"""CGW enrollment preserves gateway parity and adopted state boundaries."""
import contextlib
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
sys.path.insert(0, str(ROOT / 'install'))
import preflight
import installer
from core import Failure, app_registration, host_registration, load, save

IMAGE = 'ghcr.io/thedemontuan/9router-cgw-runtime@sha256:' + 'c' * 64


class GatewayEnrollment(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = Path(self.tmp.name)
        self.runtime = self.config / 'runtime.env'
        self.runtime.write_text('INITIAL_PASSWORD=fixture-only\n')
        self.registration = app_registration(ROOT, '9router')
        self.binding = host_registration(ROOT, 'oracle-main')['apps']['9router']
        self.base = {
            'services': {name: {'container_name': name, 'environment': {'INITIAL_PASSWORD': 'fixture-only'},
                               'networks': ['edge'], 'volumes': [{'type': 'volume', 'target': '/app/data', 'source': '9router-data'}]}
                         for name in ('9router-blue', '9router-green')},
            'networks': {'edge': {'name': 'edge-9router'}},
        }
        self.live = {'State': {'Running': True}, 'Config': {'Env': ['INITIAL_PASSWORD=fixture-only']},
                     'NetworkSettings': {'Networks': {'edge-9router': {}}},
                     'Mounts': [{'Type': 'volume', 'Destination': '/app/data', 'Name': '9router-data'}]}
        for target, value in [('preflight.container', self.live), ('preflight.container_digest', 'fixture@sha256:' + 'a' * 64),
                              ('cgw.diagnostics', {'operationFence': None}), ('preflight.runtime_parity', {})]:
            patcher = mock.patch(target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch('cgw.network')
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch('cgw.validate_tunnel_secrets')
        patcher.start()
        self.addCleanup(patcher.stop)
        secret = SimpleNamespace(stat=lambda: SimpleNamespace(st_mode=0o640, st_gid=10001))
        def trusted(path):
            if path.name in ('cgw.env', 'cgw-seccomp.json'):
                return SimpleNamespace(stat=lambda: SimpleNamespace(st_mode=0o600, st_gid=0))
            return secret
        patcher = mock.patch('core.trusted_path', side_effect=trusted)
        patcher.start()
        self.addCleanup(patcher.stop)

    def compose(self, argv, **kwargs):
        composed = copy.deepcopy(self.base)
        if any(str(arg).endswith('docker-compose.chatgpt-web.yml') for arg in argv):
            composed['networks']['cgw'] = {'name': '9router-cgw'}
            for service in composed['services'].values():
                service['networks'].append('cgw')
                service['environment']['CHATGPT_WEB_RUNTIME_URL'] = 'http://cgw-runtime:17841'
                service['volumes'].append({'type': 'bind', 'target': '/run/secrets/cgw-data-token',
                                          'source': str(self.config / 'cgw-data-token'), 'read_only': True})
        return SimpleNamespace(returncode=0, stdout=json.dumps(composed).encode())

    def test_verified_first_enrollment_accepts_old_gateway_but_still_requires_runtime(self):
        with mock.patch('preflight.subprocess.run', side_effect=self.compose):
            preflight.check(ROOT, '9router', self.registration, self.binding, self.runtime,
                            {'platform_ref': 'a' * 40}, cgw_transition=True)
            with mock.patch('preflight.runtime_parity', side_effect=Failure('CGW_SANDBOX_POLICY')):
                with self.assertRaisesRegex(Failure, 'CGW_SANDBOX_POLICY'):
                    preflight.check(ROOT, '9router', self.registration, self.binding, self.runtime,
                                    {'platform_ref': 'a' * 40}, cgw_transition=True)
            with mock.patch('cgw.diagnostics', return_value={'operationFence': {'operationId': 'pending', 'state': 'draining'}}):
                with self.assertRaisesRegex(Failure, 'CGW_FENCE'):
                    preflight.check(ROOT, '9router', self.registration, self.binding, self.runtime,
                                    {'platform_ref': 'a' * 40}, cgw_transition=True)

    def test_existing_cgw_enrollment_cannot_skip_missing_gateway_overlay(self):
        with mock.patch('preflight.subprocess.run', side_effect=self.compose):
            with self.assertRaisesRegex(Failure, 'COMPOSE_PARITY'):
                preflight.check(ROOT, '9router', self.registration, self.binding, self.runtime,
                                {'platform_ref': 'a' * 40, 'cgw_network': '9router-cgw'})
            with self.assertRaisesRegex(Failure, 'CGW_TRANSITION_POLICY'):
                preflight.check(ROOT, '9router', self.registration, self.binding, self.runtime,
                                {'platform_ref': 'a' * 40, 'cgw_network': '9router-cgw'}, cgw_transition=True)
            with self.assertRaisesRegex(Failure, 'CGW_TRANSITION_POLICY'):
                preflight.check(ROOT, '9router', self.registration, self.binding, self.runtime, None, cgw_transition=True)


class RuntimeAdoption(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = {'version': 1, 'revision': 7, 'active': {'slot': 'green', 'image': 'gateway-digest'},
                      'previous': {'slot': 'blue', 'image': 'old-gateway-digest'}, 'generation': '1' * 32,
                      'operation': None, 'draining': None, 'rtk': {'current': 'rtk-digest', 'previous': None}}
        self.path = self.root / 'state.json'
        save(self.path, self.state)
        self.profile = {'app': '9router', 'cgw_image_repository': 'ghcr.io/thedemontuan/9router-cgw-runtime'}
        for target, value in [('core.trusted_path', self.path), ('operations.matching', None),
                              ('preflight.container', {}), ('preflight.container_digest', IMAGE),
                              ('cgw.diagnostics', {'operationFence': None, 'idle': True}),
                              ('preflight.runtime_parity', {})]:
            patcher = mock.patch(target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_adoption_only_adds_runtime_and_advances_revision(self):
        preflight.adopt_cgw(ROOT, self.root, self.root, self.profile)
        observed = load(self.path)
        expected = dict(self.state, revision=8, cgw={'current': IMAGE, 'previous': None})
        self.assertEqual(observed, expected)
        with self.assertRaisesRegex(Failure, 'CGW_ADOPTION_UNSAFE'):
            preflight.adopt_cgw(ROOT, self.root, self.root, self.profile)
        self.assertEqual(load(self.path), expected)

    def test_busy_fenced_or_invalid_runtime_never_changes_state(self):
        original = self.path.read_bytes()
        for proof, code in [({'operationFence': None, 'idle': False}, 'CGW_ADOPTION_BUSY'),
                            ({'operationFence': {'operationId': 'upgrade', 'state': 'draining'}, 'idle': True}, 'CGW_FENCE')]:
            with self.subTest(code=code), mock.patch('cgw.diagnostics', return_value=proof):
                with self.assertRaisesRegex(Failure, code):
                    preflight.adopt_cgw(ROOT, self.root, self.root, self.profile)
                self.assertEqual(self.path.read_bytes(), original)
        with mock.patch('preflight.runtime_parity', side_effect=Failure('CGW_SANDBOX_POLICY')):
            with self.assertRaisesRegex(Failure, 'CGW_SANDBOX_POLICY'):
                preflight.adopt_cgw(ROOT, self.root, self.root, self.profile)
            self.assertEqual(self.path.read_bytes(), original)
        pending = dict(self.state, operation={'request_id': 'pending', 'phase': 'prepared'})
        save(self.path, pending)
        with self.assertRaisesRegex(Failure, 'CGW_ADOPTION_UNSAFE'):
            preflight.adopt_cgw(ROOT, self.root, self.root, self.profile)
        self.assertEqual(load(self.path), pending)

    def test_installer_restores_state_bytes_if_key_install_fails_after_adoption(self):
        cfg = self.root / 'config/9router'
        state_dir = self.root / 'state/9router'
        cfg.mkdir(parents=True)
        state_dir.mkdir(parents=True)
        initial = self.path.read_bytes()
        (state_dir / 'state.json').write_bytes(initial)
        (cfg / 'host.json').write_bytes(b'{"platform_ref":"old"}')
        (cfg / 'app.yml').write_bytes(b'old-manifest')
        (cfg / 'runtime.env').write_bytes(b'INITIAL_PASSWORD=fixture-only\n')
        releases = self.root / 'releases'
        release = releases / ('a' * 40)
        (release / 'install').mkdir(parents=True)
        for name in ('vps-deploy-drain@.service', 'vps-deploy-drain@.timer', 'vps-deploy-app'):
            (release / 'install' / name).write_text('fixture @APP@ @RELEASE@ @ACTION@')
        directories = {name: self.root / name for name in ('locks', 'systemd', 'libexec', 'sudoers', 'home')}
        for directory in directories.values():
            directory.mkdir()
        args = SimpleNamespace(app='9router', release='a' * 40, public_key=self.root / 'fixture.pub')
        original_path = Path
        def mapped_path(path):
            if str(path) == '/etc/sudoers.d':
                return directories['sudoers']
            if str(path) == '/home':
                return directories['home']
            return original_path(path)
        def run(*argv, **kwargs):
            if str(argv[0]) == '/usr/bin/bash':
                self.assertEqual(load(state_dir / 'state.json')['cgw']['current'], IMAGE)
                raise Failure('KEY_INSTALL_FAILED')
            return SimpleNamespace(returncode=0)
        with contextlib.ExitStack() as stack:
            for name, value in [('CONFIG', cfg.parent), ('STATE', state_dir.parent), ('RELEASES', releases),
                                ('LOCKS', directories['locks']), ('SYSTEMD', directories['systemd']),
                                ('LIBEXEC', directories['libexec'])]:
                stack.enter_context(mock.patch.object(installer, name, value))
            stack.enter_context(mock.patch('installer.Path', side_effect=mapped_path))
            stack.enter_context(mock.patch('installer.trusted_path', side_effect=lambda path, **kw: path))
            stack.enter_context(mock.patch('installer.optional_trusted', side_effect=lambda path, **kw: path.exists()))
            stack.enter_context(mock.patch('installer.acquire', side_effect=lambda *a: contextlib.nullcontext()))
            stack.enter_context(mock.patch('installer.busy'))
            stack.enter_context(mock.patch('installer.stop_drain', return_value=('fixture.timer', False, False)))
            stack.enter_context(mock.patch('installer.restore_timers'))
            stack.enter_context(mock.patch('installer.release_copy'))
            stack.enter_context(mock.patch('installer.app_registration', return_value={'app': '9router'}))
            stack.enter_context(mock.patch('core.host', return_value=self.profile))
            stack.enter_context(mock.patch('core.trusted_path', side_effect=lambda path, **kw: path))
            stack.enter_context(mock.patch('installer.run', side_effect=run))
            with self.assertRaisesRegex(Failure, 'KEY_INSTALL_FAILED'):
                installer.activation(args, ROOT, b'new-manifest', {}, {'traefik': {'dynamic_dir': '/fixture'}},
                                     {'platform_ref': 'old'}, cfg / 'runtime.env', {}, cgw_transition=True)
        self.assertEqual((state_dir / 'state.json').read_bytes(), initial)
        self.assertEqual((cfg / 'host.json').read_bytes(), b'{"platform_ref":"old"}')
        self.assertEqual((cfg / 'app.yml').read_bytes(), b'old-manifest')


if __name__ == '__main__':
    unittest.main()
