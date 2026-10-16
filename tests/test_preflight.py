"""CGW enrollment preserves gateway parity and adopted state boundaries."""
import contextlib
import copy
import json
import os
import runpy
import subprocess
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
        activation = ROOT / 'tests/fixtures/activation'
        self.registration = app_registration(activation, '9router')
        self.binding = host_registration(activation, 'oracle-main')['apps']['9router']
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

    def test_verified_suspension_keeps_gateway_parity_without_runtime_dependency(self):
        self.live['NetworkSettings']['Networks']['9router-cgw'] = {}
        self.live['Config']['Env'].append('CHATGPT_WEB_RUNTIME_URL=http://cgw-runtime:17841')
        self.live['Mounts'].append({'Type': 'bind', 'Destination': '/run/secrets/cgw-data-token',
                                    'Source': str(self.config / 'cgw-data-token'), 'RW': False})
        registration = app_registration(ROOT, '9router')
        binding = host_registration(ROOT, 'oracle-main')['apps']['9router']
        previous = {'platform_ref': 'a' * 40, 'cgw_network': '9router-cgw'}
        with mock.patch('preflight.subprocess.run', side_effect=self.compose), \
             mock.patch('cgw.diagnostics', side_effect=AssertionError('Suspension must not probe CGW')), \
             mock.patch('preflight.runtime_parity', side_effect=AssertionError('Suspension must not require CGW')):
            preflight.check(ROOT, '9router', registration, binding, self.runtime, previous, cgw_suspension=True)
            self.live['Mounts'][-1]['RW'] = True
            with self.assertRaisesRegex(Failure, 'COMPOSE_PARITY:secrets'):
                preflight.check(ROOT, '9router', registration, binding, self.runtime, previous, cgw_suspension=True)
            with self.assertRaisesRegex(Failure, 'CGW_TRANSITION_POLICY'):
                preflight.check(ROOT, '9router', registration, binding, self.runtime, None, cgw_suspension=True)


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


@unittest.skipUnless(os.geteuid() == 0, 'requires root-owned locks (use unshare --user --map-root-user)')
class InstallerPenpotAdoption(unittest.TestCase):
    """Exercise actual flock exclusion; only host/runtime dependencies are stubbed."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.directories = {name: self.root / name for name in
                            ('config', 'state', 'releases', 'locks', 'systemd', 'libexec', 'sudoers', 'home')}
        for directory in self.directories.values():
            directory.mkdir(mode=0o700)
        self.cfg = self.directories['config'] / 'penpot'
        self.state = self.directories['state'] / 'penpot'
        self.cfg.mkdir(mode=0o700)
        self.state.mkdir(mode=0o700)
        self.release = self.directories['releases'] / ('a' * 40)
        (self.release / 'install').mkdir(parents=True)
        (self.release / 'bin').mkdir()
        (self.release / 'bin/deployctl').write_bytes((ROOT / 'bin/deployctl').read_bytes())
        for name in ('vps-deploy-drain@.service', 'vps-deploy-drain@.timer', 'vps-deploy-app'):
            (self.release / 'install' / name).write_text('fixture @APP@ @RELEASE@ @ACTION@')
        (self.cfg / 'runtime.env').write_text('fixture-only\n')
        (self.cfg / 'runtime.env').chmod(0o600)
        self.profile = {'app': 'penpot', 'fixture_ci': True,
                        'registration': {'host': 'fixture-local', 'manifest': {'strategy': 'penpot'}}}
        self.adopted = {'version': 1, 'revision': 1, 'generation': 'b' * 32, 'operation': None}
        self.args = SimpleNamespace(app='penpot', release='a' * 40, public_key=self.root / 'fixture.pub')
        stack = self.enterContext(contextlib.ExitStack())
        for name, value in [('CONFIG', self.directories['config']), ('STATE', self.directories['state']),
                            ('RELEASES', self.directories['releases']), ('LOCKS', self.directories['locks']),
                            ('SYSTEMD', self.directories['systemd']), ('LIBEXEC', self.directories['libexec'])]:
            stack.enter_context(mock.patch.object(installer, name, value))
        def mapped_path(path):
            if str(path) == '/etc/sudoers.d':
                return self.directories['sudoers']
            if str(path) == '/home':
                return self.directories['home']
            return Path(path)
        stack.enter_context(mock.patch.object(installer, 'Path', side_effect=mapped_path))
        stack.enter_context(mock.patch.object(installer, 'trusted_path', side_effect=lambda path, **kw: path))
        stack.enter_context(mock.patch.object(installer, 'busy'))
        stack.enter_context(mock.patch.object(installer, 'stop_drain', return_value=('fixture.timer', False, False)))
        stack.enter_context(mock.patch.object(installer, 'restore_timers'))
        stack.enter_context(mock.patch.object(installer, 'release_copy'))
        stack.enter_context(mock.patch.object(installer, 'app_registration', return_value=self.profile['registration']))
        stack.enter_context(mock.patch('core.host', return_value=self.profile))
        stack.enter_context(mock.patch('core.fixture_authorized', return_value=True))
        stack.enter_context(mock.patch('penpot.trusted_path', side_effect=lambda path, **kw: Path(path)))
        stack.enter_context(mock.patch('core.trusted_path', side_effect=lambda path, **kw: Path(path)))
        stack.enter_context(mock.patch('penpot_backup.files', return_value={}))
        self.preflight = stack.enter_context(mock.patch('route.preflight', return_value=(self.root / 'route.yml', b'fixture', None)))
        stack.enter_context(mock.patch('route.dynamic', return_value=self.root))
        stack.enter_context(mock.patch('route.route_state', return_value=('single', 'b' * 32)))
        self.ack = stack.enter_context(mock.patch('route.ack'))
        self.identity = stack.enter_context(mock.patch('penpot.adopt_state', side_effect=self.runtime_identity))
        self.runtime = stack.enter_context(mock.patch('penpot.runtime_values', return_value={}))
        self.controller = self.load_controller(str(self.release / 'bin/deployctl'))
        # Load the installed controller's real functions, not a mocked adopt helper.
        stack.enter_context(mock.patch.object(runpy, 'run_path', side_effect=self.load_controller))
        stack.enter_context(mock.patch.object(installer, 'run', side_effect=self.host_command))

    def load_controller(self, path):
        namespace = self.run_path(path)
        functions = namespace['adopt'].__globals__
        functions['registered'] = lambda cfg, registration: ({}, 'c' * 64)
        functions['trusted_path'] = lambda path, **kw: path
        functions['state_status'] = lambda state, req, cfg, profile: load(state / 'state.json')
        functions['app_registration'] = lambda release, app: self.profile['registration']
        functions['host_registration'] = lambda release, host: {}
        functions['Path'] = lambda path: (self.directories['releases'] if str(path) == '/opt/vps-deploy/releases' else Path(path))
        return namespace

    run_path = staticmethod(runpy.run_path)

    def contend(self, name):
        # A different process opens the same inode; no lock/acquire/fcntl mocks.
        program = '''import sys
from core import Failure, lock
try:
    with lock(sys.argv[1]):
        print("acquired")
except Failure as exc:
    print(exc.code)
'''
        env = dict(os.environ, PYTHONPATH=str(ROOT / 'lib'), PYTHONDONTWRITEBYTECODE='1')
        result = subprocess.run([sys.executable, '-c', program, str(self.directories['locks'] / name)],
                                capture_output=True, timeout=10, env=env, check=True)
        return result.stdout.decode().strip()

    def runtime_identity(self, profile, manifest_sha, generation):
        self.assertEqual(self.contend('penpot@operation.lock'), 'APP_BUSY')
        self.assertEqual(self.contend('traefik.lock'), 'APP_BUSY')
        self.assertEqual((manifest_sha, generation), ('c' * 64, 'b' * 32))
        self.ack.assert_called_with(profile, ('single', generation))
        return self.adopted

    def host_command(self, *argv, **kwargs):
        if len(argv) > 1 and argv[1] == 'adopt':
            # The old installer reopens its held operation lock here and fails.
            self.controller['adopt'](self.cfg, self.state, self.directories['locks'], self.profile)
        elif len(argv) > 1 and argv[1] == 'status':
            self.assertEqual(load(self.state / 'state.json'), self.adopted)
        elif argv[0] == '/usr/bin/bash':
            self.assertEqual(self.contend('penpot@operation.lock'), 'APP_BUSY')
            self.assertEqual(load(self.state / 'state.json'), self.adopted)
        return SimpleNamespace(returncode=0)

    def activate(self):
        installer.activation(self.args, ROOT, b'fixture-manifest', {},
                             {'traefik': {'dynamic_dir': '/fixture'}}, None,
                             self.cfg / 'runtime.env', {})

    def test_activation_adopts_without_reopening_its_operation_lock(self):
        self.activate()
        self.identity.assert_called_once()
        self.runtime.assert_called_once_with(b'fixture-only\n', self.profile['registration'])
        self.assertEqual(load(self.state / 'state.json'), self.adopted)
        self.assertEqual(self.contend('penpot@operation.lock'), 'acquired')
        self.assertEqual(self.contend('traefik.lock'), 'acquired')

    def test_standalone_adopt_is_excluded_then_succeeds_after_unlock(self):
        from core import lock
        with lock(self.directories['locks'] / 'penpot@operation.lock'):
            # Execute the real standalone adoption entry point in another process.
            program = '''import core, json, runpy, sys
from core import Failure
core.fixture_authorized = lambda: True
controller = runpy.run_path(sys.argv[1])
try:
    controller['adopt'](*map(__import__('pathlib').Path, sys.argv[2:5]), json.loads(sys.argv[5]))
except Failure as exc:
    print(exc.code)
'''
            env = dict(os.environ, PYTHONPATH=str(ROOT / 'lib'), PYTHONDONTWRITEBYTECODE='1')
            result = subprocess.run([sys.executable, '-c', program, str(self.release / 'bin/deployctl'),
                                     str(self.cfg), str(self.state), str(self.directories['locks']), json.dumps(self.profile)],
                                    capture_output=True, timeout=10, env=env, check=True)
            self.assertEqual(result.stdout.decode().strip(), 'APP_BUSY')
            self.preflight.assert_not_called()
            self.assertFalse((self.state / 'state.json').exists())
        self.controller['adopt'](self.cfg, self.state, self.directories['locks'], self.profile)
        self.assertEqual(load(self.state / 'state.json'), self.adopted)

    def test_activation_preserves_runtime_route_and_identity_failures(self):
        for failure in ('INVALID_RUNTIME_ENV', 'ROUTE_MISMATCH', 'PENPOT_IMAGE_REVISION'):
            with self.subTest(failure=failure), contextlib.ExitStack() as stack:
                self.preflight.reset_mock()
                if failure == 'INVALID_RUNTIME_ENV':
                    stack.enter_context(mock.patch('penpot.runtime_values', side_effect=Failure(failure)))
                elif failure == 'ROUTE_MISMATCH':
                    stack.enter_context(mock.patch('route.route_state', return_value=('blue', 'b' * 32)))
                else:
                    stack.enter_context(mock.patch('penpot.adopt_state', side_effect=Failure(failure)))
                with self.assertRaisesRegex(Failure, failure):
                    self.activate()
                self.assertFalse((self.state / 'state.json').exists())
                if failure == 'INVALID_RUNTIME_ENV':
                    self.preflight.assert_not_called()
                self.assertEqual(self.contend('penpot@operation.lock'), 'acquired')
                self.assertEqual(self.contend('traefik.lock'), 'acquired')


class InstallerCommandErrors(unittest.TestCase):
    def test_controller_error_survives_without_forwarding_secret_output(self):
        report = json.dumps({'status': 'failed', 'error_code': 'PENPOT_PUBLIC_HEALTH',
                             'detail': 'private credential'}).encode()
        result = SimpleNamespace(returncode=1, stdout=report, stderr=b'private credential')
        with mock.patch.object(installer.subprocess, 'run', return_value=result):
            with self.assertRaises(Failure) as caught:
                installer.run('/fixture/bin/deployctl', 'adopt', '--app', 'penpot')
        self.assertEqual(caught.exception.code, 'PENPOT_PUBLIC_HEALTH')
        self.assertNotIn('private credential', str(caught.exception))

    def test_unstructured_or_foreign_command_output_stays_private(self):
        for command, output in (
                ('/fixture/bin/deployctl', b'private credential'),
                ('/fixture/bin/deployctl', b'[]'),
                ('/fixture/bin/deployctl', b'{"status":"failed","error_code":"private credential"}'),
                ('/bin/bash', b'{"status":"failed","error_code":"PENPOT_PUBLIC_HEALTH"}')):
            with self.subTest(command=command, output=output):
                result = SimpleNamespace(returncode=1, stdout=output, stderr=b'private credential')
                with mock.patch.object(installer.subprocess, 'run', return_value=result):
                    with self.assertRaises(Failure) as caught:
                        installer.run(command)
                self.assertEqual(caught.exception.code, 'COMMAND_FAILED')


class RuntimePolicy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = Path(self.tmp.name)
        (self.config / 'cgw-seccomp.json').write_text(json.dumps({
            'defaultAction': 'SCMP_ACT_ERRNO',
            'syscalls': [{'action': 'SCMP_ACT_ALLOW', 'names': ['clone', 'setns', 'unshare']}]}))
        self.composed = {
            'services': {'browser-init': {}, 'cgw-runtime': {
                'environment': {'CGW_DATA_DIR': '/data'},
                'volumes': [{'type': 'volume', 'source': 'cgw-data', 'target': '/data'},
                            {'type': 'volume', 'source': 'cgw-browser', 'target': '/opt/cgw-browser',
                             'read_only': True}]}},
            'volumes': {'cgw-data': {'name': '9router-cgw-data'},
                        'cgw-browser': {'name': '9router-cgw-browser'}}}
        self.live = {
            'Config': {'User': '10001:10001', 'Env': ['CGW_DATA_DIR=/data']},
            'HostConfig': {'ReadonlyRootfs': True, 'Init': True, 'Privileged': False,
                           'CapDrop': ['ALL'], 'CapAdd': [], 'ShmSize': 1073741824,
                           'NanoCpus': 1000000000, 'Memory': 2147483648,
                           'IpcMode': 'private', 'PidMode': '', 'NetworkMode': '9router-cgw',
                           'SecurityOpt': ['no-new-privileges:true', 'seccomp=fixture'],
                           'Tmpfs': {'/tmp': '', '/run': ''},
                           'PortBindings': {'5900/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '17842'}]}},
            'NetworkSettings': {'Networks': {'9router-cgw': {}, '9router-cgw-egress': {}}},
            'Mounts': [{'Type': 'volume', 'Name': '9router-cgw-data', 'Destination': '/data', 'RW': True},
                       {'Type': 'volume', 'Name': '9router-cgw-browser', 'Destination': '/opt/cgw-browser',
                        'RW': False}]}

    def parity(self):
        with mock.patch('preflight.container', return_value=self.live), \
             mock.patch('preflight.container_digest', return_value=IMAGE), \
             mock.patch('preflight.subprocess.run', return_value=SimpleNamespace(
                 returncode=0, stdout=json.dumps(self.composed).encode())):
            return preflight.runtime_parity(ROOT, self.config, {})

    def test_named_cache_and_separate_account_volume_adopt(self):
        self.assertEqual(self.parity(), self.composed)

    def test_writable_anonymous_or_host_browser_cache_denies_adoption(self):
        original = copy.deepcopy(self.live['Mounts'][1])
        for mutation in ({'RW': True}, {'Name': 'other'}, {'Type': 'bind', 'Source': '/host/browser'}):
            with self.subTest(mutation=mutation):
                self.live['Mounts'][1] = dict(original, **mutation)
                with self.assertRaisesRegex(Failure, 'CGW_BROWSER_MOUNT'):
                    self.parity()

    def test_sandbox_or_cpu_memory_limits_cannot_be_relaxed(self):
        original = copy.deepcopy(self.live['HostConfig'])
        for mutation in ({'NanoCpus': 0}, {'Memory': 0}, {'Privileged': True}, {'ReadonlyRootfs': False},
                         {'CapAdd': ['SYS_ADMIN']}, {'SecurityOpt': ['no-new-privileges:true', 'seccomp=unconfined']}):
            with self.subTest(mutation=mutation):
                self.live['HostConfig'] = dict(original, **mutation)
                with self.assertRaisesRegex(Failure, 'CGW_SANDBOX_POLICY'):
                    self.parity()

    def test_viewer_never_binds_publicly(self):
        self.live['HostConfig']['PortBindings']['5900/tcp'][0]['HostIp'] = '0.0.0.0'
        with self.assertRaisesRegex(Failure, 'CGW_VIEWER_POLICY'):
            self.parity()


if __name__ == '__main__':
    unittest.main()
