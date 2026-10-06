import base64
import importlib.util
import io
import json
from pathlib import Path
import shutil
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
sys.path.insert(0, str(ROOT / 'install'))
from core import Failure, app_registration, host_registration


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


controller = load('activation_controller', ROOT / 'scripts/activate-platform.py')
remote = load('activation_remote', ROOT / 'install/activate-reviewed-release.py')
installer = load('activation_installer', ROOT / 'install/installer.py')
P = 'a' * 40
A = 'b' * 40
OLD = 'c' * 40
# RFC 8709-shaped Ed25519 wire data; keygen itself remains the validation boundary.
KEY = b'ssh-ed25519 ' + base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + bytes(range(32))) + b' operator\n'
REGISTRATION = app_registration(ROOT, 'opendesign')
HOST = host_registration(ROOT, 'oracle-main')
MANIFEST = yaml.safe_dump(REGISTRATION['manifest'], sort_keys=False).encode()


def result(stdout=b'', stderr=b'', returncode=0):
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


def ci_run(**changes):
    value = {'id': 20, 'head_sha': P, 'head_branch': 'main', 'event': 'push',
             'path': '.github/workflows/ci.yml', 'status': 'completed', 'conclusion': 'success', 'run_attempt': 1}
    value.update(changes)
    return value


def container():
    return {'Id': 'container-id', 'Image': 'sha256:image', 'State': {'Running': True, 'Status': 'running',
            'Paused': False, 'Restarting': False, 'Dead': False, 'ExitCode': 0, 'Health': {'Status': 'healthy'}},
            'Config': {'Env': ['OD_DISABLE_API_AUTH=1', 'OD_ALLOWED_ORIGINS=https://design.example.test']},
            'HostConfig': {'PortBindings': {}}, 'NetworkSettings': {'Ports': {'7456/tcp': None}}}


def snapshot(ref=OLD):
    return {'platform_ref': ref, 'container': remote.container_snapshot(container()),
            'route': b'private route bytes', 'runtime_env': (b'private hash', 0, 0, 0o600)}


class ControllerInputs(unittest.TestCase):
    def test_nonhex_injection_never_reaches_io_or_ssh(self):
        for bad in ('', 'A' * 40, 'a' * 39, 'a' * 41, P + '\n', P + ';id', '../main'):
            for platform, app in ((bad, A), (P, bad)):
                with self.subTest(platform=platform, app=app), mock.patch.object(controller, 'run') as command, \
                        mock.patch.object(controller, 'github') as api, mock.patch.object(controller, 'activate') as activate:
                    with mock.patch('sys.stderr', new=io.StringIO()):
                        self.assertEqual(controller.main(['--platform-ref', platform, '--app-ref', app,
                                                          '--admin-key-file', '/key', '--public-key-file', '/pub']), 1)
                    command.assert_not_called()
                    api.assert_not_called()
                    activate.assert_not_called()

    def test_main_membership_requires_ancestor(self):
        for status, merge in (('behind', P), ('diverged', P), ('ahead', A), ('identical', A)):
            with self.subTest(status=status, merge=merge), mock.patch.object(controller, 'github', return_value={
                    'status': status, 'merge_base_commit': {'sha': merge}}):
                with self.assertRaisesRegex(Failure, 'COMMIT_NOT_ON_MAIN'):
                    controller.main_membership(controller.APP_REPOSITORY, P)
        for status in ('ahead', 'identical'):
            with mock.patch.object(controller, 'github', return_value={'status': status, 'merge_base_commit': {'sha': P}}):
                controller.main_membership(controller.PLATFORM_REPOSITORY, P)

    def test_latest_exact_main_ci_rejections(self):
        cases = [[], [ci_run(status='queued', conclusion=None)], [ci_run(status='in_progress', conclusion=None)],
                 [ci_run(conclusion='failure')], [ci_run(head_sha=A)], [ci_run(event='pull_request')],
                 [ci_run(head_branch='feature')], [ci_run(path='.github/workflows/other.yml')],
                 [ci_run(id=19), ci_run(id=20, status='queued', conclusion=None)],
                 [ci_run(id=19), ci_run(id=20, conclusion='cancelled')]]
        for runs in cases:
            with self.subTest(runs=runs), mock.patch.object(controller, 'github', return_value={'workflow_runs': runs}):
                with self.assertRaises(Failure):
                    controller.latest_ci(P)
        for event in ('push', 'workflow_dispatch'):
            with mock.patch.object(controller, 'github', return_value={'workflow_runs': [ci_run(event=event)]}):
                controller.latest_ci(P)

    def test_ci_pagination_does_not_hide_newer_failure(self):
        first = [ci_run(id=i) for i in range(100)]
        with mock.patch.object(controller, 'github', side_effect=[{'workflow_runs': first},
                {'workflow_runs': [ci_run(id=101, conclusion='failure')]}]) as api:
            with self.assertRaisesRegex(Failure, 'CI_NOT_SUCCESSFUL'):
                controller.latest_ci(P)
            self.assertEqual(api.call_count, 2)

    def inputs_api(self, path, raw=MANIFEST, app_on_main=True, runs=None):
        if '/compare/' in path:
            return {'status': 'ahead' if app_on_main or controller.APP_REPOSITORY not in path else 'diverged',
                    'merge_base_commit': {'sha': P if controller.PLATFORM_REPOSITORY in path else A}}
        if '/actions/' in path:
            return {'workflow_runs': [ci_run()] if runs is None else runs}
        if '/contents/' in path:
            self.assertTrue(path.endswith('?ref=' + A))
            return {'type': 'file', 'encoding': 'base64', 'content': base64.b64encode(raw).decode()}
        self.fail('unexpected API boundary')

    def test_full_validation_keeps_manifest_bytes_and_requires_checkout(self):
        raw = b'# original bytes must survive\n' + MANIFEST
        with mock.patch.object(controller, 'run', side_effect=[result(P.encode() + b'\n'), result()]), \
                mock.patch.object(controller, 'github', side_effect=lambda path: self.inputs_api(path, raw)), \
                mock.patch.object(controller, 'manifest', wraps=controller.manifest) as check:
            self.assertEqual(controller.check_inputs(P, A), HOST)
            self.assertEqual(check.call_args.args[0], raw)
        for head, dirty in ((A.encode(), b''), (P.encode(), b' M lib/core.py\n')):
            with mock.patch.object(controller, 'run', side_effect=[result(head), result(dirty)]), \
                    mock.patch.object(controller, 'github') as api:
                with self.assertRaisesRegex(Failure, 'CHECKOUT_NOT_REVIEWED'):
                    controller.check_inputs(P, A)
                api.assert_not_called()

    def test_app_membership_ci_manifest_rejections_never_open_admin(self):
        for options in ({'app_on_main': False}, {'runs': []}, {'runs': [ci_run(conclusion='failure')]},
                        {'raw': b'version: 1\napp: impostor\n'}):
            with self.subTest(options=options), mock.patch.object(controller, 'run', side_effect=[result(P.encode()), result()]), \
                    mock.patch.object(controller, 'github', side_effect=lambda path: self.inputs_api(path, **options)), \
                    mock.patch.object(controller, 'activate') as ssh, mock.patch('sys.stderr', new=io.StringIO()):
                self.assertEqual(controller.main(['--platform-ref', P, '--app-ref', A,
                                                  '--admin-key-file', '/key', '--public-key-file', '/pub']), 1)
                ssh.assert_not_called()

    def test_check_only_needs_no_admin_identity(self):
        with mock.patch.object(controller, 'run', side_effect=[result(P.encode()), result()]), \
                mock.patch.object(controller, 'github', side_effect=self.inputs_api), \
                mock.patch.object(controller, 'activate') as ssh, mock.patch('sys.stdout', new=io.StringIO()) as output:
            self.assertEqual(controller.main(['--platform-ref', P, '--app-ref', A, '--check-inputs']), 0)
            self.assertEqual(json.loads(output.getvalue()), {'platform_ref': P, 'app_ref': A})
            ssh.assert_not_called()


class Transport(unittest.TestCase):
    def test_public_key_rejects_malformed_and_keygen_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'public'
            for raw in (b'', KEY.rstrip(b'\n'), KEY + KEY, KEY.replace(b'ssh-ed25519', b'ssh-rsa'), b'ssh-ed25519 invalid!\n'):
                path.write_bytes(raw)
                with self.subTest(raw=raw), mock.patch.object(controller, 'run') as command:
                    with self.assertRaisesRegex(Failure, 'INVALID_PUBLIC_KEY'):
                        controller.public_key(path)
                    command.assert_not_called()
            path.write_bytes(KEY)
            with mock.patch.object(controller, 'run', return_value=result(returncode=1)):
                with self.assertRaisesRegex(Failure, 'INVALID_PUBLIC_KEY'):
                    controller.public_key(path)

    def test_host_fingerprint_rejected_before_admin_connection(self):
        with mock.patch.object(controller, 'run', return_value=result(b'host ssh-ed25519 AAAA\n')) as command:
            with self.assertRaisesRegex(Failure, 'HOST_KEY_MISMATCH'):
                controller.host_key({'address': 'host.example.test', 'port': 22, 'fingerprint': 'SHA256:wrong'})
            self.assertEqual(command.call_count, 1)
            self.assertEqual(command.call_args.args[0][0], '/usr/bin/ssh-keyscan')

    def test_transport_is_nonretrying_pinned_and_sanitizes_disconnect(self):
        with tempfile.TemporaryDirectory() as name:
            admin, public = Path(name) / 'admin', Path(name) / 'public'
            admin.write_bytes(b'private fixture')
            admin.chmod(0o600)
            public.write_bytes(KEY)
            calls = []
            known_paths = []
            def boundary(argv, **kwargs):
                calls.append(argv)
                if argv[0] == '/usr/bin/ssh-keygen':
                    return result()
                self.assertEqual(argv[0], '/usr/bin/ssh')
                self.assertIn('StrictHostKeyChecking=yes', argv)
                self.assertIn('IdentitiesOnly=yes', argv)
                self.assertIn('ForwardAgent=no', argv)
                self.assertIn('ClearAllForwardings=yes', argv)
                self.assertIn('GlobalKnownHostsFile=/dev/null', argv)
                self.assertIn('opc@' + HOST['ssh']['address'], argv)
                self.assertTrue(argv[-1].startswith('sudo -n /usr/bin/python3 - ' + P + ' ' + A + ' '))
                known = Path(next(item.split('=', 1)[1] for item in argv if item.startswith('UserKnownHostsFile=')))
                known_paths.append(known)
                self.assertEqual(stat.S_IMODE(known.stat().st_mode), 0o600)
                self.assertEqual(kwargs['input'], (ROOT / 'install/activate-reviewed-release.py').read_bytes())
                return result(stderr=b'secret-looking diagnostic', returncode=255)
            with mock.patch.object(controller, 'run', side_effect=boundary), mock.patch.object(controller, 'host_key', return_value='ssh-ed25519 AAAA'):
                with self.assertRaisesRegex(Failure, '^SSH_ACTIVATION_FAILED$'):
                    controller.activate(P, A, admin, public, HOST)
            self.assertEqual(sum(argv[0] == '/usr/bin/ssh' for argv in calls), 1)
            self.assertTrue(known_paths)
            self.assertTrue(all(not path.exists() for path in known_paths))

    def test_receipt_rejects_unsanitized_or_incomplete_success(self):
        good = {'app': 'opendesign', 'host': 'oracle-main', 'platform_ref': P, 'app_ref': A,
                'previous_platform_ref': OLD, 'healthy': True, 'container_unchanged': True, 'runtime_env_unchanged': True}
        self.assertEqual(controller.validate_receipt(good, P, A), good)
        for changes in ({'env_hash': 'secret'}, {'platform_ref': OLD}, {'app_ref': OLD}, {'healthy': 1},
                        {'container_unchanged': False}, {'previous_platform_ref': 'bad'}):
            with self.subTest(changes=changes), self.assertRaisesRegex(Failure, 'INVALID_RECEIPT'):
                controller.validate_receipt(dict(good, **changes), P, A)


class RemoteBoundaries(unittest.TestCase):
    def test_existing_forced_key_must_match_exactly(self):
        prefix = b'restrict,command="sudo -n /usr/local/libexec/vps-deploy-opendesign" '
        identity = remote.key_identity(KEY)
        expected = prefix + identity + b'\n'
        with tempfile.TemporaryDirectory() as name:
            public, authorized = Path(name) / 'public', Path(name) / 'authorized'
            with mock.patch.object(remote, 'AUTHORIZED', authorized), mock.patch.object(remote, 'secure_path', side_effect=lambda path: path), \
                    mock.patch.object(remote, 'run', return_value=result()):
                authorized.write_bytes(expected)
                remote.enrolled_key(KEY, public)
                self.assertEqual(stat.S_IMODE(public.stat().st_mode), 0o600)
                for raw in (expected + expected, identity + b'\n', expected.replace(b'restrict,', b''),
                            expected.replace(b'vps-deploy-opendesign', b'vps-deploy-9router'), expected.replace(identity, b'ssh-ed25519 AAAA')):
                    authorized.write_bytes(raw)
                    with self.subTest(raw=raw), self.assertRaisesRegex(remote.Failure, 'DEPLOY_KEY_MISMATCH'):
                        remote.enrolled_key(KEY, public)

    def test_missing_or_busy_enrollment_never_bootstraps(self):
        with tempfile.TemporaryDirectory() as name:
            config, state = Path(name) / 'config', Path(name) / 'state'
            config.mkdir()
            state.mkdir()
            with mock.patch.object(remote, 'CONFIG', config), mock.patch.object(remote, 'STATE', state), \
                    mock.patch.object(remote, 'secure_path', side_effect=lambda path, **kwargs: path):
                with self.assertRaisesRegex(remote.Failure, 'NOT_ENROLLED'):
                    remote.enrolled()
                (config / 'host.json').write_text(json.dumps({'platform_ref': OLD}))
                for operation, active in (({}, {'image': 'digest'}), (None, None)):
                    (state / 'state.json').write_text(json.dumps({'operation': operation, 'active': active}))
                    with self.assertRaisesRegex(remote.Failure, 'INSTALL_BUSY'):
                        remote.enrolled()
                (state / 'state.json').write_text(json.dumps({'operation': None, 'active': {'image': 'digest'}}))
                requests = state / 'requests'
                requests.mkdir()
                request = requests / 'pending'
                request.mkdir()
                with self.assertRaisesRegex(remote.Failure, 'INSTALL_BUSY'):
                    remote.enrolled()
                (request / 'result.json').write_text('{"status":"recovery_required"}')
                with self.assertRaisesRegex(remote.Failure, 'INSTALL_BUSY'):
                    remote.enrolled()

    def test_exact_checkout_rejects_wrong_head_and_dirty_tree(self):
        for head, dirty in ((A.encode(), b''), (P.encode(), b'?? extra\n')):
            with mock.patch.object(remote, 'run', side_effect=[result(), result(), result(), result(head), result(dirty)]) as command:
                with self.assertRaisesRegex(remote.Failure, 'CHECKOUT_NOT_REVIEWED'):
                    remote.checkout(Path('/stage/platform'), 'TheDemonTuan/vps-deploy', P)
                fetch = command.call_args_list[1].args[0]
                self.assertIn('https://github.com/TheDemonTuan/vps-deploy.git', fetch)
                self.assertEqual(fetch[-1], P)

    def test_real_manifest_policy_rejects_before_installer(self):
        with mock.patch.object(remote, 'run', return_value=result(b'version: 1\napp: wrong\n')):
            with self.assertRaises(Failure):
                remote.validate_checkout(ROOT, Path('/fixture/app'), A)

    def test_container_security_policy(self):
        changes = [lambda v: v['HostConfig']['PortBindings'].update({'7456/tcp': [{'HostPort': '7456'}]}),
                   lambda v: v['NetworkSettings']['Ports'].update({'7456/tcp': [{'HostPort': '7456'}]}),
                   lambda v: v['Config'].update(Env=['OD_DISABLE_API_AUTH=0', 'OD_ALLOWED_ORIGINS=private']),
                   lambda v: v['Config'].update(Env=['OD_DISABLE_API_AUTH=1']),
                   lambda v: v['State'].update(Running=False), lambda v: v['State'].update(Restarting=True)]
        for change in changes:
            value = container()
            change(value)
            with self.subTest(value=value), self.assertRaises(remote.Failure):
                remote.container_snapshot(value)

    def test_runtime_snapshot_preserves_hash_ownership_and_mode(self):
        import operations
        with tempfile.TemporaryDirectory() as name:
            config = Path(name) / 'config'
            config.mkdir()
            runtime = config / 'runtime.env'
            runtime.write_bytes(b'OD_DISABLE_API_AUTH=1\nOD_ALLOWED_ORIGINS=https://design.example.test\n')
            runtime.chmod(0o600)
            route = Path(name) / 'opendesign.yml'
            route.write_bytes(b'unchanged route')
            profile = dict(HOST['apps']['opendesign'], platform_ref=OLD, dynamic_dir=name)
            host = dict(HOST, traefik=dict(HOST['traefik'], dynamic_dir=name))
            original_stat = Path.stat
            uid, mode = 0, 0o600
            def metadata(path, *args, **kwargs):
                if path == runtime:
                    return SimpleNamespace(st_uid=uid, st_gid=0, st_mode=stat.S_IFREG | mode)
                return original_stat(path, *args, **kwargs)
            with mock.patch.object(remote, 'CONFIG', config), mock.patch.object(Path, 'stat', metadata), \
                    mock.patch.object(remote, 'secure_path', side_effect=lambda path, **kwargs: path), \
                    mock.patch.object(operations, 'trusted_path', side_effect=lambda path, **kwargs: path), \
                    mock.patch.object(remote, 'run', return_value=result(json.dumps([container()]).encode())):
                first = remote.snapshot(profile, REGISTRATION, host)
                self.assertEqual(first['runtime_env'][1:], (0, 0, 0o600))
                runtime.write_bytes(runtime.read_bytes() + b'NODE_OPTIONS=--max-old-space-size=512\n')
                self.assertNotEqual(remote.snapshot(profile, REGISTRATION, host)['runtime_env'][0], first['runtime_env'][0])
                for uid, mode in ((1, 0o600), (0, 0o644)):
                    with self.assertRaisesRegex(remote.Failure, 'UNSAFE_RUNTIME_ENV'):
                        remote.snapshot(profile, REGISTRATION, host)

    def test_snapshot_drift_rejections(self):
        before = snapshot()
        for field, value, code in (('platform_ref', OLD, 'PROFILE_NOT_ACTIVATED'),
                                   ('container', {'id': 'changed'}, 'CONTAINER_CHANGED'),
                                   ('route', b'changed', 'ROUTE_CHANGED'),
                                   ('runtime_env', (b'changed', 0, 0, 0o600), 'RUNTIME_ENV_CHANGED'),
                                   ('runtime_env', (b'private hash', 1, 0, 0o600), 'RUNTIME_ENV_CHANGED'),
                                   ('runtime_env', (b'private hash', 0, 0, 0o644), 'RUNTIME_ENV_CHANGED')):
            after = snapshot(P)
            after[field] = value
            with self.subTest(field=field, value=value), self.assertRaisesRegex(remote.Failure, code):
                remote.invariants(before, after, P)

    def test_installer_check_requires_marker_and_preserves_release_error(self):
        for output in (result(b'not a proof'), result(stderr=b'RELEASE_MODIFIED\n', returncode=1)):
            with mock.patch.object(remote, 'run', return_value=output):
                with self.assertRaises(remote.Failure):
                    remote.installer(Path('/stage/platform'), Path('/stage/app'), P, A, Path('/stage/public'), True)
        with mock.patch.object(remote, 'run', side_effect=[result(b'CHECK_OK\n'), result(('INSTALLED opendesign ' + P + '\n').encode())]) as command:
            remote.installer(Path('/stage/platform'), Path('/stage/app'), P, A, Path('/stage/public'), True)
            remote.installer(Path('/stage/platform'), Path('/stage/app'), P, A, Path('/stage/public'), False)
            check, apply = [call.args[0] for call in command.call_args_list]
            self.assertEqual([arg for arg in check if arg != '--check'], apply)

    def test_immutable_release_idempotency_and_changed_bytes(self):
        with tempfile.TemporaryDirectory() as name:
            source, destination = Path(name) / 'source', Path(name) / 'release'
            source.mkdir()
            for area in installer.AREAS:
                (source / area).mkdir()
            (source / 'lib/example.py').write_bytes(b'original\n')
            shutil.copytree(source, destination)
            with mock.patch.object(installer, 'trusted_path', side_effect=lambda path, **kwargs: path), \
                    mock.patch.object(installer.os, 'replace') as replace:
                expected = installer.tree(source)
                installer.release_copy(source, destination, expected)
                replace.assert_not_called()
                (destination / 'lib/example.py').write_bytes(b'user drift\n')
                with self.assertRaisesRegex(Failure, 'RELEASE_MODIFIED'):
                    installer.release_copy(source, destination, expected)
                self.assertEqual((destination / 'lib/example.py').read_bytes(), b'user drift\n')
                replace.assert_not_called()


class RemoteActivation(unittest.TestCase):
    def harness(self, directory, snapshots=None, validation_error=None, check_error=None, strict_error=None):
        stack = __import__('contextlib').ExitStack()
        self.addCleanup(stack.close)
        for target, value in (('BASE', Path(directory)),):
            stack.enter_context(mock.patch.object(remote, target, value))
        stack.enter_context(mock.patch.object(remote.os, 'geteuid', return_value=0))
        stack.enter_context(mock.patch.object(remote, 'secure_path', side_effect=lambda path, **kwargs: path))
        stack.enter_context(mock.patch.object(remote, 'enrolled', return_value={'platform_ref': OLD}))
        key = stack.enter_context(mock.patch.object(remote, 'enrolled_key'))
        fetch = stack.enter_context(mock.patch.object(remote, 'checkout'))
        validation = stack.enter_context(mock.patch.object(remote, 'validate_checkout', return_value=(REGISTRATION, HOST), side_effect=validation_error))
        stack.enter_context(mock.patch.object(remote, 'snapshot', side_effect=snapshots or [snapshot(), snapshot(), snapshot(P)]))
        apply = stack.enter_context(mock.patch.object(remote, 'installer'))
        if check_error:
            apply.side_effect = check_error
        strict = stack.enter_context(mock.patch.object(remote, 'strict_status', side_effect=strict_error))
        return key, fetch, validation, apply, strict

    def test_valid_activation_receipt_and_staging_cleanup(self):
        with tempfile.TemporaryDirectory() as name:
            key, fetch, validation, apply, strict = self.harness(name)
            receipt = remote.activate(P, A, KEY)
            self.assertEqual(receipt['previous_platform_ref'], OLD)
            self.assertEqual(set(receipt), controller.RECEIPT_FIELDS)
            self.assertTrue(receipt['healthy'])
            self.assertEqual([call.args[-1] for call in apply.call_args_list], [True, False])
            strict.assert_called_once_with(P)
            self.assertEqual(list(Path(name).iterdir()), [])
            self.assertEqual(fetch.call_args_list[0].args[1:], ('TheDemonTuan/vps-deploy', P))
            self.assertEqual(fetch.call_args_list[1].args[1:], ('TheDemonTuan/open-design', A))

    def test_rejections_before_apply_and_no_retry(self):
        cases = [('manifest', {'validation_error': Failure('MANIFEST_POLICY')}),
                 ('changed_release', {'check_error': remote.Failure('RELEASE_MODIFIED')}),
                 ('missing_check_proof', {'check_error': remote.Failure('INSTALLER_PROOF_MISSING')})]
        for label, options in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as name:
                key, fetch, validation, apply, strict = self.harness(name, **options)
                with self.assertRaises(remote.Failure):
                    remote.activate(P, A, KEY)
                self.assertFalse(any(call.args[-1] is False for call in apply.call_args_list))
                strict.assert_not_called()
                self.assertEqual(list(Path(name).iterdir()), [])

    def test_preapply_drift_cannot_reach_apply(self):
        drift = snapshot()
        drift['route'] = b'changed during preflight'
        with tempfile.TemporaryDirectory() as name:
            key, fetch, validation, apply, strict = self.harness(name, snapshots=[snapshot(), drift])
            with self.assertRaisesRegex(remote.Failure, 'installer_check:ROUTE_CHANGED'):
                remote.activate(P, A, KEY)
            self.assertEqual([call.args[-1] for call in apply.call_args_list], [True])
            strict.assert_not_called()

    def test_postcheck_failure_has_no_receipt_or_second_apply(self):
        after = snapshot(P)
        after['runtime_env'] = (b'changed', 0, 0, 0o600)
        with tempfile.TemporaryDirectory() as name:
            key, fetch, validation, apply, strict = self.harness(name, snapshots=[snapshot(), snapshot(), after])
            with self.assertRaisesRegex(remote.Failure, 'postcheck:RUNTIME_ENV_CHANGED'):
                remote.activate(P, A, KEY)
            self.assertEqual([call.args[-1] for call in apply.call_args_list], [True, False])
            self.assertEqual(list(Path(name).iterdir()), [])

    def test_invalid_remote_sha_never_fetches_or_installs(self):
        with mock.patch.object(remote.os, 'geteuid', return_value=0), mock.patch.object(remote, 'enrolled') as enrolled, \
                mock.patch.object(remote, 'checkout') as fetch, mock.patch.object(remote, 'installer') as apply:
            for bad in (P + ';id', 'A' * 40, P + '\n'):
                with self.assertRaisesRegex(remote.Failure, 'preflight:INVALID_SHA'):
                    remote.activate(bad, A, KEY)
            enrolled.assert_not_called()
            fetch.assert_not_called()
            apply.assert_not_called()

    def test_key_mismatch_stops_before_fetch_or_apply(self):
        with tempfile.TemporaryDirectory() as name:
            key, fetch, validation, apply, strict = self.harness(name)
            key.side_effect = remote.Failure('DEPLOY_KEY_MISMATCH')
            with self.assertRaisesRegex(remote.Failure, 'preflight:DEPLOY_KEY_MISMATCH'):
                remote.activate(P, A, KEY)
            fetch.assert_not_called()
            apply.assert_not_called()
            self.assertEqual(list(Path(name).iterdir()), [])

    def test_strict_failure_does_not_rollback_or_reapply(self):
        with tempfile.TemporaryDirectory() as name:
            key, fetch, validation, apply, strict = self.harness(name, strict_error=remote.Failure('STRICT_STATUS_FAILED'))
            with self.assertRaisesRegex(remote.Failure, 'postcheck:STRICT_STATUS_FAILED'):
                remote.activate(P, A, KEY)
            self.assertEqual([call.args[-1] for call in apply.call_args_list], [True, False])
            self.assertEqual(list(Path(name).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
