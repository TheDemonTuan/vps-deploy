import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
import core


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


controller = load('recovery_controller', ROOT / 'scripts/recover-opendesign.py')
remote = load('recovery_remote', ROOT / 'install/recover-reviewed-operation.py')
P, A = 'a' * 40, 'b' * 40
IMAGE = 'ghcr.io/thedemontuan/opendesign@sha256:' + '0' * 64


def state():
    old = {'slot': 'single', 'image': IMAGE}
    return {'version': 1, 'active': old, 'operation': {
        'request_id': remote.REQUEST_ID, 'component': 'app', 'target': 'single',
        'phase': 'candidate_started', 'old_entry': dict(old)}}


def receipt():
    return {'app': 'opendesign', 'host': 'oracle-main', 'platform_ref': P, 'app_ref': A,
            'request_id': remote.REQUEST_ID, 'healthy': True, 'accepting': True,
            'operation_cleared': True, 'restored_image': IMAGE}


class ControllerBoundaries(unittest.TestCase):
    def test_invalid_sha_never_opens_admin_transport(self):
        for bad in ('', 'A' * 40, P + ';id', P + '\n', 'a' * 39):
            with mock.patch.object(controller.activation, 'github') as api, \
                    mock.patch.object(controller.activation, 'run') as command, \
                    mock.patch.object(controller.activation, 'reviewed_admin') as ssh, \
                    mock.patch('sys.stderr', new=io.StringIO()):
                self.assertEqual(controller.main(['--platform-ref', bad, '--app-ref', A,
                    '--admin-key-file', '/key', '--public-key-file', '/pub']), 1)
                api.assert_not_called()
                command.assert_not_called()
                ssh.assert_not_called()

    def test_missing_architecture_cannot_reach_admin_transport(self):
        with mock.patch.object(controller.activation, 'check_inputs', return_value={}), \
                mock.patch.object(controller.activation, 'latest_ci', return_value={'id': 12, 'run_attempt': 2}), \
                mock.patch.object(controller.activation, 'github', return_value={'jobs': []}), \
                mock.patch.object(controller.activation, 'reviewed_admin') as ssh, \
                mock.patch('sys.stderr', new=io.StringIO()):
            self.assertEqual(controller.main(['--platform-ref', P, '--app-ref', A,
                '--admin-key-file', '/key', '--public-key-file', '/pub']), 1)
            ssh.assert_not_called()

    def test_exact_successful_architectures_required(self):
        jobs = [{'name': name, 'status': 'completed', 'conclusion': 'success'} for name in
                ('verify (ubuntu-24.04, amd64)', 'verify (ubuntu-24.04-arm, arm64)')]
        with mock.patch.object(controller.activation, 'latest_ci', return_value={'id': 12, 'run_attempt': 2}), \
                mock.patch.object(controller.activation, 'github', return_value={'jobs': jobs}) as api:
            controller.verify_architectures(P)
            self.assertIn('/runs/12/attempts/2/jobs?', api.call_args.args[0])
        for changed in (jobs[:1], jobs + [jobs[0]],
                        [jobs[0], {**jobs[1], 'conclusion': 'skipped'}],
                        [jobs[0], {**jobs[1], 'status': 'in_progress'}]):
            with self.subTest(jobs=changed), \
                    mock.patch.object(controller.activation, 'latest_ci', return_value={'id': 12}), \
                    mock.patch.object(controller.activation, 'github', return_value={'jobs': changed}):
                with self.assertRaisesRegex(core.Failure, 'CI_ARCHITECTURES_NOT_SUCCESSFUL'):
                    controller.verify_architectures(P)

    def test_check_inputs_never_uses_admin_key(self):
        with mock.patch.object(controller.activation, 'check_inputs', return_value={}), \
                mock.patch.object(controller, 'verify_architectures'), \
                mock.patch.object(controller.activation, 'reviewed_admin') as ssh, \
                mock.patch('sys.stdout', new=io.StringIO()):
            self.assertEqual(controller.main(['--platform-ref', P, '--app-ref', A, '--check-inputs']), 0)
            ssh.assert_not_called()

    def test_receipt_rejects_credentials_and_unproven_success(self):
        self.assertEqual(controller.validate_receipt(receipt(), P, A), receipt())
        for changes in ({'credential': 'secret'}, {'accepting': False}, {'healthy': False},
                        {'operation_cleared': False}, {'request_id': 'another-operation'},
                        {'platform_ref': A}, {'restored_image': 'latest'}):
            with self.subTest(changes=changes), self.assertRaisesRegex(core.Failure, 'INVALID_RECEIPT'):
                controller.validate_receipt({**receipt(), **changes}, P, A)


class RemoteBoundaries(unittest.TestCase):
    def test_rejects_other_operation_before_reconciliation(self):
        for change in ({'request_id': 'gh-other'}, {'phase': 'committed'}, {'component': 'rtk'},
                       {'old_entry': {'slot': 'single', 'image': 'wrong'}}):
            value = state()
            value['operation'].update(change)
            with self.subTest(change=change), self.assertRaises(remote.Failure):
                remote.pending(value)

    def test_root_and_sha_fail_before_checkout_or_staging(self):
        for uid, platform in ((1, P), (0, P + ';id')):
            with mock.patch.object(remote.os, 'geteuid', return_value=uid), \
                    mock.patch.object(remote, 'checkout') as checkout, \
                    mock.patch.object(remote.tempfile, 'mkdtemp') as staging:
                with self.assertRaises(remote.Failure):
                    remote.recover(platform, A, b'public')
                checkout.assert_not_called()
                staging.assert_not_called()

    def test_foreign_pending_never_fetches(self):
        profile = {'platform_ref': P}
        value = state()
        value['operation']['request_id'] = 'foreign'
        with mock.patch.object(remote, 'secure_path', side_effect=lambda path, **kwargs: path), \
                mock.patch.object(Path, 'read_bytes', side_effect=[json.dumps(profile).encode(), json.dumps(value).encode()]), \
                mock.patch.object(Path, 'exists', return_value=False), \
                mock.patch.object(remote.os, 'geteuid', return_value=0), \
                mock.patch.object(remote, 'checkout') as checkout:
            with self.assertRaisesRegex(remote.Failure, 'UNEXPECTED_OPERATION'):
                remote.recover(P, A, b'public')
            checkout.assert_not_called()

    def test_snapshot_path_mismatch_fails_before_data_restore(self):
        value = state()
        candidate = 'ghcr.io/thedemontuan/opendesign@sha256:' + '1' * 64
        value['operation'].update(image=candidate, target_entry={'image': candidate},
                                  snapshot='/arbitrary/route', data_snapshot='/arbitrary/data')
        request = {'request_id': remote.REQUEST_ID, 'op': 'deploy', 'component': 'app', 'image': candidate}
        boundary = SimpleNamespace(trusted_path=lambda path, **kwargs: path,
                                   request=mock.Mock(return_value=request),
                                   verify_request=mock.Mock(return_value=Path('/installed')))
        with mock.patch.object(Path, 'read_bytes', return_value=b'original request'):
            with self.assertRaisesRegex(remote.Failure, 'UNEXPECTED_SNAPSHOT'):
                remote.request_contract(value, {}, boundary, SimpleNamespace())
        boundary.verify_request.assert_called_once_with(request, remote.CONFIG, {})

    def test_restored_admission_rejects_foreign_fence(self):
        recreate = SimpleNamespace(internal_call=mock.Mock(return_value=(200, {
            'accepting': True, 'operationId': 'foreign-operation'})))
        with self.assertRaisesRegex(remote.Failure, 'RESTORED_NOT_ACCEPTING'):
            remote.admission(recreate, {}, SimpleNamespace(container=mock.Mock()), IMAGE, remote.REQUEST_ID)

    def run_recovery(self, side_effect, current, accepting=True):
        boundary = SimpleNamespace(Failure=core.Failure, load=mock.Mock(side_effect=lambda path: copy.deepcopy(current)),
                                   trusted_path=lambda path: path, container=mock.Mock())
        recreate = SimpleNamespace(reconcile=mock.Mock(side_effect=side_effect), internal_call=mock.Mock(
            return_value=(200, {'accepting': accepting, 'operationId': None})))
        return boundary, recreate

    def test_exact_restored_transition_has_one_bounded_continuation(self):
        current = state()
        phases = []
        def reconcile(req, value, *args):
            phases.append(value['operation']['phase'])
            if len(phases) == 1:
                current['operation'].update(phase='recovery_required', error_code='RECREATE_CANDIDATE_FAILED')
                raise core.Failure('RECOVERY_REQUIRED')
            current['operation'] = None
        boundary, recreate = self.run_recovery(reconcile, current)
        self.assertEqual(remote.reconcile_fixed(state(), {}, Path('/installed'), {}, boundary, recreate), IMAGE)
        self.assertEqual(phases, ['candidate_started', 'recovery_required'])
        self.assertEqual(recreate.internal_call.call_count, 2)
        self.assertEqual(recreate.reconcile.call_count, 2)

    def test_failed_readiness_or_foreign_phase_never_continues(self):
        for code, phase, accepting in (('DEPLOYMENT_NOT_READY', 'candidate_started', False),
                                        ('RECOVERY_REQUIRED', 'candidate_started', True),
                                        ('RECOVERY_REQUIRED', 'recovery_required', False)):
            current = state()
            current['operation'].update(phase=phase, error_code='RECREATE_CANDIDATE_FAILED')
            boundary, recreate = self.run_recovery(core.Failure(code), current, accepting)
            with self.subTest(code=code, phase=phase), self.assertRaises(remote.Failure):
                remote.reconcile_fixed(state(), {}, Path('/installed'), {}, boundary, recreate)
            self.assertEqual(recreate.reconcile.call_count, 1)

    def test_wrong_image_or_non_accepting_cannot_report_success(self):
        for image, accepting in ((IMAGE, False), ('wrong-image', True)):
            current = state()
            current['operation'] = None
            current['active']['image'] = image
            boundary, recreate = self.run_recovery(None, current, accepting)
            with self.subTest(image=image, accepting=accepting), self.assertRaises(remote.Failure):
                remote.reconcile_fixed(state(), {}, Path('/installed'), {}, boundary, recreate)
            self.assertEqual(recreate.reconcile.call_count, 1)


if __name__ == '__main__':
    unittest.main()
