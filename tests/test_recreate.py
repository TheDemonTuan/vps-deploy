import os
import sys
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from contextlib import nullcontext
import subprocess

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import operations
import recreate
from core import Failure

class RecreateStrategyTests(unittest.TestCase):
    def test_uncached_candidate_is_acquired_before_runtime_fence(self):
        old = {'slot': 'single', 'image': 'old'}
        state = {'active': old, 'operation': None, 'generation': 'generation'}
        ref = 'ghcr.io/thedemontuan/opendesign@sha256:' + 'a' * 64
        profile = {'app': 'opendesign', 'edge_network': 'edge-opendesign',
                   'dynamic_dir': '/fixture', 'route_name': 'route.yml',
                   'image_repository': 'ghcr.io/thedemontuan/opendesign'}
        acquired = False
        def image_identity(value):
            if not acquired:
                raise Failure('COMMAND_FAILED')
            return 'candidate-id'
        def download(*args, **kwargs):
            nonlocal acquired
            acquired = True
        with mock.patch.object(recreate, 'container', return_value={'NetworkSettings': {'Networks': {'edge-opendesign': {}}}}), \
                mock.patch.object(recreate, 'entry_record', return_value={}), \
                mock.patch.object(recreate.route, 'dynamic', return_value=Path('/fixture')), \
                mock.patch.object(recreate.route, 'preflight', return_value=(None, b'route', None)), \
                mock.patch.object(recreate, 'image_id', side_effect=image_identity), \
                mock.patch.object(operations, 'image_id', side_effect=image_identity), \
                mock.patch.object(operations, 'anonymous_image'), \
                mock.patch.object(operations, 'environment', return_value={}), \
                mock.patch.object(operations, 'command', side_effect=download), \
                mock.patch.object(recreate, 'lock', side_effect=Failure('BOUNDARY_REACHED')), \
                mock.patch.object(recreate, 'fence') as fence:
            with self.assertRaisesRegex(Failure, 'BOUNDARY_REACHED'):
                recreate.transaction({'image': ref, 'request_id': 'request'}, state, Path('/state'), Path('/config'), Path('/release'), profile, Path('/locks'))
            self.assertTrue(acquired)
            self.assertIsNone(state['operation'])
            fence.assert_not_called()

    def test_rollback_compatibility_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            compat_file = tmp_path / 'rollback-compatibility.json'
            profile = {
                'app': 'opendesign',
                'rollback_compat_file': str(compat_file),
            }
            # Missing file raises
            with self.assertRaises(Failure) as ctx:
                recreate.check_rollback_compatibility(profile, 'img-2', 'img-1')
            self.assertEqual(ctx.exception.code, 'RECREATE_ROLLBACK_INCOMPATIBLE')

            # Empty pairs raises
            compat_file.write_text(json.dumps({
                'schemaVersion': 1,
                'approvedPairs': [],
            }))
            with self.assertRaises(Failure) as ctx:
                recreate.check_rollback_compatibility(profile, 'img-2', 'img-1')
            self.assertEqual(ctx.exception.code, 'RECREATE_ROLLBACK_INCOMPATIBLE')

            # Approved pair passes
            compat_file.write_text(json.dumps({
                'schemaVersion': 1,
                'approvedPairs': [
                    {'currentImage': 'img-2', 'previousImage': 'img-1'},
                ],
            }))
            self.assertTrue(recreate.check_rollback_compatibility(profile, 'img-2', 'img-1'))

            # Unapproved pair with same file raises
            with self.assertRaises(Failure) as ctx:
                recreate.check_rollback_compatibility(profile, 'img-3', 'img-2')
            self.assertEqual(ctx.exception.code, 'RECREATE_ROLLBACK_INCOMPATIBLE')

    def test_backup_pruning_retention(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            profile = {'app': 'opendesign'}
            root = state_dir / 'backups'
            root.mkdir(parents=True, exist_ok=True)
            for i in range(10):
                bdir = root / f"req-{i}"
                bdir.mkdir()
                manifest = {
                    'schemaVersion': 1,
                    'app': 'opendesign',
                    'timestamp': 1000 + i,
                }
                (bdir / 'manifest.json').write_text(json.dumps(manifest))

            recreate.prune_backups(state_dir, profile, keep=7)
            remaining = [p.name for p in root.iterdir() if p.is_dir()]
            self.assertEqual(len(remaining), 7)
            # The 3 oldest (req-0, req-1, req-2) should be pruned
            self.assertNotIn('req-0', remaining)
            self.assertNotIn('req-1', remaining)
            self.assertNotIn('req-2', remaining)
            self.assertIn('req-9', remaining)

class VirtualClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class ApiReadinessTests(unittest.TestCase):
    def setUp(self):
        self.clock = VirtualClock()
        self.profile = {'app': 'opendesign'}
        self.enterContext(mock.patch.object(recreate.time, 'monotonic', self.clock.monotonic))
        self.enterContext(mock.patch.object(recreate.time, 'sleep', self.clock.sleep))

    def test_connection_refused_then_ready_keeps_status_and_operation(self):
        data = {'accepting': False, 'phase': 'quiesced', 'operationId': 'original'}
        with mock.patch.object(recreate, 'internal_call', side_effect=[
                Failure('DEPLOYMENT_CONNECTION_REFUSED'),
                Failure('DEPLOYMENT_CONNECTION_REFUSED'), (200, data)]) as api:
            self.assertEqual(recreate.wait_api_ready(self.profile, timeout=5), (200, data))
        self.assertEqual(self.clock.now, 4)
        self.assertEqual(api.call_count, 3)
        for call in api.call_args_list:
            self.assertEqual(call.args, ('opendesign-single', 'GET', '/api/deployment/status'))
        self.assertEqual(api.call_args_list[-1].kwargs['timeout'], 1)

    def test_deadline_clamps_last_sleep_and_never_probes_after_expiry(self):
        with mock.patch.object(recreate, 'internal_call', side_effect=Failure('DEPLOYMENT_CONNECTION_REFUSED')) as api:
            with self.assertRaisesRegex(Failure, 'DEPLOYMENT_READINESS_TIMEOUT'):
                recreate.wait_api_ready(self.profile, timeout=5)
        self.assertEqual(self.clock.now, 5)
        self.assertEqual(self.clock.sleeps, [2, 2, 1])
        self.assertEqual(api.call_count, 3)

    def test_probe_budget_is_part_of_deadline(self):
        def slow_probe(*args, timeout):
            self.clock.now += timeout
            raise Failure('DEPLOYMENT_TIMEOUT')
        with mock.patch.object(recreate, 'internal_call', side_effect=slow_probe) as api:
            with self.assertRaisesRegex(Failure, 'DEPLOYMENT_READINESS_TIMEOUT'):
                recreate.wait_api_ready(self.profile, timeout=3)
        self.assertEqual(self.clock.now, 3)
        self.assertEqual(api.call_count, 1)
        self.assertEqual(self.clock.sleeps, [])

    def test_late_response_does_not_pass_deadline(self):
        def late_probe(*args, **kwargs):
            self.clock.now += 6
            return 200, {'accepting': False}
        with mock.patch.object(recreate, 'internal_call', side_effect=late_probe):
            with self.assertRaisesRegex(Failure, 'DEPLOYMENT_READINESS_TIMEOUT'):
                recreate.wait_api_ready(self.profile, timeout=5)

    def test_http_auth_and_bad_status_are_not_retried(self):
        for status in (401, 403, 404, 409, 500, 503):
            with self.subTest(status=status), mock.patch.object(recreate, 'internal_call', return_value=(status, {})) as api:
                with self.assertRaisesRegex(Failure, 'DEPLOYMENT_STATUS_FAILED'):
                    recreate.wait_api_ready(self.profile)
                self.assertEqual(api.call_count, 1)
        self.assertEqual(self.clock.sleeps, [])

    def test_exec_and_malformed_failures_are_not_retried(self):
        for code in ('DEPLOYMENT_EXEC_FAILED', 'DEPLOYMENT_RESPONSE_MALFORMED'):
            with self.subTest(code=code), mock.patch.object(recreate, 'internal_call', side_effect=Failure(code)) as api:
                with self.assertRaisesRegex(Failure, code):
                    recreate.wait_api_ready(self.profile)
                self.assertEqual(api.call_count, 1)
        with mock.patch.object(recreate, 'internal_call', return_value=(200, [])):
            with self.assertRaisesRegex(Failure, 'DEPLOYMENT_RESPONSE_MALFORMED'):
                recreate.wait_api_ready(self.profile)

    def test_internal_transport_classifies_only_structured_connection_refusal(self):
        for stdout, code in (('{"error":"ECONNREFUSED"}', 'DEPLOYMENT_CONNECTION_REFUSED'),
                             ('{"error":"EACCES"}', 'DEPLOYMENT_EXEC_FAILED'),
                             ('', 'DEPLOYMENT_EXEC_FAILED')):
            with self.subTest(stdout=stdout), mock.patch.object(recreate.subprocess, 'run', return_value=
                    subprocess.CompletedProcess([], 1, stdout, 'exec failed')) as run:
                with self.assertRaisesRegex(Failure, code):
                    recreate.internal_call('singleton', 'GET', '/api/deployment/status', timeout=0.5)
                self.assertEqual(run.call_args.kwargs['timeout'], 0.5)

    def test_internal_transport_timeout_is_bounded_and_explicit(self):
        with mock.patch.object(recreate.subprocess, 'run', side_effect=subprocess.TimeoutExpired('docker', 0.5)):
            with self.assertRaisesRegex(Failure, 'DEPLOYMENT_TIMEOUT'):
                recreate.internal_call('singleton', 'GET', '/api/deployment/status', timeout=0.5)

    def test_resume_waits_without_changing_operation_id(self):
        with mock.patch.object(recreate, 'internal_call', side_effect=[
                Failure('DEPLOYMENT_CONNECTION_REFUSED'),
                (200, {'operationId': 'original', 'accepting': False}),
                (200, {'accepting': True})]) as api:
            self.assertEqual(recreate.resume(self.profile, 'original'), {'accepting': True})
        self.assertEqual(api.call_args.args, ('opendesign-single', 'POST', '/api/deployment/resume', {'operationId': 'original'}))
        self.assertEqual(self.clock.now, 2)

    def test_resume_does_not_mask_operation_conflict(self):
        with mock.patch.object(recreate, 'internal_call', side_effect=[(200, {}), (409, {})]) as api:
            with self.assertRaisesRegex(Failure, 'DEPLOYMENT_RESUME_FAILED'):
                recreate.resume(self.profile, 'original')
        self.assertEqual(api.call_count, 2)


class RestartReadinessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(self.tmp)
        self.route_path = self.root / 'route.yml'
        self.route_path.write_bytes(b'route')
        self.data_path = self.root / 'data.tar'
        self.data_path.write_bytes(b'snapshot')
        self.clock = VirtualClock()
        self.profile = {'app': 'opendesign', 'edge_network': 'edge-opendesign',
                        'dynamic_dir': self.tmp, 'route_name': 'route.yml', 'platform_ref': 'platform'}
        self.old = {'slot': 'single', 'image': 'old'}
        self.state = {'active': self.old, 'previous': {'slot': 'single', 'image': 'previous'},
                      'operation': None, 'generation': 'old-generation', 'revision': 0}
        self.req = {'request_id': 'original', 'image': 'candidate', 'platform_ref': 'platform', 'manifest_sha256': 'manifest'}
        self.events = []
        self.running_image = 'old'
        self.refusals = 0
        self.accepting = False
        self.unsafe_candidate = False
        self.fail_integrity = False
        self.never_ready = False
        self.http_status = 200
        patches = {
            'container': mock.Mock(return_value={'NetworkSettings': {'Networks': {'edge-opendesign': {}}}}),
            'inspect': mock.Mock(side_effect=lambda *args: {'Id': 'cid', 'Image': self.running_image, 'State': {'Running': True}}),
            'image_id': mock.Mock(side_effect=lambda image: image),
            'pull': mock.Mock(), 'lock': mock.Mock(side_effect=lambda *args: nullcontext()),
            'atomic': mock.Mock(), 'save': mock.Mock(), 'fault': mock.Mock(),
            'docker': mock.Mock(), 'verify_no_writers': mock.Mock(),
            'snapshot_data_volume': mock.Mock(return_value=(str(self.data_path), 'checksum')),
            'restore_data_volume': mock.Mock(side_effect=lambda *args: self.events.append(('restore', args[-1]))),
            'get_volume_mountpoint': mock.Mock(return_value=self.root),
            'check_sqlite_integrity': mock.Mock(side_effect=self.integrity),
            'check_rollback_compatibility': mock.Mock(), 'matching': mock.Mock(), 'prune_backups': mock.Mock(),
            'compose': mock.Mock(side_effect=self.start), 'internal_call': mock.Mock(side_effect=self.api),
        }
        self.boundaries = patches
        for name, value in patches.items():
            self.enterContext(mock.patch.object(recreate, name, value))
        for name, result in (('dynamic', self.root), ('preflight', (None, b'route', {})),
                             ('render', b'new-route'), ('publish', None), ('ack', None), ('unchanged', None)):
            self.enterContext(mock.patch.object(recreate.route, name, return_value=result))
        self.enterContext(mock.patch.object(recreate.time, 'monotonic', self.clock.monotonic))
        self.enterContext(mock.patch.object(recreate.time, 'sleep', self.clock.sleep))

    def start(self, release, profile, cfg, image, *args):
        self.running_image = image
        self.refusals = 2
        self.accepting = False
        self.events.append(('start', image))

    def integrity(self, *args):
        self.events.append(('integrity', self.running_image))
        if self.fail_integrity and self.running_image != 'old':
            raise Failure('SQLITE_CORRUPT')

    def api(self, cname, method, path, body=None, timeout=10):
        self.events.append((method, path, body))
        if method == 'GET':
            if self.never_ready or self.refusals:
                self.refusals = max(0, self.refusals - 1)
                raise Failure('DEPLOYMENT_CONNECTION_REFUSED')
            return self.http_status, {'accepting': self.accepting or (self.unsafe_candidate and self.running_image != 'old'),
                                     'idle': True, 'phase': 'quiesced', 'operationId': 'original'}
        self.assertIn(body['operationId'], ('original', getattr(self, 'backup_id', None)))
        if path.endswith('/resume'):
            self.assertEqual(self.refusals, 0, 'resume sent before API readiness')
            self.accepting = True
        elif path.endswith('/fence'):
            self.accepting = False
        return 200, {'phase': 'quiesced', 'idle': True, 'accepting': self.accepting}

    def run_operation(self, function):
        return function(self.req, self.state, self.root, self.root, self.root, self.profile, self.root)

    def pending(self, phase):
        self.state['operation'] = {'request_id': 'original', 'phase': phase, 'image': 'candidate',
                                   'target_entry': {'slot': 'single', 'image': 'candidate'},
                                   'data_checksum': 'checksum', 'data_snapshot': str(self.data_path),
                                   'snapshot': str(self.route_path), 'old_hash': recreate.digest(b'route')}

    def test_candidate_waits_before_fence_admission_and_data_verification(self):
        self.run_operation(recreate.transaction)
        self.assertGreaterEqual(self.clock.now, 4)
        self.assertIn(('integrity', 'candidate'), self.events)
        self.assertEqual(self.state['active']['image'], 'candidate')
        self.assertIsNone(self.state['operation'])
        self.boundaries['restore_data_volume'].assert_not_called()
        self.assertEqual([event[2] for event in self.events if event[:2] == ('POST', '/api/deployment/resume')], [{'operationId': 'original'}])

    def test_rollback_candidate_waits_before_admission(self):
        self.run_operation(recreate.rollback)
        self.assertGreaterEqual(self.clock.now, 4)
        self.assertEqual(self.state['active']['image'], 'previous')
        self.assertIn(('integrity', 'previous'), self.events)
        self.assertIsNone(self.state['operation'])

    def test_unfenced_candidate_is_rejected_and_old_waits_before_resume(self):
        self.unsafe_candidate = True
        with self.assertRaisesRegex(Failure, 'RECREATE_CANDIDATE_FAILED') as exc:
            self.run_operation(recreate.transaction)
        self.assertEqual(exc.exception.__cause__.code, 'CANDIDATE_NOT_FENCED')
        self.assertEqual(self.running_image, 'old')
        self.assertGreaterEqual(self.clock.now, 8)
        self.assertIn(('restore', 'checksum'), self.events)
        self.assertNotIn(('integrity', 'candidate'), self.events)
        self.assertIsNone(self.state['operation'])

    def test_transaction_restore_still_verifies_data_and_waits(self):
        self.fail_integrity = True
        with self.assertRaisesRegex(Failure, 'RECREATE_CANDIDATE_FAILED') as exc:
            self.run_operation(recreate.transaction)
        self.assertEqual(exc.exception.__cause__.code, 'SQLITE_CORRUPT')
        self.assertGreaterEqual(self.clock.now, 8)
        self.assertIsNone(self.state['operation'])
        self.assertIn(('restore', 'checksum'), self.events)

    def test_rollback_restore_waits_before_old_resume(self):
        self.fail_integrity = True
        with self.assertRaisesRegex(Failure, 'RECREATE_CANDIDATE_FAILED'):
            self.run_operation(recreate.rollback)
        self.assertGreaterEqual(self.clock.now, 8)
        self.assertEqual(self.running_image, 'old')
        self.assertIsNone(self.state['operation'])

    def test_reconcile_snapshot_restore_waits_and_preserves_recovery_semantics(self):
        self.pending('candidate_started')
        with self.assertRaisesRegex(Failure, 'RECOVERY_REQUIRED'):
            self.run_operation(recreate.reconcile)
        self.assertGreaterEqual(self.clock.now, 4)
        self.assertTrue(self.accepting)
        self.assertEqual(self.state['operation']['phase'], 'recovery_required')
        self.assertEqual(self.state['operation']['request_id'], 'original')
        self.assertIn(('restore', 'checksum'), self.events)
        # The official second reconcile completes the recovered operation without
        # repeating data restoration or substituting the original fence ID.
        self.run_operation(recreate.reconcile)
        self.assertIsNone(self.state['operation'])
        self.assertEqual(self.boundaries['restore_data_volume'].call_count, 1)

    def test_candidate_auth_failure_is_not_treated_as_startup_delay(self):
        original_start = self.start
        def start_with_candidate_auth_failure(*args):
            original_start(*args)
            self.http_status = 401 if self.running_image == 'candidate' else 200
        self.boundaries['compose'].side_effect = start_with_candidate_auth_failure
        with self.assertRaisesRegex(Failure, 'RECREATE_CANDIDATE_FAILED') as exc:
            self.run_operation(recreate.transaction)
        self.assertEqual(exc.exception.__cause__.code, 'DEPLOYMENT_STATUS_FAILED')
        self.assertEqual(self.clock.now, 8)
        self.assertNotIn(('integrity', 'candidate'), self.events)
        self.assertIn(('restore', 'checksum'), self.events)

    def test_failed_old_readiness_keeps_snapshot_operation_for_recovery(self):
        self.fail_integrity = True
        original_start = self.start
        def start_with_old_unavailable(*args):
            original_start(*args)
            self.never_ready = self.running_image == 'old'
        self.boundaries['compose'].side_effect = start_with_old_unavailable
        with self.assertRaisesRegex(Failure, 'DEPLOYMENT_READINESS_TIMEOUT'):
            self.run_operation(recreate.transaction)
        self.assertEqual(self.clock.now, 124)
        self.assertEqual(self.state['operation']['phase'], 'candidate_started')
        self.assertEqual(self.state['operation']['request_id'], 'original')
        self.assertEqual(self.state['operation']['data_checksum'], 'checksum')
        self.assertFalse(any(event[:2] == ('POST', '/api/deployment/resume') for event in self.events))

    def test_reconcile_committed_auth_failure_does_not_clear_operation(self):
        self.pending('committed')
        self.http_status = 401
        with self.assertRaisesRegex(Failure, 'DEPLOYMENT_STATUS_FAILED'):
            self.run_operation(recreate.reconcile)
        self.assertEqual(self.state['operation']['phase'], 'committed')
        self.assertFalse(self.accepting)

    def test_reconcile_stopped_old_waits_then_clears_intact_operation(self):
        self.pending('stopped')
        self.boundaries['inspect'].side_effect = None
        self.boundaries['inspect'].return_value = {'State': {'Running': False}, 'Image': 'old'}
        self.run_operation(recreate.reconcile)
        self.assertGreaterEqual(self.clock.now, 4)
        self.assertTrue(self.accepting)
        self.assertIsNone(self.state['operation'])
        self.boundaries['restore_data_volume'].assert_not_called()

    def test_reconcile_deadline_preserves_operation_and_never_resumes(self):
        self.pending('stopped')
        self.never_ready = True
        self.boundaries['inspect'].side_effect = None
        self.boundaries['inspect'].return_value = {'State': {'Running': False}, 'Image': 'old'}
        with self.assertRaisesRegex(Failure, 'DEPLOYMENT_READINESS_TIMEOUT'):
            self.run_operation(recreate.reconcile)
        self.assertEqual(self.clock.now, 120)
        self.assertEqual(self.state['operation']['request_id'], 'original')
        self.assertFalse(any(event[:2] == ('POST', '/api/deployment/resume') for event in self.events))

    def test_backup_restart_waits_and_uses_original_backup_operation(self):
        self.backup_id = 'backup-100-' + 'a' * 8
        with mock.patch.object(recreate, 'load', return_value=self.state), \
                mock.patch.object(recreate.time, 'time', return_value=100), \
                mock.patch.object(recreate.uuid, 'uuid4', return_value=mock.Mock(hex='a' * 32)):
            result = recreate.backup(self.profile, self.root, self.root, self.root)
        self.assertEqual(result['backupId'], self.backup_id)
        self.assertGreaterEqual(self.clock.now, 4)
        self.assertTrue(self.accepting)
        self.assertEqual(self.events[-1], ('POST', '/api/deployment/resume', {'operationId': self.backup_id}))

    def test_backup_auth_failure_is_not_reported_as_success(self):
        self.backup_id = 'backup-100-' + 'a' * 8
        original_start = self.start
        def start_with_auth_failure(*args):
            original_start(*args)
            self.http_status = 403
        self.boundaries['compose'].side_effect = start_with_auth_failure
        with mock.patch.object(recreate, 'load', return_value=self.state), \
                mock.patch.object(recreate.time, 'time', return_value=100), \
                mock.patch.object(recreate.uuid, 'uuid4', return_value=mock.Mock(hex='a' * 32)):
            with self.assertRaisesRegex(Failure, 'DEPLOYMENT_STATUS_FAILED'):
                recreate.backup(self.profile, self.root, self.root, self.root)
        self.assertFalse(self.accepting)


if __name__ == '__main__':
    unittest.main()
