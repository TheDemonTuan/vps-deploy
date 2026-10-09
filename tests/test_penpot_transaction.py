import copy
import unittest
from unittest import mock

import test_penpot_intent as intent
import core
import penpot
import route


class PenpotTransaction(unittest.TestCase):
    def setUp(self):
        self.fixture = intent.PenpotIntent()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f = self.fixture
        self.f.prepare()
        with mock.patch.object(route, 'ack'), mock.patch.object(penpot, 'public_ack'), mock.patch.object(penpot, 'stop_applications'):
            self.f.close()
        self.args = (self.f.state, self.f.directory, self.f.cfg, intent.ROOT, self.f.profile, self.f.locks)
        self.metadata = {'images': self.f.old['images'], 'sourceSha': self.f.old['source_sha'],
                         'platformRef': self.f.old['platform_ref'],
                         'sha256': {'app.yml': self.f.old['manifest_sha256'], 'route.yml': core.digest(self.f.normal)}}
        self.events = []
        def snapshot(*args):
            self.events.append('snapshot')
            self.assertEqual(core.load(self.f.directory / 'state.json')['operation']['phase'], 'stopped')
            return self.f.directory / 'backups' / self.f.request['request_id']
        for patch in (mock.patch.object(penpot, 'snapshot', side_effect=snapshot),
                      mock.patch.object(penpot, 'verify_snapshot', return_value=self.metadata),
                      mock.patch.object(penpot, 'writers_stopped'),
                      mock.patch.object(penpot, 'transaction_writers'),
                      mock.patch.object(penpot, 'start_applications'),
                      mock.patch.object(penpot, 'application_command'),
                      mock.patch.object(penpot, 'restore_data'),
                      mock.patch.object(route, 'ack'), mock.patch.object(penpot, 'public_ack')):
            patch.start()
            self.addCleanup(patch.stop)

    def test_snapshot_and_applying_intent_precede_migration(self):
        def start(release, profile, cfg, entry):
            self.events.append('start')
            operation = core.load(self.f.directory / 'state.json')['operation']
            self.assertEqual(operation['phase'], 'applying')
            self.assertIsNotNone(operation['snapshot'])
            self.assertEqual(entry, operation['target'])
            self.assertEqual(self.f.route_path.read_bytes(), penpot.intent_routes(self.f.state, self.f.directory, self.f.profile, intent.ROOT)['maintenance'])
        with mock.patch.object(penpot, 'start_applications', side_effect=start):
            penpot.apply_candidate(*self.args)
        self.assertEqual(self.events, ['snapshot', 'start'])
        self.assertEqual(self.f.state['operation']['phase'], 'checking')
        self.assertEqual(self.f.state['active'], self.f.old)
        self.assertFalse(self.f.state['operation']['committed'])

    def test_migration_failure_restores_snapshot_then_old_without_exposing_target(self):
        def start(release, profile, cfg, entry):
            self.events.append('target' if entry != self.f.old else 'old')
            if entry != self.f.old:
                raise core.Failure('COMMAND_FAILED')
        def restore(*args):
            self.events.append('restore')
            self.assertEqual(core.load(self.f.directory / 'state.json')['operation']['phase'], 'restoring')
        with mock.patch.object(penpot, 'start_applications', side_effect=start), mock.patch.object(penpot, 'application_command'), mock.patch.object(penpot, 'restore_data', side_effect=restore), self.assertRaisesRegex(core.Failure, 'COMMAND_FAILED'):
            penpot.apply_candidate(*self.args)
        self.assertEqual(self.events, ['snapshot', 'target', 'restore', 'old'])
        self.assertIsNone(self.f.state['operation'])
        self.assertEqual(self.f.state['active'], self.f.old)
        self.assertEqual(self.f.route_path.read_bytes(), self.f.normal)

    def test_snapshot_failure_restarts_old_without_restoring_dump(self):
        with mock.patch.object(penpot, 'snapshot', side_effect=core.Failure('PENPOT_BACKUP_COMMAND_FAILED')), mock.patch.object(penpot, 'start_applications') as start, mock.patch.object(penpot, 'application_command'), mock.patch.object(penpot, 'restore_data') as restore, self.assertRaises(core.Failure):
            penpot.apply_candidate(*self.args)
        restore.assert_not_called()
        start.assert_called_once_with(intent.ROOT, self.f.profile, self.f.cfg, self.f.old)
        self.assertIsNone(self.f.state['operation'])
        self.assertEqual(self.f.route_path.read_bytes(), self.f.normal)

    def test_corrupt_snapshot_keeps_maintenance_and_recovery_intent(self):
        with mock.patch.object(penpot, 'start_applications', side_effect=core.Failure('COMMAND_FAILED')), mock.patch.object(penpot, 'verify_snapshot', side_effect=[self.metadata, core.Failure('PENPOT_BACKUP_CHECKSUM')]), mock.patch.object(penpot, 'application_command'), mock.patch.object(penpot, 'restore_data') as restore, self.assertRaises(core.Failure):
            penpot.apply_candidate(*self.args)
        restore.assert_not_called()
        operation = self.f.state['operation']
        self.assertEqual(operation['phase'], 'recovery_required')
        self.assertEqual(operation['recovery_from'], 'restoring')
        self.assertFalse(operation['committed'])
        self.assertEqual(self.f.route_path.read_bytes(), penpot.intent_routes(self.f.state, self.f.directory, self.f.profile, intent.ROOT)['maintenance'])

    def candidate(self):
        with mock.patch.object(penpot, 'start_applications'):
            penpot.apply_candidate(*self.args)

    def test_commit_is_durable_before_publication_and_success_clears_intent(self):
        self.candidate()
        original = route.publish
        target = copy.deepcopy(self.f.state['operation']['target'])
        def publish(path, raw, previous):
            stored = core.load(self.f.directory / 'state.json')
            self.assertTrue(stored['operation']['committed'])
            self.assertEqual(stored['operation']['phase'], 'exposing')
            self.assertEqual(stored['active'], target)
            self.assertEqual(stored['previous'], self.f.old)
            return original(path, raw, previous)
        with mock.patch.object(route, 'publish', side_effect=publish):
            penpot.expose_candidate(*self.args)
        self.assertIsNone(self.f.state['operation'])
        self.assertEqual(self.f.state['active'], target)
        self.assertEqual(self.f.state['previous'], self.f.old)
        self.assertEqual(route.route_state(self.f.route_path.read_bytes(), self.f.profile), ('single', self.f.state['generation']))

    def test_post_boundary_failure_closes_public_and_recovers_forward_without_restore(self):
        self.candidate()
        target = copy.deepcopy(self.f.state['operation']['target'])
        with mock.patch.object(penpot, 'public_ack', side_effect=core.Failure('PENPOT_PUBLIC_ROUTE_ACK')), mock.patch.object(penpot, 'restore_data') as restore, self.assertRaises(core.Failure):
            penpot.expose_candidate(*self.args)
        restore.assert_not_called()
        self.assertEqual(self.f.state['active'], target)
        self.assertTrue(self.f.state['operation']['committed'])
        self.assertEqual(self.f.state['operation']['phase'], 'recovery_required')
        self.assertEqual(self.f.route_path.read_bytes(), penpot.intent_routes(self.f.state, self.f.directory, self.f.profile, intent.ROOT)['maintenance'])
        with mock.patch.object(penpot, 'restore_data') as restore:
            penpot.expose_candidate(*self.args)
        restore.assert_not_called()
        self.assertIsNone(self.f.state['operation'])
        self.assertEqual(self.f.state['active'], target)

    def test_crash_before_boundary_reconcile_restores_only_after_migration_intent(self):
        for point, must_restore in (('penpot_backed_up', False), ('penpot_applying', True)):
            with self.subTest(point=point):
                # A fresh intent, with a persisted maintenance route, for each crash point.
                if self.f.state['operation'] is None:
                    self.f.request['request_id'] += '-next'
                    self.f.prepare()
                    with mock.patch.object(penpot, 'stop_applications'):
                        self.f.close()
                def crash(profile, label):
                    if label == point:
                        raise SystemExit('simulated power loss')
                with mock.patch.object(penpot, 'fault', side_effect=crash), self.assertRaises(SystemExit):
                    penpot.apply_candidate(*self.args)
                self.f.state.clear()
                self.f.state.update(core.load(self.f.directory / 'state.json'))
                with mock.patch.object(penpot, 'restore_data') as restore:
                    penpot.reconcile_transaction(*self.args)
                self.assertEqual(restore.call_count, int(must_restore))
                self.assertIsNone(self.f.state['operation'])
                self.assertEqual(self.f.state['active'], self.f.old)

    def test_crash_after_old_reopens_does_not_replay_restore_over_new_writes(self):
        self.candidate()
        def crash(profile, label):
            if label == 'penpot_old_exposed':
                raise SystemExit('simulated power loss')
        with mock.patch.object(penpot, 'fault', side_effect=crash), mock.patch.object(penpot, 'restore_data') as restore, self.assertRaises(SystemExit):
            penpot.reconcile_transaction(*self.args)
        restore.assert_called_once()
        stored = core.load(self.f.directory / 'state.json')
        self.assertEqual(stored['operation']['phase'], 'resuming')
        self.assertEqual(self.f.route_path.read_bytes(), self.f.normal)
        self.f.state.clear()
        self.f.state.update(stored)
        with mock.patch.object(penpot, 'restore_data') as restore:
            penpot.reconcile_transaction(*self.args)
        restore.assert_not_called()
        self.assertIsNone(self.f.state['operation'])

    def test_crash_after_commit_reconcile_never_restores_old_database(self):
        self.candidate()
        target = copy.deepcopy(self.f.state['operation']['target'])
        def crash(profile, label):
            if label == 'penpot_exposed':
                raise SystemExit('simulated power loss')
        with mock.patch.object(penpot, 'fault', side_effect=crash), self.assertRaises(SystemExit):
            penpot.expose_candidate(*self.args)
        self.f.state.clear()
        self.f.state.update(core.load(self.f.directory / 'state.json'))
        self.assertEqual(self.f.state['active'], target)
        with mock.patch.object(penpot, 'restore_data') as restore, mock.patch.object(penpot, 'start_applications') as start:
            penpot.reconcile_transaction(*self.args)
        restore.assert_not_called()
        start.assert_called_once_with(intent.ROOT, self.f.profile, self.f.cfg, target)
        self.assertIsNone(self.f.state['operation'])
        self.assertEqual(self.f.state['active'], target)

    def test_foreign_route_or_stale_state_blocks_reconcile_before_writer_mutation(self):
        self.candidate()
        self.f.route_path.write_bytes(b'# foreign\n' + self.f.route_path.read_bytes())
        with mock.patch.object(penpot, 'application_command') as stop, mock.patch.object(penpot, 'restore_data') as restore, self.assertRaisesRegex(core.Failure, 'PENPOT_ROUTE_DRIFT'):
            penpot.reconcile_transaction(*self.args)
        stop.assert_not_called()
        restore.assert_not_called()
        self.assertTrue(self.f.route_path.read_bytes().startswith(b'# foreign'))

    def reset_for_backup(self):
        self.f.state['operation'] = None
        self.f.state['revision'] += 1
        core.save(self.f.directory / 'state.json', self.f.state)
        self.f.route_path.write_bytes(self.f.normal)
        self.f.request.update(request_id='backup-current', images=self.f.old['images'], source_sha=self.f.old['source_sha'])

    def test_backup_keeps_current_release_and_generation_and_never_restores_data(self):
        self.reset_for_backup()
        initial = copy.deepcopy(self.f.state)
        def snapshot(*args):
            stored = core.load(self.f.directory / 'state.json')
            operation = stored['operation']
            self.assertEqual(operation['kind'], 'backup')
            self.assertEqual(operation['old'], operation['target'])
            self.assertEqual(operation['old_generation'], operation['generation'])
            self.assertEqual(stored['active'], initial['active'])
            return self.f.directory / 'backups' / self.f.request['request_id']
        with mock.patch.object(penpot, 'snapshot', side_effect=snapshot), mock.patch.object(penpot, 'restore_data') as restore, mock.patch.object(penpot, 'stop_applications'), mock.patch.object(penpot, 'prune_snapshots') as prune:
            path = penpot.backup(self.f.request, *self.args)
        restore.assert_not_called()
        prune.assert_called_once()
        self.assertEqual(path.name, 'backup-current')
        for name in ('active', 'previous', 'generation'):
            self.assertEqual(self.f.state[name], initial[name])
        self.assertIsNone(self.f.state['operation'])
        self.assertEqual(self.f.route_path.read_bytes(), self.f.normal)

    def test_crashed_backup_reconcile_only_resumes_current(self):
        self.reset_for_backup()
        initial = copy.deepcopy(self.f.state)
        def crash(profile, label):
            if label == 'penpot_backed_up':
                raise SystemExit('simulated power loss')
        with mock.patch.object(penpot, 'fault', side_effect=crash), mock.patch.object(penpot, 'stop_applications'), self.assertRaises(SystemExit):
            penpot.backup(self.f.request, *self.args)
        self.f.state.clear()
        self.f.state.update(core.load(self.f.directory / 'state.json'))
        self.assertEqual(self.f.state['operation']['kind'], 'backup')
        with mock.patch.object(penpot, 'restore_data') as restore:
            penpot.reconcile_transaction(*self.args)
        restore.assert_not_called()
        self.assertIsNone(self.f.state['operation'])
        self.assertEqual(self.f.state['active'], initial['active'])
        self.assertEqual(self.f.state['generation'], initial['generation'])

    def test_pre_boundary_restore_is_forbidden_after_commit(self):
        self.candidate()
        with mock.patch.object(penpot, 'public_ack', side_effect=core.Failure('PENPOT_PUBLIC_ROUTE_ACK')), self.assertRaises(core.Failure):
            penpot.expose_candidate(*self.args)
        with mock.patch.object(penpot, 'restore_data') as restore, self.assertRaisesRegex(core.Failure, 'PENPOT_COMMITTED'):
            penpot.recover_pre_boundary(*self.args)
        restore.assert_not_called()


if __name__ == '__main__':
    unittest.main()
