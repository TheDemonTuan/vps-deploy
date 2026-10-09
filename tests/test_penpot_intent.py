import copy
from contextlib import nullcontext
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_penpot_contract import ROOT, deploy_request, profile
import core
import penpot
import route


class PenpotIntent(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.directory = self.root / 'state'
        self.directory.mkdir(mode=0o700)
        self.locks = self.root / 'locks'
        self.locks.mkdir(mode=0o700)
        self.dynamic = self.root / 'dynamic'
        self.dynamic.mkdir()
        self.cfg = self.root / 'cfg'
        self.cfg.mkdir(mode=0o700)
        self.request = deploy_request()
        self.profile = dict(profile(), platform_ref=self.request['platform_ref'], route_name='penpot.yml',
                            api_host='design.tuannguyenviet.site', dashboard_host='', dashboard_alias_host='',
                            compose_project='penpot', edge_network='edge-penpot')
        self.old = penpot.release_entry(self.request, self.profile)
        self.request['source_sha'] = 'd' * 40
        self.request['images'] = {role: ref.split('@')[0] + '@sha256:' + 'd' * 64
                                  for role, ref in self.request['images'].items()}
        self.state = {'version': 1, 'revision': 1, 'active': self.old, 'previous': None,
                      'generation': 'a' * 32, 'operation': None, 'draining': None, 'rtk': None}
        core.save(self.directory / 'state.json', self.state)
        with mock.patch.object(route, 'trusted_path', side_effect=lambda path, **kwargs: Path(path)):
            self.normal = route.render(self.profile, 'single', 'a' * 32, release_root=ROOT)
        self.route_path = self.dynamic / 'penpot.yml'
        self.route_path.write_bytes(self.normal)
        self.route_path.chmod(0o644)
        self.shared = self.dynamic / 'shared.yml'
        self.shared.write_bytes(b'http: {}\n')
        self.shared.chmod(0o644)
        self.hashes = {str(self.shared): core.digest(self.shared.read_bytes())}
        for owner in (penpot, route):
            patch = mock.patch.object(owner, 'trusted_path', side_effect=lambda path, **kwargs: Path(path))
            patch.start()
            self.addCleanup(patch.stop)
        patches = [mock.patch.object(penpot, 'lock', side_effect=lambda *args, **kwargs: nullcontext()),
                   mock.patch.object(penpot, 'verify_request', return_value=ROOT),
                   mock.patch.object(penpot, 'prepare_images', side_effect=lambda req, selected: penpot.release_entry(req, selected)),
                   mock.patch.object(penpot, 'stack_health'), mock.patch.object(penpot, 'fault'),
                   mock.patch.object(route, 'dynamic', return_value=self.dynamic),
                   mock.patch.object(route, 'preflight', return_value=(self.route_path, self.normal, self.hashes)),
                   mock.patch.object(route, 'probe', return_value=('single', 'a' * 32))]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def prepare(self):
        return penpot.prepare_transaction(self.request, self.state, self.directory, self.cfg, ROOT, self.profile, self.locks)

    def test_prepared_intent_records_all_route_forms_before_any_route_or_data_change(self):
        operation = self.prepare()
        stored = core.load(self.directory / 'state.json')
        self.assertEqual(stored['operation'], operation)
        self.assertEqual(stored['active'], self.old)
        self.assertEqual(stored['revision'], 2)
        self.assertEqual(operation['phase'], 'prepared')
        self.assertFalse(operation['committed'])
        self.assertIsNone(operation['snapshot'])
        self.assertEqual(operation['target']['images'], self.request['images'])
        self.assertEqual(self.route_path.read_bytes(), self.normal)
        self.assertEqual(self.shared.read_bytes(), b'http: {}\n')
        forms = penpot.intent_routes(stored, self.directory, self.profile, ROOT)
        self.assertEqual(forms['old'], self.normal)
        self.assertEqual(forms['maintenance'], penpot.maintenance_route(forms['target'], self.profile))
        self.assertEqual(route.route_state(forms['target'], self.profile), ('single', operation['generation']))
        directory = self.directory / 'operations' / self.request['request_id']
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in directory.iterdir()))

    def test_pending_or_stale_state_is_rejected_before_any_intent_is_created(self):
        for fault in ('pending', 'stale'):
            selected = copy.deepcopy(self.state)
            if fault == 'pending':
                selected['operation'] = {'request_id': 'previous', 'phase': 'prepared'}
                core.save(self.directory / 'state.json', selected)
            else:
                core.save(self.directory / 'state.json', dict(self.state, revision=2))
            with self.subTest(fault=fault), self.assertRaises(core.Failure):
                penpot.prepare_transaction(self.request, selected, self.directory, self.cfg, ROOT, self.profile, self.locks)
            self.assertFalse((self.directory / 'operations').exists())

    def test_failed_image_proof_leaves_state_and_route_unchanged(self):
        with mock.patch.object(penpot, 'prepare_images', side_effect=core.Failure('PENPOT_IMAGE_REVISION')), self.assertRaises(core.Failure):
            self.prepare()
        self.assertEqual(core.load(self.directory / 'state.json'), self.state)
        self.assertEqual(self.route_path.read_bytes(), self.normal)
        self.assertFalse((self.directory / 'operations').exists())

    def test_saved_route_tampering_is_rejected_before_use(self):
        self.prepare()
        stored = core.load(self.directory / 'state.json')
        directory = self.directory / 'operations' / self.request['request_id']
        (directory / 'normal-target.yml').write_bytes(b'foreign-route')
        with self.assertRaises(core.Failure):
            penpot.intent_routes(stored, self.directory, self.profile, ROOT)
        self.assertEqual(self.route_path.read_bytes(), self.normal)

    def close(self):
        return penpot.close_and_stop(self.state, self.directory, self.cfg, ROOT, self.profile, self.locks)

    def test_route_acknowledgements_and_stop_intent_precede_writer_stop(self):
        self.prepare()
        events = []
        def internal(*args, **kwargs):
            self.assertEqual(core.load(self.directory / 'state.json')['operation']['phase'], 'maintenance')
            events.append('internal')
        def public(*args, **kwargs):
            forms = penpot.intent_routes(self.state, self.directory, self.profile, ROOT)
            self.assertEqual(self.route_path.read_bytes(), forms['maintenance'])
            self.assertTrue(kwargs['maintenance'])
            events.append('public')
        def stop(*args):
            self.assertEqual(core.load(self.directory / 'state.json')['operation']['phase'], 'stopped')
            events.append('stop')
        with mock.patch.object(route, 'ack', side_effect=internal), mock.patch.object(penpot, 'public_ack', side_effect=public), mock.patch.object(penpot, 'stop_applications', side_effect=stop):
            self.close()
        self.assertEqual(events, ['internal', 'public', 'stop'])
        self.assertEqual(self.state['operation']['phase'], 'stopped')
        self.assertEqual(self.state['active'], self.old)
        self.assertEqual(self.shared.read_bytes(), b'http: {}\n')

    def test_missing_public_ack_never_stops_writers(self):
        self.prepare()
        with mock.patch.object(route, 'ack'), mock.patch.object(penpot, 'public_ack', side_effect=core.Failure('PENPOT_PUBLIC_ROUTE_ACK')), mock.patch.object(penpot, 'stop_applications') as stop, self.assertRaises(core.Failure):
            self.close()
        stop.assert_not_called()
        self.assertIsNone(core.load(self.directory / 'state.json')['operation'])
        self.assertEqual(self.route_path.read_bytes(), self.normal)
        self.assertEqual(self.state['active'], self.old)

    def test_failed_abort_keeps_maintenance_and_intent_without_stopping(self):
        self.prepare()
        with mock.patch.object(route, 'ack', side_effect=[None, core.Failure('ROUTE_ACK_TIMEOUT')]), mock.patch.object(penpot, 'public_ack', side_effect=core.Failure('PENPOT_PUBLIC_ROUTE_ACK')), mock.patch.object(penpot, 'stop_applications') as stop, self.assertRaises(core.Failure):
            self.close()
        stop.assert_not_called()
        self.assertEqual(core.load(self.directory / 'state.json')['operation']['phase'], 'maintenance')
        self.assertEqual(self.route_path.read_bytes(), penpot.intent_routes(self.state, self.directory, self.profile, ROOT)['maintenance'])

    def test_foreign_route_or_shared_route_drift_is_not_overwritten(self):
        for which in ('own', 'shared'):
            # Fresh prepared state and intent for each drift case.
            selected = copy.deepcopy(dict(self.state, operation=None))
            selected['revision'] = core.load(self.directory / 'state.json')['revision']
            core.save(self.directory / 'state.json', selected)
            self.state = selected
            self.request['request_id'] = 'intent-drift-' + which
            self.route_path.write_bytes(self.normal)
            self.shared.write_bytes(b'http: {}\n')
            self.prepare()
            path = self.route_path if which == 'own' else self.shared
            path.write_bytes(b'# foreign change\n' + path.read_bytes())
            before = path.read_bytes()
            with self.subTest(which=which), mock.patch.object(penpot, 'stop_applications') as stop, self.assertRaises(core.Failure):
                self.close()
            stop.assert_not_called()
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(self.state['operation']['phase'], 'prepared')

    def test_crash_after_maintenance_intent_can_retry_from_old_route(self):
        self.prepare()
        def crash(selected, label):
            if label == 'penpot_maintenance_intent':
                raise core.Failure('SIMULATED_CRASH')
        with mock.patch.object(penpot, 'fault', side_effect=crash), self.assertRaisesRegex(core.Failure, 'SIMULATED_CRASH'):
            self.close()
        self.assertEqual(self.route_path.read_bytes(), self.normal)
        self.state = core.load(self.directory / 'state.json')
        self.assertEqual(self.state['operation']['phase'], 'maintenance')
        with mock.patch.object(route, 'ack'), mock.patch.object(penpot, 'public_ack'), mock.patch.object(penpot, 'stop_applications') as stop:
            self.close()
        stop.assert_called_once()
        self.assertEqual(self.state['operation']['phase'], 'stopped')

    def test_stopped_intent_retry_requires_public_maintenance_but_not_live_backend(self):
        self.prepare()
        with mock.patch.object(route, 'ack'), mock.patch.object(penpot, 'public_ack'), mock.patch.object(penpot, 'stop_applications'):
            self.close()
        with mock.patch.object(route, 'ack', side_effect=AssertionError('backend already stopped')), mock.patch.object(penpot, 'public_ack') as public, mock.patch.object(penpot, 'stop_applications') as stop:
            self.close()
        public.assert_called_once_with(self.profile, maintenance=True)
        stop.assert_called_once()

    def test_foreign_intent_directory_or_target_source_is_rejected(self):
        self.prepare()
        stored = core.load(self.directory / 'state.json')
        for fault in ('directory', 'source'):
            selected = copy.deepcopy(stored)
            if fault == 'directory':
                selected['operation']['directory'] = str(self.root)
            else:
                selected['operation']['target']['source_sha'] = 'bad'
            with self.subTest(fault=fault), self.assertRaises(core.Failure):
                penpot.intent_routes(selected, self.directory, self.profile, ROOT)


if __name__ == '__main__':
    unittest.main()
