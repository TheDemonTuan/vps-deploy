import hashlib
import copy
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from contextlib import closing

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import cgw
from core import Failure, json_bytes, request, resource_collisions

OLD = cgw.REPOSITORY + '@sha256:' + 'a' * 64
NEW = cgw.REPOSITORY + '@sha256:' + 'b' * 64


class Crash(BaseException):
    pass


class RuntimeFixture:
    def __init__(self):
        self.image = OLD
        self.fence = None
        self.accepted = 9
        self.idle = True
        self.events = []
        self.running = True

    def diagnostics(self, profile, ref=None, operation_id=None, fence_state=None, budget=None):
        if not self.running or ref and self.image != ref:
            raise Failure('CGW_IMAGE')
        if operation_id and self.fence != {'operationId': operation_id, 'state': fence_state}:
            raise Failure('CGW_FENCE')
        return dict(operationFence=copy.deepcopy(self.fence), idle=self.idle,
                    stateSchemaVersion=1, acceptedRequestCount=self.accepted, profiles=[])

    def admin(self, path, body=None, budget=None):
        self.events.append(path)
        if path == '/admin/drain':
            self.fence = dict(operationId=body['operationId'], state='draining')
        elif path == '/admin/quiesce':
            if not self.idle:
                raise Failure('CGW_NOT_IDLE')
            self.fence['state'] = 'quiesced'
        elif path == '/admin/resume':
            if self.fence['operationId'] != body['operationId']:
                raise Failure('CGW_FENCE')
            self.fence = None
        return {}

    def stop(self, release, cfg, ref, budget):
        if self.fence and self.fence['state'] == 'draining':
            raise AssertionError('stopped without physical quiescence')
        self.events.append('stop')
        self.running = False

    def start(self, release, cfg, ref, budget):
        if self.running:
            raise AssertionError('two writers')
        self.events.append('start:' + ref)
        self.image, self.running = ref, True


class CgwLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.state = dict(version=1, revision=1, operation=None, cgw=dict(current=OLD, previous=None))
        self.req = dict(request_id='upgrade1', component='cgw', image=NEW)
        self.profile = dict(cgw_image_repository=cgw.REPOSITORY, cgw_network='9router-cgw')
        self.runtime = RuntimeFixture()
        anonymous = patch('operations.anonymous_image', return_value=None)
        anonymous.start()
        self.addCleanup(anonymous.stop)
        for name, fn in (('diagnostics', self.runtime.diagnostics), ('admin', self.runtime.admin),
                         ('stop', self.runtime.stop), ('start', self.runtime.start),
                         ('image_id', lambda ref: ref), ('compose', lambda *args: None),
                         ('docker', lambda *args, **kwargs: ''), ('container', lambda *args, **kwargs: {}),
                         ('browser_directory', lambda *args: self.directory / 'browser'),
                         ('browser_mount', lambda *args: self.directory / 'browser'),
                         ('fault', lambda *args: None), ('snapshot', lambda *args: ('/private/snapshot', 'hash')),
                         ('inspect', lambda *args: {'Image': self.runtime.image, 'State': {'Running': self.runtime.running, 'Pid': 123 if self.runtime.running else 0, 'Restarting': False}}),
                         ('writers_gone', lambda *args: None)):
            mock = patch.object(cgw, name, side_effect=fn)
            mock.start()
            self.addCleanup(mock.stop)

    def deploy(self):
        cgw.deploy(self.req, self.state, self.directory, self.directory, self.directory, self.profile)

    def reconcile(self):
        self.state = json.loads((self.directory / 'state.json').read_bytes())
        cgw.reconcile(self.req, self.state, self.directory, self.directory, self.directory, self.profile)

    def test_private_browser_failure_never_drains_or_stops_old_writer(self):
        for code in ('UNTRUSTED_PATH', 'CGW_BROWSER_MANIFEST', 'CGW_BROWSER_PROOF'):
            with self.subTest(code=code), patch.object(cgw, 'browser_directory', side_effect=Failure(code)):
                with self.assertRaisesRegex(Failure, code):
                    self.deploy()
                self.assertTrue(self.runtime.running)
                self.assertEqual(self.runtime.image, OLD)
                self.assertNotIn('stop', self.runtime.events)
                self.assertNotIn('/admin/drain', self.runtime.events)
                self.assertIsNone(self.state['operation'])

    def test_old_browser_mount_mismatch_denies_before_drain(self):
        with patch.object(cgw, 'browser_mount', side_effect=Failure('CGW_BROWSER_MOUNT')):
            with self.assertRaisesRegex(Failure, 'CGW_BROWSER_MOUNT'):
                self.deploy()
        self.assertNotIn('stop', self.runtime.events)
        self.assertNotIn('/admin/drain', self.runtime.events)
        self.assertEqual(self.runtime.image, OLD)

    def test_commit_then_resume_and_single_writer(self):
        self.deploy()
        self.assertEqual(self.state['cgw'], dict(current=NEW, previous=OLD))
        self.assertIsNone(self.state['operation'])
        self.assertIsNone(self.runtime.fence)
        self.assertLess(self.runtime.events.index('/admin/quiesce'), self.runtime.events.index('stop'))

    def test_snapshot_failure_reopens_old_without_reset(self):
        with patch.object(cgw, 'snapshot', side_effect=Failure('CGW_SNAPSHOT_DATABASE')):
            with self.assertRaisesRegex(Failure, 'CGW_SNAPSHOT_DATABASE'):
                self.deploy()
        self.assertEqual(self.runtime.image, OLD)
        self.assertTrue(self.runtime.running)
        self.assertEqual(self.runtime.accepted, 9)
        self.assertIsNone(self.runtime.fence)

    def test_candidate_admission_refuses_stale_restore(self):
        original = self.runtime.start
        def start(*args):
            original(*args)
            if args[2] == NEW:
                self.runtime.accepted += 1
        with patch.object(cgw, 'start', side_effect=start), patch.object(cgw, 'verified_snapshot') as snapshot:
            with self.assertRaisesRegex(Failure, 'RECOVERY_REQUIRED'):
                self.deploy()
            snapshot.assert_not_called()
        self.assertEqual(self.runtime.image, NEW)
        self.assertEqual(self.runtime.fence['state'], 'quiesced')
        self.assertEqual(self.state['cgw']['current'], OLD)

    def test_pre_switch_crash_resumes_old_at_each_phase(self):
        for stage in ('cgw_prepared', 'cgw_draining', 'cgw_quiescing', 'cgw_quiesced', 'cgw_stopped', 'cgw_snapshot_verified'):
            with self.subTest(stage=stage):
                self.state = dict(version=1, revision=1, operation=None, cgw=dict(current=OLD, previous=None))
                self.runtime = RuntimeFixture()
                with patch.object(cgw, 'diagnostics', side_effect=self.runtime.diagnostics), patch.object(cgw, 'admin', side_effect=self.runtime.admin), patch.object(cgw, 'stop', side_effect=self.runtime.stop), patch.object(cgw, 'start', side_effect=self.runtime.start), patch.object(cgw, 'inspect', side_effect=lambda *args: {'Image': self.runtime.image, 'State': {'Running': self.runtime.running, 'Pid': 123 if self.runtime.running else 0, 'Restarting': False}}), patch.object(cgw, 'writers_gone'):
                    def fault(profile, label):
                        if label == stage:
                            raise Crash()
                    with patch.object(cgw, 'fault', side_effect=fault):
                        with self.assertRaises(Crash):
                            self.deploy()
                    self.reconcile()
                    self.assertEqual(self.runtime.image, OLD)
                    self.assertIsNone(self.runtime.fence)
                    self.assertIsNone(self.state['operation'])

    def test_unreachable_active_draining_old_is_never_stopped_during_recovery(self):
        self.state['operation'] = dict(component='cgw', phase='cgw_draining', previous=OLD,
                                       previous_id=OLD, image=NEW, operationId='upgrade1')
        self.runtime.fence = dict(operationId='upgrade1', state='draining')
        self.runtime.idle = False
        with patch.object(cgw, 'diagnostics', side_effect=Failure('CGW_DIAGNOSTIC')), \
             patch.object(cgw, 'inspect', return_value={'Image': OLD, 'State': {'Running': True, 'Pid': 123}}), \
             patch.object(cgw, 'stop') as stop:
            with self.assertRaisesRegex(Failure, 'RECOVERY_REQUIRED'):
                cgw.resume_old(self.state, self.directory, self.directory, self.directory,
                               self.profile, cgw.Budget())
            stop.assert_not_called()
        self.assertFalse(self.runtime.idle)
        self.assertEqual(self.runtime.fence['state'], 'draining')

    def test_commit_crash_resumes_candidate_not_snapshot(self):
        with patch.object(cgw, 'fault', side_effect=lambda profile, label: (_ for _ in ()).throw(Crash()) if label == 'cgw_committed' else None):
            with self.assertRaises(Crash):
                self.deploy()
        with patch.object(cgw, 'restore') as restore:
            self.reconcile()
            restore.assert_not_called()
        self.assertEqual(self.state['cgw']['current'], NEW)
        self.assertIsNone(self.runtime.fence)

    def test_post_resume_crash_preserves_new_admissions(self):
        def fault(profile, label):
            if label == 'cgw_resumed':
                self.runtime.accepted += 3
                raise Crash()
        with patch.object(cgw, 'fault', side_effect=fault):
            with self.assertRaises(Crash):
                self.deploy()
        self.reconcile()
        self.assertEqual(self.runtime.accepted, 12)
        self.assertEqual(self.runtime.image, NEW)
        self.assertIsNone(self.state['operation'])

    def test_foreign_fence_cannot_be_resumed(self):
        self.runtime.fence = dict(operationId='foreign', state='draining')
        with self.assertRaisesRegex(Failure, 'CGW_FENCE'):
            self.deploy()
        self.assertEqual(self.runtime.fence['operationId'], 'foreign')

    def test_drain_timeout_does_not_kill_active_turn(self):
        self.runtime.idle = False
        original = cgw.Budget.remaining
        fired = False
        def remaining(budget, ceiling=300):
            nonlocal fired
            if not fired and self.runtime.fence and self.runtime.fence['state'] == 'draining' and ceiling == 300:
                fired = True
                raise Failure('CGW_DEADLINE')
            return original(budget, ceiling)
        with patch.object(cgw.Budget, 'remaining', remaining):
            with self.assertRaisesRegex(Failure, 'CGW_DRAIN_BUSY'):
                self.deploy()
        self.assertNotIn('stop', self.runtime.events)
        self.assertEqual(self.runtime.image, OLD)
        self.assertIsNone(self.runtime.fence)


class CgwBrowserTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = Path(self.tmp.name)
        self.sha = 'd' * 64
        self.binary = hashlib.sha256(b'official pinned ELF fixture').hexdigest()
        self.path = self.cfg / 'cgw-browsers' / self.sha
        self.path.mkdir(parents=True)
        self.path.chmod(0o755)
        (self.path / 'chrome').write_bytes(b'official pinned ELF fixture')
        (self.path / 'chrome').chmod(0o755)
        (self.path / 'LICENSE').write_text('retained upstream license')
        (self.path / 'LICENSE').chmod(0o644)
        self.proof = dict(version='154.0.8037.92', architecture='arm64', archiveSha256=self.sha,
                          binarySha256=self.binary, files={'chrome': self.binary,
                          'LICENSE': hashlib.sha256((self.path / 'LICENSE').read_bytes()).hexdigest()})
        (self.path / '.cgw-chrome.json').write_text(json.dumps(self.proof))
        (self.path / '.cgw-chrome.json').chmod(0o644)
        for name, kwargs in [('browser_manifest', {'return_value': ({'version': self.proof['version']}, 'arm64',
                                           {'sha256': self.sha, 'binarySha256': self.binary})}),
                             ('trusted_path', {'side_effect': lambda path, **kw: path})]:
            mock = patch.object(cgw, name, **kwargs)
            mock.start()
            self.addCleanup(mock.stop)

    def test_pin_selects_archive_directory_and_full_payload(self):
        self.assertEqual(cgw.browser_directory(self.cfg, NEW, cgw.Budget()), self.path)
        (self.path / 'LICENSE').write_text('changed')
        with self.assertRaisesRegex(Failure, 'CGW_BROWSER_PROOF'):
            cgw.browser_directory(self.cfg, NEW, cgw.Budget())

    def test_missing_binary_proof_mismatch_and_extra_file_fail_closed(self):
        for mutation in ('missing', 'proof', 'extra'):
            with self.subTest(mutation=mutation):
                chrome = self.path / 'chrome'
                chrome.write_bytes(b'official pinned ELF fixture')
                chrome.chmod(0o755)
                (self.path / '.cgw-chrome.json').write_text(json.dumps(self.proof))
                if mutation == 'missing':
                    chrome.unlink()
                elif mutation == 'proof':
                    (self.path / '.cgw-chrome.json').write_text(json.dumps(dict(self.proof, archiveSha256='e' * 64)))
                else:
                    (self.path / 'unlisted').write_text('unexpected payload')
                with self.assertRaisesRegex(Failure, 'CGW_BROWSER_PROOF'):
                    cgw.browser_directory(self.cfg, NEW, cgw.Budget())

    def test_unsafe_path_is_rejected_and_mount_must_match_readonly_pin(self):
        with patch.object(cgw, 'trusted_path', side_effect=Failure('UNTRUSTED_PATH')):
            with self.assertRaisesRegex(Failure, 'UNTRUSTED_PATH'):
                cgw.browser_directory(self.cfg, NEW, cgw.Budget())
        for source, writable in [(str(self.path), True), (str(self.cfg / 'shared-browser'), False)]:
            live = {'Mounts': [{'Destination': '/opt/cgw-browser', 'Type': 'bind', 'RW': writable, 'Source': source}]}
            with self.assertRaisesRegex(Failure, 'CGW_BROWSER_MOUNT'):
                cgw.browser_mount(live, self.cfg, NEW, cgw.Budget())


class CgwSnapshotTests(unittest.TestCase):
    def test_database_requires_integrity_and_checkpointed_wal(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            with closing(sqlite3.connect(path / 'runtime.sqlite')) as db:
                for name in ('profiles', 'thread_bindings', 'request_claims'):
                    db.execute('CREATE TABLE ' + name + ' (id INTEGER PRIMARY KEY)')
                db.commit()
            self.assertEqual(cgw.validate_database(path), 0)
            (path / 'runtime.sqlite-wal').write_bytes(b'uncheckpointed')
            with self.assertRaisesRegex(Failure, 'CGW_LIVE_WAL'):
                cgw.validate_database(path)

    def test_symlink_is_not_snapshot_state(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            try:
                (path / 'escape').symlink_to(Path(temp).parent, target_is_directory=True)
            except OSError:
                self.skipTest('symlink privilege unavailable')
            with self.assertRaisesRegex(Failure, 'CGW_SNAPSHOT_TYPE'):
                cgw.tree_manifest(path, cgw.Budget())

    def test_optional_component_requires_registration_and_digest(self):
        profile = {'app': '9router', 'image_repository': 'ghcr.io/example/app', 'cgw_image_repository': cgw.REPOSITORY,
                   'registration': {'manifest': {'cgw': {'image': cgw.REPOSITORY}}}}
        req = dict(version=1, op='deploy', app='9router', component='cgw', request_id='upgrade', image=NEW,
                   platform_ref='a' * 40, source_sha='b' * 40, manifest_sha256='c' * 64)
        self.assertEqual(request(json_bytes(req), profile)['image'], NEW)
        req['image'] = cgw.REPOSITORY + ':latest'
        with self.assertRaisesRegex(Failure, 'INVALID_IMAGE'):
            request(json_bytes(req), profile)
        req['image'] = NEW
        profile['registration']['manifest'] = {}
        with self.assertRaisesRegex(Failure, 'INVALID_COMPONENT'):
            request(json_bytes(req), profile)

    def test_cgw_reserved_network_collides_with_other_app(self):
        binding = dict(work_dir='/work/one', compose_project='9router', route_name='one.yml', api_host='api.one.test',
                       dashboard_host='', dashboard_alias_host='', edge_network='edge-one', cgw_network='9router-cgw')
        other = dict(binding, work_dir='/work/two', compose_project='other', route_name='two.yml',
                     api_host='api.two.test', edge_network='9router-cgw')
        other.pop('cgw_network')
        with self.assertRaisesRegex(Failure, 'RESOURCE_COLLISION'):
            resource_collisions({'apps': {'9router': binding, 'other': other}})


if __name__ == '__main__':
    unittest.main()
