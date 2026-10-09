import copy
from contextlib import nullcontext
import shutil
import subprocess
import sys
import unittest
from unittest import mock

import test_penpot_intent as intent
import test_penpot_storage as storage
import core
import penpot
import penpot_restore as restore


class PenpotOfflineRestore(unittest.TestCase):
    def setUp(self):
        self.f = intent.PenpotIntent()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.s = storage.PenpotStorage()
        self.s.setUp()
        self.addCleanup(self.s.doCleanups)
        backups = self.f.directory / 'backups'
        backups.mkdir(mode=0o700)
        self.selected = backups / 'selected'
        shutil.copytree(self.s.backup, self.selected)
        for name in ('app.yml', 'runtime.env'):
            core.atomic(self.f.cfg / name, (self.selected / name).read_bytes())
        core.atomic(self.f.cfg / 'runtime.env', self.s.runtime.replace(b'A' * 86, b'B' * 86))
        self.f.old['manifest_sha256'] = core.digest((self.f.cfg / 'app.yml').read_bytes())
        self.f.state['active'] = copy.deepcopy(self.f.old)
        core.save(self.f.directory / 'state.json', self.f.state)
        self.args = (self.selected, self.f.directory, self.f.cfg, intent.ROOT, self.f.profile, self.f.locks)
        self.events = []
        self.change_password = restore.change_password
        def snapshot(profile, cfg, state_dir, request_id, entry, raw):
            self.events.append('safety')
            target = state_dir / 'backups' / request_id
            shutil.copytree(self.selected, target)
            for name in ('app.yml', 'runtime.env'):
                core.atomic(target / name, (cfg / name).read_bytes())
            core.atomic(target / 'route.yml', raw)
            metadata = core.load(target / 'manifest.json')
            metadata.update(images=entry['images'], sourceSha=entry['source_sha'], platformRef=entry['platform_ref'])
            metadata['sha256'] = {name: penpot.file_hash(target / name) for name in penpot.SNAPSHOT_FILES}
            core.save(target / 'manifest.json', metadata)
            return target
        for patch in (mock.patch.object(restore, 'lock', side_effect=lambda *args, **kwargs: nullcontext()),
                      mock.patch.object(restore.os, 'geteuid', return_value=0),
                      mock.patch.object(penpot, 'owned_volumes'), mock.patch.object(penpot, 'postgres_owned'),
                      mock.patch.object(penpot, 'image_id'), mock.patch.object(penpot, 'matching'),
                      mock.patch.object(penpot, 'transaction_writers'), mock.patch.object(penpot, 'application_command'),
                      mock.patch.object(penpot, 'writers_stopped'), mock.patch.object(penpot, 'start_applications'),
                      mock.patch.object(penpot, 'public_ack'), mock.patch.object(intent.route, 'ack'),
                      mock.patch.object(penpot, 'snapshot', side_effect=snapshot),
                      mock.patch.object(restore, 'change_password', side_effect=lambda *args: self.events.append('password')),
                      mock.patch.object(penpot, 'restore_data', side_effect=lambda *args: self.events.append('data'))):
            patch.start()
            self.addCleanup(patch.stop)

    def test_check_does_not_change_config_state_or_data(self):
        before = (self.f.cfg / 'runtime.env').read_bytes()
        result = restore.check(self.selected, self.f.directory, self.f.cfg, self.f.profile)
        self.assertEqual(result['status'], 'checked')
        self.assertEqual(self.events, [])
        self.assertEqual((self.f.cfg / 'runtime.env').read_bytes(), before)
        self.assertIsNone(core.load(self.f.directory / 'state.json')['operation'])

    def test_apply_safety_backup_precedes_secrets_and_data_then_commits_selected_source(self):
        result = restore.apply(*self.args)
        self.assertEqual(self.events, ['safety', 'password', 'data'])
        state = core.load(self.f.directory / 'state.json')
        self.assertIsNone(state['operation'])
        self.assertEqual(state['active']['source_sha'], self.s.metadata['sourceSha'])
        self.assertEqual(state['previous'], self.f.old)
        self.assertEqual(result['data_timestamp'], self.s.metadata['createdAt'])
        self.assertEqual((self.f.cfg / 'runtime.env').read_bytes(), self.s.runtime)
        self.assertEqual(penpot.bounded_file(self.selected / 'runtime.env'), self.s.runtime)
        self.assertNotIn('PENPOT_SECRET_KEY', repr(result))

    def test_crash_in_restore_repeats_data_with_writers_stopped(self):
        def crash(*args):
            raise SystemExit('simulated power loss')
        with mock.patch.object(penpot, 'restore_data', side_effect=crash), self.assertRaises(SystemExit):
            restore.apply(*self.args)
        stored = core.load(self.f.directory / 'state.json')
        self.assertEqual(stored['operation']['kind'], 'restore')
        self.assertEqual(stored['operation']['phase'], 'restoring')
        result = restore.apply(*self.args)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(self.events.count('safety'), 1)
        self.assertEqual(self.events.count('data'), 1)

    def test_crash_after_exposure_never_replays_old_data(self):
        def crash(profile, label):
            if label == 'penpot_restore_complete':
                raise SystemExit('simulated power loss')
        with mock.patch.object(restore, 'fault', side_effect=crash), self.assertRaises(SystemExit):
            restore.apply(*self.args)
        self.assertTrue(core.load(self.f.directory / 'state.json')['operation']['committed'])
        restore.apply(*self.args)
        self.assertEqual(self.events.count('data'), 1)
        self.assertEqual(self.events.count('safety'), 1)

    def test_app_reconcile_rejects_operator_restore_checkpoint(self):
        def crash(profile, label):
            if label == 'penpot_restore_prepared':
                raise SystemExit('simulated power loss')
        with mock.patch.object(restore, 'fault', side_effect=crash), self.assertRaises(SystemExit):
            restore.apply(*self.args)
        state = core.load(self.f.directory / 'state.json')
        with self.assertRaises(core.Failure):
            penpot.reconcile_transaction(state, self.f.directory, self.f.cfg, intent.ROOT, self.f.profile, self.f.locks)
        self.assertEqual(self.events, [])

    def test_password_uses_stdin_after_separate_log_settings_command(self):
        with mock.patch.object(restore.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run:
            self.change_password(self.selected, self.f.profile)
        args, kwargs = run.call_args
        self.assertNotIn('1' * 64, repr(args))
        self.assertIn(b'1' * 64, kwargs['input'])
        self.assertIn('-c', args[0])
        self.assertEqual(args[0][-2:], ['-f', '-'])
        self.assertIn("log_statement='none'", args[0][args[0].index('-c') + 1])
        self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)

    def test_real_cli_has_no_nonroot_apply_access(self):
        if core.os.getuid() == 0:
            self.skipTest('Requires a nonroot runner')
        result = subprocess.run([sys.executable, str(intent.ROOT / 'install/restore-penpot.py'),
                                 '--backup', str(self.selected), '--apply'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('ROOT_REQUIRED', result.stdout)
        self.assertNotIn('PENPOT_SECRET_KEY', result.stdout + result.stderr)

    def test_corrupt_snapshot_or_nonroot_never_changes_state(self):
        (self.selected / 'assets.tar').write_bytes(b'corrupt')
        with self.assertRaises(core.Failure):
            restore.apply(*self.args)
        self.assertIsNone(core.load(self.f.directory / 'state.json')['operation'])
        self.assertEqual(self.events, [])
        with mock.patch.object(restore.os, 'geteuid', return_value=1000), self.assertRaisesRegex(core.Failure, 'ROOT_REQUIRED'):
            restore.apply(*self.args)


if __name__ == '__main__':
    unittest.main()
