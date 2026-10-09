import subprocess
import unittest
from unittest import mock

import test_penpot_storage as storage
from test_penpot_contract import profile
import core
import penpot


class PenpotRestore(unittest.TestCase):
    def setUp(self):
        self.fixture = storage.PenpotStorage()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.cfg = self.fixture.root / 'cfg'
        self.cfg.mkdir(mode=0o700)
        for name in ('runtime.env', 'app.yml'):
            path = self.cfg / name
            path.write_bytes((self.fixture.backup / name).read_bytes())
            path.chmod(0o600)
        self.selected = dict(profile(), compose_project='penpot')
        self.entry = dict(self.fixture.entry, manifest_sha256=core.digest((self.cfg / 'app.yml').read_bytes()))
        self.calls = []
        def run(argv, **kwargs):
            payload = kwargs['stdin'].read() if 'stdin' in kwargs else kwargs['input']
            self.calls.append((argv, payload))
            return subprocess.CompletedProcess(argv, 0)
        def postgres(name, ref=None, **kwargs):
            self.assertEqual(name, 'penpot-postgres')
            self.assertEqual(ref, penpot.DATASTORE_IMAGES[name])
            return {'Config': {'Labels': {'vps-deploy.app': 'penpot',
                    'com.docker.compose.project': 'penpot', 'com.docker.compose.service': name}},
                    'Mounts': [{'Type': 'volume', 'Name': 'penpot_postgres_v15',
                                'Destination': '/var/lib/postgresql/data', 'RW': True}]}
        for patch in (mock.patch.object(penpot, 'owned_volumes'),
                      mock.patch.object(penpot, 'writers_stopped'),
                      mock.patch.object(penpot, 'container', side_effect=postgres),
                      mock.patch.object(penpot, 'image_id', return_value='sha256:' + '1' * 64),
                      mock.patch.object(penpot.subprocess, 'run', side_effect=run)):
            patch.start()
            self.addCleanup(patch.stop)

    def restore(self):
        return penpot.restore_data(self.selected, self.cfg, self.fixture.backup, self.entry)

    def test_restore_streams_only_verified_dedicated_database_and_assets(self):
        self.restore()
        self.assertEqual(len(self.calls), 3)
        reset, database, assets = self.calls
        self.assertIn('psql', reset[0])
        self.assertIn(b'DROP DATABASE IF EXISTS penpot;', reset[1])
        self.assertIn(b'CREATE DATABASE penpot OWNER penpot TEMPLATE template0;', reset[1])
        self.assertIn('pg_restore', database[0])
        self.assertEqual(database[1], (self.fixture.backup / 'database.dump').read_bytes())
        self.assertEqual(assets[1], (self.fixture.backup / 'assets.tar').read_bytes())
        self.assertIn('type=volume,src=penpot_assets,dst=/opt/data/assets', assets[0])
        self.assertIn('--pull=never', assets[0])
        self.assertIn(self.entry['images']['backend'], assets[0])
        self.assertNotIn('compose', assets[0])
        self.assertNotIn(self.fixture.runtime.decode().splitlines()[0], repr(self.calls))

    def test_corrupt_snapshot_or_changed_secret_never_mutates_data(self):
        for fault in ('snapshot', 'secret'):
            if fault == 'snapshot':
                (self.fixture.backup / 'database.dump').write_bytes(b'corrupt')
            else:
                self.fixture.write_snapshot()
                (self.cfg / 'runtime.env').write_bytes(b'changed')
            with self.subTest(fault=fault), self.assertRaises(core.Failure):
                self.restore()
            self.assertEqual(self.calls, [])

    def test_foreign_postgres_or_running_writer_never_mutates_data(self):
        with mock.patch.object(penpot, 'container', return_value={'Config': {'Labels': {}}, 'Mounts': []}), self.assertRaisesRegex(core.Failure, 'PENPOT_CONTAINER_OWNERSHIP'):
            self.restore()
        self.assertEqual(self.calls, [])
        with mock.patch.object(penpot, 'writers_stopped', side_effect=core.Failure('PENPOT_WRITER_RUNNING')), self.assertRaisesRegex(core.Failure, 'PENPOT_WRITER_RUNNING'):
            self.restore()
        self.assertEqual(self.calls, [])

    def test_database_restore_failure_never_starts_asset_extraction(self):
        def fail(argv, **kwargs):
            self.calls.append(argv)
            return subprocess.CompletedProcess(argv, 1 if 'pg_restore' in argv else 0)
        with mock.patch.object(penpot.subprocess, 'run', side_effect=fail), self.assertRaises(core.Failure):
            self.restore()
        self.assertEqual(len(self.calls), 2)
        self.assertTrue(all('run' not in argv for argv in self.calls))


if __name__ == '__main__':
    unittest.main()
