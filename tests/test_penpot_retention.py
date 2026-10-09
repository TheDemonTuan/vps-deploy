import shutil
import unittest

import test_penpot_storage as storage
from test_penpot_contract import profile
import core
import penpot


class PenpotRetention(unittest.TestCase):
    def setUp(self):
        self.fixture = storage.PenpotStorage()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.state_dir = self.fixture.root / 'state'
        self.state_dir.mkdir(mode=0o700)
        self.backups = self.state_dir / 'backups'
        self.backups.mkdir(mode=0o700)
        self.state = {'previous': dict(self.fixture.entry, source_sha='b' * 40), 'operation': None}

    def create(self, index, source=None):
        path = self.backups / ('backup-%02d' % index)
        shutil.copytree(self.fixture.backup, path)
        metadata = core.load(path / 'manifest.json')
        metadata['createdAt'] = '2026-10-07T07:%02d:00Z' % index
        if source:
            metadata['sourceSha'] = source
        core.save(path / 'manifest.json', metadata)
        return path

    def test_keeps_seven_newest_previous_sources_and_referenced_operation(self):
        for index in range(12):
            self.create(index, 'b' * 40 if index in (1, 2) else None)
        self.state['operation'] = {'snapshot': str(self.backups / 'backup-00')}
        incomplete = self.backups / 'incomplete'
        incomplete.mkdir(mode=0o700)
        (incomplete / 'database.dump').write_bytes(b'partial')
        removed = penpot.prune_snapshots(self.state_dir, self.state, profile())
        self.assertEqual(removed, ['backup-03', 'backup-04'])
        self.assertEqual({p.name for p in self.backups.iterdir()},
                         {'backup-00', 'backup-01', 'backup-02', 'incomplete'} |
                         {'backup-%02d' % i for i in range(5, 12)})

    def test_corrupt_complete_backup_prevents_all_pruning(self):
        for index in range(9):
            self.create(index)
        (self.backups / 'backup-08' / 'assets.tar').write_bytes(b'corrupt')
        with self.assertRaises(core.Failure):
            penpot.prune_snapshots(self.state_dir, self.state, profile())
        self.assertEqual(len(list(self.backups.iterdir())), 9)

    def test_symlink_entry_is_never_followed_or_removed(self):
        path = self.create(0)
        (self.backups / 'foreign').symlink_to(path, target_is_directory=True)
        with self.assertRaises(core.Failure):
            penpot.prune_snapshots(self.state_dir, self.state, profile())
        self.assertTrue((path / 'manifest.json').exists())
        self.assertTrue((self.backups / 'foreign').is_symlink())


if __name__ == '__main__':
    unittest.main()
