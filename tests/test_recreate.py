import os
import sys
import json
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import recreate
from core import Failure

class RecreateStrategyTests(unittest.TestCase):
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

if __name__ == '__main__':
    unittest.main()
