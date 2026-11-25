import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import edge_lb  # noqa: E402
from tunnel_api import Failure  # noqa: E402


class EdgeLb(unittest.TestCase):
    def test_committed_worker_config_matches_the_registry(self):
        # Weights, nodes and rules live in hosts/ and registry/; config.mjs is only their rendering.
        self.assertEqual((edge_lb.WORKER / 'config.mjs').read_text(), edge_lb.rendered())

    def test_a_replica_host_without_an_edge_identity_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('hosts', 'registry'):
                shutil.copytree(edge_lb.ROOT / name, root / name)
            path = root / 'hosts/oracle-sg2.yml'
            text = path.read_text()
            start = text.index('edge:\n')
            path.write_text(text[:start] + text[text.index('apps:\n'):])
            with self.assertRaisesRegex(Failure, 'EDGE_NODE_REQUIRED'):
                edge_lb.plan(root)


if __name__ == '__main__':
    unittest.main()
