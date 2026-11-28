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
            path = root / 'hosts/n2-oci-sin2-arm-4c24g.yml'
            text = path.read_text()
            start = text.index('edge:\n')
            path.write_text(text[:start] + text[text.index('apps:\n'):])
            with self.assertRaisesRegex(Failure, 'EDGE_NODE_REQUIRED'):
                edge_lb.plan(root)

    def test_the_lease_object_migrates_once_and_secrets_survive_uploads(self):
        edge = edge_lb.plan()
        first = edge_lb.bindings(edge, None)
        self.assertEqual(first['migrations'], {'new_tag': 'v1', 'new_sqlite_classes': ['Lease']})
        self.assertEqual(first['keep_bindings'], ['secret_text'])
        self.assertIn({'type': 'queue', 'name': 'WRITES', 'queue_name': 'edge-lb-writes'}, first['bindings'])
        self.assertIn(edge_lb.WRITE_LIMIT, first['bindings'])
        self.assertNotIn('migrations', edge_lb.bindings(edge, 'v1'))

    def test_narrower_routes_on_a_balanced_host_are_removed_but_not_other_workers(self):
        class Routes:
            def get(self, path):
                return [{'id': 'a', 'pattern': 'thedemontuan.dev/*', 'script': 'edge-lb', 'request_limit_fail_open': True},
                        {'id': 'b', 'pattern': 'thedemontuan.dev/_astro/*', 'script': None},
                        {'id': 'c', 'pattern': 'other.thedemontuan.dev/*', 'script': None}]
        changes = edge_lb.route_changes(Routes(), {'z': 'zone'}, {'z': {'thedemontuan.dev/*': 'edge-lb'}})
        self.assertEqual(changes, [('DELETE', '/zones/zone/workers/routes/b', {'pattern': 'thedemontuan.dev/_astro/*'})])
        class Foreign(Routes):
            def get(self, path):
                return super().get(path) + [{'id': 'd', 'pattern': 'thedemontuan.dev/x/*', 'script': 'someone-else'}]
        self.assertEqual(len(edge_lb.route_changes(Foreign(), {'z': 'zone'}, {'z': {'thedemontuan.dev/*': 'edge-lb'}})), 1)


if __name__ == '__main__':
    unittest.main()
