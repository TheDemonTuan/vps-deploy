"""The orchestrator's order, stop and fleet rollback, with a fake host transport."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
from rollout import rollout  # noqa: E402

HOSTS = ["n1", "n2", "n3"]


def fleet(fails=(), rollback_fails=()):
    calls = []

    def run(host, operation):
        calls.append((operation, host))
        return (host, operation) not in fails and (operation != "rollback" or host not in rollback_fails)
    return calls, run


class Rollout(unittest.TestCase):
    def test_every_host_in_registry_order(self):
        calls, run = fleet()
        self.assertEqual(rollout(HOSTS, "deploy", run), (None, {}))
        self.assertEqual(calls, [("deploy", "n1"), ("deploy", "n2"), ("deploy", "n3")])

    def test_a_failed_host_stops_it_and_moved_hosts_roll_back_newest_first(self):
        calls, run = fleet(fails={("n3", "deploy")}, rollback_fails={"n1"})
        self.assertEqual(rollout(HOSTS, "deploy", run), ("n3", {"n2": True, "n1": False}))
        self.assertEqual(calls, [("deploy", "n1"), ("deploy", "n2"), ("deploy", "n3"),
                                 ("rollback", "n2"), ("rollback", "n1")])

    def test_first_host_failing_moves_nothing(self):
        calls, run = fleet(fails={("n1", "deploy")})
        self.assertEqual(rollout(HOSTS, "deploy", run), ("n1", {}))
        self.assertEqual(calls, [("deploy", "n1")])

    def test_other_operations_stop_without_rolling_back(self):
        calls, run = fleet(fails={("n2", "reconcile")})
        self.assertEqual(rollout(HOSTS, "reconcile", run), ("n2", {}))
        self.assertEqual(calls, [("reconcile", "n1"), ("reconcile", "n2")])


if __name__ == "__main__":
    unittest.main()
