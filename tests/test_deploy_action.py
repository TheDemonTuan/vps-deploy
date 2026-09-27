"""Exercise the composite transport boundary without contacting production."""
import os
import pathlib
import subprocess
import unittest

import yaml


class DeployActionBoundary(unittest.TestCase):
    def test_preflight(self):
        action = yaml.safe_load((pathlib.Path(__file__).resolve().parents[1] / ".github/actions/deploy/action.yml").read_text())
        script = action["runs"]["steps"][0]["run"]
        sha = "a" * 40
        base = dict(CALLER_REPO="TheDemonTuan/9router", CALLER_REF="refs/heads/master",
                    CALLER_SHA=sha, ACTION_REF=sha, SOURCE_SHA=sha, PLATFORM_REF=sha,
                    CONFIG=".deploy/app.yml", OPERATION="deploy", COMPONENT="app",
                    IMAGE_REF="ghcr.io/thedemontuan/9router@sha256:" + "b" * 64)
        cases = (({}, True), ({"CALLER_REPO": "attacker/repo"}, False),
                 ({"ACTION_REF": "c" * 40}, False),
                 ({"IMAGE_REF": "ghcr.io/thedemontuan/9router:latest"}, False),
                 ({"OPERATION": "status", "IMAGE_REF": ""}, True),
                 ({"OPERATION": "reconcile", "COMPONENT": "rtk", "IMAGE_REF": ""}, True),
                 ({"OPERATION": "rollback", "COMPONENT": "rtk", "IMAGE_REF": ""}, False))
        for changes, permitted in cases:
            with self.subTest(changes=changes):
                result = subprocess.run(["bash", "-c", script], env={**os.environ, **base, **changes},
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, permitted, result.stderr)
