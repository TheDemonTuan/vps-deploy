"""Exercise registered caller validation without credentials or SSH."""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts/check-caller.py"


class DeployActionBoundary(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        platform = self.root / "platform"
        source = self.root / "source"
        for directory in (platform, source):
            directory.mkdir()
        for folder, name in (("registry", "9router.yml"), ("hosts", "oracle-main.yml")):
            dest = platform / folder
            dest.mkdir()
            shutil.copyfile(ROOT / folder / name, dest / name)
        sys.path.insert(0, str(ROOT / "lib"))
        self.addCleanup(sys.path.remove, str(ROOT / "lib"))
        from core import app_registration
        registration = app_registration(platform, "9router")
        self.caller = registration["caller"]
        manifest = source / ".deploy/app.yml"
        manifest.parent.mkdir()
        manifest.write_text(yaml.safe_dump(registration["manifest"], sort_keys=False))
        workflows = source / ".github/workflows"
        workflows.mkdir(parents=True)
        self.workflow = workflows / "deploy.yml"
        self.workflow.write_text("jobs:\n  build:\n    uses: approved\n")
        for name in ("rtk-sidecar.yml", "deploy-ops.yml"):
            (workflows / name).write_text("jobs:\n  deploy:\n    steps:\n      - uses: approved\n")
        for directory in (platform, source):
            subprocess.run(["git", "init", "-q", str(directory)], check=True)
            subprocess.run(["git", "-C", str(directory), "add", "."], check=True)
            subprocess.run(["git", "-C", str(directory), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "fixture"], check=True)
        self.platform_sha = subprocess.check_output(["git", "-C", str(platform), "rev-parse", "HEAD"], text=True).strip()
        self.source_sha = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        self.env = dict(APP="9router", HOST="oracle-main", CALLER_REPO=self.caller["repository"],
                        CALLER_REF=self.caller["ref"], CALLER_SHA=self.source_sha, ACTION_REF=self.platform_sha,
                        SOURCE_SHA=self.source_sha, PLATFORM_REF=self.platform_sha, CONFIG=self.caller["config"],
                        OPERATION="deploy", COMPONENT="app", IMAGE_REF=registration["manifest"]["image"] + "@sha256:" + "b" * 64)
        self.pin = "TheDemonTuan/vps-deploy/.github/actions/deploy@" + self.platform_sha
        self.workflow.write_text("jobs:\n  deploy:\n    steps:\n      - uses: " + self.pin + "\n")
        for name in ("rtk-sidecar.yml", "deploy-ops.yml"):
            (workflows / name).write_text("jobs:\n  deploy:\n    steps:\n      - uses: " + self.pin + "\n")
        # Recommit source after inserting the platform pin, then bind caller SHA.
        subprocess.run(["git", "-C", str(source), "add", "."], check=True)
        subprocess.run(["git", "-C", str(source), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "pin"], check=True)
        self.source_sha = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        self.env.update(CALLER_SHA=self.source_sha, SOURCE_SHA=self.source_sha)

    def check(self, changes=None, preflight=False):
        return subprocess.run([sys.executable, str(CHECKER), "deploy/action.yml", *(["--preflight"] if preflight else [])],
                              cwd=self.root, env={**os.environ, **self.env, **(changes or {})}, capture_output=True, text=True)

    def test_registered_caller_and_denials(self):
        self.assertEqual(self.check().returncode, 0)
        self.assertEqual(self.check(preflight=True).returncode, 0)
        for changes in ({"APP": "../9router"}, {"HOST": "other"}, {"CALLER_REPO": "attacker/repo"},
                        {"CALLER_REF": "refs/heads/evil"}, {"ACTION_REF": "c" * 40},
                        {"SOURCE_SHA": "c" * 40}, {"CONFIG": "other.yml"},
                        {"IMAGE_REF": "ghcr.io/attacker/app@sha256:" + "b" * 64},
                        {"IMAGE_REF": "ghcr.io/thedemontuan/9router:latest"},
                        {"OPERATION": "rollback", "COMPONENT": "rtk", "IMAGE_REF": ""}):
            with self.subTest(changes=changes):
                self.assertNotEqual(self.check(changes, preflight=True).returncode, 0)

    def test_actual_uses_not_comment_or_duplicate(self):
        self.workflow.write_text("# " + self.pin + "\njobs:\n  deploy:\n    uses: attacker/action@" + self.platform_sha + "\n")
        self.assertNotEqual(self.check().returncode, 0)
        self.workflow.write_text("jobs:\n  deploy:\n    uses: " + self.pin + "\n    uses: attacker/action@" + self.platform_sha + "\n")
        self.assertNotEqual(self.check().returncode, 0)
        self.workflow.unlink()
        self.assertNotEqual(self.check().returncode, 0)

    def test_build_uses_reusable_workflow(self):
        pin = "TheDemonTuan/vps-deploy/.github/workflows/build-docker.yml@" + self.platform_sha
        self.workflow.write_text("jobs:\n  build:\n    uses: " + pin + "\n")
        env = {**os.environ, **self.env, "OPERATION": "build", "COMPONENT": "app", "IMAGE_REF": ""}
        result = subprocess.run([sys.executable, str(CHECKER), "build-docker.yml"], cwd=self.root,
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.workflow.write_text("# " + pin + "\njobs:\n  build:\n    uses: attacker/workflow@" + self.platform_sha + "\n")
        self.assertNotEqual(subprocess.run([sys.executable, str(CHECKER), "build-docker.yml"],
                                         cwd=self.root, env=env, capture_output=True).returncode, 0)

    def test_security_trivy_uses_reusable_workflow(self):
        pin = "TheDemonTuan/vps-deploy/.github/workflows/security-trivy.yml@" + self.platform_sha
        self.workflow.write_text("jobs:\n  security:\n    uses: " + pin + "\n")
        env_src = {**os.environ, **self.env, "SCAN_MODE": "source", "IMAGE_REF": ""}
        self.assertEqual(subprocess.run([sys.executable, str(CHECKER), "security-trivy.yml"],
                                         cwd=self.root, env=env_src, capture_output=True).returncode, 0)
        env_img = {**os.environ, **self.env, "SCAN_MODE": "image"}
        self.assertEqual(subprocess.run([sys.executable, str(CHECKER), "security-trivy.yml"],
                                         cwd=self.root, env=env_img, capture_output=True).returncode, 0)
        env_bad_mode = {**os.environ, **self.env, "SCAN_MODE": "invalid"}
        self.assertNotEqual(subprocess.run([sys.executable, str(CHECKER), "security-trivy.yml"],
                                            cwd=self.root, env=env_bad_mode, capture_output=True).returncode, 0)
        env_bad_img = {**os.environ, **self.env, "SCAN_MODE": "image", "IMAGE_REF": "ghcr.io/other/repo@sha256:" + "a"*64}
        self.assertNotEqual(subprocess.run([sys.executable, str(CHECKER), "security-trivy.yml"],
                                            cwd=self.root, env=env_bad_img, capture_output=True).returncode, 0)

    def test_transport_validates_user_and_fingerprint(self):
        def make_mock(name, py_body):
            target = self.root / name
            target.write_text(f"#!/usr/bin/env python3\n{py_body}\n")
            target.chmod(0o700)
            if sys.platform == "win32":
                cmd = self.root / f"{name}.cmd"
                cmd.write_text(f"@\"{sys.executable}\" \"{target}\" %*\n")
        make_mock("ssh-keyscan", "print('target.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA754IShwuzQAEHyEvFSNs2b8NkkeO9SaeB2TVpNpVWw')")
        make_mock("ssh", "import json, os, sys\nopen(os.environ['SSH_CAPTURE'], 'w').write(json.dumps(sys.argv[1:]))\nprint(json.dumps({'status':'complete','healthy':True,'image':'fixture','configured_generation':'fixture','active':'blue','draining':[]}))")
        captured = self.root / "ssh-argv"
        summary = self.root / "summary"
        key = self.root / "key"
        key.write_text("fixture-only")
        key.chmod(0o600)
        bad_env = {**os.environ, "PATH": str(self.root) + os.pathsep + os.environ["PATH"],
                   "DEPLOY_HOST": "target.example", "DEPLOY_PORT": "22", "DEPLOY_USER": "attacker",
                   "DEPLOY_KEY_FILE": str(key), "GITHUB_STEP_SUMMARY": str(summary), "SSH_CAPTURE": str(captured)}
        res_bad = subprocess.run([sys.executable, str(ROOT / "scripts/ssh-request.py"),
                                  "--app", "9router", "--host", "oracle-main", "--operation", "status",
                                  "--source-sha", self.source_sha, "--platform-ref", self.platform_sha,
                                  "--config", self.caller["config"], "--request-id", "fixture-status"],
                                 cwd=self.root / "source", env=bad_env, capture_output=True, text=True)
        self.assertNotEqual(res_bad.returncode, 0)
        self.assertIn("invalid DEPLOY_USER", res_bad.stderr)

        good_env = {**os.environ, "PATH": str(self.root) + os.pathsep + os.environ["PATH"],
                    "DEPLOY_HOST": "target.example", "DEPLOY_PORT": "22", "DEPLOY_USER": "deploy-9router",
                    "DEPLOY_KEY_FILE": str(key), "GITHUB_STEP_SUMMARY": str(summary), "SSH_CAPTURE": str(captured)}
        res_good = subprocess.run([sys.executable, str(ROOT / "scripts/ssh-request.py"),
                                   "--app", "9router", "--host", "oracle-main", "--operation", "status",
                                   "--source-sha", self.source_sha, "--platform-ref", self.platform_sha,
                                   "--config", self.caller["config"], "--request-id", "fixture-status"],
                                  cwd=self.root / "source", env=good_env, capture_output=True, text=True)
        self.assertEqual(res_good.returncode, 0, res_good.stderr)
        import json
        argv = json.loads(captured.read_text())
        self.assertIn("deploy-9router@target.example", argv)
        self.assertIn("GlobalKnownHostsFile=/dev/null", argv)
        self.assertIn("ClearAllForwardings=yes", argv)
        self.assertIn("ForwardAgent=no", argv)
        self.assertNotIn("attacker", argv)

        make_mock("ssh-keyscan", "print('target.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP//////////////////////////////////////////')")
        res_mitm = subprocess.run([sys.executable, str(ROOT / "scripts/ssh-request.py"),
                                   "--app", "9router", "--host", "oracle-main", "--operation", "status",
                                   "--source-sha", self.source_sha, "--platform-ref", self.platform_sha,
                                   "--config", self.caller["config"], "--request-id", "fixture-status"],
                                  cwd=self.root / "source", env=good_env, capture_output=True, text=True)
        self.assertNotEqual(res_mitm.returncode, 0)
        self.assertIn("fingerprint mismatch", res_mitm.stderr)

if __name__ == "__main__":
    unittest.main()
