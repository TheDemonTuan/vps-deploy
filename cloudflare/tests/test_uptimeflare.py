import copy
from email.message import Message
from itertools import count
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

spec = importlib.util.spec_from_file_location("uptimeflare", Path(__file__).parents[1] / "uptimeflare.py")
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)
SHA = "a" * 40
OLD_SHA = "b" * 40
INFRA = {"d1_id": adapter.D1_ID, "namespace_id": "f" * 32, "cron": "* * * * *"}
IDS = count(1)


def new_id():
    return str(uuid.UUID(int=next(IDS)))


def version(worker, sha=None):
    bindings = [{"name": "UPTIMEFLARE_D1", "type": "d1", "id": adapter.D1_ID}]
    if worker == adapter.MONITOR:
        bindings.append({"name": "REMOTE_CHECKER_DO", "type": "durable_object_namespace", "class_name": "RemoteChecker", "namespace_id": INFRA["namespace_id"]})
        bindings.extend({"name": name, "type": "secret_text"} for name in adapter.SECRETS)
    else:
        bindings.extend([{"name": "ASSETS", "type": "assets"}, {"name": "WORKER_SELF_REFERENCE", "type": "service", "service": adapter.WEB}])
        if sha:
            bindings.append({"name": "MONITOR_WORKER", "type": "service", "service": adapter.MONITOR})
    if sha:
        bindings.append({"name": "RELEASE_SHA", "type": "plain_text", "text": sha})
    return {"id": new_id(), "metadata": {"annotations": {"workers/tag": sha} if sha else {}}, "resources": {"bindings": bindings}}


class FakeCloudflare:
    def __init__(self, old_sha=OLD_SHA):
        self.versions = {}
        self.live = {}
        self.calls = []
        self.fail_worker = None
        for worker in adapter.WORKERS:
            old = version(worker, old_sha)
            self.versions[(worker, old["id"])] = old
            self.live[worker] = {"id": new_id(), "versions": [{"version_id": old["id"], "percentage": 100}], "annotations": {}}
        self.original = copy.deepcopy(self.live)

    def infrastructure(self):
        return INFRA.copy()

    def active(self, worker):
        return copy.deepcopy(self.live[worker])

    def version(self, worker, version_id):
        if (worker, version_id) not in self.versions:
            raise adapter.DeployError("Worker version not found")
        return copy.deepcopy(self.versions[(worker, version_id)])

    def deploy(self, worker, version_id, message):
        self.calls.append((worker, version_id))
        self.live[worker] = {"id": new_id(), "versions": [{"version_id": version_id, "percentage": 100}], "annotations": {"workers/message": message}}
        if self.fail_worker == worker:
            self.fail_worker = None
            raise adapter.DeployError("API failed after accepting candidate")
        return copy.deepcopy(self.live[worker])

    def upload(self, root, sha, worker, directory):
        item = version(worker, sha)
        self.versions[(worker, item["id"])] = item
        return item["id"]


def fixture(root):
    contents = {"manifest.json": json.dumps({"app": "uptimeflare", "source_repository": "TheDemonTuan/tuan-uptimeflare", "source_sha": SHA}),
                "__release": SHA + "\n", "SHA256SUMS": "checked by controller\n", "worker/dist/index.js": "export default {}", "web/dist/worker.js": "export default {}", ".open-next/assets/_next/static/chunk.js": "console.log('ready')"}
    for name, body in contents.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body.encode())


class TransitionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        fixture(self.root)
        self.api = FakeCloudflare()
        self.summary = {}

    def publish(self, smoke=None):
        with patch.object(adapter, "upload", side_effect=self.api.upload), patch.object(adapter, "smoke", side_effect=smoke or (lambda *args: {"http": "passed"})):
            adapter.execute(self.api, self.root, SHA, "publish", self.summary)

    def test_current_pair_is_checked_without_upload_or_deploy(self):
        self.api = FakeCloudflare(SHA)
        self.publish()
        self.assertEqual(self.summary['status'], 'already_current')
        self.assertEqual(self.api.calls, [])
        self.assertEqual(self.api.live, self.api.original)

    def test_publishes_both_compiled_versions_without_infrastructure_mutation(self):
        self.publish()
        self.assertEqual(self.summary["status"], "success")
        self.assertFalse(self.summary["d1_mutation"])
        self.assertEqual([worker for worker, _ in self.api.calls], list(adapter.WORKERS))
        for worker in adapter.WORKERS:
            candidate = adapter.active_version(self.api.live[worker])
            self.assertEqual(adapter.release_sha(self.api.version(worker, candidate)), SHA)
            self.assertEqual(self.summary["after"][worker], candidate)

    def test_failed_health_restores_both_exact_versions(self):
        def fail_candidate(web, monitor):
            if web == SHA:
                raise adapter.DeployError("Candidate unavailable")
            self.assertEqual((web, monitor), (OLD_SHA, OLD_SHA))
            return {"http": "passed"}
        with self.assertRaises(adapter.DeployError):
            self.publish(fail_candidate)
        for worker in adapter.WORKERS:
            self.assertEqual(adapter.active_version(self.api.live[worker]), adapter.active_version(self.api.original[worker]))
        self.assertEqual(self.summary["status"], "failed")
        self.assertEqual(len(self.api.calls), 4)
        self.assertNotIn("private-value", json.dumps(self.summary))

    def test_api_failure_after_switch_restores_only_attempted_worker(self):
        self.api.fail_worker = adapter.MONITOR
        with self.assertRaises(adapter.DeployError):
            self.publish()
        self.assertEqual([worker for worker, _ in self.api.calls], [adapter.MONITOR, adapter.MONITOR])
        self.assertEqual(self.api.live[adapter.WEB], self.api.original[adapter.WEB])

    def test_rollback_does_not_overwrite_another_operators_deployment(self):
        drift_id = new_id()
        def drift(web, monitor):
            self.api.live[adapter.WEB] = {"id": new_id(), "versions": [{"version_id": drift_id, "percentage": 100}], "annotations": {"workers/message": "operator"}}
            raise adapter.DeployError("Health mismatch")
        with self.assertRaises(adapter.DeployError):
            self.publish(drift)
        self.assertEqual(adapter.active_version(self.api.live[adapter.WEB]), drift_id)
        self.assertTrue(any("drift" in error for error in self.summary["rollback_errors"]))
        self.assertEqual(adapter.active_version(self.api.live[adapter.MONITOR]), adapter.active_version(self.api.original[adapter.MONITOR]))

    def test_same_version_redeployment_is_still_ownership_drift(self):
        changed = {}
        def redeploy(web, monitor):
            self.api.live[adapter.WEB]["id"] = new_id()
            changed.update(self.api.live[adapter.WEB])
            return {"http": "passed"}
        with self.assertRaises(adapter.DeployError):
            self.publish(redeploy)
        self.assertEqual(self.api.live[adapter.WEB], changed)
        self.assertTrue(any("drift" in error for error in self.summary["rollback_errors"]))

    def test_legacy_previous_versions_have_no_invented_release_sha(self):
        self.api = FakeCloudflare(old_sha=None)
        seen = []
        def smoke(web, monitor):
            seen.append((web, monitor))
            if web == SHA:
                raise adapter.DeployError("Candidate failed")
            return {"http": "passed", "previous_sha_verified": False}
        with self.assertRaises(adapter.DeployError):
            self.publish(smoke)
        self.assertEqual(seen[-1], (None, None))
        self.assertIsNone(self.summary["before"][adapter.MONITOR]["source_sha"])
        self.assertFalse(self.summary["rollback_verification"]["previous_sha_verified"])

    def test_missing_secret_or_source_config_fails_before_upload(self):
        current = self.api.versions[(adapter.MONITOR, adapter.active_version(self.api.live[adapter.MONITOR]))]
        current["resources"]["bindings"] = [binding for binding in current["resources"]["bindings"] if binding["name"] != adapter.SECRETS[0]]
        with patch.object(adapter, "upload") as upload:
            with self.assertRaises(adapter.DeployError):
                adapter.execute(self.api, self.root, SHA, "publish", self.summary)
            upload.assert_not_called()
        self.api = FakeCloudflare()
        path = self.root / "web/dist/wrangler.json"
        path.write_text('{"build":{"command":"steal-token"}}')
        with self.assertRaises(adapter.DeployError):
            self.publish()
        self.assertEqual(self.api.calls, [])

    def test_manual_rollback_requires_exact_pair_and_sha(self):
        candidates = {worker: version(worker, SHA) for worker in adapter.WORKERS}
        for worker, item in candidates.items():
            self.api.versions[(worker, item["id"])] = item
        with self.assertRaises(adapter.DeployError):
            adapter.execute(self.api, self.root, SHA, "rollback", {}, candidates[adapter.WEB]["id"], None)
        with patch.object(adapter, "smoke", return_value={"http": "passed"}):
            adapter.execute(self.api, self.root, SHA, "rollback", self.summary, candidates[adapter.WEB]["id"], candidates[adapter.MONITOR]["id"])
        self.assertEqual(self.summary["status"], "success")
        self.assertEqual(self.summary["after"], {worker: item["id"] for worker, item in candidates.items()})

    def test_wrong_database_namespace_or_secret_type_is_rejected(self):
        for name, key, value in (("UPTIMEFLARE_D1", "id", new_id()), ("REMOTE_CHECKER_DO", "namespace_id", "other"), (adapter.SECRETS[0], "type", "plain_text")):
            with self.subTest(name=name):
                item = version(adapter.MONITOR, SHA)
                next(binding for binding in item["resources"]["bindings"] if binding["name"] == name)[key] = value
                with self.assertRaises(adapter.DeployError):
                    adapter.validate_version(adapter.MONITOR, item, INFRA, SHA, paired=True)




class ReadinessTests(unittest.TestCase):
    @staticmethod
    def response(mime, body):
        headers = Message()
        headers["Content-Type"] = mime
        headers["Cache-Control"] = "no-store"
        return 200, headers, body

    def test_requires_real_html_assets_json_and_both_release_markers(self):
        def get(path):
            if path.startswith(("/__release?", "/__monitor_release?")):
                return self.response("text/plain", (SHA + "\n").encode())
            if path == "/":
                return self.response("text/html", b'<script id="__NEXT_DATA__" type="application/json">{}</script><script src="/_next/static/main.js"></script>')
            if path == "/api/data":
                return self.response("application/json", b'{"monitors":{"one":{"up":false}},"updatedAt":123}')
            return self.response("application/javascript", b'console.log("loaded")')
        with patch.object(adapter, "public_get", side_effect=get):
            self.assertTrue(adapter.smoke(SHA, SHA)["previous_sha_verified"])
        with patch.object(adapter, "public_get", return_value=self.response("text/html", b"Cloudflare challenge")):
            with self.assertRaises(adapter.DeployError):
                adapter.smoke(SHA, SHA)

    def test_worker_runtime_marker_must_match(self):
        with patch.object(adapter, "public_get", side_effect=[self.response("text/plain", (SHA + "\n").encode()), self.response("text/plain", (OLD_SHA + "\n").encode())]):
            with self.assertRaises(adapter.DeployError):
                adapter.smoke(SHA, SHA)

    def test_cloudflare_json_error_is_not_a_success(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def read(self, *args): return b'{"success":false,"result":{},"errors":[{"message":"private-body"}]}'
        api = adapter.Cloudflare("a" * 32, "never-print-token")
        with patch.object(api.opener, "open", return_value=Response()):
            with self.assertRaises(adapter.DeployError) as caught:
                api.request("/workers/scripts")
        self.assertNotIn("private-body", str(caught.exception))
        self.assertNotIn("never-print-token", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
