#!/usr/bin/env python3
"""Publish checked compiled UptimeFlare artifacts without running source tooling.

Versions only: never changes routes, DNS, Cron, Durable Object migrations, or D1 data.
"""
import argparse
import base64
from email.message import Message
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid

HERE = Path(__file__).resolve().parent
MONITOR = "uptimeflare_worker"
WEB = "uptimeflare-web"
WORKERS = (MONITOR, WEB)
D1_ID = "431a0d2e-6413-4e80-9d27-1ee933f14f05"
ORIGIN = "https://status.tuannguyenviet.site"
SECRETS = ("CF_ACCESS_CLIENT_ID", "CF_ACCESS_CLIENT_SECRET", "BESZEL_ACCESS_CLIENT_ID", "BESZEL_ACCESS_CLIENT_SECRET", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID")
MODULE_SUFFIXES = {".js", ".mjs", ".cjs", ".wasm", ".bin", ".txt", ".html", ".json"}
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
UUID_RE = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")


class DeployError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Cloudflare:
    def __init__(self, account, token):
        if not re.fullmatch(r"[0-9a-f]{32}", account) or not token:
            raise DeployError("Missing or invalid central Cloudflare credentials")
        self.base = f"https://api.cloudflare.com/client/v4/accounts/{account}"
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, path, *, method="GET", data=None, envelope=False):
        body = None if data is None else json.dumps(data).encode()
        request = urllib.request.Request(self.base + path, data=body, method=method,
                                         headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=45) as response:
                payload = json.loads(response.read(8 * 1024 * 1024))
        except urllib.error.HTTPError as exc:
            raise DeployError(f"Cloudflare {method} {path.split('?')[0]} failed: HTTP {exc.code}") from None
        except (OSError, ValueError):
            raise DeployError(f"Cloudflare {method} request failed") from None
        if payload.get("success") is not True or "result" not in payload:
            raise DeployError(f"Cloudflare {method} {path.split('?')[0]} rejected request")
        return payload if envelope else payload["result"]

    def active(self, worker):
        result = self.request(f"/workers/scripts/{worker}/deployments?per_page=1")
        deployments = result.get("deployments", [])
        if not deployments:
            raise DeployError(f"Existing deployment required for {worker}; bootstrap is not supported")
        deployment = deployments[0]
        versions = deployment.get("versions", [])
        if len(versions) != 1 or versions[0].get("percentage") != 100:
            raise DeployError(f"Refusing gradual/multiple-version deployment for {worker}")
        if not UUID_RE.fullmatch(versions[0].get("version_id", "")) or not UUID_RE.fullmatch(deployment.get("id", "")):
            raise DeployError(f"Malformed deployment response for {worker}")
        return deployment

    def version(self, worker, version_id):
        if not UUID_RE.fullmatch(version_id):
            raise DeployError("Invalid exact version UUID")
        result = self.request(f"/workers/scripts/{worker}/versions/{version_id}")
        if result.get("id") != version_id:
            raise DeployError(f"Version identity mismatch for {worker}")
        return result

    def deploy(self, worker, version_id, message):
        return self.request(f"/workers/scripts/{worker}/deployments", method="POST", data={
            "strategy": "percentage", "versions": [{"version_id": version_id, "percentage": 100}],
            "annotations": {"workers/message": message}})

    def infrastructure(self):
        schedules = self.request(f"/workers/scripts/{MONITOR}/schedules")
        if [item.get("cron") for item in schedules.get("schedules", [])] != ["* * * * *"]:
            raise DeployError("Existing every-minute monitoring Cron is required")
        matches = []
        page = 1
        while True:
            payload = self.request(f"/workers/durable_objects/namespaces?per_page=1000&page={page}", envelope=True)
            result = payload["result"]
            if not isinstance(result, list):
                raise DeployError("Malformed Durable Object namespace listing")
            matches.extend(item for item in result if item.get("script") == MONITOR and item.get("class") == "RemoteChecker")
            total_pages = payload.get("result_info", {}).get("total_pages")
            if total_pages is not None:
                if not isinstance(total_pages, int) or total_pages < page:
                    raise DeployError("Malformed namespace pagination")
                if page == total_pages:
                    break
            elif len(result) < 1000:
                break
            page += 1
        if len(matches) != 1 or not matches[0].get("id"):
            raise DeployError("Exactly one existing RemoteChecker namespace is required; no migration permitted")
        self.request(f"/d1/database/{D1_ID}")
        return {"d1_id": D1_ID, "namespace_id": matches[0]["id"], "cron": "* * * * *"}


def active_version(deployment):
    return deployment["versions"][0]["version_id"]


def release_sha(version):
    tag = version.get("metadata", {}).get("annotations", {}).get("workers/tag")
    if not tag:
        tag = version.get("annotations", {}).get("workers/tag")
    return tag if isinstance(tag, str) and SHA_RE.fullmatch(tag) else None


def validate_version(worker, version, infrastructure, expected_sha=None, *, paired=False):
    bindings = version.get("resources", {}).get("bindings", [])
    if not isinstance(bindings, list):
        raise DeployError(f"Malformed bindings for {worker}")
    names = [binding.get("name") for binding in bindings]
    if len(names) != len(set(names)):
        raise DeployError(f"Duplicate bindings for {worker}")
    by_name = {binding["name"]: binding for binding in bindings}
    d1 = by_name.get("UPTIMEFLARE_D1", {})
    if d1.get("type") != "d1" or d1.get("id") != D1_ID:
        raise DeployError(f"Production D1 binding mismatch for {worker}")
    if worker == MONITOR:
        do = by_name.get("REMOTE_CHECKER_DO", {})
        if do.get("type") != "durable_object_namespace" or do.get("class_name") != "RemoteChecker" or do.get("namespace_id") != infrastructure["namespace_id"]:
            raise DeployError("RemoteChecker binding must retain the exact existing namespace")
        if do.get("script_name", MONITOR) != MONITOR:
            raise DeployError("Unexpected RemoteChecker script")
        for secret in SECRETS:
            if by_name.get(secret, {}).get("type") != "secret_text":
                raise DeployError(f"Required monitoring secret binding missing: {secret}")
        allowed = set(SECRETS) | {"UPTIMEFLARE_D1", "REMOTE_CHECKER_DO", "RELEASE_SHA"}
    else:
        if by_name.get("ASSETS", {}).get("type") != "assets":
            raise DeployError("OpenNext ASSETS binding is required")
        self_binding = by_name.get("WORKER_SELF_REFERENCE", {})
        if self_binding.get("type") != "service" or self_binding.get("service") != WEB:
            raise DeployError("OpenNext self-reference binding mismatch")
        if paired:
            monitor = by_name.get("MONITOR_WORKER", {})
            if monitor.get("type") != "service" or monitor.get("service") != MONITOR:
                raise DeployError("Trusted monitor runtime service binding missing")
        auth = by_name.get("STATUS_PAGE_AUTH")
        if auth and auth.get("type") != "secret_text":
            raise DeployError("STATUS_PAGE_AUTH must remain a secret")
        allowed = {"UPTIMEFLARE_D1", "ASSETS", "WORKER_SELF_REFERENCE", "STATUS_PAGE_AUTH", "MONITOR_WORKER", "RELEASE_SHA"}
    if set(by_name) - allowed:
        raise DeployError(f"Unexpected bindings for {worker}")
    if expected_sha is not None:
        release = by_name.get("RELEASE_SHA", {})
        if release_sha(version) != expected_sha or release.get("type") != "plain_text" or release.get("text") != expected_sha:
            raise DeployError(f"Version does not carry the expected source SHA for {worker}")


def validate_artifact(root, sha):
    if not SHA_RE.fullmatch(sha):
        raise DeployError("Expected full lowercase source SHA")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    if manifest != {"app": "uptimeflare", "source_repository": "TheDemonTuan/tuan-uptimeflare", "source_sha": sha}:
        raise DeployError("Artifact manifest does not match the trusted UptimeFlare source")
    if (root / "__release").read_bytes() != (sha + "\n").encode():
        raise DeployError("Artifact release identity mismatch")
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if path.is_symlink():
            raise DeployError("Artifact contains a symlink")
        if path.is_dir():
            continue
        name = relative.as_posix()
        if not path.is_file() or any(c in name for c in "\n\r\\"):
            raise DeployError("Invalid artifact path")
        if name in {"manifest.json", "__release", "SHA256SUMS"}:
            continue
        if any(part.startswith(".env") or part == "node_modules" for part in relative.parts) or path.suffix in {".map", ".ts", ".tsx", ".tf", ".tfstate", ".key", ".pem"}:
            raise DeployError("Source or private data is not a deployable artifact")
        if path.name in {"wrangler.toml", "wrangler.json", "wrangler.jsonc", "package.json", "package-lock.json"}:
            raise DeployError("Source-provided deployment configuration is forbidden")
        if name.startswith(("worker/dist/", "web/dist/")):
            if path.suffix not in MODULE_SUFFIXES:
                raise DeployError("Unsupported compiled module")
        elif name.startswith(".open-next/assets/"):
            if path.stat().st_size > 25 * 1024 * 1024:
                raise DeployError("Asset exceeds the Cloudflare upload limit")
        else:
            raise DeployError("Artifact contains files outside compiled runtime/assets")
    for name in ("worker/dist/index.js", "web/dist/worker.js", "SHA256SUMS"):
        path = root / name
        if not path.is_file() or not path.stat().st_size:
            raise DeployError(f"Missing compiled artifact component: {name}")
    assets = root / ".open-next/assets"
    if not any(assets.rglob("*.js")) or any((assets / name).exists() for name in ("__release", "__monitor_release")):
        raise DeployError("OpenNext assets missing or shadowing release endpoints")


def upload(root, sha, worker, directory):
    prefix = "uptimeflare-monitor" if worker == MONITOR else "uptimeflare-web"
    work = directory / worker
    work.mkdir()
    source = root / ("worker/dist" if worker == MONITOR else "web/dist")
    shutil.copytree(source, work / "runtime")
    shutil.copyfile(HERE / (prefix + ".mjs"), work / "entry.mjs")
    config = json.loads((HERE / (prefix + ".json")).read_text(encoding="utf-8"))
    config["vars"] = {"RELEASE_SHA": sha}
    if worker == WEB:
        shutil.copytree(root / ".open-next/assets", work / "assets")
    config_path = work / "wrangler.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    wrangler = Path(os.environ.get("WRANGLER_BIN", str(HERE / "node_modules/wrangler/bin/wrangler.js"))).resolve()
    # This is an operator-provided central tool path, never a value taken from the artifact.
    if not wrangler.is_file() or wrangler.is_relative_to(root):
        raise DeployError("Trusted central Wrangler installation is required")
    command = ["node", str(wrangler), "versions", "upload", "--config", str(config_path), "--no-bundle", "--keep-vars", "--tag", sha, "--message", "central uptimeflare " + sha]
    env = {name: value for name, value in os.environ.items() if name not in SECRETS}
    env.update({"CI": "true", "NO_COLOR": "1", "WRANGLER_SEND_METRICS": "false"})
    try:
        result = subprocess.run(command, cwd=work, env=env, capture_output=True, text=True, timeout=300, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise DeployError(f"Version upload failed for {worker}") from None
    # Never forward Wrangler output: it can contain binding values and API responses.
    if result.returncode:
        raise DeployError(f"Version upload failed for {worker} (exit {result.returncode})")
    ids = re.findall(r"Worker Version ID:\s*([0-9a-f-]{36})", result.stdout)
    if len(ids) != 1 or not UUID_RE.fullmatch(ids[0]):
        raise DeployError(f"Cannot identify the exact uploaded version for {worker}")
    return ids[0]


class Entries(HTMLParser):
    def __init__(self):
        super().__init__()
        self.assets = set()

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == 'script' and (values.get('src') or '').startswith('/_next/static/'):
            self.assets.add((values['src'], 'js'))
        if tag == 'link' and values.get('rel') == 'stylesheet' and (values.get('href') or '').startswith('/_next/static/'):
            self.assets.add((values['href'], 'css'))


def public_get(path):
    opener = urllib.request.build_opener(NoRedirect())
    try:
        request = urllib.request.Request(ORIGIN + path, headers={"Cache-Control": "no-cache", "Accept-Encoding": "identity"})
        with opener.open(request, timeout=20) as response:
            body = response.read(8 * 1024 * 1024 + 1)
            if len(body) > 8 * 1024 * 1024:
                raise DeployError("Public readiness response exceeds size limit")
            return response.status, response.headers, body
    except urllib.error.HTTPError as exc:
        raise DeployError(f"Public readiness {path.split('?')[0]} failed: HTTP {exc.code}") from None
    except OSError:
        raise DeployError("Public readiness request failed") from None


def browser_transport(web_sha, monitor_sha):
    public_env = {name: value for name, value in os.environ.items()
                  if not name.startswith(('CLOUDFLARE_', 'UPTIMEFLARE_')) and name not in (*SECRETS, 'GH_TOKEN', 'GITHUB_TOKEN')}
    result = subprocess.run(['node', str(HERE / 'uptimeflare-http.mjs'), web_sha or '', monitor_sha or ''],
                            env=public_env, capture_output=True, timeout=90, check=False)
    if result.returncode:
        failure = re.search(rb'failed at (launch|navigation|read-html|enumerate-resources|validate-resource|fetch-resources) \((HTTP_[0-9]{3}|[A-Z_]+|unclassified)\)', result.stderr)
        reason = ' at ' + failure[1].decode() + ' (' + failure[2].decode() + ')' if failure else ''
        raise DeployError('Actual Chromium public readiness failed' + reason + '; no HTTP fallback accepted')
    responses = json.loads(result.stdout)
    def get(path):
        if path not in responses:
            raise DeployError('Public browser did not observe a required readiness resource')
        response = responses[path]
        headers = Message()
        for name, value in response['headers'].items():
            headers[name] = value
        return response['status'], headers, base64.b64decode(response['body'], validate=True)
    return get


def smoke(web_sha=None, monitor_sha=None):
    get = browser_transport(web_sha, monitor_sha) if os.environ.get('UPTIMEFLARE_PUBLIC_TRANSPORT') == 'chromium' else public_get
    for path, sha in (("/__release", web_sha), ("/__monitor_release", monitor_sha)):
        if sha is None:
            continue
        status, headers, body = get(path + "?smoke=" + sha)
        if status != 200 or headers.get_content_type() != "text/plain" or body != (sha + "\n").encode() or "no-store" not in headers.get("Cache-Control", ""):
            raise DeployError("Public runtime release identity mismatch")
    status, headers, body = get("/")
    if status != 200 or headers.get_content_type() != "text/html" or b"__NEXT_DATA__" not in body:
        raise DeployError("Public OpenNext HTML readiness failed")
    entries = Entries()
    entries.feed(body.decode("utf-8"))
    if not entries.assets or not any(kind == "js" for _, kind in entries.assets):
        raise DeployError("Public OpenNext entry scripts missing")
    for path, kind in entries.assets:
        url = urllib.parse.urlsplit(path)
        if url.scheme or url.netloc or not url.path.startswith("/_next/static/"):
            raise DeployError("Unexpected public OpenNext asset origin")
        status, headers, body = get(path)
        mime = headers.get_content_type()
        if status != 200 or not body or (kind == "js" and mime not in {"text/javascript", "application/javascript"}) or (kind == "css" and mime != "text/css"):
            raise DeployError("Public OpenNext asset readiness failed")
    status, headers, body = get("/api/data")
    if status != 200 or headers.get_content_type() != "application/json":
        raise DeployError("Public D1-backed status API readiness failed")
    try:
        data = json.loads(body)
        if not isinstance(data.get("monitors"), dict) or not data["monitors"] or not isinstance(data.get("updatedAt"), (int, float)) or data["updatedAt"] <= 0:
            raise ValueError()
    except (ValueError, AttributeError, TypeError):
        raise DeployError("Public status API returned an invalid monitoring snapshot") from None
    return {"http": "passed", "web_sha": web_sha, "monitor_sha": monitor_sha,
            "previous_sha_verified": web_sha is not None and monitor_sha is not None}


def execute(api, root, sha, mode, summary, version_id=None, monitor_version_id=None):
    infrastructure = api.infrastructure()
    before = {worker: api.active(worker) for worker in WORKERS}
    previous = {worker: api.version(worker, active_version(before[worker])) for worker in WORKERS}
    for worker in WORKERS:
        validate_version(worker, previous[worker], infrastructure)
    previous_shas = {worker: release_sha(previous[worker]) for worker in WORKERS}
    summary.update({"app": "uptimeflare", "source_sha": sha, "mode": mode, "status": "pending",
                    "before": {worker: {"version_id": active_version(before[worker]), "source_sha": previous_shas[worker]} for worker in WORKERS},
                    "infrastructure": infrastructure, "d1_mutation": False})
    if mode == 'check' or (mode == 'publish' and all(previous_shas[worker] == sha for worker in WORKERS)):
        if mode == 'publish':
            validate_artifact(root, sha)
            for worker in WORKERS:
                validate_version(worker, previous[worker], infrastructure, sha, paired=True)
        summary['verification'] = smoke(previous_shas[WEB], previous_shas[MONITOR] if previous_shas[WEB] else None)
        for worker in WORKERS:
            if api.active(worker)['id'] != before[worker]['id']:
                raise DeployError('Deployment drift during read-only verification')
        if api.infrastructure() != infrastructure:
            raise DeployError('Infrastructure drift during read-only verification')
        summary.update(status='checked_no_mutation' if mode == 'check' else 'already_current',
                       after={worker: active_version(before[worker]) for worker in WORKERS})
        return
    candidates = {}
    if mode == "rollback":
        candidates = {WEB: version_id, MONITOR: monitor_version_id}
        for worker in WORKERS:
            if not candidates[worker]:
                raise DeployError("Rollback requires exact web and monitor UUIDs")
            validate_version(worker, api.version(worker, candidates[worker]), infrastructure, sha, paired=True)
    else:
        summary['baseline_verification'] = smoke(previous_shas[WEB], previous_shas[MONITOR] if previous_shas[WEB] else None)
        validate_artifact(root, sha)
        summary["artifact_manifest_sha256"] = hashlib.sha256((root / "SHA256SUMS").read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory(prefix="uptimeflare-central-") as temp:
            directory = Path(temp)
            os.chmod(directory, 0o700)
            for worker in WORKERS:
                candidates[worker] = upload(root, sha, worker, directory)
                validate_version(worker, api.version(worker, candidates[worker]), infrastructure, sha, paired=True)
    summary["candidate"] = candidates.copy()
    operation = "central uptimeflare " + str(uuid.uuid4()) + " " + sha
    messages = {worker: operation + " " + worker for worker in WORKERS}
    attempted = []
    owned = {}
    try:
        # Both versions are uploaded and checked before either receives traffic.
        for worker in WORKERS:
            if api.active(worker)["id"] != before[worker]["id"]:
                raise DeployError(f"Deployment drift before publishing {worker}")
        for worker in WORKERS:
            if api.active(worker)["id"] != before[worker]["id"]:
                raise DeployError(f"Deployment drift before switching {worker}")
            attempted.append(worker)
            deployed = api.deploy(worker, candidates[worker], messages[worker])
            owned[worker] = deployed["id"]
            live = api.active(worker)
            if live["id"] != owned[worker] or active_version(live) != candidates[worker] or live.get("annotations", {}).get("workers/message") != messages[worker]:
                raise DeployError(f"Candidate deployment not active for {worker}")
        if api.infrastructure() != infrastructure:
            raise DeployError("Infrastructure drift during publication")
        summary["verification"] = smoke(sha, sha)
        for worker in WORKERS:
            live = api.active(worker)
            if live["id"] != owned[worker] or active_version(live) != candidates[worker] or live.get("annotations", {}).get("workers/message") != messages[worker]:
                raise DeployError(f"Deployment drift after verifying {worker}")
        summary["status"] = "success"
        summary["after"] = candidates.copy()
    except Exception:
        summary["status"] = "failed"
        restored = {}
        errors = []
        for worker in reversed(attempted):
            try:
                live = api.active(worker)
                if live["id"] == before[worker]["id"]:
                    restored[worker] = "unchanged"
                    continue
                if (worker in owned and live["id"] != owned[worker]) or active_version(live) != candidates[worker] or live.get("annotations", {}).get("workers/message") != messages[worker]:
                    raise DeployError(f"Rollback refused: deployment drift for {worker}")
                api.deploy(worker, active_version(before[worker]), operation + " restore " + worker)
                if active_version(api.active(worker)) != active_version(before[worker]):
                    raise DeployError(f"Rollback version verification failed for {worker}")
                restored[worker] = active_version(before[worker])
            except Exception as exc:
                errors.append(str(exc) if isinstance(exc, DeployError) else "Rollback API verification failed")
        summary["restored"] = restored
        if not errors:
            try:
                for worker in WORKERS:
                    if active_version(api.active(worker)) != active_version(before[worker]):
                        raise DeployError(f"Rollback refused: remaining deployment drift for {worker}")
                # Legacy untagged versions have no release marker: prove exact API IDs and
                # real HTTP availability, and never claim a fabricated previous SHA.
                summary["rollback_verification"] = smoke(previous_shas[WEB], previous_shas[MONITOR] if previous_shas[WEB] else None)
                if api.infrastructure() != infrastructure:
                    raise DeployError("Infrastructure drift after rollback")
            except Exception as exc:
                errors.append(str(exc) if isinstance(exc, DeployError) else "Rollback HTTP verification failed")
        if errors:
            summary["rollback_errors"] = errors
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--mode", choices=("publish", "rollback", "check"), required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--version-id")
    parser.add_argument("--monitor-version-id")
    args = parser.parse_args()
    summary = {"app": "uptimeflare", "status": "failed"}
    code = 0
    try:
        if args.mode != 'check' and not SHA_RE.fullmatch(args.sha):
            raise DeployError("Expected full lowercase source SHA")
        if os.environ.get("UPTIMEFLARE_D1_ID") != D1_ID:
            raise DeployError("Central production D1 ID must equal the retained existing database")
        if args.mode == "publish" and (args.version_id or args.monitor_version_id):
            raise DeployError("Publish must not accept rollback version IDs")
        api = Cloudflare(os.environ.get("CLOUDFLARE_ACCOUNT_ID", ""), os.environ.get("CLOUDFLARE_API_TOKEN", ""))
        execute(api, args.root.resolve(), args.sha, args.mode, summary, args.version_id, args.monitor_version_id)
    except Exception as exc:
        summary["status"] = "failed"
        summary["error"] = str(exc) if isinstance(exc, DeployError) else "Adapter failed; no sensitive exception details emitted"
        code = 1
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    raise SystemExit(code)


if __name__ == "__main__":
    main()
