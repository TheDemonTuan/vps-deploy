#!/usr/bin/env python3
"""Submit a bounded deployment request; SSH disconnect never cancels host work."""
import argparse
import base64
import binascii
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "lib"))
from core import Failure, app_registration, fixture_authorized, host_registration, image_map, manifest, parse_json, trusted_path


def require(pattern, value, name):
    if not re.fullmatch(pattern, value or ""):
        raise ValueError("invalid " + name)
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--fixture", action="store_true")
    parser.add_argument("--platform-root", type=pathlib.Path)
    parser.add_argument("--operation", choices=("deploy", "status", "rollback", "reconcile"), required=True)
    parser.add_argument('--component', choices=('app', 'rtk', 'cgw'), default='app')
    image_options = parser.add_mutually_exclusive_group()
    image_options.add_argument('--image', default='')
    image_options.add_argument('--images', default='')
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--platform-ref", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--request-id", required=True)
    args = parser.parse_args()
    require(r"[0-9a-f]{40}", args.source_sha, "source SHA")
    require(r"[0-9a-f]{40}", args.platform_ref, "platform SHA")
    require(r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}", args.request_id, "request ID")
    if args.fixture:
        if os.geteuid() != 0 or not fixture_authorized() or args.host != "fixture-local" or args.platform_root != pathlib.Path("/opt/vps-deploy/releases") / args.platform_ref:
            raise ValueError("fixture transport not authorized")
        root = trusted_path(args.platform_root, directory=True)
    else:
        if args.platform_root:
            raise ValueError("fixture release not allowed")
        root = pathlib.Path(__file__).resolve().parents[1]
    registration = app_registration(root, args.app)
    if args.host != registration["host"]:
        raise ValueError("app-host binding mismatch")
    host_record = host_registration(root, args.host)
    if args.config != registration["caller"]["config"]:
        raise ValueError("invalid config path")
    policy = registration["manifest"]
    if args.component != 'app' and args.component not in policy:
        raise ValueError('unregistered component')
    penpot = policy['strategy'] == 'penpot'
    repositories = policy.get('images')
    repository = None if penpot else (policy['image'] if args.component == 'app' else policy[args.component]['image'])
    if args.fixture:
        profile = pathlib.Path("/etc/vps-deploy/apps") / args.app / "host.json"
        selected = json.loads(trusted_path(profile).read_bytes())
        if selected.get("platform_ref") != args.platform_ref or selected.get("fixture_ci") is not True:
            raise ValueError("fixture release mismatch")
        if penpot:
            repositories = selected['image_repositories']
            if repositories != {role: 'localhost:5000/penpot-' + role for role in policy['images']}:
                raise ValueError('invalid fixture image repositories')
        elif args.component != 'cgw':
            repository = selected['image_repository' if args.component == 'app' else 'rtk_image_repository']
            if not re.fullmatch(r'localhost:5000/[a-z0-9/_-]+', repository):
                raise ValueError('invalid fixture image repository')
    if penpot:
        if args.component != 'app' or args.image:
            raise ValueError('invalid Penpot component or single image')
        if args.operation == 'rollback':
            raise ValueError('PENPOT_ROLLBACK_REQUIRES_OFFLINE_RESTORE')
        if args.operation == 'deploy':
            args.images = image_map(parse_json(args.images.encode()), repositories)
        elif args.images:
            raise ValueError('images not accepted for operation')
    else:
        if args.images:
            raise ValueError('image map requires Penpot strategy')
        if args.operation == 'deploy':
            require(re.escape(repository) + r'@sha256:[0-9a-f]{64}', args.image, 'image')
        elif args.image:
            raise ValueError('image not accepted for operation')
    if args.operation == "rollback" and args.component != "app":
        raise ValueError("rollback only accepts app")
    if args.operation != "status":
        manifest_bytes = pathlib.Path(args.config).read_bytes()
        if len(manifest_bytes) > 65536:
            raise ValueError("oversize manifest")
        manifest(manifest_bytes, registration)
        payload = dict(version=1, op=args.operation, request_id=args.request_id,
                       app=args.app, component=args.component, platform_ref=args.platform_ref,
                       manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(), source_sha=args.source_sha)
        if args.operation == "deploy":
            payload['images' if penpot else 'image'] = args.images if penpot else args.image
    else:
        payload = dict(version=1, op="status", app=args.app, request_id=args.request_id)

    identity = host_record["ssh"]
    hostname = os.environ.get("DEPLOY_HOST") or identity.get("address")
    if not hostname:
        raise ValueError("DEPLOY_HOST required")
    require(r"[A-Za-z0-9_.-]+", hostname, "host address")
    port = int(os.environ.get("DEPLOY_PORT") or identity.get("port", 22))
    deploy_user = os.environ.get("DEPLOY_USER") or ("deploy-" + args.app)
    expected_user = "deploy-" + args.app
    if deploy_user != expected_user:
        raise ValueError("invalid DEPLOY_USER: expected %s, got %s" % (expected_user, deploy_user))
    expected_fingerprint = identity["fingerprint"]
    if identity.get("host_key"):
        host_key_raw = identity["host_key"]
    else:
        scan_bin = shutil.which("ssh-keyscan") or "ssh-keyscan"
        scan_proc = subprocess.run([scan_bin, "-p", str(port), "-t", "ed25519", hostname], capture_output=True, text=True, timeout=15, check=False)
        if scan_proc.returncode != 0 or not scan_proc.stdout.strip():
            raise RuntimeError("ssh-keyscan failed: %s" % scan_proc.stderr.strip())
        scanned_lines = [line.strip() for line in scan_proc.stdout.splitlines() if line.strip() and not line.startswith("#")]
        if not scanned_lines:
            raise RuntimeError("ssh-keyscan returned no valid host keys")
        parts = scanned_lines[0].split()
        if len(parts) < 3 or parts[-2] != "ssh-ed25519":
            raise ValueError("unexpected ssh-keyscan output format")
        host_key_raw = parts[-2] + " " + parts[-1]
    key_type, encoded = host_key_raw.split()
    try:
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(encoded, validate=True)).digest()).decode().rstrip("=")
    except (binascii.Error, ValueError):
        raise ValueError("invalid host key encoding")
    if key_type != "ssh-ed25519" or fingerprint != expected_fingerprint:
        raise ValueError("host key fingerprint mismatch: expected %s, got %s" % (expected_fingerprint, fingerprint))
    key = os.environ["DEPLOY_KEY_FILE"]
    with tempfile.TemporaryDirectory(prefix="vps-deploy-ssh-") as temporary:
        known = pathlib.Path(temporary) / "known_hosts"
        known_host = ("[%s]:%d" % (hostname, port) if port != 22 else hostname)
        known.write_text(known_host + " " + key_type + " " + encoded + "\n", encoding="ascii")
        known.chmod(0o600)
        ssh_bin = shutil.which("ssh") or "ssh"
        ssh = [ssh_bin, "-F", "/dev/null", "-i", key, "-p", str(port), "-o", "BatchMode=yes",
               "-o", "IdentitiesOnly=yes", "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
               "-o", "GlobalKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=yes",
               "-o", "UserKnownHostsFile=" + str(known), "-o", "ConnectTimeout=10",
               "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
               "-T", deploy_user + "@" + hostname, "deployctl"]
        return dispatch(args, payload, ssh)

def dispatch(args, payload, ssh):

    def call(request):
        result = subprocess.run(ssh, input=json.dumps(request, separators=(",", ":")),
                                text=True, capture_output=True, timeout=40, check=False)
        if result.returncode and not result.stdout.strip():
            raise RuntimeError("SSH request failed (exit %d): %s" % (result.returncode, result.stderr[-500:]))
        response = json.loads(result.stdout)
        if not isinstance(response, dict):
            raise ValueError("invalid host response")
        return response

    deadline = time.monotonic() + (1860 if args.app == 'penpot' or args.component == 'cgw' else 960)

    def connected(request):
        while True:
            try:
                return call(request)
            except (RuntimeError, subprocess.TimeoutExpired) as error:
                if isinstance(error, RuntimeError) and any(token in str(error).lower() for token in ("host key", "host identification", "host key verification failed", "permission denied", "request_conflict", "invalid")):
                    raise
                if time.monotonic() >= deadline:
                    raise
                time.sleep(5)

    # A lost submit receipt is replayed with exactly the same request ID and payload.
    answer = connected(payload)
    if args.operation != "status":
        print(json.dumps({"receipt": answer}, sort_keys=True), flush=True)
        status_request = dict(version=1, op="status", app=args.app, request_id=args.request_id)
        while answer.get("status") not in ("complete", "failed", "recovery_required"):
            if time.monotonic() >= deadline:
                raise TimeoutError("host operation still running; request_id=" + args.request_id)
            time.sleep(5)
            answer = connected(status_request)
        # A submit receipt is deliberately small; status provides final strict proof.
        answer = connected(status_request)
    print(json.dumps(answer, sort_keys=True))
    if answer.get("status") in ("failed", "recovery_required"):
        raise RuntimeError("host operation " + str(answer.get("error_code") or answer["status"]))
    if args.operation != "status" and answer.get("status") != "complete":
        raise RuntimeError("host operation did not complete")
    if answer.get("healthy") is not True:
        raise RuntimeError("strict route, image, or health proof failed")
    if args.operation == 'deploy' and args.component == 'app':
        if args.app == 'penpot':
            if answer.get('images') != args.images or answer.get('source_sha') != args.source_sha:
                raise RuntimeError('deployed Penpot release digest or source mismatch')
        elif answer.get('image') != args.image:
            raise RuntimeError('deployed image digest mismatch')
    if args.operation == 'deploy' and args.component == 'cgw' and (answer.get('cgw') or {}).get('current') != args.image:
        raise RuntimeError('deployed CGW image digest mismatch')
    if args.operation != "status" and answer.get("platform_ref") != args.platform_ref:
        raise RuntimeError("deployed platform SHA mismatch")
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
        summary.write("\n| Request | Source | Image | Platform | Active | Generation | Draining |\n"
                      "|---|---|---|---|---|---|---|\n"
                      "| {request_id} | {source} | {image} | {platform} | {active} | {generation} | {draining} |\n".format(
                          request_id=args.request_id, source=args.source_sha,
                          image=json.dumps(answer.get('images'), sort_keys=True) if args.app == 'penpot' else (args.image or answer.get('image')),
                          platform=args.platform_ref, active=answer.get("active"),
                          generation=answer.get("configured_generation"), draining=answer.get("draining")))


if __name__ == "__main__":
    try:
        main()
    except (Failure, ValueError, KeyError, TypeError, OSError, RuntimeError, TimeoutError, binascii.Error, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
