#!/usr/bin/env python3
"""Submit a bounded deployment request; SSH disconnect never cancels host work."""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time


def require(pattern, value, name):
    if not re.fullmatch(pattern, value or ""):
        raise ValueError("invalid " + name)
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--operation", choices=("deploy", "status", "rollback", "reconcile"), required=True)
    parser.add_argument("--component", choices=("app", "rtk"), default="app")
    parser.add_argument("--image", default="")
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--platform-ref", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--request-id", required=True)
    args = parser.parse_args()
    require(r"[0-9a-f]{40}", args.source_sha, "source SHA")
    require(r"[0-9a-f]{40}", args.platform_ref, "platform SHA")
    require(r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}", args.request_id, "request ID")
    if args.config != ".deploy/app.yml":
        raise ValueError("invalid config path")
    image_repo = "9router" if args.component == "app" else "rtk-sidecar"
    if args.operation == "deploy":
        require(r"ghcr\.io/thedemontuan/" + image_repo + r"@sha256:[0-9a-f]{64}", args.image, "image")
    elif args.image:
        raise ValueError("image not accepted for operation")
    if args.operation == "rollback" and args.component != "app":
        raise ValueError("rollback only accepts app")
    if args.operation != "status":
        manifest = open(args.config, "rb").read(65537)
        if len(manifest) > 65536:
            raise ValueError("oversize manifest")
        payload = dict(version=1, op=args.operation, request_id=args.request_id,
                       app="9router", component=args.component, platform_ref=args.platform_ref,
                       manifest_sha256=hashlib.sha256(manifest).hexdigest(), source_sha=args.source_sha)
        if args.operation == "deploy":
            payload["image"] = args.image
    else:
        payload = dict(version=1, op="status", app="9router", request_id=args.request_id)

    host = require(r"[A-Za-z0-9.-]+", os.environ["DEPLOY_HOST"], "host")
    port = require(r"[0-9]{1,5}", os.environ["DEPLOY_PORT"], "port")
    user = require(r"[a-z][a-z0-9-]*", os.environ["DEPLOY_USER"], "user")
    key, known = os.environ["DEPLOY_KEY_FILE"], os.environ["DEPLOY_KNOWN_HOSTS_FILE"]
    ssh = ["ssh", "-i", key, "-p", port, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
           "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + known,
           "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
           "-T", user + "@" + host, "deployctl"]

    def call(request):
        result = subprocess.run(ssh, input=json.dumps(request, separators=(",", ":")),
                                text=True, capture_output=True, timeout=40, check=False)
        if result.returncode and not result.stdout.strip():
            raise RuntimeError("SSH request failed (exit %d): %s" % (result.returncode, result.stderr[-500:]))
        response = json.loads(result.stdout)
        if not isinstance(response, dict):
            raise ValueError("invalid host response")
        return response

    deadline = time.monotonic() + 16 * 60

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
        status_request = dict(version=1, op="status", app="9router", request_id=args.request_id)
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
    if args.operation == "deploy" and args.component == "app" and answer.get("image") != args.image:
        raise RuntimeError("deployed image digest mismatch")
    if args.operation != "status" and answer.get("platform_ref") != args.platform_ref:
        raise RuntimeError("deployed platform SHA mismatch")
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
        summary.write("\n| Request | Source | Image | Platform | Active | Generation | Draining |\n"
                      "|---|---|---|---|---|---|---|\n"
                      "| {request_id} | {source} | {image} | {platform} | {active} | {generation} | {draining} |\n".format(
                          request_id=args.request_id, source=args.source_sha, image=args.image or answer.get("image"),
                          platform=args.platform_ref, active=answer.get("active"),
                          generation=answer.get("configured_generation"), draining=answer.get("draining")))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
