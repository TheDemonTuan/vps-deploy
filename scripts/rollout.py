#!/usr/bin/env python3
"""Roll one app out to its registered hosts one at a time: the deploy action's orchestrator.

Order is the registry's: `host` first (mc-hub-api's writer, whose migrations the replicas then
receive), then `replica_hosts`. Each host swaps its own containers without downtime and must prove
the new release through ssh-request.py (status complete, healthy route, image and platform) before
the next host starts. A failed deploy stops there: that host keeps its old release (its engine
reverts itself) and the hosts already moved are rolled back, newest first, so readers never stay
split across two builds. Arguments are ssh-request.py's; without --host, every registered host."""
import argparse
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
from core import app_hosts, app_registration  # noqa: E402

REQUEST = ROOT / "scripts/ssh-request.py"


def rollout(hosts, operation, run):
    """run(host, operation) -> True once the host proved it. Returns the host that failed (None when
    all succeeded) and, after a failed deploy, each moved host's rollback result, newest first."""
    moved = []
    for host in hosts:
        if run(host, operation):
            moved.append(host)
            continue
        return host, ({h: run(h, "rollback") for h in reversed(moved)} if operation == "deploy" else {})
    return None, {}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", required=True)
    parser.add_argument("--host", default="")
    parser.add_argument("--operation", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--image", default="")
    args, rest = parser.parse_known_args()
    hosts = [args.host] if args.host else app_hosts(app_registration(ROOT, args.app))
    if len(hosts) > 1 and os.environ.get("DEPLOY_HOST"):
        raise SystemExit("DEPLOY_HOST names one machine: unset it, or pass the host")

    def run(host, operation):
        suffix = "" if operation == args.operation else "-" + operation
        command = [sys.executable, str(REQUEST), "--app", args.app, "--host", host, "--operation", operation,
                   "--request-id", args.request_id + suffix, *rest]
        if operation == "deploy":
            command += ["--image", args.image]
        print("::group::%s %s %s" % (args.app, operation, host), flush=True)
        ok = subprocess.run(command, check=False).returncode == 0
        print("::endgroup::", flush=True)
        return ok

    failed, rolled_back = rollout(hosts, args.operation, run)
    if failed is None:
        outcome = "%s: %s proved on %s" % (args.app, args.operation, ", ".join(hosts))
    else:
        outcome = "%s: %s failed on %s%s" % (args.app, args.operation, failed, "".join(
            "; rolled back %s: %s" % (host, "ok" if ok else "FAILED, recover it by hand")
            for host, ok in rolled_back.items()))
    print(outcome if failed is None else "::error::" + outcome, flush=True)
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
        summary.write("\n**Rollout** " + outcome + "\n")
    if failed is not None:
        sys.exit(1)


if __name__ == "__main__":
    main()
