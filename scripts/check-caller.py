#!/usr/bin/env python3
"""Validate a registered caller before checkout, then verify its immutable source."""
import os
import pathlib
import re
import subprocess
import sys

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "lib"))
from core import Failure, app_registration, host_registration, manifest


class UniqueBaseLoader(yaml.BaseLoader):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in result:
                raise ValueError("duplicate workflow key")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def checkout_path(root, relative):
    path = root / relative
    if not path.is_file() or not path.resolve().is_relative_to(root.resolve()) or any(part.is_symlink() for part in (path, *path.parents) if part != root and root in part.parents):
        raise ValueError("missing or untrusted caller file")
    return path


def checked_sha(directory, expected):
    actual = subprocess.check_output(["git", "-C", str(directory), "rev-parse", "HEAD"], text=True).strip()
    if actual != expected:
        raise ValueError("checkout revision mismatch")


def main():
    workflow = sys.argv[1] if len(sys.argv) > 1 else None
    preflight = sys.argv[2:] == ["--preflight"]
    if workflow not in ("build-docker.yml", "deploy/action.yml") or (sys.argv[2:] and not preflight):
        raise ValueError("unknown workflow or option")
    env = os.environ
    source, platform_sha = env["SOURCE_SHA"], env["PLATFORM_REF"]
    if not re.fullmatch(r"[0-9a-f]{40}", source) or not re.fullmatch(r"[0-9a-f]{40}", platform_sha):
        raise ValueError("invalid revision")
    if source != env["CALLER_SHA"] or (workflow != "build-docker.yml" and env["ACTION_REF"] != platform_sha):
        raise ValueError("caller revision or action pin mismatch")
    platform = pathlib.Path("platform")
    registration = app_registration(platform, env["APP"])
    registered_host = registration["host"]
    host_registration(platform, registered_host)
    allowed_refs = registration["caller"].get("refs") or [registration["caller"]["ref"]]
    if (workflow != "build-docker.yml" and registered_host != env["HOST"]) or registration["caller"]["repository"] != env["CALLER_REPO"] or env["CALLER_REF"] not in allowed_refs or registration["caller"]["config"] != env["CONFIG"]:
        raise ValueError("caller binding mismatch")
    policy = registration["manifest"]
    if workflow == "build-docker.yml":
        if env["OPERATION"] != "build" or env["COMPONENT"] != "app" or env["IMAGE_REF"]:
            raise ValueError("invalid build inputs")
        callers = registration["caller"]["build_workflows"]
        pin = "TheDemonTuan/vps-deploy/.github/workflows/build-docker.yml@" + platform_sha
    else:
        component, operation, image = env["COMPONENT"], env["OPERATION"], env["IMAGE_REF"]
        if component not in ("app", "rtk") or (component == "rtk" and "rtk" not in policy):
            raise ValueError("unregistered component")
        if operation == "deploy":
            repository = policy["image"] if component == "app" else policy["rtk"]["image"]
            if not re.fullmatch(re.escape(repository) + r"@sha256:[0-9a-f]{64}", image):
                raise ValueError("invalid image")
        elif operation not in ("status", "reconcile", "rollback") or image or (operation == "rollback" and component != "app"):
            raise ValueError("invalid operation")
        callers = registration["caller"]["deploy_workflows"]
        pin = "TheDemonTuan/vps-deploy/.github/actions/deploy@" + platform_sha
    if preflight:
        return
    checked_sha(platform, platform_sha)
    root = pathlib.Path("source")
    checked_sha(root, source)
    raw = checkout_path(root, env["CONFIG"]).read_bytes()
    if len(raw) > 65536:
        raise ValueError("oversize manifest")
    manifest(raw, registration)
    for name in callers:
        if not re.fullmatch(r"[a-zA-Z0-9_-]+\.yml", name):
            raise ValueError("invalid workflow filename")
        document = yaml.load(checkout_path(root, ".github/workflows/" + name).read_text(encoding="utf-8"), Loader=UniqueBaseLoader)
        jobs = document.get("jobs", {}) if isinstance(document, dict) else {}
        if not isinstance(jobs, dict) or not any(
            isinstance(job, dict) and (job.get("uses") == pin or any(isinstance(step, dict) and step.get("uses") == pin for step in job.get("steps", []) if isinstance(job.get("steps"), list)))
            for job in jobs.values()
        ):
            raise ValueError("caller workflow does not use pinned platform")


if __name__ == "__main__":
    try:
        main()
    except (Failure, ValueError, TypeError, KeyError, OSError, subprocess.CalledProcessError, yaml.YAMLError) as error:
        sys.exit(str(error))
