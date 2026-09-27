#!/usr/bin/env python3
"""Check immutable checkouts and the caller's approved platform pin."""
import os
import pathlib
import re
import subprocess
import sys


name = sys.argv[1]
source = os.environ["SOURCE_SHA"]
platform = os.environ["PLATFORM_REF"]
config = os.environ["CONFIG"]
if name not in ("build-docker.yml", "deploy/action.yml"):
    sys.exit("unknown workflow or action")
if config != ".deploy/app.yml" or not re.fullmatch(r"[0-9a-f]{40}", source) or not re.fullmatch(r"[0-9a-f]{40}", platform):
    sys.exit("invalid workflow input")
for directory, sha in (("source", source), ("platform", platform)):
    result = subprocess.check_output(["git", "-C", directory, "rev-parse", "HEAD"], text=True).strip()
    if result != sha:
        sys.exit("checkout revision mismatch: " + directory)
if name == "build-docker.yml":
    callers = ("deploy.yml",)
    needle = "TheDemonTuan/vps-deploy/.github/workflows/build-docker.yml@" + platform
else:
    callers = ("deploy.yml", "rtk-sidecar.yml", "deploy-ops.yml")
    needle = "TheDemonTuan/vps-deploy/.github/actions/deploy@" + platform
if not any(needle in (pathlib.Path("source/.github/workflows") / caller).read_text(encoding="utf-8") for caller in callers):
    sys.exit("caller does not pin running platform SHA")
if not pathlib.Path("source", config).is_file():
    sys.exit("manifest missing")
