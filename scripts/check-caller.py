#!/usr/bin/env python3
"""Check the actual caller commit pins this reusable workflow's approved commit."""
import os
import pathlib
import re
import subprocess
import sys


name = sys.argv[1]
source = os.environ["SOURCE_SHA"]
platform = os.environ["PLATFORM_REF"]
config = os.environ["CONFIG"]
if name not in ("build-docker.yml", "deploy-vps.yml", "operate-vps.yml"):
    sys.exit("unknown workflow")
if config != ".deploy/app.yml" or not re.fullmatch(r"[0-9a-f]{40}", source) or not re.fullmatch(r"[0-9a-f]{40}", platform):
    sys.exit("invalid workflow input")
for directory, sha in (("source", source), ("platform", platform)):
    result = subprocess.check_output(["git", "-C", directory, "rev-parse", "HEAD"], text=True).strip()
    if result != sha:
        sys.exit("checkout revision mismatch: " + directory)
callers = {
    "build-docker.yml": ("deploy.yml",),
    "deploy-vps.yml": ("deploy.yml", "rtk-sidecar.yml"),
    "operate-vps.yml": ("deploy-ops.yml",),
}[name]
needle = "TheDemonTuan/vps-deploy/.github/workflows/" + name + "@" + platform
if not any(needle in (pathlib.Path("source/.github/workflows") / caller).read_text(encoding="utf-8") for caller in callers):
    sys.exit("caller does not pin running platform SHA")
if not pathlib.Path("source", config).is_file():
    sys.exit("manifest missing")
