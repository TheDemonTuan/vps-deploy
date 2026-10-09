#!/usr/bin/python3
"""Run offline restore only from the installed root-owned engine release."""
import argparse
import importlib.util
import importlib.machinery
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
from core import Failure, paths, require, trusted_path
import penpot_restore


def controller():
    loader = importlib.machinery.SourceFileLoader('penpot_restore_controller', str(ROOT / 'bin/deployctl'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description='Root-only offline Penpot restore; no app SSH access.')
    parser.add_argument('--backup', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'ROOT_REQUIRED')
    require(args.backup.is_absolute(), 'PENPOT_RESTORE_DIRECTORY')
    cfg, state_dir, locks = paths('penpot', operator=True)
    trusted_path(state_dir, directory=True)
    trusted_path(locks, directory=True)
    engine = controller()
    profile = engine.load_profile(cfg, 'penpot')
    if args.check:
        response = penpot_restore.check(args.backup, state_dir, cfg, profile)
    else:
        # Activation remains forbidden until the complete release engine is verified.
        engine.ready_engine(profile)
        response = penpot_restore.apply(args.backup, state_dir, cfg, ROOT, profile, locks)
    print(json.dumps(response, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Failure, OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired) as error:
        code = error.code if isinstance(error, Failure) else 'HOST_IO_ERROR'
        print(json.dumps({'status': 'failed', 'error_code': code}))
        sys.exit(1)
