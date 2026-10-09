#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import sys
import subprocess

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from core import Failure, atomic, json_bytes, load, require
from penpot_publish import publish


def failure_report(error):
    code = error.code if isinstance(error, Failure) else 'BUILD_IO_ERROR'
    if isinstance(error, subprocess.TimeoutExpired):
        code = 'BUILD_TIMEOUT'
    print(json.dumps({'status': 'failed', 'error_code': code}))
    if code in ('ANONYMOUS_IMAGE_REQUIRED', 'IMAGE_NOT_PUBLIC') and os.environ.get('GITHUB_STEP_SUMMARY'):
        # Never include the exception text, registry response or authentication URL.
        try:
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as stream:
                stream.write('\nPenpot anonymous pull verification failed. Check the original error code '
                             'and registry/network availability; this does not prove the packages are private. '
                             'If these newly created packages are private, make all four penpot-frontend, '
                             'penpot-backend, penpot-exporter and penpot-mcp packages Public at '
                             'https://github.com/users/TheDemonTuan/packages, then rerun the failed '
                             'publication job using the build artifact from this same run. '
                             'If the artifact has expired, rerun the complete chain. '
                             'Do not add an admin PAT or combine digests from different runs.\n')
        except OSError:
            pass  # Summary delivery must not replace the original publication failure.


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--metadata', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('GITHUB_REPOSITORY') == 'TheDemonTuan/penpot'
            and os.environ.get('GITHUB_REF') == 'refs/heads/main', 'PENPOT_BUILD_CALLER')
    require(not args.output.exists() and not args.output.is_symlink(), 'PENPOT_RELEASE_OUTPUT_EXISTS')
    result = publish(args.archive, load(args.metadata), os.environ.get('GITHUB_SHA'), os.environ.get('PLATFORM_REF'))
    images = json.dumps(result['images'], sort_keys=True, separators=(',', ':'))
    try:
        atomic(args.output, json_bytes(result))
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='ascii') as stream:
            stream.write('images=' + images + '\n')
    except (OSError, KeyError):
        # A failed output hand-off must not leave a release for a later upload step.
        args.output.unlink(missing_ok=True)
        raise
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Failure, OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired) as error:
        failure_report(error)
        sys.exit(1)
