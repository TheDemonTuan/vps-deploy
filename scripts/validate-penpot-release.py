#!/usr/bin/env python3
"""Bind a downloaded same-run release artifact to the build job outputs."""
import argparse
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from core import Failure, parse_json, require
from penpot_publish import release_record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('record', type=Path)
    args = parser.parse_args()
    require(os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('GITHUB_REPOSITORY') == 'TheDemonTuan/penpot'
            and os.environ.get('GITHUB_REF') == 'refs/heads/main', 'PENPOT_BUILD_CALLER')
    require(args.record.is_file() and not args.record.is_symlink()
            and 0 < args.record.stat().st_size <= 65536, 'PENPOT_RELEASE_ARTIFACT')
    images = release_record(parse_json(args.record.read_bytes()), os.environ.get('GITHUB_SHA'),
                            os.environ.get('PLATFORM_REF'), parse_json(os.environ.get('EXPECTED_IMAGES', '').encode()))
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='ascii') as stream:
        stream.write('images=' + json.dumps(images, sort_keys=True, separators=(',', ':')) + '\n')


if __name__ == '__main__':
    try:
        main()
    except (Failure, OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({'status': 'failed', 'error_code': error.code if isinstance(error, Failure) else 'BUILD_IO_ERROR'}))
        raise SystemExit(1)
