#!/usr/bin/env python3
"""GitHub-reviewed recovery of the one interrupted OpenDesign transaction."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('platform_activation', Path(__file__).with_name('activate-platform.py'))
activation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(activation)
REQUEST_ID = 'gh-37424292784-1-app'
FIELDS = {'app', 'host', 'platform_ref', 'app_ref', 'request_id', 'healthy', 'accepting',
          'operation_cleared', 'restored_image'}

def verify_architectures(platform_ref):
    run = activation.latest_ci(platform_ref)
    prefix = 'repos/' + activation.PLATFORM_REPOSITORY + '/actions/runs/' + str(run['id'])
    prefix += '/attempts/' + str(run.get('run_attempt', 1)) + '/jobs?per_page=100&page='
    jobs = []
    page = 1
    while True:
        batch = activation.github(prefix + str(page))['jobs']
        activation.require(type(batch) is list, 'CI_INVALID')
        jobs.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    for name in ('verify (ubuntu-24.04, amd64)', 'verify (ubuntu-24.04-arm, arm64)'):
        matching = [job for job in jobs if job.get('name') == name]
        activation.require(len(matching) == 1 and matching[0].get('status') == 'completed' and
                           matching[0].get('conclusion') == 'success', 'CI_ARCHITECTURES_NOT_SUCCESSFUL')



def validate_receipt(value, platform_ref, app_ref):
    activation.require(type(value) is dict and set(value) == FIELDS and
                       value['app'] == 'opendesign' and value['host'] == 'oracle-main' and
                       value['platform_ref'] == platform_ref and value['app_ref'] == app_ref and
                       value['request_id'] == REQUEST_ID and
                       all(value[key] is True for key in ('healthy', 'accepting', 'operation_cleared')) and
                       type(value['restored_image']) is str and re.fullmatch(
                           r'ghcr\.io/thedemontuan/opendesign@sha256:[0-9a-f]{64}', value['restored_image']),
                       'INVALID_RECEIPT')
    return value


def summary(stage, code):
    path = os.environ.get('GITHUB_STEP_SUMMARY')
    if path:
        with open(path, 'a', encoding='utf-8') as stream:
            stream.write('\nOpenDesign recovery: stage `' + stage + '`, code `' + code + '`.\n')


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform-ref', required=True)
    parser.add_argument('--app-ref', required=True)
    parser.add_argument('--check-inputs', action='store_true')
    parser.add_argument('--admin-key-file', type=Path)
    parser.add_argument('--public-key-file', type=Path)
    args = parser.parse_args(argv)
    stage = 'validation'
    try:
        activation.require((args.check_inputs and args.admin_key_file is None and args.public_key_file is None) or
                           (not args.check_inputs and args.admin_key_file is not None and args.public_key_file is not None),
                           'INVALID_ARGUMENTS')
        host = activation.check_inputs(args.platform_ref, args.app_ref)
        verify_architectures(args.platform_ref)
        if args.check_inputs:
            value = {'platform_ref': args.platform_ref, 'app_ref': args.app_ref}
            output = os.environ.get('GITHUB_OUTPUT')
            if output:
                with open(output, 'a', encoding='ascii') as stream:
                    stream.write('platform_ref=' + args.platform_ref + '\napp_ref=' + args.app_ref + '\n')
        else:
            stage = 'transport'
            value = activation.reviewed_admin(args.platform_ref, args.app_ref, args.admin_key_file,
                                               args.public_key_file, host, 'recover-reviewed-operation.py',
                                               validate_receipt, 'SSH_RECOVERY_FAILED')
        print(json.dumps(value, sort_keys=True))
        return 0
    except Exception as exc:
        code = exc.code if isinstance(exc, activation.Failure) else 'RECOVERY_IO_ERROR'
        summary(stage, code)
        print(json.dumps({'stage': stage, 'error_code': code}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
