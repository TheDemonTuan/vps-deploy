#!/usr/bin/env python3
"""Review-bound transport for the fixed OpenDesign AppSec method-rule scope."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('reviewed_platform', ROOT / 'scripts/activate-platform.py')
reviewed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reviewed)
FIELDS = {'app', 'host', 'platform_ref', 'app_ref', 'rule_id', 'policy_name', 'healthy',
          'legitimate_pass', 'negative_controls_pass', 'security_retained', 'runtime_boundary_pass',
          'profile_unchanged', 'container_unchanged', 'runtime_env_unchanged'}


def validate_receipt(value, platform_ref, app_ref):
    reviewed.require(type(value) is dict and set(value) == FIELDS and
                     value['app'] == 'opendesign' and value['host'] == 'oracle-main' and
                     value['platform_ref'] == platform_ref and value['app_ref'] == app_ref and
                     type(value['rule_id']) is int and value['rule_id'] == 911100 and
                     value['policy_name'] == 'local/opendesign-crs-scope' and
                     all(value[field] is True for field in FIELDS -
                         {'app', 'host', 'platform_ref', 'app_ref', 'rule_id', 'policy_name'}), 'INVALID_RECEIPT')
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform-ref', required=True)
    parser.add_argument('--app-ref', required=True)
    parser.add_argument('--check-inputs', action='store_true')
    parser.add_argument('--admin-key-file', type=Path)
    parser.add_argument('--public-key-file', type=Path)
    args = parser.parse_args(argv)
    stage = 'validation'
    try:
        reviewed.require((args.check_inputs and args.admin_key_file is None and args.public_key_file is None) or
                         (not args.check_inputs and args.admin_key_file is not None and args.public_key_file is not None),
                         'INVALID_ARGUMENTS')
        host = reviewed.check_inputs(args.platform_ref, args.app_ref)
        if args.check_inputs:
            value = {'platform_ref': args.platform_ref, 'app_ref': args.app_ref}
            if os.environ.get('GITHUB_OUTPUT'):
                with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='ascii') as stream:
                    stream.write('platform_ref=' + args.platform_ref + '\napp_ref=' + args.app_ref + '\n')
        else:
            stage = 'transport'
            value = reviewed.reviewed_admin(args.platform_ref, args.app_ref, args.admin_key_file,
                                            args.public_key_file, host, 'tune-reviewed-opendesign-waf.py',
                                            validate_receipt, 'SSH_WAF_TUNE_FAILED')
        print(json.dumps(value, sort_keys=True))
        return 0
    except Exception as exc:
        code = exc.code if isinstance(exc, reviewed.Failure) else 'WAF_TUNE_IO_ERROR'
        reviewed.summary(stage, code)
        print(json.dumps({'stage': stage, 'error_code': code}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
