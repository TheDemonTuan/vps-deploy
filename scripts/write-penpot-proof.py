#!/usr/bin/env python3
"""Checksum only the allowlisted, sanitized reports from one native build run."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import urllib.parse

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from core import Failure, SHA, atomic, json_bytes, pairs, require


SENSITIVE = r'(?:userToken|token|access_token|authorization|password|passwd|PENPOT_DB_PASSWORD|PENPOT_SECRET_KEY|GITHUB_TOKEN|DEPLOY_SSH_KEY)'
ASSIGNMENT = re.compile(r'\b' + SENSITIVE + r'\b[\s\"\']*[:=][\s\"\']*([^\s&,;\"\']+)', re.IGNORECASE)
PRIVATE_KEY = re.compile(r'-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----')
AUTHORITY = re.compile(r'https?://[^\s/]+@', re.IGNORECASE)
QUERY_URL = re.compile(r'https?://[^\s\"\'<>]*[?#]', re.IGNORECASE)
BEARER = re.compile(r'\bBearer\s+([^\s\"\']+)', re.IGNORECASE)
REDACTED = {'[redacted]', '<redacted>', 'redacted', '***'}
SMOKE_CHECKS = {'frontend', 'activeAccount', 'mcpInitialize', 'mcpToolsList', 'appRecreation',
                'databasePersistence', 'assetPersistence', 'datastoresUnchanged'}
RAW_INSPECT = re.compile(r'[\"\'](?:Env|Args|Cmd|Entrypoint)[\"\']\s*:')


def sanitized(text):
    # Decode diagnostics too: URL-encoded credentials are still credentials.
    for _ in range(4):
        require(not PRIVATE_KEY.search(text) and not AUTHORITY.search(text)
                and not QUERY_URL.search(text) and not RAW_INSPECT.search(text)
                and '\x00' not in text, 'PENPOT_PROOF_SECRET')
        for pattern in (ASSIGNMENT, BEARER):
            require(all(match.group(1).lower() in REDACTED for match in pattern.finditer(text)),
                    'PENPOT_PROOF_SECRET')
        for name in ('PENPOT_DB_PASSWORD', 'PENPOT_SECRET_KEY', 'GITHUB_TOKEN', 'DEPLOY_SSH_KEY'):
            secret = os.environ.get(name, '')
            require(not secret or secret not in text, 'PENPOT_PROOF_SECRET')
        decoded = urllib.parse.unquote(text)
        if decoded == text:
            break
        text = decoded


def safe_json(value):
    if isinstance(value, dict):
        # These are raw Docker inspect/config fields, not sanitized evidence.
        require(not {'Env', 'Args', 'Cmd', 'Entrypoint'} & set(value), 'PENPOT_PROOF_SECRET')
        for key, item in value.items():
            if re.fullmatch(SENSITIVE, key, re.IGNORECASE):
                require(isinstance(item, str) and item.lower() in REDACTED, 'PENPOT_PROOF_SECRET')
            safe_json(item)
    elif isinstance(value, list):
        for item in value:
            safe_json(item)


def proof_record(directory, source, platform, run_id, run_attempt):
    require(type(source) is str and SHA.fullmatch(source) and type(platform) is str
            and SHA.fullmatch(platform), 'PENPOT_PROOF_IDENTITY')
    require(type(run_id) is str and re.fullmatch(r'[1-9][0-9]*', run_id)
            and type(run_attempt) is str and re.fullmatch(r'[1-9][0-9]*', run_attempt),
            'PENPOT_PROOF_IDENTITY')
    directory = Path(directory)
    require(directory.is_dir() and not directory.is_symlink(), 'PENPOT_PROOF_FILES')
    files = []
    for path in directory.iterdir():
        require(not path.is_symlink(), 'PENPOT_PROOF_FILES')
        if path.name == 'proof.json':
            require(path.is_file(), 'PENPOT_PROOF_FILES')
        elif path.name == 'logs':
            require(path.is_dir(), 'PENPOT_PROOF_FILES')
            for log in path.iterdir():
                require(not log.is_symlink() and log.is_file()
                        and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*\.log', log.name), 'PENPOT_PROOF_FILES')
                files.append(log)
        else:
            require(path.name in ('smoke.json', 'lifecycle.json', 'runtime.log') and path.is_file(),
                    'PENPOT_PROOF_FILES')
            files.append(path)
    names = {path.relative_to(directory).as_posix() for path in files}
    require({'smoke.json', 'lifecycle.json'} <= names
            and any(name.endswith('.log') for name in names), 'PENPOT_PROOF_FILES')
    identity = {'schemaVersion': 1, 'sourceSha': source, 'platformRef': platform,
                'runId': run_id, 'runAttempt': run_attempt, 'platform': 'linux/arm64'}
    hashes = {}
    reports = {}
    total = 0
    for path in sorted(files):
        name = path.relative_to(directory).as_posix()
        size = path.stat().st_size
        require(0 < size <= (1024 * 1024 if name.endswith('.json') else 16 * 1024 * 1024),
                'PENPOT_PROOF_SIZE')
        total += size
        require(total <= 64 * 1024 * 1024, 'PENPOT_PROOF_SIZE')
        data = path.read_bytes()
        require(len(data) == size, 'PENPOT_PROOF_FILES')
        text = data.decode('utf-8')
        sanitized(text)
        if name.endswith('.json'):
            report = json.loads(text, object_pairs_hook=pairs)
            require(type(report) is dict, 'PENPOT_PROOF_REPORT')
            safe_json(report)
            reports[name] = report
        hashes[name] = hashlib.sha256(data).hexdigest()
    smoke = reports['smoke.json']
    require(set(smoke) == SMOKE_CHECKS | {'sourceSha', 'platform'} and smoke['sourceSha'] == source
            and smoke['platform'] == 'linux/arm64' and all(smoke[key] is True for key in SMOKE_CHECKS),
            'PENPOT_PROOF_SMOKE')
    lifecycle = reports['lifecycle.json']
    require(type(lifecycle.get('schemaVersion')) is int
            and all(lifecycle.get(key) == value for key, value in identity.items())
            and lifecycle.get('status') in ('passed', 'failed')
            and type(lifecycle.get('cases')) is list, 'PENPOT_PROOF_LIFECYCLE')
    # A failed lifecycle report is valid diagnostic evidence, never release approval.
    return dict(identity, files=hashes)


def write_proof(directory, source, platform, run_id, run_attempt):
    directory = Path(directory)
    output = directory / 'proof.json'
    # Remove only our derived manifest, so rejected replacement evidence cannot reuse it.
    require(directory.is_dir() and not directory.is_symlink(), 'PENPOT_PROOF_FILES')
    require(not output.is_symlink(), 'PENPOT_PROOF_FILES')
    if output.exists():
        require(output.is_file(), 'PENPOT_PROOF_FILES')
        output.unlink()
    record = proof_record(directory, source, platform, run_id, run_attempt)
    atomic(output, json_bytes(record))
    return record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    record = write_proof(args.directory, os.environ.get('SOURCE_SHA'), os.environ.get('PLATFORM_REF'),
                         os.environ.get('GITHUB_RUN_ID'), os.environ.get('GITHUB_RUN_ATTEMPT'))
    print(json.dumps({'status': 'recorded', 'files': len(record['files'])}))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Failure, OSError, ValueError, TypeError, KeyError) as error:
        print(json.dumps({'status': 'failed', 'error_code': error.code if isinstance(error, Failure)
                          else 'PENPOT_PROOF_IO_ERROR'}))
        sys.exit(1)
