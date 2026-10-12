#!/usr/bin/env python3
"""Load a trusted fork build for disposable diagnostics, never publication."""
import argparse
import datetime
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import yaml

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
from core import Failure, HASH, SHA, app_registration, host_registration, load, manifest, parse_json, require
from penpot_publish import archive_hash, load_bundle

caller_spec = importlib.util.spec_from_file_location('penpot_caller', ROOT / 'scripts/check-caller.py')
caller_checks = importlib.util.module_from_spec(caller_spec)
caller_spec.loader.exec_module(caller_checks)

REPOSITORY = 'TheDemonTuan/penpot'
BUILD_WORKFLOW = 'TheDemonTuan/vps-deploy/.github/workflows/build-penpot.yml@'
MAX_ARCHIVE = 32 * 1024 * 1024 * 1024


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        require(urllib.parse.urlsplit(newurl).scheme == 'https', 'PENPOT_ARTIFACT_REDIRECT')
        result = super().redirect_request(req, fp, code, msg, headers, newurl)
        if result and urllib.parse.urlsplit(req.full_url).netloc != urllib.parse.urlsplit(newurl).netloc:
            result.remove_header('Authorization')
        return result


class GitHub:
    def __init__(self):
        token = os.environ.get('GH_TOKEN', '')
        require(bool(token), 'PENPOT_ARTIFACT_TOKEN')
        self.headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
                        'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'vps-deploy-penpot-diagnostic'}
        self.opener = urllib.request.build_opener(SafeRedirect())

    def open(self, suffix):
        request = urllib.request.Request('https://api.github.com/repos/' + REPOSITORY + suffix,
                                         headers=self.headers)
        return self.opener.open(request, timeout=60)

    def get(self, suffix):
        with self.open(suffix) as response:
            # These endpoints return one artifact or run, not an unbounded listing.
            return parse_json(response.read(65537))


def provenance(api, run_id, artifact_id, source):
    require(SHA.fullmatch(source) is not None and run_id > 0 and artifact_id > 0,
            'PENPOT_DIAGNOSTIC_INPUT')
    artifact = api.get('/actions/artifacts/' + str(artifact_id))
    run = api.get('/actions/runs/' + str(run_id))
    pattern = r'penpot-built-unverified-' + source + '-' + str(run_id) + r'-([1-9][0-9]*)'
    name = artifact.get('name')
    match = re.fullmatch(pattern, name) if type(name) is str else None
    require(match is not None and artifact.get('id') == artifact_id
            and artifact.get('expired') is False, 'PENPOT_ARTIFACT_IDENTITY')
    attempt = int(match.group(1))
    require(type(run.get('run_attempt')) is int and attempt <= run['run_attempt'],
            'PENPOT_ARTIFACT_ATTEMPT')
    if attempt != run['run_attempt']:
        run = api.get('/actions/runs/' + str(run_id) + '/attempts/' + str(attempt))
    require(run.get('id') == run_id and run.get('run_attempt') == attempt
            and run.get('path') == '.github/workflows/fork-deploy.yml'
            and run.get('event') == 'push' and run.get('head_branch') == 'main'
            and run.get('head_sha') == source and run.get('status') == 'completed',
            'PENPOT_ARTIFACT_RUN')
    repository, head = run.get('repository') or {}, run.get('head_repository') or {}
    require(repository.get('full_name') == REPOSITORY and head.get('full_name') == REPOSITORY
            and type(repository.get('id')) is int and repository['id'] == head.get('id'),
            'PENPOT_ARTIFACT_REPOSITORY')
    origin = artifact.get('workflow_run') or {}
    require(origin.get('id') == run_id and origin.get('head_sha') == source
            and origin.get('head_branch') == 'main'
            and origin.get('repository_id') == repository['id']
            and origin.get('head_repository_id') == repository['id'], 'PENPOT_ARTIFACT_ORIGIN')
    references = run.get('referenced_workflows')
    require(type(references) is list, 'PENPOT_ARTIFACT_BUILDER')
    builders = [entry for entry in references if type(entry) is dict
                and type(entry.get('path')) is str and entry['path'].startswith(BUILD_WORKFLOW)]
    require(len(builders) == 1, 'PENPOT_ARTIFACT_BUILDER')
    platform = builders[0].get('sha')
    require(type(platform) is str and SHA.fullmatch(platform)
            and builders[0]['path'] == BUILD_WORKFLOW + platform, 'PENPOT_ARTIFACT_BUILDER')
    digest = artifact.get('digest')
    require(type(digest) is str and digest.startswith('sha256:') and HASH.fullmatch(digest[7:]),
            'PENPOT_ARTIFACT_DIGEST')
    expires = artifact.get('expires_at')
    require(type(expires) is str and datetime.datetime.fromisoformat(expires.replace('Z', '+00:00'))
            > datetime.datetime.now(datetime.timezone.utc), 'PENPOT_ARTIFACT_EXPIRED')
    require(type(artifact.get('size_in_bytes')) is int
            and 0 < artifact['size_in_bytes'] <= MAX_ARCHIVE, 'PENPOT_ARTIFACT_SIZE')
    return platform, digest


def check_source(source, platform, current_platform, app):
    for directory, expected in ((ROOT, current_platform), (app, source)):
        caller_checks.checked_sha(directory, expected)
    registration = app_registration(ROOT, 'penpot')
    host_registration(ROOT, registration['host'])
    caller = registration['caller']
    require(caller['repository'] == REPOSITORY and caller['config'] == '.deploy/app.yml'
            and 'fork-deploy.yml' in caller['build_workflows']
            and 'refs/heads/main' in (caller.get('refs') or [caller['ref']]), 'PENPOT_DIAGNOSTIC_CALLER')
    manifest_path = caller_checks.checkout_path(app, caller['config'])
    workflow_path = caller_checks.checkout_path(app, '.github/workflows/fork-deploy.yml')
    manifest(manifest_path.read_bytes(), registration)
    require(workflow_path.stat().st_size <= 65536, 'PENPOT_DIAGNOSTIC_CALLER')
    document = yaml.load(workflow_path.read_text(encoding='utf-8'), Loader=caller_checks.UniqueBaseLoader)
    build = document.get('jobs', {}).get('build', {})
    require(build.get('uses') == BUILD_WORKFLOW + platform
            and build.get('with') == {'app': 'penpot', 'source-sha': '${{ github.sha }}',
                                     'platform-ref': platform, 'config': caller['config']},
            'PENPOT_DIAGNOSTIC_CALLER')


def download(api, artifact_id, directory, digest):
    require(not directory.exists() and not directory.is_symlink(), 'PENPOT_DIAGNOSTIC_DIRECTORY')
    directory.mkdir(mode=0o700)
    archive = directory / 'artifact.zip'
    total = 0
    with api.open('/actions/artifacts/' + str(artifact_id) + '/zip') as response, archive.open('xb') as output:
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            require(total <= MAX_ARCHIVE, 'PENPOT_ARTIFACT_SIZE')
            output.write(chunk)
    require('sha256:' + archive_hash(archive) == digest, 'PENPOT_ARTIFACT_DIGEST')
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        require(len(entries) == 2 and {entry.filename for entry in entries} == {'build.json', 'images.tar.zst'},
                'PENPOT_ARTIFACT_FILES')
        for entry in entries:
            mode = entry.external_attr >> 16
            require(not entry.is_dir() and not stat.S_ISLNK(mode)
                    and (not stat.S_IFMT(mode) or stat.S_ISREG(mode))
                    and 0 < entry.file_size <= (65536 if entry.filename == 'build.json' else MAX_ARCHIVE),
                    'PENPOT_ARTIFACT_FILES')
            with bundle.open(entry) as source, (directory / entry.filename).open('xb') as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
    archive.unlink()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--artifact-id', type=int, required=True)
    parser.add_argument('--run-id', type=int, required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    env = os.environ
    current = env.get('GITHUB_SHA', '')
    require(env.get('GITHUB_ACTIONS') == 'true' and env.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and env.get('GITHUB_REPOSITORY') == 'TheDemonTuan/vps-deploy'
            and env.get('GITHUB_REF') == 'refs/heads/main' and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and SHA.fullmatch(current) and os.uname().machine == 'aarch64', 'PENPOT_DIAGNOSTIC_HOST')
    api = GitHub()
    platform, digest = provenance(api, args.run_id, args.artifact_id, args.source_sha)
    check_source(args.source_sha, platform, current, Path(env['GITHUB_WORKSPACE']) / 'source')
    download(api, args.artifact_id, args.directory, digest)
    load_bundle(args.directory / 'images.tar.zst', load(args.directory / 'build.json'), args.source_sha, platform)
    # Deliberately no GITHUB_OUTPUT, digest map, release file, registry push or deploy operation.
    print(json.dumps({'status': 'loaded-unverified', 'sourceSha': args.source_sha,
                      'builtPlatformRef': platform, 'diagnosticPlatformRef': current}))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Failure, OSError, ValueError, TypeError, KeyError, AttributeError,
            subprocess.SubprocessError, zipfile.BadZipFile, yaml.YAMLError) as error:
        print(json.dumps({'status': 'failed', 'error_code': error.code if isinstance(error, Failure)
                          else 'PENPOT_DIAGNOSTIC_IO_ERROR'}))
        sys.exit(1)
