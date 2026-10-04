#!/usr/bin/env python3
"""Manage only the two static-hosting route sets; never proxy backend traffic."""
import argparse
import datetime
import fnmatch
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

API_BASE = 'https://api.cloudflare.com/client/v4'
WORKER = 'acb-web'
HOSTS = {'bank': 'bank.tuannguyenviet.site', 'viewer': 'transactions.tuannguyenviet.site'}


class RouteError(RuntimeError):
    pass


def patterns(host):
    prefixes = ['/api*', '/internal*', '/health*', '/ready*']
    if host == HOSTS['viewer']:
        prefixes.insert(2, '/admin*')
    return [(host + path, None) for path in prefixes] + [(host + '/*', WORKER)]


def value(record):
    return {'id': record['id'], 'pattern': record['pattern'], 'script': record.get('script') or None}


class API:
    def __init__(self):
        self.token = os.environ.get('CLOUDFLARE_API_TOKEN', '')
        self.zone = os.environ.get('CLOUDFLARE_ZONE_ID', '')
        if not self.token or not re.fullmatch(r'[0-9a-f]{32}', self.zone):
            raise RouteError('CLOUDFLARE_API_TOKEN and a valid CLOUDFLARE_ZONE_ID are required')

    def request(self, method, suffix='', body=None):
        url = f'{API_BASE}/zones/{self.zone}/workers/routes{suffix}'
        request = urllib.request.Request(url, method=method, headers={
            'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'},
            data=None if body is None else json.dumps(body).encode())
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                result = json.load(response)
        except (urllib.error.URLError, ValueError) as error:
            # Never include response bodies or token-bearing request representations.
            raise RouteError(f'Cloudflare {method} failed ({type(error).__name__})') from None
        if not isinstance(result, dict) or result.get('success') is not True or 'result' not in result:
            raise RouteError(f'Cloudflare {method} reported unsuccessful or malformed response')
        return result

    def routes(self):
        records, page = [], 1
        while True:
            result = self.request('GET', f'?page={page}&per_page=100')
            if not isinstance(result['result'], list):
                raise RouteError('Malformed route list')
            records.extend(value(record) for record in result['result'])
            info = result.get('result_info', {})
            total = info.get('total_pages', 1)
            if not isinstance(total, int) or total < page:
                raise RouteError('Malformed route pagination')
            if page >= total:
                break
            page += 1
        if len({record['id'] for record in records}) != len(records):
            raise RouteError('Duplicate route IDs')
        return records

    def put(self, before, pattern, script):
        body = {'pattern': pattern}
        if script is not None:
            body['script'] = script
        result = self.request('PUT' if before else 'POST', '/' + before['id'] if before else '', body)['result']
        after = value(result)
        if after['pattern'] != pattern or after['script'] != script or (before and after['id'] != before['id']):
            raise RouteError('Cloudflare write returned unexpected route identity')
        return after

    def delete(self, record):
        self.request('DELETE', '/' + record['id'])


def affects_host(pattern, host):
    text = re.sub(r'^https?://', '', pattern)
    hostname = text.split('/', 1)[0]
    # A foreign host-wide/subpath route can supersede or be superseded by the
    # migration. Conservatively require an operator to resolve every overlap.
    return fnmatch.fnmatchcase(host, hostname)


def inspect(records, host, require=False):
    expected = dict(patterns(host))
    found = {}
    for record in records:
        if not affects_host(record['pattern'], host):
            continue
        pattern = record['pattern']
        if pattern not in expected:
            raise RouteError(f'Overlapping unmanaged route: {pattern} (ID {record["id"]})')
        if pattern in found:
            raise RouteError(f'Duplicate route pattern: {pattern}')
        if record['script'] != expected[pattern]:
            raise RouteError(f'Route ownership conflict: {pattern} (ID {record["id"]})')
        found[pattern] = record
    if require:
        missing = set(expected) - set(found)
        if missing:
            raise RouteError('Missing routes: ' + ', '.join(sorted(missing)))
    return found


def save(path, snapshot, create=False):
    data = (json.dumps(snapshot, indent=2, sort_keys=True) + '\n').encode()
    if create:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    else:
        temporary = str(path) + '.tmp'
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)


def snapshot_path(text):
    path = Path(text)
    if not path.is_absolute():
        raise RouteError('Snapshot path must be absolute')
    return path


def resolve_pending(api, path, snapshot):
    pending = snapshot.get('pending')
    if pending is None:
        return
    allowed = dict(patterns(snapshot['host']))
    if pending['pattern'] not in allowed or pending['script'] != allowed[pending['pattern']]:
        raise RouteError('Invalid pending route intent')
    live = inspect(api.routes(), snapshot['host'])
    after = live.get(pending['pattern'])
    if after is not None:
        if after['id'] in pending['existing_ids']:
            raise RouteError('Pending route ID conflicts with pre-write inventory')
        snapshot['changes'].append({'before': None, 'after': after, 'restored': False})
    snapshot['pending'] = None
    save(path, snapshot)


def restore(api, path, catchall_only=False):
    snapshot = json.loads(path.read_text())
    if snapshot.get('schema') != 1 or snapshot.get('zone_id') != api.zone or snapshot.get('host') not in HOSTS.values():
        raise RouteError('Snapshot schema, zone or host mismatch')
    resolve_pending(api, path, snapshot)
    host = snapshot['host']
    allowed = dict(patterns(host))
    records = {record['id']: record for record in api.routes()}
    changes = snapshot['changes']
    for change in changes:
        before, after = change['before'], change['after']
        if after['pattern'] not in allowed or after['script'] != allowed[after['pattern']]:
            raise RouteError('Snapshot contains an unmanaged post-value')
        if before is not None and (before['id'] != after['id'] or before['pattern'] != after['pattern'] or before['script'] != after['script']):
            raise RouteError('Snapshot contains unsupported pre-value')
        if change.get('restored'):
            expected = before
            actual = records.get(after['id'])
            if actual != expected:
                raise RouteError('Restored route drift: ' + after['pattern'])
        elif records.get(after['id']) != after:
            raise RouteError('Live route drift: ' + after['pattern'])
    # Restore static origin first. Exceptions remain until catch-all restoration
    # succeeds; do not expose backend namespaces to a still-active assets route.
    ordered = sorted(changes, key=lambda change: change['after']['pattern'] != host + '/*')
    for change in ordered:
        after, before = change['after'], change['before']
        if change.get('restored') or (catchall_only and after['pattern'] != host + '/*'):
            continue
        current = {record['id']: record for record in api.routes()}
        if current.get(after['id']) != after:
            raise RouteError('Route drift before restore write: ' + after['pattern'])
        if before is None:
            api.delete(after)
        else:
            api.put(after, before['pattern'], before['script'])
        change['restored'] = True
        save(path, snapshot)
    snapshot['status'] = 'catchall-restored' if catchall_only else 'restored'
    save(path, snapshot)


def apply(api, host, path):
    records = api.routes()
    found = inspect(records, host)
    snapshot = {'schema': 1, 'zone_id': api.zone, 'host': host,
                'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'existing_records': list(found.values()), 'changes': [], 'status': 'applying'}
    save(path, snapshot, create=True)
    switched = False
    switch_attempted = False
    try:
        for pattern, script in patterns(host):
            # Re-read ownership before every write, not just at startup.
            live = inspect(api.routes(), host)
            if script == WORKER:
                for exception, _ in patterns(host)[:-1]:
                    if exception not in live:
                        raise RouteError('Exception not confirmed before catch-all: ' + exception)
            if pattern in live:
                if live[pattern] != found.get(pattern):
                    raise RouteError('Route appeared or changed during apply: ' + pattern)
                continue
            snapshot['pending'] = {'pattern': pattern, 'script': script,
                                   'existing_ids': [record['id'] for record in api.routes()]}
            save(path, snapshot)
            if script == WORKER:
                switch_attempted = True
            after = api.put(None, pattern, script)
            snapshot['changes'].append({'before': None, 'after': after, 'restored': False})
            snapshot['pending'] = None
            save(path, snapshot)
            if script == WORKER:
                switched = True
            confirmed = inspect(api.routes(), host)
            if confirmed.get(pattern) != after:
                raise RouteError('Route write not confirmed: ' + pattern)
        inspect(api.routes(), host, require=True)
        snapshot['status'] = 'applied'
        save(path, snapshot)
    except BaseException:
        resolve_pending(api, path, snapshot)
        if switched or switch_attempted:
            restore(api, path, catchall_only=True)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('check')
    applying = commands.add_parser('apply')
    applying.add_argument('--host', choices=HOSTS, required=True)
    applying.add_argument('--snapshot', required=True)
    restoring = commands.add_parser('restore')
    restoring.add_argument('--snapshot', required=True)
    args = parser.parse_args(argv)
    try:
        api = API()
        if args.command == 'check':
            records = api.routes()
            for host in HOSTS.values():
                inspect(records, host, require=True)
            print('PASS: both static catch-alls and all no-script backend exceptions')
        elif args.command == 'apply':
            apply(api, HOSTS[args.host], snapshot_path(args.snapshot))
            print('PASS: exceptions confirmed before static switch for ' + HOSTS[args.host])
        else:
            restore(api, snapshot_path(args.snapshot))
            print('PASS: snapshot-owned routes restored')
        return 0
    except (RouteError, OSError, ValueError, KeyError, TypeError) as error:
        print('Cloudflare route operation failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
