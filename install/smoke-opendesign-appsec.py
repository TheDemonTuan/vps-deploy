#!/usr/bin/python3
"""Real native AppSec proof inside a mandatory fresh network namespace.

Only rule assets/configuration are copied. The fake LAPI has no decision store;
all addresses are namespace loopback and request IPs are documentation addresses.
Neither production credentials, databases nor notification bodies are copied.
"""
import base64
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

import yaml

sys.dont_write_bytecode = True
ETC = Path('/etc/crowdsec')
DATA = Path('/var/lib/crowdsec/data')


class SmokeFailure(Exception):
    pass


def require(ok, code):
    if not ok:
        raise SmokeFailure(code)


def port():
    with socket.socket() as value:
        value.bind(('127.0.0.1', 0))
        return value.getsockname()[1]


def get(url):
    with urllib.request.urlopen(url, timeout=2) as response:
        return response.read().decode()


def counters(text):
    result = {}
    for line in text.splitlines():
        match = re.fullmatch(r'(cs_appsec_[a-z_]+)(\{[^\n]*\})? ([0-9.eE+\-]+)', line)
        if match:
            result[(match[1], match[2] or '')] = float(match[3])
    return result


def total(values, name):
    return sum(value for (metric, _), value in values.items() if metric == name)


def rule_delta(before, after):
    ids = set()
    for (name, labels), value in after.items():
        if name == 'cs_appsec_rule_hits' and value > before.get((name, labels), 0):
            found = re.search(r'rule_name="(?:native_rule:)?([0-9]+)"', labels)
            if found:
                ids.add(int(found[1]))
            else:
                # Custom in-band matches must not disappear from the positive proof.
                ids.add(-1)
    return ids


class FakeLapi(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def answer(self, value):
        raw = json.dumps(value).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(raw)

    def do_HEAD(self):
        self.answer({})

    def do_GET(self):
        self.answer([])

    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
        if self.path.rstrip('/') == '/v1/watchers/login':
            encode = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
            token = encode({'alg': 'HS256', 'typ': 'JWT'}) + '.' + encode({'exp': int(time.time()) + 3600}) + '.c21va2U'
            self.answer({'token': token, 'expire': '2099-01-01T00:00:00Z'})
        else:
            self.answer([])

    def do_DELETE(self):
        self.send_error(405)


def clone(root, lapi_port, metrics_port, appsec_port, acquisition):
    clone = root / 'etc'
    clone.mkdir()
    # Dereference trusted hub symlinks to private bytes; no plugin or credential copy.
    for name in ('patterns', 'parsers', 'scenarios', 'postoverflows', 'appsec-configs', 'appsec-rules', 'collections', 'hub'):
        source = ETC / name
        if source.exists():
            shutil.copytree(source, clone / name, symlinks=False)
    for name in ('logs', 'data', 'notifications'):
        (root / name).mkdir()
    asset_suffixes = {'.mmdb', '.txt', '.json', '.data', '.regex', '.csv', '.conf'}
    sensitive_name = re.compile(r'(?:credential|identity|token|password|secret)', re.IGNORECASE)
    for source in DATA.iterdir():
        if source.is_file() and source.suffix in asset_suffixes and not sensitive_name.search(source.name):
            shutil.copy2(source, root / 'data' / source.name)
    # CRS seclang_files_rules includes plugin configuration/before/after rules.
    # Copy only this rule subtree, never arbitrary nested data/identity stores.
    plugins = DATA / 'crs-plugins'
    if plugins.is_dir():
        for source in plugins.rglob('*'):
            if source.is_file() and source.suffix in {'.conf', '.data', '.regex', '.txt', '.csv'} and not sensitive_name.search(source.name):
                destination = root / 'data' / source.relative_to(DATA)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
    credentials = clone / 'fixture-credentials.yaml'
    credentials.write_text(yaml.safe_dump({'url': 'http://127.0.0.1:' + str(lapi_port),
                                          'login': 'isolated-fixture', 'password': 'isolated-fixture'}))
    credentials.chmod(0o600)
    paths = {'config_dir': str(clone), 'data_dir': str(root / 'data'), 'hub_dir': str(clone / 'hub'),
             'index_path': str(clone / 'hub/.index.json'), 'notification_dir': str(root / 'notifications'),
             'plugin_dir': str(root / 'notifications')}
    # Reconstruct service configuration, never retain console/CTI/online/plugin settings.
    service = {'acquisition_path': str(clone / 'acquis.yaml'), 'acquisition_dir': str(clone / 'acquis.d'),
               'parser_routines': 1, 'buckets_routines': 1, 'output_routines': 1}
    (clone / 'acquis.d').mkdir()
    config = {'common': {'daemonize': False, 'log_media': 'file', 'log_dir': str(root / 'logs'), 'log_level': 'info'},
              'config_paths': paths, 'crowdsec_service': service,
              'db_config': {'type': 'sqlite', 'db_path': str(root / 'data/smoke.db'), 'use_wal': True},
              'api': {'client': {'credentials_path': str(credentials)}},
              'prometheus': {'enabled': True, 'level': 'full', 'listen_addr': '127.0.0.1', 'listen_port': metrics_port}}
    for name in ('profiles.yaml', 'simulation.yaml'):
        (clone / name).write_text('' if name == 'profiles.yaml' else 'simulation: false\n')
    acquisition = copy.deepcopy(acquisition)
    acquisition['listen_addr'] = '127.0.0.1:' + str(appsec_port)
    (clone / 'acquis.yaml').write_text(yaml.safe_dump(acquisition, sort_keys=False))
    (clone / 'config.yaml').write_text(yaml.safe_dump(config, sort_keys=False))
    return clone


def phase(root, acquisition, cases, policy, updated, inband=False):
    lapi_port, metrics_port, appsec_port = port(), port(), port()
    server = ThreadingHTTPServer(('127.0.0.1', lapi_port), FakeLapi)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    process = None
    try:
        cloned = clone(root, lapi_port, metrics_port, appsec_port, acquisition)
        target = cloned / 'appsec-configs/opendesign-crs-scope.yaml'
        target.unlink(missing_ok=True)
        if updated:
            target.write_bytes(policy)
            document = yaml.safe_load((cloned / 'acquis.yaml').read_bytes())
            document['appsec_configs'].append('local/opendesign-crs-scope')
            (cloned / 'acquis.yaml').write_text(yaml.safe_dump(document, sort_keys=False))
        if inband:
            matches = [path for path in (cloned / 'appsec-configs').iterdir()
                       if path.suffix in ('.yaml', '.yml') and yaml.safe_load(path.read_bytes()).get('name') == 'crowdsecurity/crs']
            require(len(matches) == 1, 'INBAND_CRS_CONFIG_MISSING')
            document = yaml.safe_load(matches[0].read_bytes())
            document['inband_rules'] = document.pop('outofband_rules')
            matches[0].write_text(yaml.safe_dump(document, sort_keys=False))
        argv = ['/usr/bin/crowdsec', '-c', str(cloned / 'config.yaml'), '-no-api', '-no-capi']
        check = subprocess.run(argv + ['-t'], capture_output=True, timeout=90)
        require(check.returncode == 0, 'SANDBOX_CONFIG_INVALID')
        with open(root / 'native-output.log', 'wb') as output:
            process = subprocess.Popen(argv, stdout=output, stderr=output)
            metrics_url = 'http://127.0.0.1:' + str(metrics_port) + '/metrics'
            until = time.monotonic() + 60
            while True:
                require(process.poll() is None, 'SANDBOX_EXITED')
                try:
                    before = counters(get(metrics_url))
                    with socket.create_connection(('127.0.0.1', appsec_port), timeout=1):
                        break
                except (OSError, urllib.error.URLError):
                    require(time.monotonic() < until, 'SANDBOX_NOT_READY')
                    time.sleep(0.1)
            def send(case):
                headers = {'X-Crowdsec-Appsec-Ip': '192.0.2.123', 'X-Crowdsec-Appsec-Uri': case['path'],
                           'X-Crowdsec-Appsec-Host': case['host'], 'X-Crowdsec-Appsec-Verb': case['method'],
                           'X-Crowdsec-Appsec-Api-Key': 'isolated-fixture', 'X-Crowdsec-Appsec-Http-Version': 'HTTP/1.1',
                           'X-Crowdsec-Appsec-User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0.0.0 Safari/537.36',
                           'Content-Type': case.get('content_type', 'application/json'),
                           'Accept': 'application/json'}
                request = urllib.request.Request('http://127.0.0.1:' + str(appsec_port) + '/',
                                                 data=case['body'].encode(), headers=headers, method='POST')
                try:
                    response = urllib.request.urlopen(request, timeout=10)
                except urllib.error.HTTPError as exc:
                    response = exc
                with response:
                    return json.load(response)
            results = []
            completion_metric = ('cs_appsec_inband_parsing_time_seconds_count' if inband else
                                 'cs_appsec_outband_parsing_time_seconds_count')
            barrier = {'host': 'design.tuannguyenviet.site', 'method': 'GET', 'path': '/api/app-config',
                       'body': '', 'content_type': 'application/json'}
            for case in cases:
                before = counters(get(metrics_url))
                answer = send(case)
                # Acquisition routines is pinned to one. Receiving the following
                # clean GET's inband response serializes after the previous complete
                # handler, including its async outband event/rule-hit accumulation.
                require(send(barrier).get('action') == 'allow', 'SANDBOX_BARRIER_DENIED')
                until = time.monotonic() + 10
                while True:
                    after = counters(get(metrics_url))
                    if total(after, completion_metric) >= total(before, completion_metric) + 2:
                        break
                    require(time.monotonic() < until and process.poll() is None, 'SANDBOX_REQUEST_INCOMPLETE')
                    time.sleep(0.05)
                ids = rule_delta(before, after)
                expected = case['expected_rule_ids'] if updated else case.get('baseline_rule_ids', case['expected_rule_ids'])
                require(set(expected) <= ids, 'SMOKE_EXPECTED_RULE_MISSING')
                if updated:
                    require(not set(case['forbidden_rule_ids']) & ids, 'SMOKE_SCOPE_BOUNDARY_FAILED')
                    if not expected:
                        require(not ids and answer.get('action') == 'allow', 'SMOKE_LEGITIMATE_DENIED')
                results.append({'name': case['name'], 'rule_ids': sorted(ids), 'pass': True})
            return results
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main(argv):
    try:
        require(len(argv) == 2 and os.geteuid() == 0, 'SMOKE_ARGUMENTS_INVALID')
        require(os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net'), 'NETWORK_ISOLATION_REQUIRED')
        subprocess.run(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'], capture_output=True, check=True, timeout=5)
        platform, root = map(Path, argv)
        acquisition = yaml.safe_load((root / 'baseline-acquisition.yaml').read_bytes())
        acquisition['appsec_configs'] = [name for name in acquisition['appsec_configs'] if name != 'local/opendesign-crs-scope']
        policy = (platform / 'security/crowdsec/opendesign-crs-scope.yaml').read_bytes()
        cases = json.loads((platform / 'security/crowdsec/opendesign-scope-smoke.json').read_bytes())['cases']
        for updated in (False, True):
            directory = root / ('candidate' if updated else 'baseline')
            directory.mkdir(mode=0o700)
            phase(directory, acquisition, cases, policy, updated)
        contracts = json.loads((platform / 'security/crowdsec/opendesign-scope-smoke.json').read_bytes())['scope']['contracts']
        inband_cases = [dict(next(case for case in cases if case['name'] == 'legitimate-' + contract['name']),
                              expected_rule_ids=[911100], forbidden_rule_ids=[])
                        for contract in contracts]
        directory = root / 'inband'
        directory.mkdir(mode=0o700)
        phase(directory, acquisition, inband_cases, policy, True, inband=True)
        print(json.dumps({'runtime_boundary_pass': True, 'legitimate_pass': True, 'negative_controls_pass': True}), flush=True)
        return 0
    except Exception as exc:
        code = str(exc) if isinstance(exc, SmokeFailure) else 'SANDBOX_IO_ERROR'
        print(json.dumps({'error_code': code}), flush=True)
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
