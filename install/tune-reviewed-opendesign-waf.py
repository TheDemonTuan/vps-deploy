#!/usr/bin/python3
"""Stdin-only reviewed mutation of exactly two fixed CrowdSec configuration files."""
import base64
import fnmatch
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.dont_write_bytecode = True
BASE = Path('/opt/vps-deploy')
ETC = Path('/etc/crowdsec')
ACQUISITION = ETC / 'acquis.d/appsec.yaml'
POLICY = ETC / 'appsec-configs/opendesign-crs-scope.yaml'
LOCKS = Path('/run/lock/vps-deploy')
CONFIG_NAME = 'local/opendesign-crs-scope'
ORDER = ['crowdsecurity/appsec-default', 'crowdsecurity/crs', 'crowdsecurity/appsec-bot-*',
         'local/body-scope', 'local/beszel-crs-scope', 'local/transactions-crs-scope', 'local/bot-scope']
SHA = re.compile(r'[0-9a-f]{40}\Z')


class Failure(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(ok, code):
    if not ok:
        raise Failure(code)


def secure_path(path, directory=False):
    for entry in (*reversed(path.parents), path):
        value = entry.lstat()
        require(value.st_uid == 0 and not value.st_mode & 0o022 and
                (stat.S_ISDIR(value.st_mode) if entry != path or directory else stat.S_ISREG(value.st_mode)), 'UNTRUSTED_PATH')
    return path


def checkout(destination, repository, ref):
    for argv in (['/usr/bin/git', 'init', '--quiet', str(destination)],
                 ['/usr/bin/git', '-C', str(destination), 'fetch', '--quiet', '--no-tags', '--depth=1',
                  'https://github.com/' + repository + '.git', ref],
                 ['/usr/bin/git', '-C', str(destination), 'checkout', '--quiet', '--detach', ref]):
        require(subprocess.run(argv, capture_output=True, timeout=180).returncode == 0, 'FETCH_FAILED')
    head = subprocess.run(['/usr/bin/git', '-C', str(destination), 'rev-parse', 'HEAD'], capture_output=True, timeout=30)
    clean = subprocess.run(['/usr/bin/git', '-C', str(destination), 'status', '--porcelain', '--untracked-files=all'],
                           capture_output=True, timeout=30)
    require(head.returncode == clean.returncode == 0 and head.stdout.strip().decode() == ref and not clean.stdout,
            'CHECKOUT_NOT_REVIEWED')


def load_yaml(raw):
    import yaml
    class UniqueLoader(yaml.SafeLoader):
        pass
    def mapping(loader, node, deep=False):
        pairs = loader.construct_pairs(node, deep=deep)
        keys = [key for key, _ in pairs]
        require(len(set(keys)) == len(keys), 'DUPLICATE_YAML_KEY')
        return dict(pairs)
    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    return yaml.load(raw, Loader=UniqueLoader)


def acquisition_candidate(raw):
    """Append a block list entry without rewriting any existing settings/comments."""
    value = load_yaml(raw)
    require(type(value) is dict and value.get('source') == 'appsec' and
            value.get('listen_addr') == '172.31.254.1:7422' and value.get('routines') == 1 and
            value.get('name') == 'traefikAppSec' and value.get('labels') == {'type': 'appsec'}, 'UNEXPECTED_ACQUISITION')
    configs = value.get('appsec_configs')
    require(configs in (ORDER, ORDER + [CONFIG_NAME]), 'UNEXPECTED_POLICY_ORDER')
    if configs == ORDER + [CONFIG_NAME]:
        return raw
    # Require the observed block-list shape rather than guessing at another YAML representation.
    lines = raw.decode().splitlines(keepends=True)
    starts = [index for index, line in enumerate(lines) if line.rstrip('\r\n') == 'appsec_configs:']
    require(len(starts) == 1, 'UNEXPECTED_ACQUISITION_FORMAT')
    index = starts[0] + 1
    for name in ORDER:
        require(index < len(lines) and lines[index].rstrip('\r\n') == '  - ' + name, 'UNEXPECTED_ACQUISITION_FORMAT')
        index += 1
    lines.insert(index, '  - ' + CONFIG_NAME + '\n')
    candidate = ''.join(lines).encode()
    changed = load_yaml(candidate)
    expected = dict(value, appsec_configs=ORDER + [CONFIG_NAME])
    require(changed == expected, 'ACQUISITION_SETTINGS_CHANGED')
    return candidate


def trusted_asset(path):
    # Installed hub configs commonly are symlinks. Both the link and resolved target
    # must remain in root-owned, non-writable CrowdSec configuration trees.
    if path.is_symlink():
        secure_path(path.parent, directory=True)
        require(path.lstat().st_uid == 0, 'UNTRUSTED_PATH')
        resolved = path.resolve(strict=True)
        require(resolved.is_relative_to(ETC), 'EXTERNAL_SECURITY_SYMLINK')
        return secure_path(resolved)
    return secure_path(path)


def policy_baseline(platform, policy):
    expected = json.loads((platform / 'security/crowdsec/oracle-main-appsec-baseline.json').read_bytes())
    actual = {}
    for path in sorted((ETC / 'appsec-configs').iterdir()):
        if path.suffix not in ('.yaml', '.yml'):
            continue
        raw = trusted_asset(path).read_bytes()
        doc = load_yaml(raw)
        require(type(doc) is dict and type(doc.get('name')) is str, 'INVALID_LOADED_POLICY')
        name = doc['name']
        if not any(fnmatch.fnmatchcase(name, pattern) for pattern in ORDER + [CONFIG_NAME]):
            continue
        require(name not in actual, 'DUPLICATE_LOADED_POLICY')
        if name == CONFIG_NAME:
            require(path == POLICY and raw == policy, 'POLICY_MODIFIED')
            continue
        actual[name] = hashlib.sha256(raw).hexdigest()
    require(actual == expected, 'LOADED_POLICY_CHANGED')


def security_snapshot():
    result = {}
    secure_path(ETC, directory=True)
    for path in sorted(ETC.rglob('*')):
        if path in (ACQUISITION, POLICY):
            continue
        if path.is_dir() and not path.is_symlink():
            secure_path(path, directory=True)
            continue
        target = trusted_asset(path)
        meta = path.lstat()
        result[str(path.relative_to(ETC))] = (hashlib.sha256(target.read_bytes()).digest(),
                                              meta.st_uid, meta.st_gid, stat.S_IMODE(meta.st_mode),
                                              os.readlink(path) if path.is_symlink() else None)
    return result


def file_snapshot(path):
    if not path.exists():
        require(not path.is_symlink(), 'UNTRUSTED_PATH')
        secure_path(path.parent, directory=True)
        return None
    value = secure_path(path).stat()
    require(value.st_uid == value.st_gid == 0, 'UNTRUSTED_PATH')
    return (path.read_bytes(), stat.S_IMODE(value.st_mode), value.st_uid, value.st_gid)


def atomic_file(path, snapshot):
    secure_path(path.parent, directory=True)
    if path.exists() or path.is_symlink():
        secure_path(path)
    if snapshot is None:
        path.unlink(missing_ok=True)
    else:
        raw, mode, uid, gid = snapshot
        fd, name = tempfile.mkstemp(prefix='.reviewed-waf-', dir=path.parent)
        try:
            os.fchmod(fd, mode)
            os.fchown(fd, uid, gid)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, path)
        finally:
            Path(name).unlink(missing_ok=True)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def crowdsec_validate():
    require(subprocess.run(['/usr/bin/crowdsec', '-c', str(ETC / 'config.yaml'), '-t'],
                           capture_output=True, timeout=90).returncode == 0, 'CROWDSEC_CONFIG_INVALID')


def readiness():
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        active = subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet', 'crowdsec.service'],
                                capture_output=True, timeout=10).returncode == 0
        try:
            identity = subprocess.run(['/usr/bin/systemctl', 'show', '--property=MainPID', '--value', 'crowdsec.service'],
                                      capture_output=True, timeout=10)
            pid = identity.stdout.strip().decode('ascii')
            require(identity.returncode == 0 and pid.isdecimal() and int(pid) > 0, 'CROWDSEC_PROCESS_INVALID')
            arguments = (Path('/proc') / pid / 'cmdline').read_bytes().split(b'\0')
            require(arguments[0] == b'/usr/bin/crowdsec' and b'-c' in arguments and
                    arguments[arguments.index(b'-c') + 1] == b'/etc/crowdsec/config.yaml' and
                    not any(argument in (b'-no-api', b'-no-capi', b'-t') for argument in arguments),
                    'CROWDSEC_PROCESS_INVALID')
            with urllib.request.urlopen('http://127.0.0.1:6060/metrics', timeout=2) as response:
                metrics = response.read().decode()
            # A listening native AppSec datasource is required, not merely an active unit.
            import socket
            with socket.create_connection(('172.31.254.1', 7422), timeout=2):
                pass
            if active and 'cs_' in metrics:
                return
        except OSError:
            pass
        time.sleep(0.25)
    raise Failure('CROWDSEC_NOT_READY')


def restart():
    require(subprocess.run(['/usr/bin/systemctl', 'restart', 'crowdsec.service'],
                           capture_output=True, timeout=90).returncode == 0, 'CROWDSEC_RESTART_FAILED')
    readiness()


def apply_transaction(originals, candidates, postcheck):
    touched = False
    try:
        for path, snapshot in candidates.items():
            if snapshot != originals[path]:
                touched = True
                atomic_file(path, snapshot)
        crowdsec_validate()
        if touched:
            restart()
        else:
            readiness()
        postcheck()
    except Exception:
        if touched:
            try:
                for path, snapshot in originals.items():
                    atomic_file(path, snapshot)
                crowdsec_validate()
                restart()
            except Exception:
                raise Failure('WAF_ROLLBACK_FAILED') from None
        raise


def tune(platform_ref, app_ref, public_key):
    stage, staging = 'preflight', None
    try:
        require(os.geteuid() == 0 and os.uname().sysname == 'Linux', 'ROOT_REQUIRED')
        require(type(platform_ref) is str and SHA.fullmatch(platform_ref) and
                type(app_ref) is str and SHA.fullmatch(app_ref), 'INVALID_SHA')
        secure_path(BASE, directory=True)
        staging = Path(tempfile.mkdtemp(prefix='.reviewed-waf-', dir=BASE))
        staging.chmod(0o700)
        platform, app = staging / 'platform', staging / 'app'
        stage = 'fetch'
        checkout(platform, 'TheDemonTuan/vps-deploy', platform_ref)
        checkout(app, 'TheDemonTuan/open-design', app_ref)
        spec = importlib.util.spec_from_file_location('reviewed_activation', platform / 'install/activate-reviewed-release.py')
        helpers = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helpers)
        stage = 'validation'
        helpers.enrolled_key(public_key, staging / 'deploy.pub')
        registration, host = helpers.validate_checkout(platform, app, app_ref)
        import core
        core.trusted_path(LOCKS, directory=True)
        with core.lock(LOCKS / 'opendesign@submit.lock', 10), core.lock(LOCKS / 'opendesign@operation.lock'), core.lock(LOCKS / 'crowdsec-security.lock', 60):
            profile = helpers.enrolled()
            before = helpers.snapshot(profile, registration, host)
            security = security_snapshot()
            originals = {ACQUISITION: file_snapshot(ACQUISITION), POLICY: file_snapshot(POLICY)}
            require(originals[ACQUISITION] is not None, 'MISSING_ACQUISITION')
            policy = (platform / 'security/crowdsec/opendesign-crs-scope.yaml').read_bytes()
            require(load_yaml(policy).get('name') == CONFIG_NAME, 'INVALID_REVIEWED_POLICY')
            acquisition = acquisition_candidate(originals[ACQUISITION][0])
            require(originals[POLICY] is None or originals[POLICY][0] == policy, 'POLICY_MODIFIED')
            policy_baseline(platform, policy)
            # Back up only the two owned files. All other security bytes stay in place.
            for index, snapshot in enumerate(originals.values()):
                if snapshot is not None:
                    backup = staging / ('backup-' + str(index))
                    backup.write_bytes(snapshot[0])
                    backup.chmod(0o600)
            stage = 'native_smoke'
            (staging / 'baseline-acquisition.yaml').write_bytes(originals[ACQUISITION][0])
            crowdsec_validate()
            smoke = subprocess.run(['/usr/bin/unshare', '--net', '--', '/usr/bin/python3',
                                    str(platform / 'install/smoke-opendesign-appsec.py'), str(platform), str(staging)],
                                   capture_output=True, timeout=480)
            if smoke.returncode:
                try:
                    code = json.loads(smoke.stdout)['error_code']
                except (ValueError, KeyError, TypeError):
                    code = 'NATIVE_APPSEC_SMOKE_FAILED'
                require(type(code) is str and re.fullmatch(r'[A-Z_]{1,64}', code), 'NATIVE_APPSEC_SMOKE_FAILED')
                raise Failure(code)
            proof = json.loads(smoke.stdout)
            require(proof == {'runtime_boundary_pass': True, 'legitimate_pass': True, 'negative_controls_pass': True},
                    'NATIVE_APPSEC_PROOF_INVALID')
            def invariants():
                require(security_snapshot() == security, 'SECURITY_CONFIG_CHANGED')
                require(helpers.enrolled() == profile and helpers.snapshot(profile, registration, host) == before,
                        'APPLICATION_CHANGED')
            invariants()
            require(all(file_snapshot(path) == value for path, value in originals.items()), 'WAF_CONFIG_DRIFT')
            candidates = {ACQUISITION: (acquisition, *originals[ACQUISITION][1:]),
                          POLICY: originals[POLICY] or (policy, 0o600, 0, 0)}
            def postcheck():
                invariants()
                require(all(file_snapshot(path) == value for path, value in candidates.items()), 'WAF_CONFIG_DRIFT')
                policy_baseline(platform, policy)
            stage = 'apply'
            apply_transaction(originals, candidates, postcheck)
            return {'app': 'opendesign', 'host': 'oracle-main', 'platform_ref': platform_ref, 'app_ref': app_ref,
                    'rule_id': 911100, 'policy_name': CONFIG_NAME, 'healthy': True, **proof,
                    'security_retained': True, 'profile_unchanged': True, 'container_unchanged': True,
                    'runtime_env_unchanged': True}
    except Exception as exc:
        code = getattr(exc, 'code', 'WAF_TUNE_IO_ERROR')
        if not isinstance(code, str) or not re.fullmatch(r'[A-Z_]{1,64}', code):
            code = 'WAF_TUNE_IO_ERROR'
        raise Failure(stage + ':' + code) from None
    finally:
        if staging is not None:
            shutil.rmtree(staging)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        require(len(argv) == 3, 'INVALID_ARGUMENTS')
        receipt = tune(argv[0], argv[1], base64.b64decode(argv[2], validate=True))
        print(json.dumps(receipt, sort_keys=True), flush=True)
        return 0
    except Exception as exc:
        code = exc.code if isinstance(exc, Failure) else 'WAF_TUNE_IO_ERROR'
        stage, separator, error = code.partition(':')
        if not separator:
            stage, error = 'preflight', code
        print(json.dumps({'stage': stage, 'error_code': error}), flush=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
