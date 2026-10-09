#!/usr/bin/env python3
"""Real Docker/systemd Penpot proof on an empty GitHub-hosted ARM64 VM only.

Never run on production. Fixture releases retain the source image closure and
change OCI configuration labels only, except the explicitly failing migration.
All diagnostics pass through the redactor before leaving private VM storage.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import time
import urllib.parse
import uuid
import zipfile

import yaml

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'tests/integration/fixtures/penpot'
ROLES = ('frontend', 'backend', 'exporter', 'mcp')
REGISTRY = 'registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373'
HOST = 'design.tuannguyenviet.site'
CFG = Path('/etc/vps-deploy/apps/penpot')
STATE = Path('/var/lib/vps-deploy/apps/penpot')
EDGE = Path('/opt/platform/edge')
WORK = Path('/opt/penpot')


class HarnessFailure(Exception):
    pass


def require(ok, code):
    if not ok:
        raise HarnessFailure(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class Harness:
    def __init__(self):
        self.env = os.environ.copy()
        self.sha = self.env.get('PENPOT_APP_REF', '')
        self.platform = self.env.get('PENPOT_PLATFORM_REF', '')
        self.report = Path(self.env.get('PENPOT_CI_REPORT_DIR', '/nonexistent'))
        self.scope = 'penpot-ci-' + uuid.uuid4().hex
        self.private = Path('/opt') / self.scope
        self.containers, self.networks, self.volumes, self.units = [], [], [], []
        self.paths, self.images, self.secret_values = [], [], []
        self.original_hosts = None
        self.user_created = False
        self.install_attempted = False
        self.sshd = None
        self.sequence = 0
        self.logs = []
        self.foreign_containers, self.foreign_volumes, self.foreign_networks = {}, {}, {}
        self.result = dict(schemaVersion=1, sourceSha=self.sha, platformRef=self.platform,
                           runId=self.env.get('GITHUB_RUN_ID', ''),
                           runAttempt=self.env.get('GITHUB_RUN_ATTEMPT', ''),
                           platform='linux/arm64', status='failed', cases=[],
                           sourceImages={}, fixtureImages={})

    def redact(self, data):
        text = data.decode('utf-8', 'replace') if isinstance(data, bytes) else str(data)
        for value in self.secret_values:
            text = text.replace(value, '[REDACTED]').replace(urllib.parse.quote(value, safe=''), '[REDACTED]')
        text = re.sub(r'((?:https?|wss?)://[^\s"<>?#]+)[?#][^\s"<>]*', r'\1', text)
        text = re.sub(r'(/[^\s"<>?#]*)[?#][^\s"<>]*', r'\1', text)
        text = re.sub(r'(?i)((?:userToken|access_token|token|authorization|password|secret|PENPOT_DB_PASSWORD|PENPOT_SECRET_KEY)\s*[=:]\s*)[^\s,;"}]+', r'\1[REDACTED]', text)
        return text

    def log(self, text):
        self.logs.append(self.redact(text)[:65536])

    def run(self, *args, data=None, timeout=60, check=True, env=None):
        try:
            process = subprocess.run([str(a) for a in args], input=data, capture_output=True,
                                     timeout=timeout, env=env)
        except (OSError, subprocess.TimeoutExpired):
            raise HarnessFailure('NATIVE_COMMAND_UNAVAILABLE_OR_TIMEOUT') from None
        if process.returncode and check:
            self.log(process.stderr)
            raise HarnessFailure('NATIVE_COMMAND_FAILED_' + Path(str(args[0])).name.upper().replace('-', '_'))
        return process

    def docker(self, *args, **kwargs):
        return self.run('/usr/bin/docker', *args, **kwargs)

    def inspect(self, kind, name):
        return json.loads(self.docker(kind, 'inspect', name).stdout)[0]

    def put(self, path, data, mode=0o600):
        path = Path(path)
        require(not path.is_symlink(), 'FIXTURE_SYMLINK')
        path.write_bytes(data if isinstance(data, bytes) else data.encode())
        path.chmod(mode)

    def mkdir(self, path, mode=0o700):
        path = Path(path)
        if not path.exists():
            self.mkdir(path.parent, 0o755)
            path.mkdir(mode=mode)
            self.paths.append(path)
        require(path.is_dir() and not path.is_symlink() and path.stat().st_uid == 0,
                'FIXTURE_UNTRUSTED_DIRECTORY')

    def json(self, *args, **kwargs):
        return json.loads(self.run(*args, **kwargs).stdout)

    def guard(self):
        require(os.geteuid() == 0 and all(self.env.get(k) == v for k, v in
                {'CI':'true','GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted',
                 'PENPOT_DISPOSABLE_VM':'1'}.items()), 'HOSTED_DISPOSABLE_ROOT_REQUIRED')
        require(os.uname().sysname == 'Linux' and os.uname().machine == 'aarch64', 'NATIVE_ARM64_REQUIRED')
        require(Path('/proc/1/comm').read_text().strip() == 'systemd', 'SYSTEMD_PID1_REQUIRED')
        require(all(re.fullmatch('[0-9a-f]{40}', v) for v in (self.sha, self.platform)), 'EXACT_SHA_REQUIRED')
        require(all(re.fullmatch('[1-9][0-9]*', self.env.get(k, '')) for k in
                    ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')), 'RUN_ID_REQUIRED')
        self.app = Path(self.env.get('PENPOT_CI_APP_DIR', '/nonexistent')).resolve()
        require(self.app.is_dir() and self.app != ROOT and ROOT not in self.app.parents, 'SOURCE_CHECKOUT_REQUIRED')
        for path, expected in ((self.app, self.sha), (ROOT, self.platform)):
            actual = self.run('git', '-c', 'safe.directory='+str(path), '-C', path, 'rev-parse', 'HEAD').stdout.decode().strip()
            require(actual == expected, 'CHECKOUT_SHA_MISMATCH')
            require(not self.run('git', '-c', 'safe.directory='+str(path), '-C', path, 'status', '--porcelain', '--untracked-files=all').stdout,
                    'CHECKOUT_DIRTY')
        self.env.update(NO_PROXY='127.0.0.1,localhost,'+HOST)
        for key in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy'):
            self.env.pop(key, None)
            os.environ.pop(key, None)
        os.environ['NO_PROXY'] = self.env['NO_PROXY']
        require(self.docker('info', '--format', '{{.Architecture}}').stdout.strip() in (b'aarch64', b'arm64'), 'NATIVE_DOCKER_REQUIRED')
        for path in ('/etc/vps-deploy/fixture-ci','/etc/vps-deploy/apps','/var/lib/vps-deploy/apps',
                     '/opt/platform','/opt/penpot','/opt/9router','/opt/vps-deploy/current',
                     '/usr/local/libexec/vps-deploy-penpot','/etc/sudoers.d/vps-deploy-penpot',
                     '/etc/systemd/system/vps-deploy-drain@.service','/etc/systemd/system/vps-deploy-drain@.timer',
                     '/etc/systemd/system/vps-deploy-penpot-backup.service','/etc/systemd/system/vps-deploy-penpot-backup.timer'):
            require(not os.path.lexists(path), 'OCCUPIED_PRODUCTION_PATH')
        require(not os.path.lexists(Path('/opt/vps-deploy/releases')/self.platform), 'OCCUPIED_RELEASE')
        # setup-buildx-action leaves its Docker-container builder/cache behind.
        # Reject deployment/fixture resources, not unrelated build infrastructure.
        reserved=re.compile(r'^(?:penpot(?:[-_]|$)|9router(?:[-_]|$)|opendesign(?:[-_]|$)|acb(?:[-_]|$)|edge-)')
        for identity in self.docker('ps','-aq').stdout.decode().splitlines():
            value=self.inspect('container',identity)
            name=value['Name'].lstrip('/')
            labels=value.get('Config',{}).get('Labels') or {}
            require(not reserved.match(name) and not labels.get('vps-deploy.app') and
                    not labels.get('penpot.ci.scope'), 'OCCUPIED_PRODUCTION_OR_FIXTURE_CONTAINER')
            self.foreign_containers[name]=(value['Id'],value['Image'],value['State']['Running'])
        for name in self.docker('volume','ls','-q').stdout.decode().splitlines():
            value=self.inspect('volume',name)
            labels=value.get('Labels') or {}
            require(not reserved.match(name) and not labels.get('vps-deploy.app') and
                    not labels.get('penpot.ci.scope'), 'OCCUPIED_PRODUCTION_OR_FIXTURE_VOLUME')
            self.foreign_volumes[name]=self.volume_identity(value)
        for identity in self.docker('network','ls','-q').stdout.decode().splitlines():
            value=self.inspect('network',identity)
            labels=value.get('Labels') or {}
            require(not reserved.match(value['Name']) and not labels.get('vps-deploy.app') and
                    not labels.get('penpot.ci.scope'), 'OCCUPIED_PRODUCTION_OR_FIXTURE_NETWORK')
            self.foreign_networks[value['Name']]=value['Id']
        require(self.run('getent', 'passwd', 'deploy-penpot', check=False).returncode != 0, 'OCCUPIED_DEPLOY_ACCOUNT')
        for name in ('edge-penpot','penpot_penpot','penpot-egress','penpot-ci-tunnel'):
            require(self.docker('network', 'inspect', name, check=False).returncode != 0, 'OCCUPIED_NETWORK')
        for port in (443,5000,18080,22222):
            with socket.socket() as listener:
                try:
                    listener.bind(('127.0.0.1',port))
                except OSError:
                    raise HarnessFailure('OCCUPIED_FIXTURE_PORT') from None
        self.run('systemctl', 'show-environment')
        probe = self.scope+'-probe'
        self.units.append(probe)
        self.run('systemd-run', '--unit='+probe, '--property=Type=exec', '--property=RuntimeMaxSec=10',
                 '--wait', '/usr/bin/true')

    @staticmethod
    def volume_identity(value):
        return {key:value.get(key) for key in ('Name','Driver','Mountpoint','Options','Labels','Scope','CreatedAt')}

    def preserve_foreign(self):
        for name,identity in self.foreign_containers.items():
            value=self.inspect('container',name)
            require((value['Id'],value['Image'],value['State']['Running'])==identity,
                    'PREEXISTING_FOREIGN_CONTAINER_MUTATED')
        for name,identity in self.foreign_volumes.items():
            require(self.volume_identity(self.inspect('volume',name))==identity,
                    'PREEXISTING_FOREIGN_VOLUME_MUTATED')
        for name,identity in self.foreign_networks.items():
            require(self.inspect('network',name)['Id']==identity, 'PREEXISTING_FOREIGN_NETWORK_MUTATED')
        return {'containers':len(self.foreign_containers),'volumes':len(self.foreign_volumes),
                'networks':len(self.foreign_networks),'preserved':True}

    def case(self, name, action):
        case = dict(name=name, status='failed', evidence={})
        self.result['cases'].append(case)
        try:
            case['evidence'] = action() or {}
            case['status'] = 'passed'
            self.log(name+': passed')
        except Exception as error:
            case['errorCode'] = getattr(error, 'code', str(error) if isinstance(error, HarnessFailure) else type(error).__name__)
            self.log(name+': '+case['errorCode'])
            raise

    def setup(self):
        for path in (self.private, CFG, STATE, STATE/'requests', WORK, EDGE/'dynamic', EDGE/'cloudflare-ca',
                     Path('/opt/vps-deploy/releases'), Path('/run/lock/vps-deploy')):
            self.mkdir(path)
        self.put('/etc/vps-deploy/fixture-ci', '')
        self.paths.append(Path('/etc/vps-deploy/fixture-ci'))
        self.release_source = self.private/'platform'
        self.release_source.mkdir(mode=0o755)
        for area in ('bin','lib','apps','schema','install','registry','hosts'):
            shutil.copytree(ROOT/area, self.release_source/area, ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        for path in (self.release_source, *self.release_source.rglob('*')):
            path.chmod(stat.S_IMODE(path.stat().st_mode) & ~0o022)
        registry = yaml.safe_load((self.release_source/'registry/penpot.yml').read_bytes())
        registry['host'] = 'fixture-local'
        registry['manifest']['images'] = {role:'localhost:5000/penpot-'+role for role in ROLES}
        self.put(self.release_source/'registry/penpot.yml', yaml.safe_dump(registry,sort_keys=False),0o644)
        self.fixture_source = self.private/'source'
        (self.fixture_source/'.deploy').mkdir(parents=True,mode=0o700)
        raw = yaml.safe_dump(registry['manifest'],sort_keys=False).encode()
        self.put(self.fixture_source/'.deploy/app.yml',raw)
        self.run('git','-C',self.fixture_source,'init','-q')
        self.run('git','-C',self.fixture_source,'add','.deploy/app.yml')
        self.run('git','-C',self.fixture_source,'-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
                 'commit','-qm','test: immutable Penpot fixture manifest')
        self.f = self.run('git','-C',self.fixture_source,'rev-parse','HEAD').stdout.decode().strip()
        self.manifest = digest(raw)
        self.put(CFG/'app.yml',raw)
        self.secret_values += [secrets.token_urlsafe(48),secrets.token_hex(32)]
        runtime = 'PENPOT_SECRET_KEY='+self.secret_values[0]+'\nPENPOT_DB_PASSWORD='+self.secret_values[1]+'\n'
        self.put(WORK/'.env',runtime)
        self.put(CFG/'runtime.env',runtime)
        self.run('ssh-keygen','-q','-t','ed25519','-N','','-f',self.private/'key')
        self.run('ssh-keygen','-q','-t','ed25519','-N','','-f',self.private/'hostkey')
        key = (self.private/'hostkey.pub').read_text().split()
        fingerprint = self.run('ssh-keygen','-lf',self.private/'hostkey.pub').stdout.decode().split()[1]
        inventory = yaml.safe_load((self.release_source/'hosts/oracle-main.yml').read_bytes())
        inventory.update(host='fixture-local',ssh=dict(address='127.0.0.1',port=22222,
                         host_key=' '.join(key[:2]),fingerprint=fingerprint))
        inventory['apps'] = {'penpot':inventory['apps']['penpot']}
        self.put(self.release_source/'hosts/fixture-local.yml',yaml.safe_dump(inventory,sort_keys=False),0o644)
        # host.json describes an enrolled baseline, so its release must exist
        # before installer --check validates the previous installation.
        self.baseline_release = Path('/opt/vps-deploy/releases') / self.f
        require(not self.baseline_release.exists(), 'OCCUPIED_FIXTURE_RELEASE')
        shutil.copytree(self.release_source, self.baseline_release)
        self.put(CFG/'host.json',json.dumps(dict(inventory['apps']['penpot'],platform_ref=self.f,
                 dynamic_dir=str(EDGE/'dynamic'),fixture_ci=True,image_repositories=registry['manifest']['images'],
                 architecture='arm64',ca_bundle=str(EDGE/'cloudflare-ca/origin-ca.pem'),fault_file=str(WORK/'fault'))))
        self.registry = registry
        self.create_container('penpot-ci-registry','-p','127.0.0.1:5000:5000',REGISTRY)
        self.wait(lambda:self.run('curl','--noproxy','*','-fsS','http://localhost:5000/v2/',check=False).returncode==0)
        self.make_variants()
        source_smoke=module('fixture_smoke_inventory',self.app/'.deploy/smoke-stack.py')
        for ref in source_smoke.STORES.values():
            if self.docker('image','inspect',ref,check=False).returncode:
                self.docker('pull',ref,timeout=300)
        self.tls()
        for volume in ('penpot_postgres_v15','penpot_assets'):
            self.docker('volume','create','--label','vps-deploy.app=penpot','--label','penpot.ci.scope='+self.scope,volume)
            self.volumes.append(volume)
        self.docker('network','create','--internal','--label','vps-deploy.app=penpot',
                    '--label','penpot.ci.scope='+self.scope,'edge-penpot')
        self.networks.append('edge-penpot')
        self.docker('network','connect','edge-penpot','edge-traefik')
        compose_env = dict(self.env,**{'PENPOT_'+role.upper()+'_IMAGE':ref for role,ref in self.maps['old'].items()})
        self.containers += ['penpot-'+role for role in ROLES]+['penpot-postgres','penpot-valkey']
        self.networks += ['penpot_penpot','penpot-egress']
        self.docker('compose','--env-file',WORK/'.env','-p','penpot','-f',self.release_source/'apps/penpot/docker-compose.prod.yml',
                    'up','-d','--pull','never','--wait','--wait-timeout','180',env=compose_env,timeout=300)
        self.generation = uuid.uuid4().hex
        route = self.run('bash',self.release_source/'apps/penpot/adapter.sh','single',self.generation,'','',HOST).stdout
        self.put(EDGE/'dynamic/penpot.yml',route,0o644)
        self.wait(lambda:self.run('curl','--cacert',EDGE/'cloudflare-ca/origin-ca.pem','-fsS','https://'+HOST+'/readyz',check=False).stdout.strip()==b'OK')
        self.install()
        self.seed()
        self.foreign_setup()
        return {'fixtureSourceSha':self.f,'sourceDerivedOnly':True,'sixServices':True}

    def create_container(self,name,*args):
        self.containers.append(name)
        return self.docker('run','-d','--name',name,'--label','penpot.ci.scope='+self.scope,*args)

    def wait(self, condition, seconds=180):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            if condition():
                return
            time.sleep(1)
        raise HarnessFailure('FIXTURE_DEADLINE')

    def make_variants(self):
        build = self.private/'variants'
        build.mkdir(mode=0o700)
        self.put(build/'Dockerfile','ARG BASE\nFROM ${BASE}\nARG REVISION\nARG SOURCE\nARG VARIANT\nLABEL org.opencontainers.image.revision="${REVISION}" penpot.fixture.source="${SOURCE}" penpot.fixture.variant="${VARIANT}"\n')
        self.maps = {'old':{},'target':{},'bad':{}}
        for role in ROLES:
            source='ghcr.io/thedemontuan/penpot-'+role+':sha-'+self.sha
            image=self.inspect('image',source)
            labels=image['Config'].get('Labels') or {}
            require(image['Architecture']=='arm64' and image['Os']=='linux' and
                    labels.get('org.opencontainers.image.revision')==self.sha and
                    labels.get('org.opencontainers.image.source')=='https://github.com/TheDemonTuan/penpot',
                    'SOURCE_IMAGE_IDENTITY')
            self.result['sourceImages'][role]={'tag':source,'imageId':image['Id']}
            base=self.scope+'-'+role+':base'
            self.images.append(base)
            self.docker('tag',image['Id'],base)
            for variant in ('old','target'):
                tag='localhost:5000/penpot-'+role+':'+variant
                self.images.append(tag)
                self.docker('build','--build-arg','BASE='+base,'--build-arg','REVISION='+self.f,
                            '--build-arg','SOURCE='+self.sha,'--build-arg','VARIANT='+variant,'-t',tag,build,
                            env=dict(self.env,DOCKER_BUILDKIT='0'),timeout=300)
                self.maps[variant][role]=self.push_digest(tag,role)
                derived=self.inspect('image',tag)
                require(derived['RootFS']==image['RootFS'] and derived['Config']['User']==image['Config']['User'] and
                        derived['Config']['Labels'].get('penpot.fixture.source')==self.sha,'FIXTURE_SOURCE_CLOSURE_CHANGED')
        # Patch only a fixture jar; source image/tag stays untouched.
        backend_id=self.result['sourceImages']['backend']['imageId']
        extract=self.scope+'-jar'
        self.containers.append(extract)
        self.docker('create','--name',extract,backend_id)
        self.docker('cp',extract+':/opt/penpot/backend/penpot.jar',build/'penpot.jar')
        self.docker('rm',extract)
        with zipfile.ZipFile(build/'penpot.jar','a') as jar:
            require('penpot/fixture.clj' not in jar.namelist(),'FIXTURE_NAMESPACE_ALREADY_PRESENT')
            jar.writestr('penpot/fixture.clj',(FIXTURES/'fixture.clj').read_bytes())
        self.put(build/'Dockerfile.bad','ARG BASE\nFROM ${BASE}\nARG REVISION\nARG SOURCE\nLABEL org.opencontainers.image.revision="${REVISION}" penpot.fixture.source="${SOURCE}" penpot.fixture.variant="migration-failure"\nCOPY --chown=penpot:penpot penpot.jar /opt/penpot/backend/penpot.jar\nCMD ["/bin/bash", "run.sh", "penpot.fixture"]\n')
        tag='localhost:5000/penpot-backend:bad'
        self.images.append(tag)
        self.docker('build','--build-arg','BASE='+self.scope+'-backend:base','--build-arg','REVISION='+self.f,
                    '--build-arg','SOURCE='+self.sha,'-f',build/'Dockerfile.bad','-t',tag,build,
                    env=dict(self.env,DOCKER_BUILDKIT='0'),timeout=300)
        self.maps['bad']=dict(self.maps['target'],backend=self.push_digest(tag,'backend'))
        self.result['fixtureImages']={name:dict(images=values,sourceSha=self.f) for name,values in self.maps.items()}

    def push_digest(self,tag,role):
        self.docker('push',tag,timeout=300)
        self.docker('pull',tag,timeout=300)
        repository='localhost:5000/penpot-'+role
        refs=[r for r in self.inspect('image',tag).get('RepoDigests',[]) if re.fullmatch(re.escape(repository)+r'@sha256:[0-9a-f]{64}',r)]
        require(len(refs)==1,'FIXTURE_DIGEST_AMBIGUOUS')
        return refs[0]

    def tls(self):
        self.run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=Penpot disposable CA',
                 '-keyout',self.private/'ca.key','-out',self.private/'ca.crt','-addext','basicConstraints=critical,CA:TRUE')
        self.run('openssl','req','-newkey','rsa:2048','-nodes','-subj','/CN='+HOST,
                 '-keyout',self.private/'server.key','-out',self.private/'server.csr')
        self.put(self.private/'extensions','subjectAltName=DNS:'+HOST+'\nextendedKeyUsage=serverAuth\n',0o644)
        self.run('openssl','x509','-req','-in',self.private/'server.csr','-CA',self.private/'ca.crt',
                 '-CAkey',self.private/'ca.key','-CAcreateserial','-days','2','-extfile',self.private/'extensions',
                 '-out',self.private/'server.crt')
        self.put(EDGE/'cloudflare-ca/origin-ca.pem',(self.private/'ca.crt').read_bytes(),0o644)
        certs=EDGE/'certs';self.mkdir(certs,0o755)
        for name in ('server.key','server.crt'):
            self.put(certs/name,(self.private/name).read_bytes(),0o644)
        self.put(EDGE/'dynamic/tls.yml',yaml.safe_dump({'tls':{'certificates':[{'certFile':'/certs/server.crt','keyFile':'/certs/server.key'}]}}),0o644)
        shared={'http':{'middlewares':{'tunnel-only':{'ipAllowList':{'sourceRange':['172.31.250.2/32']}},
                                     'crowdsec-ip':{'headers':{'customResponseHeaders':{'X-Fixture-Policy':'active'}}}},
                        'routers':{'foreign-sentinel':{'rule':'Host(`foreign.fixture.invalid`)','entryPoints':['web'],
                                                      'service':'noop@internal'}}}}
        self.put(EDGE/'dynamic/foreign.yml',yaml.safe_dump(shared),0o644)
        self.foreign_route=digest((EDGE/'dynamic/foreign.yml').read_bytes())
        static={'entryPoints':{'web':{'address':':8080','http':{'tls':{}}},'slot-probe':{'address':':18080'}},
                'providers':{'file':{'directory':'/etc/traefik/dynamic','watch':True}},'log':{'level':'INFO'},
                'accessLog':{'format':'json','fields':{'defaultMode':'drop',
                    'names':{'DownstreamStatus':'keep','RequestPath':'keep','RouterName':'keep'},
                    'queryParameters':{'defaultMode':'drop'}}}}
        self.put(EDGE/'traefik.yml',yaml.safe_dump(static),0o644)
        self.docker('network','create','--subnet','172.31.250.0/24','--label','penpot.ci.scope='+self.scope,'penpot-ci-tunnel')
        self.networks.append('penpot-ci-tunnel')
        self.create_container('edge-traefik','--network','penpot-ci-tunnel','--ip','172.31.250.4',
            '-p','127.0.0.1:18080:18080','--mount','type=bind,src='+str(EDGE/'dynamic')+',dst=/etc/traefik/dynamic,readonly',
            '--mount','type=bind,src='+str(EDGE/'traefik.yml')+',dst=/etc/traefik/traefik.yml,readonly',
            '--mount','type=bind,src='+str(EDGE/'cloudflare-ca')+',dst=/etc/cloudflare-origin-ca,readonly',
            '--mount','type=bind,src='+str(certs)+',dst=/certs,readonly','traefik:v3.7.13')
        # Copy just public test TLS inputs to a readable bind, never production keys.
        public=self.private/'proxy';public.mkdir(mode=0o755)
        for name in ('server.key','server.crt','ca.crt'):
            self.put(public/name,(self.private/name).read_bytes(),0o644)
        self.put(public/'proxy.cjs',(FIXTURES/'tls-proxy.cjs').read_bytes(),0o644)
        self.proxy=public
        self.create_container('edge-cloudflared','--network','penpot-ci-tunnel','--ip','172.31.250.2',
            '-p','127.0.0.1:443:8443','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true',
            '--mount','type=bind,src='+str(EDGE/'cloudflare-ca')+',dst=/etc/cloudflare-origin-ca,readonly',
            '--mount','type=bind,src='+str(public)+',dst=/fixture,readonly','--entrypoint','node',
            self.maps['old']['exporter'],'/fixture/proxy.cjs')
        self.original_hosts=Path('/etc/hosts').read_bytes()
        self.put('/etc/hosts',self.original_hosts+b'\n127.0.0.1 '+HOST.encode()+b' # '+self.scope.encode()+b'\n',0o644)

    def install(self):
        args=['--fixture','--app','penpot','--host','fixture-local','--release',self.platform,
              '--app-source',str(self.fixture_source),'--app-ref',self.f,'--public-key',str(self.private/'key.pub')]
        before={str(p):digest(p.read_bytes()) for base in (CFG,STATE,EDGE/'dynamic') for p in base.rglob('*') if p.is_file()}
        self.run('bash',self.release_source/'install/install.sh','--check',*args,timeout=300)
        after={str(p):digest(p.read_bytes()) for base in (CFG,STATE,EDGE/'dynamic') for p in base.rglob('*') if p.is_file()}
        require(before==after and not (Path('/opt/vps-deploy/releases')/self.platform).exists(),
                'INSTALL_CHECK_MUTATED_FIXTURE')
        self.install_attempted=True
        self.run('bash',self.release_source/'install/install.sh',*args,timeout=300)
        self.user_created=True
        self.release=Path('/opt/vps-deploy/releases')/self.platform
        self.controller=self.release/'bin/deployctl'
        require(self.run('systemctl','is-enabled','--quiet','vps-deploy-penpot-backup.timer',check=False).returncode!=0 and
                self.run('systemctl','is-active','--quiet','vps-deploy-penpot-backup.timer',check=False).returncode!=0,
                'FRESH_BACKUP_TIMER_STARTED')
        sys.path.insert(0,str(self.release/'lib'))
        sys.path.insert(0,str(self.release/'install'))
        import installer
        expected=installer.tree(self.release_source)
        require(installer.release_copy(self.release_source,self.release,expected) is None,'RELEASE_COPY_RETURN_CONTRACT')
        require(installer.tree(self.release)==expected,'IMMUTABLE_RELEASE_COPY')
        # Run the same origin-only transport before any fixture public assertions.
        self.load_profile()
        import penpot_edge
        penpot_edge.origin_ack(self.profile,self.state()['active'],self.state()['generation'])
        self.ssh_server()

    def gate_boundary(self):
        from core import Failure
        restore=module('fixture_offline_restore',self.release/'install/restore-penpot.py')
        gate=restore.controller().ready_engine
        gate(self.profile)
        for fixture,host in ((False,'fixture-local'),(1,'fixture-local'),(True,'oracle-main')):
            rejected=dict(self.profile,fixture_ci=fixture,registration=dict(self.profile['registration'],host=host))
            try:gate(rejected)
            except Failure as error:require(error.code=='PENPOT_RELEASE_ENGINE_NOT_READY','GATE_ERROR_CHANGED')
            else:raise HarnessFailure('PRODUCTION_ENGINE_FENCE_BYPASSED')
        marker=Path('/etc/vps-deploy/fixture-ci')
        marker.chmod(0o644)
        try:
            try:gate(self.profile)
            except Failure as error:require(error.code=='PENPOT_RELEASE_ENGINE_NOT_READY','GATE_ERROR_CHANGED')
            else:raise HarnessFailure('UNTRUSTED_FIXTURE_MARKER_ACCEPTED')
        finally:marker.chmod(0o600)
        return {'strictBoolean':True,'fixtureLocalOnly':True,'root0600MarkerRequired':True,'productionFenced':True}

    def load_profile(self):
        from core import app_registration,host_registration,host
        registration=app_registration(self.release,'penpot')
        self.profile=host(CFG,registration,host_registration(self.release,'fixture-local'))

    def ssh_server(self):
        self.mkdir('/run/sshd',0o755)
        config='\n'.join(['Port 22222','ListenAddress 127.0.0.1','HostKey '+str(self.private/'hostkey'),
                         'PidFile '+str(self.private/'sshd.pid'),'AuthorizedKeysFile .ssh/authorized_keys',
                         'PasswordAuthentication no','KbdInteractiveAuthentication no','PermitRootLogin no',
                         'UsePAM no','AllowUsers deploy-penpot','LogLevel ERROR'])+'\n'
        self.put(self.private/'sshd_config',config)
        self.run('/usr/sbin/sshd','-f',self.private/'sshd_config','-E',self.private/'sshd.log')
        self.sshd=int((self.private/'sshd.pid').read_text())
        self.put(self.private/'known_hosts','[127.0.0.1]:22222 '+' '.join((self.private/'hostkey.pub').read_text().split()[:2])+'\n')
        self.ssh=['ssh','-i',str(self.private/'key'),'-p','22222','-o','UserKnownHostsFile='+str(self.private/'known_hosts'),
                  '-o','GlobalKnownHostsFile=/dev/null','-o','StrictHostKeyChecking=yes','-o','BatchMode=yes',
                  '-o','IdentitiesOnly=yes','-o','ConnectTimeout=5','deploy-penpot@127.0.0.1']

    def state(self):
        return json.loads((STATE/'state.json').read_bytes())

    def request(self,op,images=None):
        self.sequence+=1
        ident='native-'+str(self.sequence)+'-'+op
        req=dict(version=1,op=op,app='penpot',request_id=ident,component='app',platform_ref=self.platform,
                 manifest_sha256=self.manifest,source_sha=self.f)
        if op=='deploy':req['images']=images
        answer=self.json(*self.ssh,'deployctl',data=json.dumps(req).encode())
        require(answer.get('status')=='running','CONTROLLER_REQUEST_NOT_STARTED')
        self.units.append('vps-deploy-penpot@'+ident+'.service')
        return ident

    def poll(self,ident,crash=False):
        answer=None
        def terminal():
            nonlocal answer
            req=dict(version=1,op='status',app='penpot',request_id=ident)
            answer=self.json(*self.ssh,'deployctl',data=json.dumps(req).encode())
            return answer.get('status') in ('complete','failed','recovery_required')
        self.wait(terminal,360)
        require(answer['status']==('recovery_required' if crash else 'complete'),'UNEXPECTED_REQUEST_RESULT')
        if crash:
            unit='vps-deploy-penpot@'+ident+'.service'
            status=self.run('systemctl','show',unit,'--property=ExecMainCode','--property=ExecMainStatus').stdout.decode()
            require('ExecMainStatus=9' in status and 'ExecMainCode=2' in status,'SIGKILL_NOT_OBSERVED')
        return answer

    def reconcile(self):
        self.poll(self.request('reconcile'))

    def deploy(self,images):
        self.poll(self.request('deploy',images))

    def fault(self,label=None):
        if label is None:
            (WORK/'fault').unlink(missing_ok=True)
        else:self.put(WORK/'fault',label+'\n')

    def sql(self,sql):
        return self.docker('exec','-i','penpot-postgres','psql','-X','-U','penpot','-d','penpot',
                           '-At','--set=ON_ERROR_STOP=1',data=sql.encode()).stdout.decode().strip()

    def asset(self,data=None):
        args=['run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true',
              '--mount','type=volume,src=penpot_assets,dst=/opt/data/assets','--entrypoint','/bin/bash',self.maps['old']['backend']]
        if data is None:
            return self.docker(*args,'-c','cat /opt/data/assets/fixture-marker.bin').stdout
        self.docker(*args[:1],'-i',*args[1:],'-c','cat > /opt/data/assets/fixture-marker.bin',data=data.encode())

    def write_data(self,value):
        require(re.fullmatch('[a-z-]+',value),'FIXTURE_MARKER_INVALID')
        self.sql("UPDATE penpot_fixture_probe SET value='"+value+"' WHERE id='baseline';")
        self.asset(value)

    def data(self):
        return dict(database=self.sql("SELECT value FROM penpot_fixture_probe WHERE id='baseline';"),
                    assetSha256=digest(self.asset()),accountCount=int(self.sql("SELECT count(*) FROM profile WHERE email='ci-smoke@example.invalid' AND is_active;")))

    def assert_data(self,value):
        result=self.data()
        require(result==dict(database=value,assetSha256=digest(value.encode()),accountCount=1),'DATABASE_ASSET_ACCOUNT_DRIFT')
        return result

    def seed(self):
        owner=self.docker('exec','penpot-backend','stat','-c','%u:%g','/opt/data/assets').stdout.strip()
        require(owner==b'1001:1001','ASSET_VOLUME_NOT_OWNED_BY_APP_UID')
        smoke=module('native_source_smoke',self.app/'.deploy/smoke-stack.py')
        self.docker('exec','-i','penpot-backend','python3','-',data=smoke.ACCOUNT.encode())
        self.sql("CREATE TABLE penpot_fixture_probe(id text primary key,value text not null); INSERT INTO penpot_fixture_probe VALUES ('baseline','old');")
        self.asset('old')
        require(self.docker('exec','penpot-backend','stat','-c','%u:%g','/opt/data/assets/fixture-marker.bin').stdout.strip()==b'1001:1001',
                'ASSET_MARKER_NOT_OWNED_BY_APP_UID')
        self.store_ids={name:self.inspect('container',name)['Id'] for name in ('penpot-postgres','penpot-valkey')}
        self.assert_data('old')

    def foreign_setup(self):
        self.docker('volume','create','--label','penpot.ci.scope='+self.scope,'penpot-ci-foreign')
        self.volumes.append('penpot-ci-foreign')
        self.create_container('penpot-ci-foreign','--network','none','--user','0:0',
                              '--mount','type=volume,src=penpot-ci-foreign,dst=/foreign',
                              '--entrypoint','/bin/sh',self.maps['old']['frontend'],'-c','printf foreign > /foreign/sentinel; sleep 86400')
        self.foreign_id=self.inspect('container','penpot-ci-foreign')['Id']

    def invariants(self,images,value):
        self.preserve_foreign()
        status=self.json(self.controller,'status','--app','penpot','--strict')
        require(status['healthy'] is True and status['images']==images and status['source_sha']==self.f,
                'ACTIVE_RELEASE_DRIFT')
        state=self.state()
        require(state['operation'] is None and state['active']['images']==images,'DURABLE_STATE_DRIFT')
        require(digest((EDGE/'dynamic/foreign.yml').read_bytes())==self.foreign_route,'FOREIGN_ROUTE_MUTATED')
        require(self.inspect('container','penpot-ci-foreign')['Id']==self.foreign_id and
                self.docker('exec','penpot-ci-foreign','cat','/foreign/sentinel').stdout==b'foreign','FOREIGN_RESOURCE_MUTATED')
        require(all(self.inspect('container',name)['Id']==ident for name,ident in self.store_ids.items()),'DATASTORE_RECREATED')
        import route,penpot_edge
        require(route.route_state((EDGE/'dynamic/penpot.yml').read_bytes(),self.profile)==('single',state['generation']), 'ROUTE_GENERATION_DRIFT')
        penpot_edge.origin_ack(self.profile,state['active'],state['generation'])
        return dict(self.assert_data(value),generation=state['generation'],images=images,foreignSentinelsPreserved=True)

    def happy(self):
        self.deploy(self.maps['target'])
        return self.invariants(self.maps['target'],'old')

    def maintenance_failure(self):
        before={role:self.inspect('container','penpot-'+role)['Id'] for role in ROLES}
        self.put(self.proxy/'reject-maintenance','reject',0o644)
        try:
            ident=self.request('deploy',self.maps['old'])
            self.wait(lambda:(STATE/'requests'/ident/'result.json').exists(),120)
            result=json.loads((STATE/'requests'/ident/'result.json').read_bytes())
            require(result['status']=='failed','MAINTENANCE_FAILURE_NOT_REJECTED')
            require(all(self.inspect('container','penpot-'+role)['Id']==identity and
                        self.inspect('container','penpot-'+role)['State']['Running'] for role,identity in before.items()),
                    'OLD_WRITERS_STOPPED_BEFORE_MAINTENANCE_ACK')
            self.assert_data('old')
        finally:
            (self.proxy/'reject-maintenance').unlink(missing_ok=True)
        self.reconcile()
        return self.invariants(self.maps['target'],'old')

    def crash_case(self,label):
        self.deploy(self.maps['old'])
        self.write_data('old')
        old_generation=self.state()['generation']
        recovery_only=label in ('penpot_restored','penpot_old_exposed')
        self.fault(label)
        try:
            ident=self.request('deploy',self.maps['bad'] if recovery_only else self.maps['target'])
            self.poll(ident,crash=True)
            operation=self.state()['operation']
            committed=label in ('penpot_exposing','penpot_exposed','penpot_complete')
            require(operation['committed'] is committed,'COMMIT_BOUNDARY_CHANGED')
            if label in ('penpot_stopped','penpot_backed_up','penpot_applying','penpot_applied','penpot_restored','penpot_exposing'):
                import penpot_edge
                penpot_edge.origin_ack(self.profile,self.state()['active'],maintenance=True)
            if label in ('penpot_stopped','penpot_backed_up','penpot_applying','penpot_restored'):
                require(all(not self.inspect('container','penpot-'+role)['State']['Running'] for role in ROLES),
                        'WRITERS_RUNNING_AT_STOPPED_CHECKPOINT')
            if label in ('penpot_old_exposed','penpot_exposed'):
                self.write_data('after-exposure')
            self.fault()
            self.reconcile()
            self.reconcile()
            require(self.state()['generation']==(operation['generation'] if committed else old_generation),
                    'RECOVERED_ROUTE_BOUNDARY_CHANGED')
            expected='after-exposure' if label in ('penpot_old_exposed','penpot_exposed') else 'old'
            return dict(self.invariants(self.maps['target'] if committed else self.maps['old'],expected),
                        fault=label,committed=committed,reconcileCount=2)
        finally:self.fault()

    def migration_failure(self):
        self.deploy(self.maps['old'])
        self.write_data('old')
        self.fault('penpot_restoring')
        try:
            ident=self.request('deploy',self.maps['bad'])
            self.poll(ident,crash=True)
            candidate=self.assert_data('candidate')
            logs=self.docker('logs','penpot-backend',check=False).stdout+self.docker('logs','penpot-backend',check=False).stderr
            require(b'PENPOT_FIXTURE_MIGRATION_FAILURE' in logs,'REAL_MIGRATION_FAILURE_NOT_OBSERVED')
            self.log(logs)
            require(self.state()['operation']['committed'] is False,'FAILED_MIGRATION_COMMITTED')
            self.fault()
            self.reconcile();self.reconcile()
            return dict(candidate=candidate,restored=self.invariants(self.maps['old'],'old'),independentJdbcCommit=True)
        finally:self.fault()

    def security(self):
        for command in ('id','sudo -n id','python3 '+str(self.release/'install/restore-penpot.py')+' --apply'):
            require(self.run(*self.ssh,command,data=b'',check=False).returncode!=0,'ARBITRARY_SSH_COMMAND_ACCEPTED')
        require(self.run(*self.ssh[:-1],'-W','127.0.0.1:5000',self.ssh[-1],data=b'',check=False).returncode!=0,'SSH_FORWARD_ACCEPTED')
        transfer_args=['-i',str(self.private/'key'),'-o','UserKnownHostsFile='+str(self.private/'known_hosts'),
                       '-o','StrictHostKeyChecking=yes','-o','BatchMode=yes','-o','IdentitiesOnly=yes']
        require(self.run('sftp','-b','-','-P','22222',*transfer_args,'deploy-penpot@127.0.0.1',
                         data=b'ls\n',check=False).returncode!=0,'SFTP_ACCEPTED')
        require(self.run('scp','-O','-P','22222',*transfer_args,self.private/'known_hosts',
                         'deploy-penpot@127.0.0.1:/tmp/'+self.scope,check=False).returncode!=0,'SCP_ACCEPTED')
        require(not Path('/tmp',self.scope).exists(),'SCP_WROTE_ARBITRARY_FILE')
        require(self.run('id','-nG','deploy-penpot').stdout.decode().strip()=='deploy-penpot','DEPLOY_ACCOUNT_PRIVILEGED_GROUP')
        saved_known=(self.private/'known_hosts').read_bytes()
        self.run('ssh-keygen','-q','-t','ed25519','-N','','-f',self.private/'wrong-host')
        self.put(self.private/'known_hosts','[127.0.0.1]:22222 '+' '.join((self.private/'wrong-host.pub').read_text().split()[:2])+'\n')
        try:
            require(self.run(*self.ssh,'deployctl',data=b'{"version":1,"op":"status","app":"penpot"}',
                             check=False).returncode!=0,'WRONG_HOST_KEY_ACCEPTED')
        finally:self.put(self.private/'known_hosts',saved_known)
        for op in ('restore','backup','rollback'):
            request=dict(version=1,op=op,app='penpot')
            result=self.run(*self.ssh,'deployctl',data=json.dumps(request).encode(),check=False)
            require(result.returncode!=0 and json.loads(result.stdout)['status']=='failed','SSH_OFFLINE_OPERATION_ACCEPTED')
        result=self.run(*self.ssh,'deployctl',data=b'{"version":1,"op":"status","app":"9router"}',check=False)
        require(json.loads(result.stdout)['error_code']=='APP_BINDING_MISMATCH','SSH_CROSS_APP_ACCEPTED')
        return {'forcedCommand':True,'forwardingDenied':True,'offlineRestoreRootOnly':True}

    def backup(self):
        before=self.data()
        result=self.json(self.controller,'backup','--app','penpot',timeout=360)
        require(result['status']=='complete','BACKUP_NOT_COMPLETE')
        selected=Path(result['backup'])
        import penpot
        metadata=penpot.verify_snapshot(selected,self.profile['registration'])
        require(set(p.name for p in selected.iterdir())=={'manifest.json',*penpot.SNAPSHOT_FILES},'BACKUP_CLOSURE')
        require(self.data()==before,'BACKUP_MUTATED_DATABASE_OR_ASSETS')
        return selected,metadata

    def restore(self,selected,mode='--apply',check=True):
        return self.run('python3',self.release/'install/restore-penpot.py','--backup',selected,mode,
                        timeout=360,check=check)

    def offline_restore(self):
        self.write_data('old')
        selected,metadata=self.backup()
        checked=json.loads(self.restore(selected,'--check').stdout)
        require(checked['data_timestamp']==metadata['createdAt'],'RESTORE_CHECK_TIMESTAMP')
        self.write_data('changed')
        restored=json.loads(self.restore(selected).stdout)
        require(restored['data_timestamp']==metadata['createdAt'] and Path(restored['safety_backup']).is_dir(), 'RESTORE_TIMESTAMP_OR_SAFETY')
        import penpot
        safety=penpot.verify_snapshot(Path(restored['safety_backup']),self.profile['registration'])
        require(safety['createdAt']>=metadata['createdAt'],'SAFETY_SNAPSHOT_TIMESTAMP')
        evidence=self.invariants(metadata['images'],'old')
        for label in ('penpot_restore_data','penpot_restore_exposing','penpot_restore_complete'):
            self.write_data('changed')
            self.fault(label)
            process=self.restore(selected,check=False)
            require(process.returncode==-9,'OFFLINE_RESTORE_SIGKILL_NOT_OBSERVED')
            operation=self.state()['operation']
            require(operation['kind']=='restore','OFFLINE_RESTORE_CHECKPOINT_MISSING')
            # App SSH must not take over a root-only restore checkpoint.
            ident=self.request('reconcile')
            self.wait(lambda:(STATE/'requests'/ident/'result.json').exists(),60)
            answer=json.loads((STATE/'requests'/ident/'result.json').read_bytes())
            require(answer['status']=='failed','APP_RECONCILE_TOOK_OVER_OFFLINE_RESTORE')
            if label=='penpot_restore_complete':self.write_data('after-exposure')
            self.fault()
            answer=json.loads(self.restore(selected).stdout)
            require(answer['data_timestamp']==metadata['createdAt'],'RESTORE_RECOVERY_TIMESTAMP')
            expected='after-exposure' if label=='penpot_restore_complete' else 'old'
            self.invariants(metadata['images'],expected)
            self.reconcile();self.reconcile();self.assert_data(expected)
        return dict(evidence,dataTimestamp=metadata['createdAt'],safetySnapshot=True,
                    restoreFaults=['penpot_restore_data','penpot_restore_exposing','penpot_restore_complete'])

    def corruption(self):
        self.write_data('old')
        selected,_=self.backup()
        evidence={}
        for corruption in ('checksum','tar','dump'):
            destination=STATE/'backups'/('corrupt-'+corruption)
            shutil.copytree(selected,destination)
            before=self.data();state_before=(STATE/'state.json').read_bytes();route_before=(EDGE/'dynamic/penpot.yml').read_bytes()
            metadata=json.loads((destination/'manifest.json').read_bytes())
            if corruption=='checksum':
                with (destination/'database.dump').open('ab') as output:output.write(b'bad')
            elif corruption=='tar':
                with tarfile.open(destination/'assets.tar','w') as archive:
                    entry=tarfile.TarInfo('../escape');entry.size=1;archive.addfile(entry,io.BytesIO(b'x'))
                metadata['sha256']['assets.tar']=digest((destination/'assets.tar').read_bytes())
                self.put(destination/'manifest.json',json.dumps(metadata))
            else:
                self.put(destination/'database.dump',b'PGDMPinvalid')
                metadata['sha256']['database.dump']=digest((destination/'database.dump').read_bytes())
                self.put(destination/'manifest.json',json.dumps(metadata))
            for mode in ('--check','--apply'):
                require(self.restore(destination,mode,check=False).returncode!=0,'CORRUPT_BACKUP_ACCEPTED')
                require(self.data()==before and (STATE/'state.json').read_bytes()==state_before and
                        (EDGE/'dynamic/penpot.yml').read_bytes()==route_before,'CORRUPT_RESTORE_MUTATED_DATA')
            shutil.rmtree(destination)
            evidence[corruption]='rejected-before-mutation'
        return evidence

    def retention(self):
        import penpot
        state_before=self.state()
        previous_source=(state_before.get('previous') or {}).get('source_sha')
        operation_snapshot=(state_before.get('operation') or {}).get('snapshot')
        recorded={str(p):penpot.verify_snapshot(p,self.profile['registration'])
                  for p in (STATE/'backups').iterdir() if (p/'manifest.json').exists()}
        existing_references={name for name,metadata in recorded.items()
                             if metadata['sourceSha']==previous_source or name==operation_snapshot}
        # Calculate expected retention from snapshots observed BEFORE pruning,
        # including each genuinely created snapshot, never just survivors.
        for _ in range(9):
            directory,metadata=self.backup()
            recorded[str(directory)]=metadata
        state=self.state()
        require((state.get('previous') or {}).get('source_sha')==previous_source and state['operation'] is None,
                'RETENTION_REFERENCE_STATE_CHANGED')
        actual={str(p):penpot.verify_snapshot(p,self.profile['registration'])
                for p in (STATE/'backups').iterdir() if (p/'manifest.json').exists()}
        require(existing_references<=actual.keys(),'PREEXISTING_REFERENCED_SNAPSHOT_PRUNED')
        require(all(actual[name]==recorded[name] for name in existing_references),
                'PREEXISTING_REFERENCED_SNAPSHOT_MUTATED')
        ordered=sorted(recorded,key=lambda name:(recorded[name]['createdAt'],Path(name).name),reverse=True)
        newest=set(ordered[:7])
        references={name for name,metadata in recorded.items()
                    if metadata['sourceSha']==previous_source or name==operation_snapshot}
        require(actual.keys()==newest|references,'RETENTION_NOT_SEVEN_PLUS_REFERENCES')
        require(len(newest)==7,'RETENTION_NEWEST_SEVEN_MISSING')
        require(all(actual[name]==recorded[name] for name in actual),'RETAINED_SNAPSHOT_METADATA_MUTATED')
        return {'completeSnapshots':len(actual),'newestRetained':len(newest),
                'retainedReferences':len(references),'preexistingReferencesPreserved':len(existing_references),
                'unreferencedSnapshotsRemoved':len(recorded)-len(actual),'sourceVariantsShareRevision':self.f}

    def token_logs(self):
        token='fixture-'+secrets.token_hex(32)+'+/='
        self.secret_values.append(token)
        self.secret_values.append(urllib.parse.quote(token,safe=''))
        # Configure a fixture-only copy of nginx's MCP include, leaving image bytes
        # unchanged. Its normal config is restored even when leak assertions fail.
        config_path='/etc/nginx/conf.d/mcp.conf'
        listing=self.docker('exec','penpot-frontend','/bin/sh','-c',"find /etc/nginx -type f -name '*.conf' -print").stdout.decode().splitlines()
        candidate=None;original=None
        for path in listing:
            content=self.docker('exec','penpot-frontend','cat',path).stdout
            if b'location /mcp/ws' in content:
                candidate=path;original=content;break
        require(candidate is not None,'MCP_NGINX_CONFIG_NOT_FOUND')
        saved=self.private/'mcp-original.conf';self.put(saved,original,0o644)
        self.create_container('penpot-ci-timeout','--network','penpot_penpot','--entrypoint','node',
                              self.maps['old']['exporter'],'-e',"require('node:http').createServer((q,s)=>{}).listen(4401,'0.0.0.0');require('node:net').createServer(()=>{}).listen(4402,'0.0.0.0')")
        outcomes=[]
        start=self.run('date','-u','+%Y-%m-%dT%H:%M:%SZ').stdout.decode().strip()
        try:
            for scenario in ('success','404','refused','timeout'):
                config=original
                if scenario=='404':
                    config=config.replace(b'location /mcp/ws {',b'location /mcp/ws { return 404;').replace(
                        b'location /mcp/stream {',b'location /mcp/stream { return 404;')
                if scenario=='refused':config=config.replace(b'penpot-mcp:4401',b'penpot-mcp:4491').replace(b'penpot-mcp:4402',b'penpot-mcp:4492')
                if scenario=='timeout':
                    config=config.replace(b'penpot-mcp:4401',b'penpot-ci-timeout:4401').replace(b'penpot-mcp:4402',b'penpot-ci-timeout:4402')
                    config=config.replace(b'proxy_http_version 1.1;',b'proxy_http_version 1.1; proxy_read_timeout 2s; proxy_connect_timeout 2s;')
                modified=self.private/'mcp-test.conf';self.put(modified,config,0o644)
                self.docker('cp',modified,'penpot-frontend:'+candidate)
                self.docker('exec','penpot-frontend','nginx','-s','reload')
                time.sleep(2)
                for endpoint in ('/mcp/ws','/mcp/stream'):
                    path=endpoint+'?userToken='+urllib.parse.quote(token,safe='')
                    args=['curl','--cacert',str(EDGE/'cloudflare-ca/origin-ca.pem'),'--max-time','12','-sS','-o','/dev/null','-w','%{http_code}']
                    if endpoint.endswith('/ws'):
                        args += ['-H','Connection: Upgrade','-H','Upgrade: websocket','-H','Sec-WebSocket-Version: 13','-H','Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==']
                    elif scenario=='success':
                        args += ['-X','POST','-H','Content-Type: application/json','-H','Accept: application/json, text/event-stream',
                                 '--data','{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}']
                    answer=self.run(*args,'https://'+HOST+path,check=False)
                    status=answer.stdout.decode().strip()
                    if scenario=='success':require(status in ('101','200'),'MCP_SUCCESS_STATUS_NOT_OBSERVED')
                    elif scenario=='refused':require(status=='502','MCP_REFUSED_NOT_OBSERVED')
                    elif scenario=='timeout':require(status=='504','MCP_TIMEOUT_NOT_OBSERVED')
                    else:require(status=='404','MCP_404_NOT_OBSERVED')
                    outcomes.append(dict(scenario=scenario,path=endpoint,status=status))
            combined=b''
            for name in ('penpot-frontend','penpot-mcp','edge-traefik','edge-cloudflared','penpot-ci-timeout'):
                process=self.docker('logs','--since',start,name,check=False)
                raw=process.stdout+process.stderr
                require(token.encode() not in raw and urllib.parse.quote(token,safe='').encode() not in raw,
                        'QUERY_TOKEN_LOG_LEAK_'+name.upper().replace('-','_'))
                combined+=raw
                self.log(name+' logs:\n'+self.redact(raw))
            require(b'502' in combined and b'504' in combined and
                    (b'Connection refused' in combined or b'ECONNREFUSED' in combined or b'connect() failed' in combined) and
                    (b'timed out' in combined or b'ETIMEDOUT' in combined),'ERROR_CAUSE_SUPPRESSED')
            return {'observations':outcomes,'rawAndEncodedTokenAbsent':True,'errorCausesRetained':True}
        finally:
            self.docker('cp',saved,'penpot-frontend:'+candidate,check=False)
            self.docker('exec','penpot-frontend','nginx','-s','reload',check=False)

    def collect(self):
        # Never collect inspect Env, argv, runtime.env, dump, keys or checkpoint.
        for name in self.containers:
            if self.docker('container','inspect',name,check=False).returncode==0:
                process=self.docker('logs','--tail','100',name,check=False)
                self.log(name+' diagnostics:\n'+self.redact(process.stdout+process.stderr))
        for unit in self.units:
            process=self.run('journalctl','-u',unit,'--no-pager','-n','30',check=False)
            self.log(unit+' journal:\n'+self.redact(process.stdout))

    def cleanup(self):
        # Explicit ownership ledger only; no prune and no unrelated deletion.
        self.fault() if WORK.is_dir() else None
        for unit in reversed(self.units):
            self.run('systemctl','stop',unit,check=False)
            self.run('systemctl','reset-failed',unit,check=False)
        for unit in ('vps-deploy-penpot-backup.timer','vps-deploy-penpot-backup.service','vps-deploy-drain@penpot.timer'):
            if self.install_attempted:self.run('systemctl','disable','--now',unit,check=False)
        if self.sshd:
            with contextlib.suppress(ProcessLookupError):os.kill(self.sshd,15)
        for name in reversed(self.containers):self.docker('rm','-f','-v',name,check=False)
        for name in reversed(self.networks):self.docker('network','rm',name,check=False)
        for name in reversed(self.volumes):self.docker('volume','rm',name,check=False)
        for tag in self.images:self.docker('image','rm',tag,check=False)
        for value in self.result['sourceImages'].values():
            require(self.inspect('image',value['tag'])['Id']==value['imageId'],'SOURCE_IMAGE_TAG_MUTATED')
        if self.original_hosts is not None:self.put('/etc/hosts',self.original_hosts,0o644)
        if self.install_attempted:
            self.run('userdel','-r','deploy-penpot',check=False)
            for path in ('/usr/local/libexec/vps-deploy-penpot','/usr/local/libexec/vps-deploy-drain-penpot',
                         '/usr/local/libexec/vps-deploy-penpot-backup','/etc/sudoers.d/vps-deploy-penpot',
                         '/etc/systemd/system/vps-deploy-drain@.service','/etc/systemd/system/vps-deploy-drain@.timer',
                         '/etc/systemd/system/vps-deploy-penpot-backup.service','/etc/systemd/system/vps-deploy-penpot-backup.timer'):
                Path(path).unlink(missing_ok=True)
            shutil.rmtree(Path('/opt/vps-deploy/releases')/self.platform,ignore_errors=True)
            self.run('systemctl','daemon-reload',check=False)
        if hasattr(self, 'baseline_release'):
            shutil.rmtree(self.baseline_release, ignore_errors=True)
        for path in reversed(self.paths):
            if path==self.private or path in (CFG,STATE,WORK,EDGE):
                shutil.rmtree(path,ignore_errors=True)
            elif path.is_dir():
                with contextlib.suppress(OSError):path.rmdir()
            else:path.unlink(missing_ok=True)
        self.result['foreignResourceIsolation']=self.preserve_foreign()

    def finish_report(self):
        require(self.report.is_absolute() and str(self.report)!='/nonexistent','REPORT_DIRECTORY_REQUIRED')
        require(self.report.resolve()==self.report and
                ('_temp' in self.report.parts or Path('/tmp') in self.report.parents), 'UNSAFE_REPORT_DIRECTORY')
        require(self.report.is_dir() and not self.report.is_symlink(),'PRECREATED_REPORT_DIRECTORY_REQUIRED')
        owner=self.report.stat()
        logs=self.report/'logs'
        require(not logs.is_symlink(),'REPORT_SYMLINK')
        logs.mkdir(mode=0o700,exist_ok=True)
        self.put(logs/'runtime.log','\n'.join(self.logs)[-4*1024*1024:]+'\n',0o600)
        self.put(self.report/'lifecycle.json',json.dumps(self.result,sort_keys=True,indent=2)+'\n',0o600)
        for path in (logs,logs/'runtime.log',self.report/'lifecycle.json'):
            os.chown(path,owner.st_uid,owner.st_gid)
        logs.chmod(0o700)

    def execute(self):
        try:
            self.case('native-disposable-guards',self.guard)
            self.case('fixture-setup-tls-origin-copy-fresh-timer',self.setup)
            self.case('fixture-admission-production-fence',self.gate_boundary)
            self.case('seven-unreferenced-snapshot-retention',self.retention)
            self.case('forced-command-security',self.security)
            self.case('happy-deployment',self.happy)
            self.case('maintenance-ack-failure-keeps-old-writers',self.maintenance_failure)
            self.case('independent-jdbc-migration-failure-and-restore',self.migration_failure)
            for label in ('penpot_prepared','penpot_stopped','penpot_backed_up','penpot_applying','penpot_applied',
                          'penpot_restored','penpot_old_exposed','penpot_exposing','penpot_exposed','penpot_complete'):
                self.case('sigkill-'+label,lambda label=label:self.crash_case(label))
            self.case('backup-offline-restore-and-boundaries',self.offline_restore)
            self.case('corrupt-backup-refused-before-mutation',self.corruption)
            self.case('seven-snapshot-retention-plus-references',self.retention)
            self.case('synthetic-query-token-real-proxy-regression',self.token_logs)
            self.result['status']='passed'
        except Exception as error:
            self.result['errorCode']=getattr(error,'code',str(error) if isinstance(error,HarnessFailure) else type(error).__name__)
            self.log('Harness failed: '+self.result['errorCode'])
        finally:
            if self.containers:
                with contextlib.suppress(Exception):self.collect()
            if self.paths or self.units:
                try:self.cleanup()
                except Exception as error:
                    self.result['status']='failed';self.result['cleanupError']=type(error).__name__
            self.finish_report()
        return 0 if self.result['status']=='passed' else 1


if __name__=='__main__':
    raise SystemExit(Harness().execute())
