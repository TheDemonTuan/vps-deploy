#!/usr/bin/env bash
set -euo pipefail
[[ $(id -u) -eq 0 ]] || { echo ROOT_REQUIRED >&2; exit 1; }
[[ $(uname -s) == Linux ]] || { echo LINUX_REQUIRED >&2; exit 1; }
[[ ! -e /etc/vps-deploy/fixture-ci && ! -L /etc/vps-deploy/fixture-ci ]] || { echo FIXTURE_INSTALL_FORBIDDEN >&2; exit 1; }
CHECK=0
if [[ ${1:-} == --check ]]; then CHECK=1; shift; fi
[[ $# == 8 && $1 == --release && $3 == --app-source && $5 == --app-ref && $7 == --public-key ]] || { echo 'Usage: install.sh [--check] --release <SHA> --app-source <absolute checkout> --app-ref <SHA> --public-key <reviewed-public-key-file>' >&2; exit 1; }
RELEASE=$2; SOURCE=$4; APP_REF=$6; PUBLIC_KEY=$8
[[ $RELEASE =~ ^[0-9a-f]{40}$ && $APP_REF =~ ^[0-9a-f]{40}$ && $SOURCE == /* && -d $SOURCE && ! -L $SOURCE && -f $PUBLIC_KEY && ! -L $PUBLIC_KEY ]] || { echo INVALID_SOURCE >&2; exit 1; }
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
[[ ! -L $ROOT && ! -L $ROOT/bin/deployctl && ! -L $ROOT/install/install.sh ]] || { echo UNSAFE_EXECUTABLE >&2; exit 1; }
[[ $(stat -c %a "$ROOT/bin/deployctl") =~ ^[0-7]+$ ]] || exit 1
[[ $(git -C "$ROOT" rev-parse HEAD) == "$RELEASE" && -z $(git -C "$ROOT" status --porcelain --untracked-files=all) ]] || { echo RELEASE_NOT_REVIEWED >&2; exit 1; }
[[ $(git -C "$SOURCE" cat-file -t "$APP_REF") == commit ]] || { echo INVALID_APP_REF >&2; exit 1; }
MANIFEST=$(mktemp); trap 'rm -f "$MANIFEST"' EXIT
git -C "$SOURCE" show "$APP_REF:.deploy/app.yml" > "$MANIFEST"
[[ $(wc -l < "$PUBLIC_KEY") == 1 && $(cut -d' ' -f1 < "$PUBLIC_KEY") == ssh-ed25519 ]] || { echo INVALID_PUBLIC_KEY >&2; exit 1; }
ssh-keygen -lf "$PUBLIC_KEY" >/dev/null || { echo INVALID_PUBLIC_KEY >&2; exit 1; }
if [[ -f /etc/vps-deploy/apps/9router/runtime.env ]]; then
  ENV_SOURCE=/etc/vps-deploy/apps/9router/runtime.env
else
  ENV_SOURCE=/opt/9router/.env
fi
[[ -f $ENV_SOURCE && ! -L $ENV_SOURCE ]] || { echo MISSING_RUNTIME_ENV >&2; exit 1; }
[[ $(stat -c %a "$ENV_SOURCE") == 600 && $(stat -c %u "$ENV_SOURCE") == "$(stat -c %u /opt/9router)" || $ENV_SOURCE == /etc/vps-deploy/apps/9router/runtime.env && $(stat -c %u "$ENV_SOURCE") == 0 && $(stat -c %a "$ENV_SOURCE") == 600 ]] || { echo UNSAFE_RUNTIME_ENV >&2; exit 1; }
python3 - "$ROOT" <<'PY'
import sys
from pathlib import Path
root = Path(sys.argv[1])
for directory in (root, *root.parents):
    if directory.exists() and (directory.is_symlink() or directory.stat().st_mode & 0o022):
        raise SystemExit('UNTRUSTED_PARENT')
for area in ('bin', 'lib', 'apps', 'schema', 'install'):
    for path in (root / area).rglob('*'):
        if path.is_symlink() or path.stat().st_mode & 0o022:
            raise SystemExit('UNTRUSTED_RELEASE_FILE')
PY
python3 - "$ROOT" "$MANIFEST" "$CHECK" <<'PY'
import json, os, stat, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1] + '/lib')
from core import host, manifest, require, Failure
manifest(Path(sys.argv[2]).read_bytes())
for path in (Path(sys.argv[1]), Path('/opt/vps-deploy'), Path('/etc/vps-deploy')):
    if path.exists():
        require(not path.is_symlink() and not path.stat().st_mode & 0o022, 'UNTRUSTED_PARENT')
if Path('/etc/vps-deploy/apps/9router/host.json').exists():
    host(Path('/etc/vps-deploy/apps/9router'))
PY
python3 "$ROOT/install/preflight.py" "$ROOT" "$ENV_SOURCE"
if (( CHECK )); then echo CHECK_OK; exit 0; fi
RELEASE_DIR="/opt/vps-deploy/releases/$RELEASE"
install -d -m 0700 /opt/vps-deploy /opt/vps-deploy/releases /etc/vps-deploy /etc/vps-deploy/apps /etc/vps-deploy/apps/9router /var/lib/vps-deploy /var/lib/vps-deploy/apps /var/lib/vps-deploy/apps/9router /var/lib/vps-deploy/apps/9router/requests /run/lock/vps-deploy
if [[ -e $RELEASE_DIR ]]; then
  python3 - "$ROOT" "$RELEASE_DIR" <<'PY'
from pathlib import Path
import hashlib, sys
source, installed = map(Path, sys.argv[1:])
for area in ('bin', 'lib', 'apps', 'schema', 'install'):
    original = source / area
    mirror = installed / area
    files = {str(p.relative_to(original)) for p in original.rglob('*') if p.is_file()}
    existing = {str(p.relative_to(mirror)) for p in mirror.rglob('*') if p.is_file()}
    if files != existing or mirror.is_symlink():
        raise SystemExit('RELEASE_MODIFIED')
    for name in files:
        path = mirror / name
        if path.is_symlink() or path.stat().st_uid != 0 or hashlib.sha256((original/name).read_bytes()).digest() != hashlib.sha256(path.read_bytes()).digest():
            raise SystemExit('RELEASE_MODIFIED')
PY
else
  TEMP_RELEASE=$(mktemp -d /opt/vps-deploy/releases/.install.XXXXXXXX)
  for area in bin lib apps schema install; do cp -a -- "$ROOT/$area" "$TEMP_RELEASE/$area"; done
  chown -R root:root "$TEMP_RELEASE"; chmod -R go-w "$TEMP_RELEASE"
  python3 - "$TEMP_RELEASE" <<'PY'
import os,sys
from pathlib import Path
root=Path(sys.argv[1])
for path in root.rglob('*'):
    fd=os.open(path,os.O_RDONLY | (os.O_DIRECTORY if path.is_dir() else 0))
    os.fsync(fd);os.close(fd)
fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
os.fsync(fd);os.close(fd)
PY
  mv -T -- "$TEMP_RELEASE" "$RELEASE_DIR"
  python3 - "$RELEASE_DIR" <<'PY'
import os,sys
fd=os.open(os.path.dirname(sys.argv[1]),os.O_DIRECTORY)
os.fsync(fd);os.close(fd)
PY
fi
if command -v restorecon >/dev/null 2>&1 && command -v matchpathcon >/dev/null 2>&1; then
  restorecon -R "$RELEASE_DIR"
  [[ $(stat -c %C "$RELEASE_DIR/bin/deployctl" | cut -d: -f3) == "$(matchpathcon -n "$RELEASE_DIR/bin/deployctl" | cut -d: -f3)" ]] || { echo RELEASE_CONTEXT >&2; exit 1; }
fi
install -m 0600 "$MANIFEST" /etc/vps-deploy/apps/9router/app.yml
python3 - "$RELEASE" <<'PY'
import json, os, sys
from pathlib import Path
sys.path.insert(0, '/opt/vps-deploy/releases/' + sys.argv[1] + '/lib')
from core import save
cfg = Path('/etc/vps-deploy/apps/9router')
if not (cfg/'host.json').exists():
    profile = {'platform_ref':sys.argv[1], 'dynamic_dir':'/opt/platform/edge/dynamic', 'api_host':'9router-api.tuannguyenviet.site', 'dashboard_host':'9router.tuannguyenviet.site', 'dashboard_alias_host':'9router-admin.tuannguyenviet.site', 'work_dir':'/opt/9router', 'compose_project':'9router', 'edge_network':'edge-9router', 'rtk_network':'9router-rtk', 'route_name':'9router.yml'}
    save(cfg/'host.json',profile)
else:
    profile=json.loads((cfg/'host.json').read_text()); profile['platform_ref']=sys.argv[1]; save(cfg/'host.json',profile)
PY
if [[ ! -f /etc/vps-deploy/apps/9router/runtime.env ]]; then
  install -m 0600 "$ENV_SOURCE" /etc/vps-deploy/apps/9router/runtime.env
fi
id deploy-9router &>/dev/null || useradd --create-home --shell /bin/sh --user-group deploy-9router
bash "$RELEASE_DIR/install/install-key.sh" "$PUBLIC_KEY"
install -d -m 0755 /usr/local/libexec
install -m 0755 "$RELEASE_DIR/install/vps-deploy-9router" /usr/local/libexec/vps-deploy-9router
cat > /etc/sudoers.d/vps-deploy-9router.tmp <<'EOF'
deploy-9router ALL=(root) NOPASSWD: /usr/local/libexec/vps-deploy-9router ""
EOF
chmod 0440 /etc/sudoers.d/vps-deploy-9router.tmp
visudo -cf /etc/sudoers.d/vps-deploy-9router.tmp >/dev/null
mv /etc/sudoers.d/vps-deploy-9router.tmp /etc/sudoers.d/vps-deploy-9router
install -m 0644 "$RELEASE_DIR/install/vps-deploy.conf" /etc/tmpfiles.d/vps-deploy.conf
install -m 0644 "$RELEASE_DIR/install/vps-deploy-9router-drain.service" /etc/systemd/system/vps-deploy-9router-drain.service
install -m 0644 "$RELEASE_DIR/install/vps-deploy-9router-drain.timer" /etc/systemd/system/vps-deploy-9router-drain.timer
systemctl daemon-reload
python3 - "$RELEASE_DIR" <<'PY'
import os,sys
parent='/opt/vps-deploy'
temporary=parent+'/.current.tmp.'+str(os.getpid())
os.symlink(sys.argv[1],temporary)
os.replace(temporary,parent+'/current')
fd=os.open(parent,os.O_DIRECTORY)
os.fsync(fd);os.close(fd)
PY
printf 'INSTALLED %s; timer not enabled; adoption not started\n' "$RELEASE"
