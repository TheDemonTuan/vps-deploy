"""mc-hub's public hostnames, read from hosts/oracle-main.yml: the one place that names its domains.

Each app lists its api_host first, then its dashboard_alias_host (the previous domain, kept as a
fallback) when set. zone_id finds the account zone that owns a hostname, so the site and its API
may live in different zones.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
from core import host_registration  # noqa: E402
from tunnel_api import Failure, identity, inventory_list  # noqa: E402

_APPS = host_registration(ROOT, 'oracle-main')['apps']


def hosts(app):
    binding = _APPS[app]
    return [binding['api_host']] + ([binding['dashboard_alias_host']] if binding['dashboard_alias_host'] else [])


def zone_id(client, host):
    zones = [zone for zone in inventory_list(client.get('/zones?per_page=50'))
             if zone.get('account', {}).get('id') == client.account and type(zone.get('name')) is str and
             (host == zone['name'] or host.endswith('.' + zone['name']))]
    if len(zones) != 1:
        raise Failure('EXACT_ACCOUNT_ZONE_REQUIRED')
    return identity(zones[0].get('id'))
