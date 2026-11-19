#!/usr/bin/env python3
"""Put mc-hub's admin surface behind Cloudflare Access; touch nothing else.

One self-hosted app ("MC Hub Admin") covers the admin pages and the admin/auth API on every
site host (mc-hub's api_host and fallback alias in hosts/oracle-main.yml). Like the OmniRoute
admin app, it is its own policy source: one app-scoped allow
policy over exact email addresses (the token cannot create reusable policies). The first
allow list and identity providers are copied from the OmniRoute admin app; afterwards the
script only verifies shape, so dashboard edits to the email list are kept. The API host needs
no Access app: Traefik routes only SSR reads there.
Output is counts and booleans only: this repository's Actions logs are public.
"""
import argparse
import copy
import fnmatch
import json
import sys
from mc_hub_hosts import hosts
from tunnel_api import Client, Failure, domains, identity, inventory_list

SITES = tuple(hosts('mc-hub'))
APIS = tuple(hosts('mc-hub-api'))
NAME = 'MC Hub Admin'
POLICY = 'MC Hub admins'
SOURCE = 'OmniRoute Admin Dashboard'
PATHS = tuple(host + path for host in SITES for path in ('/admin', '/api/admin', '/api/auth'))


def uris(app):
    found = []
    for destination in inventory_list(app.get('destinations') or []):
        if destination.get('type') == 'public':
            if type(destination.get('uri')) is not str:
                raise Failure('ACCESS_DOMAIN_POLICY')
            found.append(destination['uri'])
    return sorted(set(found + domains(app)))


def email_rules(app):
    """The app's single allow policy; its includes must be exact email addresses."""
    policies = inventory_list(app.get('policies'))
    includes = inventory_list(policies[0].get('include')) if len(policies) == 1 else []
    if (len(policies) != 1 or policies[0].get('decision') != 'allow' or not includes or
            policies[0].get('exclude') or policies[0].get('require') or
            any(set(rule) != {'email'} or type(rule['email']) is not dict or type(rule['email'].get('email')) is not str or
                '@' not in rule['email']['email'] or '*' in rule['email']['email'] for rule in includes)):
        raise Failure('ACCESS_POLICY_SHAPE')
    return includes


def idps(app):
    value = app.get('allowed_idps')
    if type(value) is not list or not value or any(type(item) is not str for item in value):
        raise Failure('ACCESS_IDP_POLICY')
    return value


def survey(client):
    base = '/accounts/' + client.account + '/access'
    apps = inventory_list(client.get(base + '/apps?per_page=100'))
    own = [app for app in apps if app.get('name') == NAME]
    for app in apps:
        if app not in own and any(fnmatch.fnmatchcase(host, uri.split('/', 1)[0]) for uri in uris(app) for host in SITES + APIS):
            raise Failure('ACCESS_SCOPE_CONFLICT')
    if len(own) > 1:
        raise Failure('ACCESS_DUPLICATE')
    state = {'base': base, 'app': None, 'source': None}
    if own:
        app = client.get(base + '/apps/' + identity(own[0].get('id')))
        if (app.get('id') != own[0]['id'] or app.get('type') != 'self_hosted' or uris(app) != sorted(PATHS) or
                app.get('http_only_cookie_attribute') is not True):
            raise Failure('ACCESS_APP_DRIFT')
        email_rules(app)
        idps(app)
        state['app'] = app
    else:
        sources = [app for app in apps if app.get('name') == SOURCE]
        if len(sources) != 1:
            raise Failure('SOURCE_ACCESS_APP_REQUIRED')
        source = client.get(base + '/apps/' + identity(sources[0].get('id')))
        if source.get('id') != sources[0]['id']:
            raise Failure('SOURCE_ACCESS_POLICY_SHAPE')
        state['source'] = {'include': email_rules(source), 'allowed_idps': idps(source)}
    return state


def app_body(include, allowed_idps):
    return {'name': NAME, 'type': 'self_hosted',
            'destinations': [{'type': 'public', 'uri': uri} for uri in PATHS],
            'session_duration': '24h', 'http_only_cookie_attribute': True, 'same_site_cookie_attribute': 'lax',
            'app_launcher_visible': False, 'allowed_idps': list(allowed_idps),
            'auto_redirect_to_identity': len(allowed_idps) == 1,
            'policies': [{'name': POLICY, 'decision': 'allow', 'include': copy.deepcopy(include), 'precedence': 1}]}


def run(client, operation):
    state = survey(client)
    present = state['app'] is not None
    if operation == 'apply' and not present:
        source = state['source']
        client.request('POST', state['base'] + '/apps', app_body(source['include'], source['allowed_idps']))
        state = survey(client)
        if state['app'] is None:
            raise Failure('ACCESS_VERIFY_FAILED')
    rules = email_rules(state['app']) if state['app'] else state['source']['include']
    return {'operation': operation, 'app_present': present, 'paths': list(PATHS),
            'allowed_emails': len(rules), 'protected': state['app'] is not None}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--operation', choices=('survey', 'apply'), required=True)
    args = parser.parse_args()
    print(json.dumps(run(Client(), args.operation), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (Failure, KeyError, TypeError, AttributeError) as error:
        print(str(error) if isinstance(error, Failure) else 'CLOUDFLARE_INVENTORY_POLICY', file=sys.stderr)
        sys.exit(1)
