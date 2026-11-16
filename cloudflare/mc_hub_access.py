#!/usr/bin/env python3
"""Put mc-hub's admin surface behind Cloudflare Access; touch nothing else.

One self-hosted app ("MC Hub Admin") covers the admin pages and the admin/auth API on the
site host, linked to one reusable allow policy over exact email addresses. Its first allow
list and identity providers are copied from the OmniRoute admin app (the operator's existing
admin identity); afterwards the script only verifies shape, so dashboard edits to the email
list are kept. The API host needs no Access app: Traefik routes only SSR reads there.
Output is counts and booleans only: this repository's Actions logs are public.
"""
import argparse
import copy
import fnmatch
import json
import sys
from penpot_ingress import Client, Failure, inventory_list
from penpot_apply import domains, identity

SITE = 'minecraft.tuannguyenviet.site'
API = 'minecraft-api.tuannguyenviet.site'
NAME = 'MC Hub Admin'
POLICY = 'MC Hub admins'
SOURCE = 'OmniRoute Admin Dashboard'
PATHS = (SITE + '/admin', SITE + '/api/admin', SITE + '/api/auth')


def uris(app):
    found = []
    for destination in inventory_list(app.get('destinations') or []):
        if destination.get('type') == 'public':
            if type(destination.get('uri')) is not str:
                raise Failure('ACCESS_DOMAIN_POLICY')
            found.append(destination['uri'])
    return sorted(set(found + domains(app)))


def email_rules(policy):
    includes = inventory_list(policy.get('include'))
    if (policy.get('decision') != 'allow' or not includes or policy.get('exclude') or policy.get('require') or
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
        if app not in own and any(fnmatch.fnmatchcase(host, uri.split('/', 1)[0]) for uri in uris(app) for host in (SITE, API)):
            raise Failure('ACCESS_SCOPE_CONFLICT')
    named = [policy for policy in inventory_list(client.get(base + '/policies?per_page=100')) if policy.get('name') == POLICY]
    if len(own) > 1 or len(named) > 1:
        raise Failure('ACCESS_DUPLICATE')
    state = {'base': base, 'app': None, 'policy': None, 'source': None}
    if named:
        policy = client.get(base + '/policies/' + identity(named[0].get('id')))
        if policy.get('id') != named[0]['id'] or policy.get('name') != POLICY:
            raise Failure('ACCESS_POLICY_SHAPE')
        email_rules(policy)
        state['policy'] = policy
    if own:
        app = client.get(base + '/apps/' + identity(own[0].get('id')))
        links = inventory_list(app.get('policies'))
        if (app.get('id') != own[0]['id'] or app.get('type') != 'self_hosted' or uris(app) != sorted(PATHS) or
                app.get('http_only_cookie_attribute') is not True or state['policy'] is None or
                [link.get('id') for link in links] != [state['policy']['id']]):
            raise Failure('ACCESS_APP_DRIFT')
        idps(app)
        state['app'] = app
    if state['app'] is None:
        sources = [app for app in apps if app.get('name') == SOURCE]
        if len(sources) != 1:
            raise Failure('SOURCE_ACCESS_APP_REQUIRED')
        source = client.get(base + '/apps/' + identity(sources[0].get('id')))
        policies = inventory_list(source.get('policies'))
        if source.get('id') != sources[0]['id'] or len(policies) != 1:
            raise Failure('SOURCE_ACCESS_POLICY_SHAPE')
        state['source'] = {'include': email_rules(policies[0]), 'allowed_idps': idps(source)}
    return state


def app_body(policy_id, allowed_idps):
    return {'name': NAME, 'type': 'self_hosted',
            'destinations': [{'type': 'public', 'uri': uri} for uri in PATHS],
            'session_duration': '24h', 'http_only_cookie_attribute': True, 'same_site_cookie_attribute': 'lax',
            'app_launcher_visible': False, 'allowed_idps': list(allowed_idps),
            'auto_redirect_to_identity': len(allowed_idps) == 1,
            'policies': [{'id': policy_id, 'precedence': 1}]}


def run(client, operation):
    state = survey(client)
    before = {'app_present': state['app'] is not None, 'policy_present': state['policy'] is not None}
    if operation == 'apply' and state['app'] is None:
        base, source = state['base'], state['source']
        policy = state['policy'] or client.request('POST', base + '/policies',
            {'name': POLICY, 'decision': 'allow', 'include': copy.deepcopy(source['include'])})
        client.request('POST', base + '/apps', app_body(identity(policy.get('id')), source['allowed_idps']))
        state = survey(client)
        if state['app'] is None:
            raise Failure('ACCESS_VERIFY_FAILED')
    rules = state['policy']['include'] if state['policy'] else state['source']['include']
    return dict(before, operation=operation, paths=list(PATHS), allowed_emails=len(rules),
                protected=state['app'] is not None)


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
