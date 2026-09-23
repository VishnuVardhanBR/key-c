#!/usr/bin/env python3
"""Configure this dedicated authentik instance using its supported REST API."""
import json
import os
from pathlib import Path
import secrets
from deployment import load_deployment
import urllib.error
import urllib.parse
import urllib.request

RUNTIME = Path.home() / 'Library/Application Support/key-c'
SECRETS = RUNTIME / 'secrets'
ENV = dict(line.split('=', 1) for line in (SECRETS / 'authentik.env').read_text().splitlines())
BASE = 'http://127.0.0.1:19000/api/v3/'
CONFIG = load_deployment()
AAGUID = CONFIG['key_aaguid']
OWNER_EMAIL = CONFIG['owner_email']
TEAM = CONFIG['team_domain']


def api(path, data=None, method=None):
    request = urllib.request.Request(
        BASE + path, data=None if data is None else json.dumps(data).encode(),
        headers={'Authorization': 'Bearer ' + ENV['AUTHENTIK_BOOTSTRAP_TOKEN'],
                 'Content-Type': 'application/json'},
        method=method or ('GET' if data is None else 'POST'))
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
            return json.loads(body) if body else None
    except urllib.error.HTTPError as error:
        # These endpoints may contain credentials; never echo request bodies.
        detail = error.read().decode()
        for secret in ENV.values():
            detail = detail.replace(secret, '[redacted]')
        raise RuntimeError(f'{request.method} {path}: {error.code}: {detail}') from None


def all_items(path):
    page = 1
    items = []
    while True:
        response = api(path + '?' + urllib.parse.urlencode({'page_size': 100, 'page': page}))
        items.extend(response['results'])
        if not response['pagination']['next']:
            return items
        page += 1


def upsert(path, data, key='name', id_key='pk'):
    matches = [item for item in all_items(path) if item[key] == data[key]]
    if len(matches) > 1:
        raise RuntimeError(f'Ambiguous existing object in {path}')
    if matches:
        identity = matches[0][id_key]
        return api(f'{path}{identity}/', data, 'PATCH')
    return api(path, data)


def bind_policy(target, policy=None, user=None, order=0):
    data = {'target': target, 'policy': policy, 'user': user, 'order': order,
            'enabled': True, 'failure_result': False, 'timeout': 5}
    matches = [b for b in all_items('policies/bindings/')
               if b['target'] == target and b['order'] == order]
    if matches:
        return api(f"policies/bindings/{matches[0]['pk']}/", data, 'PATCH')
    return api('policies/bindings/', data)


def bind_stage(flow, stage, order):
    data = {'target': flow['pk'], 'stage': stage['pk'], 'order': order,
            'evaluate_on_plan': True, 're_evaluate_policies': True}
    matches = [b for b in all_items('flows/bindings/')
               if b['target'] == flow['pk'] and b['order'] == order]
    if matches:
        return api(f"flows/bindings/{matches[0]['pk']}/", data, 'PATCH')
    return api('flows/bindings/', data)


def flow(slug, designation, title, authentication='none'):
    return upsert('flows/instances/', {
        'slug': slug, 'name': slug, 'title': title, 'designation': designation,
        'authentication': authentication, 'denied_action': 'message',
        'policy_engine_mode': 'all'}, key='slug', id_key='slug')


def main():
    os.umask(0o077)
    device = api(f'stages/authenticator/webauthn_device_types/{AAGUID}/')
    if 'YubiKey' not in device['description']:
        raise RuntimeError('The connected key does not match Yubico metadata')
    owner = upsert('core/users/', {'username': CONFIG['owner_username'], 'name': CONFIG['owner_name'],
        'email': OWNER_EMAIL, 'is_active': True, 'groups': [], 'roles': [],
        'path': 'users', 'type': 'internal'}, key='username')
    login = upsert('stages/user_login/', {'name': 'key-c-key-login',
        'session_duration': 'hours=1', 'remember_me_offset': 'seconds=0',
        'remember_device': 'seconds=0', 'terminate_other_sessions': True})
    validation = {
        'name': 'key-c-yubikey-only', 'device_classes': ['webauthn'],
        'not_configured_action': 'deny', 'configuration_stages': [],
        'last_auth_threshold': 'seconds=0', 'webauthn_user_verification': 'required',
        'webauthn_hints': ['security-key'], 'webauthn_allowed_device_types': [AAGUID]}
    verify = upsert('stages/authenticator/validate/', validation)
    # OAuth authorization must also verify a key, even for an existing session
    # established through a local recovery procedure. Reuse at most 30 seconds
    # of a successful WebAuthn verification to avoid two immediate PIN prompts.
    authorization_verify = upsert('stages/authenticator/validate/', {
        **validation, 'name': 'key-c-oauth-key-check', 'last_auth_threshold': 'seconds=30'})
    authentication = flow('key-c-yubikey-login', 'authentication', 'Sign in with your YubiKey')
    authorization = flow('key-c-yubikey-authorize', 'authorization', 'Verify your YubiKey',
                         'require_authenticated')
    enrollment = flow('key-c-key-enrollment', 'stage_configuration', 'Register your YubiKey',
                      'require_authenticated')
    bind_stage(authentication, verify, 10)
    login_binding = bind_stage(authentication, login, 20)
    bind_stage(authorization, authorization_verify, 10)
    owner_policy = upsert('policies/expression/', {
        'name': 'key-c-owner-only', 'expression':
        f"user = request.context.get('pending_user', request.user)\nreturn bool(user and user.pk == {owner['pk']})"})
    # Identity is discovered by WebAuthn, so check it at the login stage.
    # A flow-level owner rule would reject the unauthenticated entry request.
    for binding in all_items('policies/bindings/'):
        if binding['target'] == authentication['pk']:
            api(f"policies/bindings/{binding['pk']}/", method='DELETE')
    api(f"flows/bindings/{login_binding['pk']}/", {'evaluate_on_plan': False}, 'PATCH')
    bind_policy(login_binding['pk'], owner_policy['pk'])
    bind_policy(authorization['pk'], user=owner['pk'])
    enrollment_policy = upsert('policies/expression/', {
        'name': 'key-c-first-key-only', 'expression':
        'from authentik.stages.authenticator_webauthn.models import WebAuthnDevice\n'
        f"return request.user.pk == {owner['pk']} and not WebAuthnDevice.objects.filter(user=request.user).exists()"})
    bind_policy(enrollment['pk'], enrollment_policy['pk'])
    setup = upsert('stages/authenticator/webauthn/', {
        'name': 'key-c-yubikey-enrollment', 'configure_flow': None,
        'user_verification': 'required', 'resident_key_requirement': 'required',
        'authenticator_attachment': 'cross-platform', 'hints': ['security-key'],
        'device_type_restrictions': [AAGUID], 'max_attempts': 3})
    bind_stage(enrollment, setup, 10)
    deny = upsert('policies/expression/', {'name': 'key-c-disabled-default-flow',
                                         'expression': 'return False'})
    existing_flows = all_items('flows/instances/')
    for existing in existing_flows:
        if existing['slug'].startswith('default-') and 'invalidation' not in existing['slug']:
            bind_policy(existing['pk'], deny['pk'], order=-100)
            api(f"flows/instances/{existing['slug']}/", {'policy_engine_mode': 'all'}, 'PATCH')
    invalidate = next(f for f in existing_flows if f['slug'] == 'default-provider-invalidation-flow')
    mappings = [x['pk'] for x in all_items('propertymappings/provider/scope/')
                if x['scope_name'] in ['openid', 'email', 'profile']]
    certificates = all_items('crypto/certificatekeypairs/')
    signing_key = next(x['pk'] for x in certificates if x['name'] == 'authentik Self-signed Certificate')
    oidc_path = SECRETS / 'oidc.json'
    if oidc_path.exists():
        oidc = json.loads(oidc_path.read_text())
    else:
        oidc = {'client_id': 'key-c-cloudflare', 'client_secret': secrets.token_urlsafe(48)}
        oidc_path.write_text(json.dumps(oidc, indent=2) + '\n')
        oidc_path.chmod(0o600)
    provider = upsert('providers/oauth2/', {
        'name': 'key-c Cloudflare Access', 'authentication_flow': authentication['pk'],
        'authorization_flow': authorization['pk'], 'invalidation_flow': invalidate['pk'],
        'client_type': 'confidential', **oidc, 'grant_types': ['authorization_code'],
        'access_code_validity': 'minutes=1', 'access_token_validity': 'minutes=5',
        'refresh_token_validity': 'seconds=0', 'include_claims_in_id_token': True,
        'signing_key': signing_key, 'property_mappings': mappings,
        'redirect_uris': [{'matching_mode': 'strict', 'url': f'https://{TEAM}/cdn-cgi/access/callback'}],
        'sub_mode': 'user_uuid', 'issuer_mode': 'per_provider'})
    app = upsert('core/applications/', {'name': 'Terminal on your Mac', 'slug': 'key-c-cloudflare',
        'provider': provider['pk'], 'policy_engine_mode': 'all',
        'meta_launch_url': 'https://' + CONFIG['hostname']}, key='slug', id_key='slug')
    bind_policy(app['pk'], user=owner['pk'])
    for brand in all_items('core/brands/'):
        api(f"core/brands/{brand['brand_uuid']}/", {
            'branding_title': 'key-c', 'flow_authentication': authentication['pk'],
            'flow_recovery': None, 'flow_user_settings': None, 'flow_unenrollment': None,
            'flow_user_switch': None, 'flow_device_code': None, 'flow_request': None}, 'PATCH')
    state = {'owner_id': owner['pk'], 'owner_email': OWNER_EMAIL, 'key_aaguid': AAGUID,
             'key_model': device['description'], 'authentication_flow': authentication['pk'],
             'authorization_flow': authorization['pk'], 'enrollment_flow': enrollment['pk'],
             'provider_id': provider['pk'], 'application_id': app['pk'], 'team_domain': TEAM}
    (RUNTIME / 'authentik-state.json').write_text(json.dumps(state, indent=2) + '\n')
    api('flows/instances/cache_clear/', {}, 'POST')
    print(json.dumps(state, indent=2))
    print('Key-only flows configured. No key has been enrolled by this command.')


if __name__ == '__main__':
    main()
