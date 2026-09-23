#!/usr/bin/env python3
"""Require a key check for each attachment, with 30-second browser reuse."""
import importlib.util
import json
import os
from pathlib import Path
import secrets
from fresh_login_policy import configure_login_context

spec = importlib.util.spec_from_file_location('setup', Path(__file__).with_name('configure-authentik.py'))
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)
os.umask(0o077)
path = setup.SECRETS / 'fresh-oidc.json'
if path.exists():
    credentials = json.loads(path.read_text())
else:
    credentials = {'client_id': 'terminal-fresh', 'client_secret': secrets.token_urlsafe(48)}
    path.write_text(json.dumps(credentials) + '\n')
    path.chmod(0o600)
state = json.loads((setup.RUNTIME / 'authentik-state.json').read_text())
owner_id = state['owner_id']
base = setup.api(f"providers/oauth2/{state['provider_id']}/")
flow = setup.flow('terminal-fresh-authorize', 'authorization', 'Sign in with your YubiKey',
                  'require_authenticated')
validate = setup.upsert('stages/authenticator/validate/', {
    # Must be the same stage ID used by the outer Access login. A separate
    # stage with the same threshold cannot reuse authentik's signed MFA cookie.
    'name': 'key-c-yubikey-only', 'device_classes': ['webauthn'],
    'not_configured_action': 'deny', 'configuration_stages': [],
    'last_auth_threshold': 'seconds=30', 'webauthn_user_verification': 'required',
    'webauthn_hints': ['security-key'], 'webauthn_allowed_device_types': [setup.AAGUID]})
login = setup.upsert('stages/user_login/', {'name': 'terminal-fresh-login-event',
    'session_duration': 'hours=1', 'remember_me_offset': 'seconds=0',
    'remember_device': 'seconds=0', 'terminate_other_sessions': True})
setup.bind_stage(flow, validate, 10)
login_binding = setup.bind_stage(flow, login, 20)
# Run only after key validation succeeds, including its signed 30-second reuse.
configure_login_context(setup, login_binding, owner_id)
setup.bind_policy(flow['pk'], user=owner_id)
provider = setup.upsert('providers/oauth2/', {
    **{k: base[k] for k in ['authentication_flow', 'invalidation_flow', 'signing_key', 'property_mappings']},
    'name': 'Terminal fresh YubiKey verification', 'authorization_flow': flow['pk'],
    'client_type': 'confidential', **credentials, 'grant_types': ['authorization_code'],
    'access_code_validity': 'minutes=1', 'access_token_validity': 'minutes=1',
    'refresh_token_validity': 'seconds=0', 'include_claims_in_id_token': True,
    'redirect_uris': [{'matching_mode': 'strict', 'url': 'https://' + setup.CONFIG['hostname'] + '/callback'}],
    'sub_mode': 'user_id', 'issuer_mode': 'per_provider'})
app = setup.upsert('core/applications/', {'name': 'Terminal fresh key check', 'slug': 'terminal-fresh',
    'provider': provider['pk'], 'policy_engine_mode': 'all', 'meta_launch_url': 'https://' + setup.CONFIG['hostname']},
    key='slug', id_key='slug')
setup.bind_policy(app['pk'], user=owner_id)
setup.api('flows/instances/cache_clear/', {}, 'POST')
print('Fresh key flow installed; provider ID:', provider['pk'])
