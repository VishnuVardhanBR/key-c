"""Run inside the pinned authentik container; fixtures never access the database.

python3 bin/test-authentik
"""
import os
import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import UUID

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'authentik.root.settings')
import django
django.setup()

from django.http import HttpResponse
from django.test import RequestFactory
from jwt import encode
from authentik.policies.expression.evaluator import PolicyEvaluator
from authentik.policies.types import PolicyRequest
from authentik.providers.oauth2.id_token import IDToken
from authentik.stages.user_login.stage import UserLoginStageView
from fresh_login_policy import login_context_expression
from authentik.stages.authenticator_validate.stage import (
    AuthenticatorValidateStageView, COOKIE_NAME_MFA, FlowSkipStageException,
)

MODULE = 'authentik.stages.authenticator_validate.stage'
SHARED = UUID('11111111-1111-4111-8111-111111111111')
OTHER = UUID('22222222-2222-4222-8222-222222222222')


class ReuseFixtures:
    def setUp(self):
        # Use a fixture signing key, never the deployment's tenant secret.
        self.secret = patch(MODULE + '.get_unique_identifier', return_value='test-only-secret')
        self.secret.start()
        self.addCleanup(self.secret.stop)

    def view(self, stage=SHARED, cookie=None, threshold='seconds=30'):
        view = AuthenticatorValidateStageView.__new__(AuthenticatorValidateStageView)
        view.logger = Mock()
        view.request = SimpleNamespace(COOKIES={} if cookie is None else {COOKIE_NAME_MFA: cookie})
        view.executor = SimpleNamespace(
            current_stage=SimpleNamespace(pk=stage, last_auth_threshold=threshold),
            stage_ok=lambda: HttpResponse('stage completed'),
        )
        return view

    def cookie(self):
        response = self.view().set_valid_mfa_cookie(SimpleNamespace(pk=123))
        return response.cookies[COOKIE_NAME_MFA].value


class ReuseTests(ReuseFixtures, unittest.TestCase):
    def test_same_stage_reuses_the_check_across_both_authorization_flows(self):
        cookie = self.cookie()
        for _ in range(2):
            with self.assertRaises(FlowSkipStageException):
                self.view(cookie=cookie).check_mfa_cookie([SimpleNamespace(pk=123)])

    def test_separate_stage_with_identical_threshold_does_not_reuse(self):
        self.assertIsNone(self.view(stage=OTHER, cookie=self.cookie()).check_mfa_cookie(
            [SimpleNamespace(pk=123)]))

    def test_expired_or_forged_cookie_does_not_skip_the_key(self):
        view = self.view()
        for signing_key, expires in [
            (view.cookie_jwt_key, datetime.now() - timedelta(seconds=1)),
            ('incorrect-signing-key-for-test-only', datetime.now() + timedelta(seconds=30)),
        ]:
            cookie = encode({'stage': SHARED.hex, 'device': 123,
                             'exp': expires.timestamp()}, signing_key, algorithm='HS256')
            self.assertIsNone(self.view(cookie=cookie).check_mfa_cookie([SimpleNamespace(pk=123)]))

    def test_cookie_for_another_users_device_does_not_skip(self):
        self.assertIsNone(self.view(cookie=self.cookie()).check_mfa_cookie([SimpleNamespace(pk=456)]))

    def test_zero_threshold_cannot_reuse_or_issue_a_cookie(self):
        view = self.view(cookie=self.cookie(), threshold='seconds=0')
        self.assertIsNone(view.check_mfa_cookie([SimpleNamespace(pk=123)]))
        self.assertNotIn(COOKIE_NAME_MFA, view.set_valid_mfa_cookie(SimpleNamespace(pk=123)).cookies)

    def test_reuse_does_not_renew_the_cookie_window(self):
        view = self.view(cookie=self.cookie())
        view.get_pending_user = lambda: SimpleNamespace(is_anonymous=False)
        view.get_device_challenges = lambda: view.check_mfa_cookie([SimpleNamespace(pk=123)])
        response = view.get(view.request)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(COOKIE_NAME_MFA, response.cookies)


class LoginHandoffTests(ReuseFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.owner = SimpleNamespace(pk=5, username='fixture-owner', is_authenticated=True, is_active=True)
        self.plan = SimpleNamespace(context={})
        self.request = RequestFactory().get('/')
        self.request.user = self.owner
        self.request.session = {'login_event': SimpleNamespace(
            user={'pk': 5}, context={'auth_method': 'auth_webauthn_pwl',
                                    'auth_method_args': {'device': {'pk': 123}}})}

    def prepare_login(self):
        request = PolicyRequest(self.request.user)
        request.http_request = self.request
        request.context['flow_plan'] = self.plan
        evaluator = PolicyEvaluator('login-handoff-test')
        evaluator.set_policy_request(request)
        result = evaluator.evaluate(login_context_expression(5))
        self.assertTrue(result.passing, result.messages)

    def login(self):
        executor = SimpleNamespace(plan=self.plan, flow=SimpleNamespace(slug='fixture-fresh'),
            current_stage=SimpleNamespace(
            name='fresh-login', terminate_other_sessions=False),
            stage_invalid=Mock(return_value=HttpResponse(status=403)))
        view = UserLoginStageView(executor)
        view.request = self.request
        view.set_session_duration = Mock()
        view.set_session_ip = Mock()
        view.is_known_device = Mock(return_value=True)
        view.set_known_device_cookie = Mock(return_value=HttpResponse(status=200))
        with patch('authentik.stages.user_login.stage.login') as login, \
                patch('authentik.stages.user_login.stage.messages.error'):
            response = view.do_login(self.request)
        return response, login

    def test_reused_mfa_reaches_login_with_owner_and_webauthn_method(self):
        validate = self.view(cookie=self.cookie())
        validate.get_pending_user = lambda: SimpleNamespace(is_anonymous=False)
        validate.get_device_challenges = lambda: validate.check_mfa_cookie([SimpleNamespace(pk=123)])
        self.assertEqual(validate.get(validate.request).status_code, 200)
        # This reproduces the original bug after the reuse stage completes.
        response, login = self.login()
        self.assertEqual(response.status_code, 403)
        login.assert_not_called()
        self.prepare_login()
        response, login = self.login()
        self.assertEqual(response.status_code, 200)
        self.assertIs(login.call_args.args[1], self.owner)
        self.assertEqual(self.plan.context['auth_method'], 'auth_webauthn_pwl')
        # The gateway also requires a current auth_time and WebAuthn AMR.
        now = datetime.now()
        provider = SimpleNamespace(client_id='fixture', sub_mode='user_id',
            get_issuer=lambda request: 'https://auth.example.test/', include_claims_in_id_token=False)
        grant = SimpleNamespace(user=self.owner, expires=now + timedelta(minutes=1),
                                auth_time=now, session=None)
        event = SimpleNamespace(context=self.plan.context)
        with patch('authentik.providers.oauth2.id_token.get_login_event', return_value=event):
            token = IDToken.new(provider, grant, self.request)
        self.assertEqual(token.auth_time, int(now.timestamp()))
        self.assertIn('user', token.amr)

    def test_fresh_key_context_is_preserved(self):
        context = {'pending_user': self.owner, 'auth_method': 'auth_webauthn_pwl',
                   'auth_method_args': {'mfa_devices': ['fresh-device']}}
        self.plan.context.update(context)
        self.prepare_login()
        self.assertEqual(self.plan.context, context)

    def test_missing_or_mismatched_key_login_fails_closed(self):
        for event in [None,
                      SimpleNamespace(user={'pk': 6}, context={'auth_method': 'auth_webauthn_pwl'}),
                      SimpleNamespace(user={'pk': 5}, context={'auth_method': 'password'})]:
            self.request.session['login_event'] = event
            self.plan.context.clear()
            self.prepare_login()
            response, login = self.login()
            self.assertEqual(response.status_code, 403)
            login.assert_not_called()

    def test_anonymous_inactive_or_other_owner_is_not_promoted(self):
        for user in [SimpleNamespace(pk=None, is_authenticated=False, is_active=False),
                     SimpleNamespace(pk=5, is_authenticated=True, is_active=False),
                     SimpleNamespace(pk=6, is_authenticated=True, is_active=True)]:
            self.request.user = user
            self.plan.context.clear()
            self.prepare_login()
            self.assertNotIn('pending_user', self.plan.context)


unittest.main(verbosity=2)
