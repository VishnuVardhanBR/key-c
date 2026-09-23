"""Run inside the pinned authentik container; fixtures never access the database.

bin/compose exec -T server python - < test/authentik-reuse.py
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
from jwt import encode
from authentik.stages.authenticator_validate.stage import (
    AuthenticatorValidateStageView, COOKIE_NAME_MFA, FlowSkipStageException,
)

MODULE = 'authentik.stages.authenticator_validate.stage'
SHARED = UUID('11111111-1111-4111-8111-111111111111')
OTHER = UUID('22222222-2222-4222-8222-222222222222')


class ReuseTests(unittest.TestCase):
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


unittest.main(verbosity=2)
