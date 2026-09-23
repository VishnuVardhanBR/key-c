"""Preserve the authenticated owner when MFA reuse skips user discovery."""
from textwrap import dedent


def login_context_expression(owner_id):
    return dedent(f"""\
        from authentik.events.signals import get_login_event

        plan = context['flow_plan']
        if 'pending_user' not in plan.context:
            user = request.http_request.user
            event = get_login_event(request.http_request)
            if (user.is_authenticated and user.is_active and user.pk == {int(owner_id)}
                    and event and event.user.get('pk') == user.pk
                    and event.context.get('auth_method') == 'auth_webauthn_pwl'):
                plan.context['pending_user'] = user
                plan.context['auth_method'] = event.context['auth_method']
                plan.context['auth_method_args'] = dict(event.context.get('auth_method_args', {{}}))
        # Always run the login stage: missing context must deny, not skip login.
        return True
        """)


def configure_login_context(setup, login_binding, owner_id):
    policy = setup.upsert('policies/expression/', {
        'name': 'terminal-fresh-login-context',
        'expression': login_context_expression(owner_id)})
    setup.api(f"flows/bindings/{login_binding['pk']}/", {
        'evaluate_on_plan': False, 're_evaluate_policies': True}, 'PATCH')
    setup.bind_policy(login_binding['pk'], policy['pk'])
