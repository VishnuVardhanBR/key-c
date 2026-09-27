#!/usr/bin/env python3
"""Small, JSON-only backend for the Key C menu app. Never prints credentials."""
from pathlib import Path
import argparse
import json
import os
import plistlib
import re
import subprocess
import sys

from service_watchdog import DOMAIN, NAMES, PAUSED, RUNTIME, healthy, launchctl, plist, service, service_lock

AWAKE_LABEL = 'com.keyc.awake'
MENU_LABEL = 'com.keyc.menubar'
AGENTS = Path.home() / 'Library/LaunchAgents'
PREFERENCES = RUNTIME / 'menu-settings.json'


def require(result):
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f'Command failed ({result.returncode}).')
    return result


def settings():
    if not PREFERENCES.exists():
        return {'keep_awake': True}
    value = json.loads(PREFERENCES.read_text())
    if not isinstance(value, dict):
        raise ValueError('Invalid menu settings.')
    return value


def save_settings(value):
    temporary = PREFERENCES.with_suffix('.tmp')
    temporary.write_text(json.dumps(value) + '\n')
    temporary.chmod(0o600)
    temporary.replace(PREFERENCES)


def awake_job(enabled):
    target = f'{DOMAIN}/{AWAKE_LABEL}'
    if enabled:
        require(launchctl('enable', target))
        if launchctl('print', target).returncode:
            require(launchctl('bootstrap', DOMAIN, str(AGENTS / f'{AWAKE_LABEL}.plist')))
        # No -k: leave an existing assertion in place.
        require(launchctl('kickstart', target))
    else:
        require(launchctl('disable', target))
        if launchctl('print', target).returncode == 0:
            require(launchctl('bootout', target))


def running(label):
    result = launchctl('print', f'{DOMAIN}/{label}')
    match = re.search(r'^\s*pid = (\d+)\s*$', result.stdout, re.MULTILINE)
    return int(match[1]) if match else None


def portal_url():
    value = settings().get('portal_url')
    deployment = RUNTIME / 'secrets/deployment.json'
    if deployment.is_file():
        value = 'https://' + json.loads(deployment.read_text())['hostname']
    if value and re.fullmatch(r'https://[a-zA-Z0-9.-]+/?', value):
        return value
    return None


def login_enabled():
    path = AGENTS / f'{MENU_LABEL}.plist'
    if not path.exists():
        return False
    result = launchctl('print-disabled', DOMAIN)
    require(result)
    return not re.search(r'"' + re.escape(MENU_LABEL) + r'"\s*=>\s*true', result.stdout)


def status():
    jobs = {}
    for name in NAMES:
        jobs[name] = running(service(name).split('/')[-1])
    lock = subprocess.run(['/usr/bin/defaults', 'read',
                           '/Library/Preferences/com.apple.RemoteManagement',
                           'RestoreMachineState'], capture_output=True, text=True, timeout=5)
    try:
        connected = bool(jobs['tunnel']) and healthy('tunnel')
    except (OSError, subprocess.SubprocessError):
        connected = False
    return {'enabled': not PAUSED.exists(), 'services': jobs,
            'tunnel_connected': connected,
            'keep_awake': bool(settings().get('keep_awake', True)),
            'awake_pid': running(AWAKE_LABEL),
            'open_at_login': login_enabled(),
            'keep_unlocked': lock.returncode == 0 and lock.stdout.strip() == '0',
            'portal_url': portal_url(), 'logs': str(RUNTIME / 'logs')}


def set_enabled(enabled):
    # The existing controller and watchdog serialize service changes together.
    # Stop public access first; never accidentally turn it back on after an error.
    control = str(Path(__file__).resolve().parent / 'control')
    result = subprocess.run([sys.executable, control, 'start' if enabled else 'stop'],
                            capture_output=True, text=True, timeout=150)
    if not enabled:
        with service_lock():
            awake_job(False)
    require(result)
    if enabled:
        with service_lock():
            awake_job(not PAUSED.exists() and bool(settings().get('keep_awake', True)))


def set_awake(enabled):
    with service_lock():
        awake_job(enabled and not PAUSED.exists())
        value = settings()
        value['keep_awake'] = enabled
        save_settings(value)


def set_login(enabled):
    # launchctl disable affects subsequent login loads, not this running app.
    require(launchctl('enable' if enabled else 'disable', f'{DOMAIN}/{MENU_LABEL}'))


def install_jobs(app_path, python_path, portal=None):
    """Add only the menu/awake/watchdog jobs; never reload a working service."""
    for name in NAMES:
        if not plist(name).is_file():
            raise RuntimeError(f'Install Key C services first: missing {name}.')
    AGENTS.mkdir(parents=True, exist_ok=True)
    (RUNTIME / 'logs').mkdir(parents=True, exist_ok=True)
    common = {'RunAtLoad': True, 'ThrottleInterval': 10, 'Umask': 63,
              'WorkingDirectory': str(RUNTIME),
              'EnvironmentVariables': {'HOME': str(Path.home()),
                  'PATH': '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'}}
    jobs = {
        AWAKE_LABEL: {**common, 'ProgramArguments': ['/usr/bin/caffeinate', '-dis'], 'KeepAlive': True},
        MENU_LABEL: {**common, 'ProgramArguments': [str(app_path / 'Contents/MacOS/KeyC')],
                     'KeepAlive': {'SuccessfulExit': False}},
    }
    if not plist('watchdog').exists():
        jobs[service('watchdog').split('/')[-1]] = {
            **common, 'ProgramArguments': [python_path, str(RUNTIME / 'app/bin/service_watchdog.py')],
            'StartInterval': 60, 'ProcessType': 'Background'}
    for label, job in jobs.items():
        job.update(Label=label, StandardOutPath=str(RUNTIME / 'logs' / f'{label}.log'),
                   StandardErrorPath=str(RUNTIME / 'logs' / f'{label}.log'))
        path = AGENTS / f'{label}.plist'
        path.write_bytes(plistlib.dumps(job))
        path.chmod(0o600)
    with service_lock():
        value = settings()
        if portal:
            if not re.fullmatch(r'https://[a-zA-Z0-9.-]+/?', portal):
                raise ValueError('Use an HTTPS portal URL without a path.')
            value['portal_url'] = portal
        save_settings(value)
        awake_job(not PAUSED.exists() and bool(value.get('keep_awake', True)))
    # Existing watchdog configuration is deliberately preserved.
    if launchctl('print', service('watchdog')).returncode:
        require(launchctl('bootstrap', DOMAIN, str(plist('watchdog'))))
    require(launchctl('enable', f'{DOMAIN}/{MENU_LABEL}'))
    if launchctl('print', f'{DOMAIN}/{MENU_LABEL}').returncode:
        require(launchctl('bootstrap', DOMAIN, str(AGENTS / f'{MENU_LABEL}.plist')))
    require(launchctl('kickstart', f'{DOMAIN}/{MENU_LABEL}'))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['status', 'enabled', 'awake', 'login'])
    parser.add_argument('value', nargs='?', choices=['on', 'off'])
    args = parser.parse_args()
    if args.action != 'status':
        if args.value is None:
            parser.error('Specify on or off.')
        {'enabled': set_enabled, 'awake': set_awake, 'login': set_login}[args.action](args.value == 'on')
    print(json.dumps(status()))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(json.dumps({'error': str(error)}))
        sys.exit(1)
