#!/usr/bin/env python3
"""Recover this Mac's existing key-c LaunchAgents without changing access rules."""
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import fcntl
import json
import os
import re
import subprocess
import time

RUNTIME = Path.home() / 'Library/Application Support/key-c'
def installed_prefix():
    agents = Path.home() / 'Library/LaunchAgents'
    prefixes = [prefix for prefix in ('com.keyc.remote-', 'com.vishnu.codex-remote-')
                if (agents / f'{prefix}origin.plist').is_file()]
    if len(prefixes) > 1:
        raise RuntimeError('Two Key C installations found; resolve duplicate LaunchAgents first.')
    return prefixes[0] if prefixes else 'com.keyc.remote-'


PREFIX = installed_prefix()
NAMES = ('identity', 'terminal', 'paseo', 'origin', 'tunnel')
DOMAIN = f'gui/{os.getuid()}'
PAUSED = RUNTIME / 'run/services-paused'
STATE = RUNTIME / 'run/watchdog-state.json'
COOLDOWN = 300


def launchctl(*args):
    return subprocess.run(['/bin/launchctl', *args], capture_output=True,
                          text=True, timeout=20)


def service(name):
    return f'{DOMAIN}/{PREFIX}{name}'


def plist(name):
    return Path.home() / 'Library/LaunchAgents' / f'{PREFIX}{name}.plist'


@contextmanager
def service_lock(wait=True):
    (RUNTIME / 'run').mkdir(mode=0o700, parents=True, exist_ok=True)
    with (RUNTIME / 'run/service-control.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def log(message):
    print(f'{datetime.now(timezone.utc).isoformat(timespec="seconds")} {message}', flush=True)


def healthy(name):
    # Probes are local, unauthenticated, and never print response bodies or tokens.
    probes = {
        'terminal': ('http://localhost/', '200', ['--unix-socket', str(RUNTIME / 'run/ttyd.sock')]),
        'paseo': ('http://127.0.0.1:6767/', '200', []),
        'origin': ('http://127.0.0.1:17682/', '403', []),
        'tunnel': ('http://127.0.0.1:17683/ready', '200', []),
    }
    if name == 'identity':
        # The existing identity supervisor owns container health and VM recovery.
        return True
    url, expected, extra = probes[name]
    result = subprocess.run(['/usr/bin/curl', '--silent', '--noproxy', '*',
                             '--max-time', '5', '--output', '/dev/null',
                             '--write-out', '%{http_code}', *extra, url],
                            capture_output=True, text=True, timeout=8)
    return result.returncode == 0 and result.stdout == expected


def recover(name, args, record, now, reason):
    if now - record.get('last_attempt', 0) < COOLDOWN:
        return
    record['last_attempt'] = now
    result = launchctl(*args)
    record['failures'] = 0
    log(f'{name}: {reason}; recovery ' + ('requested' if result.returncode == 0
                                        else f'failed (exit {result.returncode})'))


def check_once():
    os.umask(0o077)
    with service_lock(wait=False) as locked:
        if not locked or PAUSED.exists():
            return
        try:
            state = json.loads(STATE.read_text())
            if not isinstance(state, dict):
                state = {}
        except (OSError, ValueError):
            state = {}
        now = time.time()
        for name in NAMES:
            record = state.setdefault(name, {})
            try:
                status = launchctl('print', service(name))
                if status.returncode:
                    # Never enable a deliberately disabled job or synthesize new plists.
                    if plist(name).is_file():
                        recover(name, ('bootstrap', DOMAIN, str(plist(name))),
                                record, now, 'service was unloaded')
                elif not re.search(r'^\s*pid = \d+\s*$', status.stdout, re.MULTILINE):
                    recover(name, ('kickstart', service(name)), record, now,
                            'service was not running')
                elif healthy(name):
                    record['failures'] = 0
                else:
                    record['failures'] = record.get('failures', 0) + 1
                    log(f'{name}: health check failed ({record["failures"]}/3)')
                    if record['failures'] >= 3:
                        recover(name, ('kickstart', '-k', service(name)), record, now,
                                'three consecutive health checks failed')
            except (OSError, subprocess.SubprocessError) as error:
                log(f'{name}: check could not finish ({type(error).__name__})')
        temporary = STATE.with_suffix('.tmp')
        temporary.write_text(json.dumps(state) + '\n')
        temporary.replace(STATE)


if __name__ == '__main__':
    check_once()
