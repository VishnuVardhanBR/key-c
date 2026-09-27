"""Exercise persistent stop, recovery, and power controls without touching launchd."""
from contextlib import nullcontext
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch
import json
import subprocess
import sys

BIN = Path(__file__).resolve().parents[1] / 'bin'
sys.path.insert(0, str(BIN))
import service_watchdog as watchdog
import menu_control as menu

loader = SourceFileLoader('keyc_control', str(BIN / 'control'))
control = module_from_spec(spec_from_loader(loader.name, loader))
loader.exec_module(control)


class ServiceControls(TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.paused = self.root / 'services-paused'
        self.loaded = set(watchdog.NAMES) | {'watchdog'}
        self.calls = []
        for module in (control, menu, watchdog):
            self.enterContext(patch.object(module, 'PAUSED', self.paused))
            self.enterContext(patch.object(module, 'service_lock', lambda **kw: nullcontext(True)))
        self.enterContext(patch.object(control, 'STATE', self.root / 'state.json'))
        self.enterContext(patch.object(watchdog, 'STATE', self.root / 'watchdog-state.json'))
        self.enterContext(patch.object(menu, 'PREFERENCES', self.root / 'menu.json'))
        self.enterContext(patch.object(control, 'plist', self.plist))
        self.enterContext(patch.object(control, 'launchctl', self.launchctl))
        self.enterContext(patch.object(menu, 'launchctl', self.launchctl))
        for name in (*watchdog.NAMES, 'watchdog'):
            self.plist(name).touch()

    def plist(self, name):
        return self.root / f'{name}.plist'

    def launchctl(self, *args):
        self.calls.append(args)
        name = args[-1].split('/')[-1].removeprefix(watchdog.PREFIX)
        if args[0] == 'print':
            return subprocess.CompletedProcess(args, 0 if name in self.loaded else 1,
                                               stdout='state = running\n pid = 123\n', stderr='')
        if args[0] == 'bootout':
            # Persistent stop must exist before any service is unloaded.
            if name in watchdog.NAMES:
                self.assertTrue(self.paused.exists())
            self.loaded.discard(name)
        if args[0] == 'bootstrap':
            self.loaded.add(Path(args[-1]).stem)
        return subprocess.CompletedProcess(args, 0, stdout='', stderr='')

    def invoke(self, action):
        with patch.object(sys, 'argv', ['control', action]), patch('builtins.print'), \
                patch.object(menu, 'awake_job'):
            control.main()

    def test_start_preserves_existing_processes(self):
        self.invoke('start')
        self.assertFalse(any(c[0] in ('bootout', 'bootstrap') or '-k' in c for c in self.calls))

    def test_stop_persists_and_disables_every_service(self):
        self.invoke('stop')
        self.assertTrue(self.paused.exists())
        self.assertEqual({'watchdog'}, self.loaded)
        disabled = [c[-1] for c in self.calls if c[0] == 'disable']
        self.assertEqual([watchdog.service(n) for n in reversed(watchdog.NAMES)], disabled)

    def test_paused_watchdog_does_nothing(self):
        self.paused.touch()
        with patch.object(watchdog, 'launchctl') as launch:
            watchdog.check_once()
            launch.assert_not_called()

    def test_missing_definition_does_not_partially_start(self):
        self.paused.touch()
        self.plist('tunnel').unlink()
        with self.assertRaises(SystemExit):
            self.invoke('start')
        self.assertTrue(self.paused.exists())
        self.assertEqual([], self.calls)

    def test_failed_start_preserves_pause(self):
        self.paused.touch()
        with patch.object(control, 'launchctl', return_value=subprocess.CompletedProcess([], 1, '', 'failed')):
            with self.assertRaises(SystemExit):
                self.invoke('start')
        self.assertTrue(self.paused.exists())

    def test_awake_setting_does_not_wake_intentionally_stopped_keyc(self):
        self.paused.touch()
        with patch.object(menu, 'awake_job') as awake:
            menu.set_awake(True)
            awake.assert_called_once_with(False)
        self.assertTrue(json.loads(menu.PREFERENCES.read_text())['keep_awake'])

    def test_awake_start_does_not_restart_existing_assertion(self):
        self.loaded.add(menu.AWAKE_LABEL)
        menu.awake_job(True)
        self.assertFalse(any(c[0] in ('bootout', 'bootstrap') or '-k' in c for c in self.calls))

    def test_login_toggle_does_not_stop_current_menu_or_services(self):
        menu.set_login(False)
        self.assertEqual([('disable', f'{watchdog.DOMAIN}/{menu.MENU_LABEL}')], self.calls)

    def test_url_rejects_non_https_or_command_content(self):
        with patch.object(menu, 'RUNTIME', self.root), patch.object(menu, 'settings', return_value={'portal_url': 'file:///etc/passwd'}):
            self.assertIsNone(menu.portal_url())
        with patch.object(menu, 'RUNTIME', self.root), patch.object(menu, 'settings', return_value={'portal_url': 'https://computer.example.org'}):
            self.assertEqual('https://computer.example.org', menu.portal_url())

    def test_watchdog_requires_three_failed_probes_and_cooldown(self):
        state = self.root / 'watchdog-state.json'
        with patch.object(watchdog, 'STATE', state), patch.object(watchdog, 'NAMES', ('origin',)), \
                patch.object(watchdog, 'launchctl', self.launchctl), \
                patch.object(watchdog, 'probe_status', return_value=None), patch('builtins.print'):
            watchdog.check_once()
            watchdog.check_once()
            self.assertFalse(any('-k' in c for c in self.calls))
            watchdog.check_once()
            self.assertEqual(1, sum('-k' in c for c in self.calls))
            for _ in range(3):
                watchdog.check_once()
            self.assertEqual(1, sum('-k' in c for c in self.calls))

    def test_disconnected_tunnel_is_not_restarted_and_recovers(self):
        state = self.root / 'watchdog-state.json'
        with patch.object(watchdog, 'STATE', state), patch.object(watchdog, 'NAMES', ('tunnel',)), \
                patch.object(watchdog, 'launchctl', self.launchctl), \
                patch.object(watchdog, 'probe_status', return_value='503') as probe, patch('builtins.print'):
            for _ in range(6):
                watchdog.check_once()
            self.assertFalse(any('-k' in c for c in self.calls))
            self.assertTrue(json.loads(state.read_text())['tunnel']['disconnected'])
            probe.return_value = '200'
            watchdog.check_once()
            self.assertFalse(json.loads(state.read_text())['tunnel'].get('disconnected', False))

    def test_running_tunnel_is_not_reported_connected_when_readiness_fails(self):
        with patch.object(menu, 'running', return_value=123), \
                patch.object(menu, 'login_enabled', return_value=True), \
                patch.object(menu, 'portal_url', return_value=None), \
                patch.object(menu, 'healthy', return_value=False), \
                patch.object(menu.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '0', '')):
            state = menu.status()
            self.assertEqual(123, state['services']['tunnel'])
            self.assertFalse(state['tunnel_connected'])


if __name__ == '__main__':
    main()
