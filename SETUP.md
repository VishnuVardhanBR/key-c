# Setup

This guide provisions a dedicated instance on macOS. Use your own values everywhere; `example.com` and `YOUR_*` are placeholders. Configuration scripts alter default identity flows, so **do not run them against an authentik instance used by other applications**.

## 1. Prerequisites and private settings

Install Node.js 24, Python 3, Docker CLI with Compose v2, Colima, cloudflared, ttyd, and tmux. Ensure those commands are on PATH. Use a compatible YubiKey with FIDO2, a PIN, and a browser that supports USB/NFC security keys. Keep a separate local administrator/recovery path.

In Cloudflare, configure a Zero Trust team and create a self-hosted Access application for `computer.<your-domain>`. Initially use a **Block Everyone** policy and do not publish a tunnel route to the gateway. Record its application audience (AUD) and your team's `*.cloudflareaccess.com` domain.

Copy the example settings outside Git:

```sh
npm ci --ignore-scripts
umask 077
mkdir -p "$HOME/Library/Application Support/key-c/secrets"
cp config/deployment.example.json "$HOME/Library/Application Support/key-c/secrets/deployment.json"
```

Edit that private JSON file with your app/identity hostnames, team domain, application audience, owner email, username/display name, and YubiKey model AAGUID. The two HTTPS hostnames must differ. The configuration loaders reject unedited examples.

To read the AAGUID from an attached FIDO2 key, use a temporary Python environment (this does not enroll a credential):

```sh
python3 -m venv .venv
.venv/bin/pip install fido2
.venv/bin/python - <<'PY'
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2
for device in CtapHidDevice.list_devices():
    print(Ctap2(device).get_info().aaguid)
PY
```

Select the intended key's value if multiple devices are attached. The setup checks that authentik's device metadata recognizes it as a YubiKey. Unsupported or unavailable metadata requires resolving that mismatch before continuing; do not remove the restriction to get past an error.

## 2. Start a dedicated identity service

```sh
bin/init-secrets
colima start key-c --cpu 2 --memory 4 --activate=false --edit
```

In the Colima editor, set `mounts: []` so the dedicated VM does not expose home-directory mounts. Confirm `docker --context colima-key-c info` succeeds. The included containers use only named volumes, never the Docker socket or home bind mounts.

```sh
bin/compose up -d
bin/compose ps
```

Wait for PostgreSQL, authentik server, and worker to become healthy. Docker's loopback port mapping should make the identity service available at `127.0.0.1:19000`; verify this on the host before configuring the tunnel. See [authentik Compose installation](https://docs.goauthentik.io/install-config/install/docker-compose) and [bootstrap environment variables](https://docs.goauthentik.io/install-config/automated-install).

`secrets/authentik.env` contains generated database, signing, bootstrap admin, and API credentials. Keep it private. The bootstrap admin username is `akadmin`; use the generated bootstrap password for the initial admin session. Bootstrap variables only initialize a fresh database.

## 3. Enroll the first key behind temporary setup protection

Enrollment must occur on the final HTTPS identity hostname, so the WebAuthn credential has the correct relying-party scope. A credential enrolled at localhost will not replace one for `auth.<your-domain>`.

1. Create a temporary Cloudflare Access application covering the **entire identity hostname**. Restrict it to your exact owner email, using an already available identity method or one-time email code solely for provisioning. Confirm anonymous requests are blocked before publishing identity routes.
2. Create a named Cloudflare Tunnel. Save its token as the private file `secrets/tunnel-token` with mode `0600`. For provisioning, route **only** the identity hostname to `http://127.0.0.1:19000`, followed by a catch-all 404. Run `bin/tunnel` in a separate terminal. Keep the computer application blocked and unrouted.
3. Open `https://auth.<your-domain>`, complete the temporary Access login, then log in as `akadmin`. Keep this admin session open: the next scripts disable default password/enrollment flows.
4. Run `bin/configure-authentik.py`, then `bin/configure-fresh-login.py`. They create the owner, dedicated flows/providers, and private `authentik-state.json`, `secrets/oidc.json`, and `secrets/fresh-oidc.json`. Owner/provider IDs are discovered dynamically.
5. From the existing authentik admin session, [impersonate the configured owner](https://docs.goauthentik.io/users-sources/user/user_basic_operations). Navigate to `https://auth.<your-domain>/if/flow/key-c-key-enrollment/`. Select the physical YubiKey, enter its PIN, and touch it. The enrollment policy permits only that owner with no existing key.
6. End impersonation and revoke temporary bootstrap sessions/recovery tokens. Apply the final tunnel restrictions from `config/cloudflare.example.json`: block admin/recovery/enrollment pages, allow only named login-flow APIs, deny all other API paths, and retain the catch-all 404. Enrollment's executor is deliberately absent from the final allowlist.
7. Remove the temporary Access application on the identity hostname only after these final restrictions are active. The normal identity sign-in must remain reachable for OIDC. Keep the computer application blocked until the next section is complete.

If provisioning fails, leave temporary owner-only protection and the computer block in place. Restore local administrative access before trying again. Never expose temporary recovery or enrollment links publicly. The key configuration follows [authentik's WebAuthn setup stage](https://docs.goauthentik.io/add-secure-apps/flows-stages/stages/authenticator_webauthn/).

## 4. Connect Cloudflare Access and publish

Use the confidential client ID/secret from private `secrets/oidc.json` to configure a [generic OIDC identity provider in Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/generic-oidc/). Obtain its authorization, token, and JWKS endpoints from:

```text
https://auth.<your-domain>/application/o/key-c-cloudflare/.well-known/openid-configuration
```

The identity-provider callback is `https://<your-team>.cloudflareaccess.com/cdn-cgi/access/callback`. Use `openid email profile` scopes and the `email` claim. Select only this provider for the computer application, require it in the policy, and include only the configured owner email. Set a one-hour session, HttpOnly cookies, and SameSite Lax. Remove the initial Block Everyone policy only when the final owner/provider policy is ready; do not add bypass, service-token, or alternate email-code policies.

Replace every placeholder in `config/cloudflare.example.json` before applying its configuration. Its final computer route must require the correct Access audience at the tunnel and forward only to `127.0.0.1:17682`. Configure proxied DNS for both hostnames to the tunnel. The gateway independently validates the same audience and owner email from private deployment settings.

## 5. Install the local services

Paseo uses `~/.paseo` and port 6767. If it already runs, back up that home and stop its existing supervisor before installing this service; preserve its keypair and pairing files. Do not run two supervisors for the same home. A previously configured daemon password must be handled explicitly before using this passwordless-loopback integration. New Paseo homes default to relay disabled; existing relay settings are preserved. Configure provider credentials through the corresponding agent CLI, outside Git.

Stop the foreground tunnel used during provisioning, then:

```sh
npm test
bin/install-paseo
bin/install-local
bin/install-services
bin/control status
```

Services run as the logged-in macOS user. Runtime files live under `~/Library/Application Support/key-c`; plists are `~/Library/LaunchAgents/com.keyc.remote-*.plist`. The terminal uses a normal login shell. This preserves normal user permissions rather than granting root or bypassing macOS privacy prompts. Enable required macOS permissions through System Settings yourself if a tool needs them.

The pinned Paseo native terminal prebuild has been tested on Apple Silicon. On another platform, verify native dependency support/build prerequisites before deployment. The Mac must remain awake, online, and logged in; these are user LaunchAgents, not pre-login system daemons.

## 6. Desktop (noVNC)

The third option uses [noVNC](https://novnc.com/info.html) 1.7.0, served locally from the pinned dependency. The gateway bridges its authenticated WebSocket to **127.0.0.1:5900 only**; there is no separate websockify port or public VNC route.

On the Mac, run in an interactive terminal:

```sh
sudo python3 bin/setup-novnc
```

The helper temporarily blocks network VNC traffic, waits while you enable Screen Sharing in System Settings, then replaces the listener with a loopback-only copy. Allow only your Mac account; disable permission requests and leave legacy VNC-password access off. noVNC supports Apple's account authentication and asks for the Mac username/password when required. Credentials remain in the open page only; decline browser password-saving prompts.

The helper needs the standard macOS `com.apple/*` firewall anchor and Apple Screen Sharing service layout. It does not edit `/System` or disable SIP. It installs root-owned files at `/Library/key-c/screensharing.plist` and `/Library/LaunchDaemons/com.keyc.screensharing.plist`, leaving the original wildcard service disabled. If setup fails or is cancelled, the helper attempts to stop Screen Sharing and retains the firewall guard if isolation cannot be confirmed. Recheck after macOS updates, reboot, or changing Sharing settings: `sudo lsof -nP -iTCP:5900 -sTCP:LISTEN` must show only `127.0.0.1:5900` and `[::1]:5900`. Other macOS versions may require adjustments; do not continue with a network-facing listener.

To remove the helper, run `sudo python3 bin/setup-novnc --remove`; it leaves Screen Sharing disabled. noVNC requires the Mac to be awake. Locking key-c disconnects the viewer, not the macOS desktop; local applications keep running. Full screen, clipboard transfer, and a mobile keyboard are available in the viewer.

## 7. Acceptance, maintenance, recovery

Before depending on remote access, verify:

- A registered YubiKey opens the chooser; immediate refresh requires a new physical key check. An unregistered key and retained cookies alone cannot open an app.
- Terminal accepts a harmless command, Paseo connects, and noVNC displays the desktop and accepts input. All apps switches without a new sign-in.
- Two minutes without interaction locks and clears the page; output alone cannot keep it open. A new browser replaces the old one; disconnected browsers require fresh sign-in.
- Management APIs and recovery/enrollment routes return 404 publicly, even with an admin token. Invalid Access assertions, unknown hosts, and foreign WebSocket origins are rejected.
- Listeners are loopback or private Unix sockets. Browser disconnection preserves work; service restart, reboot, sleep/wake, and local recovery behave as expected.
- If relay is enabled, test phone reconnection and understand that it bypasses the web gateway's session rules. Protect pairing links as credentials.

Back up PostgreSQL named volumes, private runtime credentials/state, and `~/.paseo` securely. Do not commit these backups. For lost-key recovery, stop public access, use the dedicated local identity service and its protected administrator recovery tools, temporarily permit replacement-key enrollment on the correct HTTPS hostname under owner-only setup protection, then close enrollment and revoke temporary access. Repeat acceptance checks. Plan and test this procedure before losing the only key.

The first-key-only policy prevents routine extra enrollment. Registering a spare or a replacement requires an intentional, local administrator-controlled policy change and closing it afterward. Do not leave a password or email recovery path exposed for normal operation.
