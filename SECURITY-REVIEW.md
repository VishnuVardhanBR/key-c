# Security review

This is a bounded source/configuration review, not a penetration-test certification. Each operator must validate their own hosts, keys, policies, and service lifecycle.

## Controls

- Cloudflare Access admits the configured owner through the designated authentik OIDC provider. Both the tunnel and gateway validate the Access audience.
- Authentication, Access authorization, and gateway authorization share one WebAuthn stage with required user verification and a 30-second reuse threshold. Its signed, browser-held MFA cookie permits immediate redirects and refreshes without another key ceremony; the window is not renewed by reuse. A following login stage supplies a new authentication event. The gateway verifies signature, issuer, audience, owner, nonce, state, PKCE, and authentication time; that event can reuse a physical verification from the preceding 30 seconds.
- A 30-second, single-use ticket opens one browser control connection. App documents use one-use grants; APIs and WebSockets require the active in-memory capability.
- A new valid browser replaces the old one. Idle expiry, Access-token expiry, and control disconnection revoke all associated app access. Background traffic does not extend idle.
- Proxying strips browser cookies, Access assertions, and capability query parameters. Static files are constrained by realpath to the installed application bundle.
- noVNC uses the same one-use document grants and active session checks. Its binary WebSocket connects only to a fixed loopback VNC port, closes on session revocation, and bounds buffering. Browser-supplied host/port values cannot select a destination.
- The terminal uses a Unix socket. Gateway, identity, and Paseo listeners bind to loopback. Public identity management, recovery, and enrollment routes are blocked after provisioning.

## Findings addressed

| Finding | Correction |
| --- | --- |
| Retained identity cookies could replace a new key ceremony | Gateway authorization requires the shared WebAuthn stage; only its signed MFA cookie permits reuse for 30 seconds, after which the key is required again |
| OIDC freshness parameters alone were insufficient in the pinned identity-server implementation | Flow-level key verification and a new login event; no dependence on `prompt=login` or `max_age=0` alone |
| Blocking admin pages left management APIs reachable | Exact login API allowlist and denial of other identity APIs, including requests with valid admin credentials |
| Malformed request targets or aborted launch bodies could terminate the gateway | Caught parse/read failures and regression tests proving subsequent session requests still work |
| Paseo transitives had published advisories | Pinned overrides for `uuid`, `markdown-it`, `linkify-it`, `ai`, and `undici`; audit and compatibility checks required on updates |

An independent reviewer verified the original gateway corrections and its 17 regression tests. Publication adds separate configuration checks. The generalized installer has not been exercised through fresh hardware enrollment on every supported Mac; the manual acceptance steps in SETUP.md remain necessary.

## Review of 30-second key reuse

The September 23, 2026 review found no demonstrated bypass of the approved reuse window. The repository's 23 automated tests and six isolated tests of the installed authentik cookie helpers passed. Those helper tests use fixture signing keys and mocked devices; physical prompt counts and browser refresh behavior before and after expiry still require acceptance testing.

One conditional medium hardening finding remains open: authentik 2026.8.3 [emits the MFA reuse cookie without Secure or HttpOnly](https://github.com/goauthentik/authentik/blob/version/2026.8.3/authentik/stages/authenticator_validate/stage.py#L395-L419). This was confirmed against the installed cookie helper; the final browser-facing MFA response was not captured, so edge enforcement remains unverified. The signed cookie is bound to the stage and enrolled device record, not a particular browser or session. Exploitation requires an additional compromise during its short lifetime, such as cookie theft together with a usable owner session or script execution on the identity origin. Verify or enforce both flags on the final response. No cookie-hardening fix is included in this change.

## Desktop setup

noVNC is pinned and served locally; no CDN or independent public proxy is used. The macOS setup helper temporarily blocks inbound non-loopback VNC traffic, then installs a root-owned loopback listener without changing SIP. Verify its binding after installation, reboot, system updates, and Sharing-setting changes. The legacy VNC password option stays off; Mac account authentication is additional to key-c's YubiKey check. The open viewer holds authentication state and clipboard text in memory and clears its UI on disconnect. No browser storage is used for credentials; password-manager behavior is controlled by the client browser.

The VNC backend itself does not enforce key-c's single-browser rule for other local clients. Processes already running locally can reach it and still need the Mac's VNC authentication. Disconnecting key-c does not lock the physical macOS desktop.

## Trust boundaries

An unlocked browser and local processes have the Mac user's permissions. The idle timer measures input, not human presence. Malicious software in an unlocked client can generate activity or copy credentials. Cloudflare terminates public HTTPS and is trusted with application traffic.

The default Paseo daemon is passwordless on loopback and trusts local processes. It validates hostnames and WebSocket origins. Do not bind it to a public/LAN address. If a shared Paseo home already has password authentication or a conflicting listener, resolve that explicitly before installation; the included gateway assumes the documented loopback setup.

Optional phone pairing uses Paseo's relay authentication and bypasses the web gateway's YubiKey, timeout, and browser replacement rules. Treat pairing links as credentials. Enabling the hosted Paseo origin adds that origin to the daemon's trust boundary. See [Paseo security](https://paseo.sh/docs/security).

Protect private runtime files, backups, enrolled hardware keys, and the phone. Check [Yubico advisories](https://www.yubico.com/support/security-advisories/) for the key model in use. Recovery requires local administrative access and deliberate temporary enrollment; no public password/recovery fallback should remain.

Tests use generated signing keys, fixture identities, and shortened timers. A successful test run does not validate a particular Cloudflare account, physical key, browser, reboot behavior, or recovery procedure.
