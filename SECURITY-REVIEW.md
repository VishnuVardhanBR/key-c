# Security review

This is a bounded source/configuration review, not a penetration-test certification. Each operator must validate their own hosts, keys, policies, and service lifecycle.

## Controls

- Cloudflare Access admits the configured owner through the designated authentik OIDC provider. Both the tunnel and gateway validate the Access audience.
- A dedicated WebAuthn stage requires user verification with zero reuse threshold. A following login stage supplies a new authentication event. The gateway verifies signature, issuer, audience, owner, nonce, state, PKCE, and authentication time.
- A 30-second, single-use ticket opens one browser control connection. App documents use one-use grants; APIs and WebSockets require the active in-memory capability.
- A new valid browser replaces the old one. Idle expiry, Access-token expiry, and control disconnection revoke all associated app access. Background traffic does not extend idle.
- Proxying strips browser cookies, Access assertions, and capability query parameters. Static files are constrained by realpath to the installed application bundle.
- The terminal uses a Unix socket. Gateway, identity, and Paseo listeners bind to loopback. Public identity management, recovery, and enrollment routes are blocked after provisioning.

## Findings addressed

| Finding | Correction |
| --- | --- |
| Retained identity cookies could replace a new key ceremony | Dedicated mandatory WebAuthn authorization flow; signed fresh identity claims checked by the gateway |
| OIDC freshness parameters alone were insufficient in the pinned identity-server implementation | Flow-level key verification and a new login event; no dependence on `prompt=login` or `max_age=0` alone |
| Blocking admin pages left management APIs reachable | Exact login API allowlist and denial of other identity APIs, including requests with valid admin credentials |
| Malformed request targets or aborted launch bodies could terminate the gateway | Caught parse/read failures and regression tests proving subsequent session requests still work |
| Paseo transitives had published advisories | Pinned overrides for `uuid`, `markdown-it`, `linkify-it`, `ai`, and `undici`; audit and compatibility checks required on updates |

An independent reviewer verified the original gateway corrections and its 17 regression tests. Publication adds separate configuration checks. The generalized installer has not been exercised through fresh hardware enrollment on every supported Mac; the manual acceptance steps in SETUP.md remain necessary.

## Trust boundaries

An unlocked browser and local processes have the Mac user's permissions. The idle timer measures input, not human presence. Malicious software in an unlocked client can generate activity or copy credentials. Cloudflare terminates public HTTPS and is trusted with application traffic.

The default Paseo daemon is passwordless on loopback and trusts local processes. It validates hostnames and WebSocket origins. Do not bind it to a public/LAN address. If a shared Paseo home already has password authentication or a conflicting listener, resolve that explicitly before installation; the included gateway assumes the documented loopback setup.

Optional phone pairing uses Paseo's relay authentication and bypasses the web gateway's YubiKey, timeout, and browser replacement rules. Treat pairing links as credentials. Enabling the hosted Paseo origin adds that origin to the daemon's trust boundary. See [Paseo security](https://paseo.sh/docs/security).

Protect private runtime files, backups, enrolled hardware keys, and the phone. Check [Yubico advisories](https://www.yubico.com/support/security-advisories/) for the key model in use. Recovery requires local administrative access and deliberate temporary enrollment; no public password/recovery fallback should remain.

Tests use generated signing keys, fixture identities, and shortened timers. A successful test run does not validate a particular Cloudflare account, physical key, browser, reboot behavior, or recovery procedure.
