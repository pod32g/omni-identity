# Passkeys (WebAuthn)

Omni Identity supports standards-compliant WebAuthn / FIDO2 credentials —
platform passkeys (Touch ID, Windows Hello, Android, iCloud/Google Password
Manager) and roaming security keys — as a sign-in method for **every** Omni
user, local or LDAP-backed. The directory keeps owning the password; Omni
owns the passkey, exactly like Omni's TOTP layer today.

Implementation: `github.com/go-webauthn/webauthn` (FIDO2-conformant server
library). No Omni-specific protocol; any WebAuthn authenticator works.

## What is verified

| Check | Where |
|---|---|
| Challenge freshness and single use | server-side `webauthn_ceremonies` row, 5-minute TTL, deleted on first finish |
| RP ID | host name of the public URL; the authenticator data's `rpIdHash` must match |
| Origin | scheme + host (+ port) of the public URL, compared against `clientDataJSON.origin` |
| Signature, public key algorithm, attested credential parsing | library |
| Sign counter | stored and compared; a regression is a **clone warning** and the login is refused |
| User presence / user verification flags | read from the assertion's authenticator data for the MFA policy |
| Credential ownership | username-first logins only accept credentials of that user; discoverable logins resolve the user by the opaque user handle |

Attestation is requested as `none`; Omni does not maintain an FIDO metadata
allowlist (that is enterprise policy, not homelab identity). The credential
record (public key, AAGUID, flags, counter, transports) is stored as JSON;
it contains nothing secret.

Because WebAuthn forbids IP addresses as RP IDs, passkeys are only offered
when the public URL uses a DNS host name. With an IP-address public URL the
login page hides the button and the account page explains why.

## Registration

`/account/passkeys` → **Create passkey**. The browser helper at
`/static/webauthn.js` (same origin, CSP-compatible) calls
`POST /account/passkeys/begin`, runs `navigator.credentials.create()` with
`residentKey: preferred`, `userVerification: preferred`, then
`POST /account/passkeys/finish`. Existing credentials are excluded, so the
same authenticator cannot be registered twice. Users name each passkey and
can remove them; admins can remove all of a user's passkeys from the user's
page (lost authenticator).

The user handle sent to authenticators is a random 32-byte value assigned on
first registration — never the user id or username.

## Login and the MFA policy

**Sign in with a passkey** on the login page. With a username typed, the
challenge lists that user's credentials (`allowCredentials`); without one, the
browser is asked for a discoverable credential. Unknown usernames and users
without passkeys get an indistinguishable discoverable challenge, so the
endpoint does not reveal which accounts exist or have passkeys.

Authentication method references (RFC 8176) recorded on the session and in
ID tokens:

| How the user signed in | `amr` |
|---|---|
| password | `pwd` |
| password + TOTP | `pwd otp mfa` |
| passkey **with** user verification (PIN / biometric) | `webauthn user mfa` |
| passkey **without** user verification, no TOTP enrolled | `webauthn user` |
| passkey without user verification + TOTP | `webauthn user otp mfa` |

Policy, deliberately not hard-coded as "passkey → TOTP":

- A passkey assertion whose authenticator data carries the **UV** flag proves
  possession *and* a local PIN/biometric. That is phishing-resistant
  multi-factor authentication; no TOTP prompt follows even when the user has
  TOTP enabled.
- A passkey **without** UV (a security key tapped without PIN) is one factor.
  If the user has TOTP enabled they complete it; otherwise they are signed in
  with a single-factor `amr`. Relying parties can read `amr` to decide.

`userVerification: preferred` (rather than `required`) keeps PIN-less
security keys usable; the policy above makes the security consequence
explicit instead of silently accepting a weaker login as MFA.

## Audit and metrics

Events: `passkey.registered`, `passkey.register.failed`, `passkey.removed`,
`admin.passkeys.reset`, `passkey.login.success` (first factor accepted, TOTP
pending), `passkey.login.failed`, and the usual `login.success` with detail
`passkey uv=true|false`. Metrics: `omni_identity_logins_total{source="passkey",result}`.

## Relationship to devices

Passkeys are a *user* credential; enrolled devices are a *device* credential.
They compose: a user can approve a device enrollment or a Linux login with a
passkey in their browser, and the resulting ID token records both
(`amr: ["webauthn","user","mfa"]`, `device_id`, `device_trust`).

Making Omni-Auth a passkey *provider* (an authenticator) is a separate
project and is not part of this work.
