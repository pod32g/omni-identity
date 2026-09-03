# Linux Login Proof of Concept

**Answers:** *Can an enrolled Linux endpoint safely establish an interactive
Linux user identity using Omni Identity?* — Yes, with the design in
[LINUX-LOGIN-ARCHITECTURE.md](LINUX-LOGIN-ARCHITECTURE.md).

The PoC uses a **disposable Ubuntu 24.04 container** as the endpoint (a
container rather than a VM because the developer Mac has Docker but no VM
tooling; the same files install unchanged on a real Fedora/Ubuntu VM — see
§2). It exercises brief scenarios 26–35 end to end, is fully automated, and
**gates every deploy of `main`** as the `linux-login-poc` job on the
self-hosted Ubuntu runner (Ubuntu container endpoint). The job builds the
candidate image under its own tag (`omni-identity:poc`), runs the throwaway
Omni from it on a private Docker network published on loopback only, and
builds the agent inside the pinned Go builder image, so nothing is exposed on
the LAN, the host's production image tag is never touched, and no toolchain
is required on the runner. The deploy job runs only after it passes:

```bash
endpoint/poc/run-poc.sh                              # ~5 min on first run (image builds)
endpoint/poc/run-poc.sh --keep                       # keep the containers to poke at
POC_BASE=debian:stable-slim endpoint/poc/run-poc.sh  # hosts that cannot pull ubuntu:24.04
OMNI_POC_IMAGE=omni-identity:latest endpoint/poc/run-poc.sh  # Omni from an image (CI mode)
```

## 1. What the harness does

| Step | Scenario | Evidence printed |
|---|---|---|
| Build `omni-identity` for the host and `omni-endpoint:poc` (Ubuntu 24.04 + sshd + `pam_omni.so` compiled from `endpoint/pam` + `omni-enrollment`) | — | image id |
| Start Omni natively on `127.0.0.1:18080` with public URL `http://host.docker.internal:18080` (insecure-HTTP opt-in), bootstrap `admin` and `alice` through the real setup wizard and admin UI | — | `PASS: admin + alice created` |
| `omni-enrollment enroll` in the endpoint; the code is approved *as alice* through the real `/device` pages (the `approve.sh` script stands in for her phone) | 7–12 | enrollment transcript, `omni-enrollment status` |
| Start `omni-enrollment daemon --refresh-interval 15s` (no systemd in a container) | 13–14 | socket present |
| `ssh alice@localhost` via PAM keyboard-interactive: URL + code shown by PAM, approved, ID token verified, identity served by `libnss_omni` (no `/etc/passwd` entry), home created, local offline password chosen | **26, 27** | `uid=2xxxxx(alice)` from the SSH session, `getent passwd alice` |
| `ssh bob@localhost` for a user who has never touched the machine: NSS asks the daemon, the daemon asks Omni, the login proceeds | **26 (non-owner)** | `uid=2xxxxx(bob)` |
| `docker network disconnect` (the container loses all connectivity, including to the host): SSH login with the local password; wrong password refused | **28–31** | `PASS: offline login OK` |
| Daemon killed **and** network down: `ssh omni-recovery@localhost` (PAM → `pam_unix`) + `sudo` | **32** | `PASS: omni-recovery logged in over SSH via pam_unix` |
| Reconnect: daemon renews the device token and refreshes alice's trust (device-bound refresh token) | **33, 34** | daemon log lines |
| alice revokes the device under *My Devices*; daemon's next refresh marks the cache revoked; online **and** offline logins refused; break-glass still works | **35** | `refused for alice`, `login refused` |

Scenarios 1–6 (existing functionality) and 7–25 (enrollment, device auth,
revocation, passkeys) are covered by `go test ./...`; see
`internal/web/device_flow_test.go`, `internal/web/webauthn_test.go`,
`internal/enrollment/agent_test.go`, `internal/enrollment/login_test.go`.

## 2. Manual integration-test procedure (real VM)

1. Deploy Omni (HTTPS, DNS name) and create a user.
2. On a fresh Fedora/Ubuntu VM: download the agent and the PAM/systemd sources
   from **Account → Enroll a device** on your server and follow its install
   commands ([OMNI-ENROLLMENT.md](OMNI-ENROLLMENT.md), `endpoint/pam/Makefile`),
   create the break-glass user (§3), append `omni` to the `passwd:` and
   `group:` lines of `/etc/nsswitch.conf`, and add to `/etc/pam.d/sshd` (and,
   if desired, `login`, `gdm-password`) **above** the `pam_unix` lines:
   ```
   auth     sufficient pam_omni.so
   account  sufficient pam_omni.so
   ```
   In `sshd_config`: `UsePAM yes`, `KbdInteractiveAuthentication yes`,
   `LoginGraceTime 600`.
3. `sudo omni-enrollment enroll --issuer https://identity.example`, approve in
   a browser, `systemctl enable --now omni-enrollment`.
4. `ssh alice@vm`: open the printed link on your phone, approve, then choose
   the local password when prompted. Confirm `id` shows a uid in 200000–299999.
5. Disconnect the VM's network. `ssh alice@vm` with the local password → works.
   Log in as `omni-recovery` on the console → works.
6. Reconnect. `journalctl -u omni-enrollment` shows `device token renewed` and
   `trust refreshed for alice`.
7. In Omni → *My Devices* → Revoke. Within one refresh interval the journal
   shows `trust refresh refused for alice`; `ssh alice@vm` is refused online
   and offline; `omni-recovery` still works.
8. `omni-enrollment unenroll` then `enroll` again to re-establish trust (new
   key, new device id).

## 3. Break-glass account (brief §21)

`omni-recovery` is an ordinary local account in the `sudo`/`wheel` group with a
strong password set at install time (`chpasswd`). It authenticates through
`pam_unix` only:

- `pam_omni.so` returns `PAM_IGNORE` for any account it does not manage and
  whenever the daemon socket is unreachable, so it can never block a local
  login; it is stacked `sufficient` above `pam_unix`, which remains `required`.
- No Omni component reads, writes, disables, or expires the account.
- It needs no network, no Omni, no LDAP, no Tailscale, and no daemon — the
  harness proves this with the daemon killed and the network detached.

Operational use: console or SSH login as `omni-recovery` to repair the
enrollment (`omni-enrollment status`, `unenroll`, `enroll`), fix PAM
configuration, or remove the module. Rotate its password like any local
root-equivalent credential and keep it in the household's password manager.

## 4. Offline login policy summary (brief §20)

- Local password (Argon2id, root-only cache) chosen at first online login;
  never the Omni or LDAP password.
- Valid while `now < last_trust_refresh + offline_validity` (default 7 days),
  the device is not known-revoked, and the cache entry is not revoked.
- `last_trust_refresh` advances on every online login and every successful
  background refresh of the device-bound refresh token.
- A revocation issued while offline takes effect at the first successful
  connection after it; until then the offline window bounds the exposure.
  This is an inherent limit, stated in the threat model (§4.11).

## 5. What the PoC does not show

GDM/desktop greeter (text prompts should render, untested), group/sudo
mapping, TPM-sealed cache, screen-lock specifics. None affects the answer to
the PoC question.

## 6. Future Omni-OS integration notes

- The PAM/daemon split is the natural seam: an Omni-OS installer can enroll
  during first boot (the device grant needs only a second device with a
  browser), preseed `omni-recovery`, and ship `pam_omni.so` + the daemon in
  the base image.
- Replace the file key with a TPM 2.0 key through `enrollment.Signer`; seal
  the user cache to the same key; keep the ES256 algorithm already accepted
  by Omni.
- Add an NSS module only if uid consistency across machines without prior
  login becomes necessary; the deterministic uid mapping already gives
  consistency after first login.
- Use the future local token broker (device architecture §10) so Omni-OS
  apps obtain scoped tokens without storing user credentials.
- Periodic trust renewal, revocation propagation, and offline policy are
  already the daemon's job; an OS integration adds UI (greeter QR code,
  notifications), not protocol.
