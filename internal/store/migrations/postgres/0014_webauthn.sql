-- WebAuthn / passkeys. Credentials belong to Omni users regardless of auth
-- source (local or LDAP): the directory still owns the password, Omni owns the
-- passkey. Only public keys and counters are stored.
ALTER TABLE users ADD COLUMN webauthn_handle TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX idx_users_webauthn_handle ON users(webauthn_handle) WHERE webauthn_handle <> '';

CREATE TABLE webauthn_credentials (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            TEXT NOT NULL DEFAULT '',
    credential      TEXT NOT NULL,
    aaguid          TEXT NOT NULL DEFAULT '',
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL,
    last_used_at    TIMESTAMPTZ
);
CREATE INDEX idx_webauthn_credentials_user ON webauthn_credentials(user_id);

-- Pending registration/authentication ceremonies (the challenge between the
-- begin and finish steps). Single-use, short-lived.
CREATE TABLE webauthn_ceremonies (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL DEFAULT '',
    purpose      TEXT NOT NULL,
    session_data TEXT NOT NULL,
    next         TEXT NOT NULL DEFAULT '',
    req          TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_webauthn_ceremonies_expires ON webauthn_ceremonies(expires_at);

-- Record which first factor preceded a pending TOTP step so the session's amr
-- is accurate (pwd vs. a passkey without user verification).
ALTER TABLE login_challenges ADD COLUMN amr TEXT NOT NULL DEFAULT 'pwd';
