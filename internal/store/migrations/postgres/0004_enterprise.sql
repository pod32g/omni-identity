-- Audit log of security-relevant events.
CREATE TABLE audit_log (
    id            TEXT PRIMARY KEY,
    created_at    TIMESTAMPTZ NOT NULL,
    event         TEXT NOT NULL,
    actor_user_id TEXT NOT NULL DEFAULT '',
    username      TEXT NOT NULL DEFAULT '',
    client_id     TEXT NOT NULL DEFAULT '',
    ip            TEXT NOT NULL DEFAULT '',
    user_agent    TEXT NOT NULL DEFAULT '',
    success       BOOLEAN NOT NULL DEFAULT TRUE,
    detail        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_audit_log_created ON audit_log(created_at);

-- Account lockout + MFA columns on users.
ALTER TABLE users ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN totp_secret TEXT NOT NULL DEFAULT '';

-- One-time MFA recovery codes (hashed).
CREATE TABLE mfa_recovery_codes (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_mfa_recovery_user ON mfa_recovery_codes(user_id);

-- Pending second-factor challenges between password and MFA steps.
CREATE TABLE login_challenges (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    next       TEXT NOT NULL DEFAULT '',
    req        TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

-- Single-row server secret used to encrypt sensitive columns at rest.
CREATE TABLE app_secrets (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    key_b64    TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

-- Session bookkeeping: idle tracking and recorded auth methods.
ALTER TABLE sessions ADD COLUMN last_seen_at TIMESTAMPTZ;
ALTER TABLE sessions ADD COLUMN amr TEXT NOT NULL DEFAULT '';
