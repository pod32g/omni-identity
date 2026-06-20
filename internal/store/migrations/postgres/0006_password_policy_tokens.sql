-- Admin-configurable password complexity (alongside password_min_length).
ALTER TABLE settings ADD COLUMN require_upper  BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE settings ADD COLUMN require_lower  BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE settings ADD COLUMN require_number BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE settings ADD COLUMN require_symbol BOOLEAN NOT NULL DEFAULT FALSE;

-- One-time password setup/reset tokens (hashed, single-use, expiring).
CREATE TABLE password_tokens (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    purpose    TEXT NOT NULL,
    used       BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_password_tokens_user ON password_tokens(user_id);
