-- Admin-configurable password complexity (alongside password_min_length).
ALTER TABLE settings ADD COLUMN require_upper  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE settings ADD COLUMN require_lower  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE settings ADD COLUMN require_number INTEGER NOT NULL DEFAULT 1;
ALTER TABLE settings ADD COLUMN require_symbol INTEGER NOT NULL DEFAULT 0;

-- One-time password setup/reset tokens (hashed, single-use, expiring).
CREATE TABLE password_tokens (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    purpose    TEXT NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL
);
CREATE INDEX idx_password_tokens_user ON password_tokens(user_id);
