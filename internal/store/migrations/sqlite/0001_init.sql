CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    TIMESTAMP NOT NULL,
    updated_at    TIMESTAMP NOT NULL
);

CREATE TABLE clients (
    client_id          TEXT PRIMARY KEY,
    client_secret_hash TEXT NOT NULL DEFAULT '',
    name               TEXT NOT NULL,
    redirect_uris      TEXT NOT NULL DEFAULT '[]',
    allowed_scopes     TEXT NOT NULL DEFAULT '[]',
    type               TEXT NOT NULL,
    disabled           INTEGER NOT NULL DEFAULT 0,
    created_at         TIMESTAMP NOT NULL,
    updated_at         TIMESTAMP NOT NULL
);

CREATE TABLE sessions (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_secret TEXT NOT NULL,
    user_agent  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMP NOT NULL,
    expires_at  TIMESTAMP NOT NULL
);

CREATE TABLE authorization_codes (
    code_hash             TEXT PRIMARY KEY,
    client_id             TEXT NOT NULL,
    user_id               TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL,
    scope                 TEXT NOT NULL,
    nonce                 TEXT NOT NULL DEFAULT '',
    code_challenge        TEXT NOT NULL DEFAULT '',
    code_challenge_method TEXT NOT NULL DEFAULT '',
    expires_at            TIMESTAMP NOT NULL,
    used                  INTEGER NOT NULL DEFAULT 0,
    created_at            TIMESTAMP NOT NULL
);

CREATE TABLE refresh_tokens (
    id           TEXT PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE,
    client_id    TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    scope        TEXT NOT NULL,
    rotated_from TEXT NOT NULL DEFAULT '',
    revoked      INTEGER NOT NULL DEFAULT 0,
    expires_at   TIMESTAMP NOT NULL,
    created_at   TIMESTAMP NOT NULL
);

CREATE TABLE signing_keys (
    kid        TEXT PRIMARY KEY,
    alg        TEXT NOT NULL,
    public_jwk TEXT NOT NULL,
    private_pem TEXT NOT NULL,
    active     INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
CREATE INDEX idx_authorization_codes_expires ON authorization_codes(expires_at);
