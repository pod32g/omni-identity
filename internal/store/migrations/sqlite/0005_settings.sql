-- Single-row, admin-editable runtime settings. Seeded once from config on first
-- start (the `seeded` flag), after which this row is authoritative.
CREATE TABLE settings (
    id                   INTEGER PRIMARY KEY CHECK (id = 1),
    issuer               TEXT NOT NULL DEFAULT '',
    public_url           TEXT NOT NULL DEFAULT '',
    token_ttl            TEXT NOT NULL DEFAULT '15m',
    refresh_token_ttl    TEXT NOT NULL DEFAULT '720h',
    max_failed_logins    INTEGER NOT NULL DEFAULT 5,
    lockout_duration     TEXT NOT NULL DEFAULT '15m',
    password_min_length  INTEGER NOT NULL DEFAULT 12,
    session_idle_timeout TEXT NOT NULL DEFAULT '0s',
    session_lifetime     TEXT NOT NULL DEFAULT '12h',
    cookie_secure        INTEGER NOT NULL DEFAULT 1,
    seeded               INTEGER NOT NULL DEFAULT 0,
    updated_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO settings (id) VALUES (1);
