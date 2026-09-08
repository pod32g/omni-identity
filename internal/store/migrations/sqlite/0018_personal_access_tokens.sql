-- Personal access tokens (docs/BEARER.md): long-lived, individually revocable
-- bearer tokens a signed-in user creates from an enrolled client for scripts
-- and curl. Device-bound (device_id + the token's act claim), so a service
-- that requires a device still applies. id is the token's jti.
CREATE TABLE personal_access_tokens (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL,
    device_id    TEXT NOT NULL,
    client_id    TEXT NOT NULL,
    name         TEXT NOT NULL DEFAULT '',
    scope        TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMP NOT NULL,
    expires_at   TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP NULL,
    revoked_at   TIMESTAMP NULL
);
CREATE INDEX idx_pat_device ON personal_access_tokens(device_id);
CREATE INDEX idx_pat_user ON personal_access_tokens(user_id);
