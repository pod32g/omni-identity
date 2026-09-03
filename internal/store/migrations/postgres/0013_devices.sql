-- Devices: enrolled endpoints that hold their own key pair. Only the PUBLIC key
-- is stored; the private key never leaves the endpoint. See
-- docs/DEVICE-IDENTITY-ARCHITECTURE.md.
CREATE TABLE devices (
    id                   TEXT PRIMARY KEY,
    owner_user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                 TEXT NOT NULL DEFAULT '',
    hostname             TEXT NOT NULL DEFAULT '',
    platform             TEXT NOT NULL DEFAULT '',
    architecture         TEXT NOT NULL DEFAULT '',
    public_key           TEXT NOT NULL,
    public_key_algorithm TEXT NOT NULL,
    fingerprint          TEXT NOT NULL UNIQUE,
    previous_fingerprint TEXT NOT NULL DEFAULT '',
    status               TEXT NOT NULL DEFAULT 'active',
    trust_level          TEXT NOT NULL DEFAULT 'enrolled',
    created_at           TIMESTAMPTZ NOT NULL,
    enrolled_at          TIMESTAMPTZ,
    last_seen_at         TIMESTAMPTZ,
    revoked_at           TIMESTAMPTZ
);
CREATE INDEX idx_devices_owner ON devices(owner_user_id);

-- Single-use identifiers (RFC 7523 assertion jti, RFC 9449 DPoP proof jti),
-- kept until they expire so a captured proof cannot be replayed.
CREATE TABLE device_assertion_jtis (
    jti_hash   TEXT PRIMARY KEY,
    device_id  TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_device_jtis_expires ON device_assertion_jtis(expires_at);

-- RFC 8628 device authorization grants (pending until the user approves on
-- /device). device_id is set when the request was authenticated by an enrolled
-- device, binding the resulting user tokens to that device.
CREATE TABLE device_codes (
    id               TEXT PRIMARY KEY,
    device_code_hash TEXT NOT NULL UNIQUE,
    user_code        TEXT NOT NULL UNIQUE,
    client_id        TEXT NOT NULL,
    scope            TEXT NOT NULL,
    device_id        TEXT NOT NULL DEFAULT '',
    device_name      TEXT NOT NULL DEFAULT '',
    device_platform  TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'pending',
    user_id          TEXT NOT NULL DEFAULT '',
    amr              TEXT NOT NULL DEFAULT '',
    auth_time        TIMESTAMPTZ,
    last_polled_at   TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL,
    expires_at       TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_device_codes_expires ON device_codes(expires_at);

-- Refresh tokens may be bound to an enrolled device (revoked with it) and/or to
-- a DPoP key (RFC 9449 §5). amr records how the user authenticated, so ID tokens
-- minted on refresh can carry the standard amr claim.
ALTER TABLE refresh_tokens ADD COLUMN device_id TEXT NOT NULL DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN dpop_jkt TEXT NOT NULL DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN amr TEXT NOT NULL DEFAULT '';
ALTER TABLE authorization_codes ADD COLUMN amr TEXT NOT NULL DEFAULT '';

-- Lifetime of device tokens (RFC 7523 jwt-bearer grant), live-editable.
ALTER TABLE settings ADD COLUMN device_token_ttl TEXT NOT NULL DEFAULT '1h';

-- Built-in public client used by the omni-enrollment endpoint agent. It may
-- request the user's profile/email (Linux account mapping) and offline_access
-- (device-bound refresh token for the login cache) besides device:enroll.
INSERT INTO clients (client_id, client_secret_hash, name, redirect_uris, allowed_scopes, type, disabled,
                     created_at, updated_at, display_name, logo_url, homepage_url, post_logout_redirect_uris, skip_consent)
VALUES ('omni-enrollment', '', 'Omni Enrollment', '[]', '["openid","profile","email","offline_access","device:enroll"]', 'public', FALSE,
        now(), now(), 'Omni Enrollment', '', '', '[]', FALSE);
