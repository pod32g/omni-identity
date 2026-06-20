-- Extend clients with display metadata, post-logout redirect URIs, and a
-- per-client consent toggle (first-party clients skip consent).
ALTER TABLE clients ADD COLUMN display_name TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN logo_url TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN homepage_url TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN post_logout_redirect_uris TEXT NOT NULL DEFAULT '[]';
ALTER TABLE clients ADD COLUMN skip_consent INTEGER NOT NULL DEFAULT 1;

-- Single-row branding configuration for the hosted pages.
CREATE TABLE branding (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    product_name      TEXT NOT NULL DEFAULT 'Omni Identity',
    logo_blob         BLOB,
    logo_content_type TEXT NOT NULL DEFAULT '',
    accent_color      TEXT NOT NULL DEFAULT '',
    footer_text       TEXT NOT NULL DEFAULT '',
    background_style  TEXT NOT NULL DEFAULT '',
    updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO branding (id) VALUES (1);

-- Pending OIDC authorization requests, parked across the hosted login/consent
-- pages. Keyed by an opaque id handed to the browser; single-use and expiring.
CREATE TABLE auth_requests (
    id                    TEXT PRIMARY KEY,
    client_id             TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL,
    response_type         TEXT NOT NULL,
    scope                 TEXT NOT NULL,
    state                 TEXT NOT NULL DEFAULT '',
    nonce                 TEXT NOT NULL DEFAULT '',
    code_challenge        TEXT NOT NULL DEFAULT '',
    code_challenge_method TEXT NOT NULL DEFAULT '',
    created_at            TIMESTAMP NOT NULL,
    expires_at            TIMESTAMP NOT NULL
);
CREATE INDEX idx_auth_requests_expires ON auth_requests(expires_at);
