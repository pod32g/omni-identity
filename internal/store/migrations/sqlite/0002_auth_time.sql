-- Persist the end-user authentication time so the ID token auth_time claim
-- reflects when the user actually logged in (not token issuance), and is
-- preserved across refresh. SQLite requires a constant default for ADD COLUMN.
ALTER TABLE authorization_codes ADD COLUMN auth_time TIMESTAMP NOT NULL DEFAULT '1970-01-01 00:00:00';
ALTER TABLE refresh_tokens ADD COLUMN auth_time TIMESTAMP NOT NULL DEFAULT '1970-01-01 00:00:00';
