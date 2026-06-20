-- External authentication sources (LDAP and future connectors). Local users keep
-- auth_source='local'; external users are provisioned just-in-time on login with
-- an empty password_hash and a stable external_id (e.g. the LDAP entry DN).
ALTER TABLE users ADD COLUMN auth_source TEXT NOT NULL DEFAULT 'local';
ALTER TABLE users ADD COLUMN external_id TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX idx_users_external ON users(auth_source, external_id)
    WHERE external_id <> '';
