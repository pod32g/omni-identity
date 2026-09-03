-- Let the built-in enrollment client use the RFC 8252 §7.3 loopback redirect
-- (authorization code + PKCE via the system browser). The port is ignored
-- for loopback redirects at match time, so any ephemeral port works.
UPDATE clients SET redirect_uris = '["http://127.0.0.1/callback","http://[::1]/callback"]'
WHERE client_id = 'omni-enrollment' AND redirect_uris = '[]';
