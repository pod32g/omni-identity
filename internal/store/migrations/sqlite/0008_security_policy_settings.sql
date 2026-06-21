ALTER TABLE settings ADD COLUMN rate_limit_window TEXT NOT NULL DEFAULT '15m';
ALTER TABLE settings ADD COLUMN login_ip_max_attempts INTEGER NOT NULL DEFAULT 20;
ALTER TABLE settings ADD COLUMN password_verify_concurrency INTEGER NOT NULL DEFAULT 4;
ALTER TABLE settings ADD COLUMN max_login_username_bytes INTEGER NOT NULL DEFAULT 320;
ALTER TABLE settings ADD COLUMN max_login_password_bytes INTEGER NOT NULL DEFAULT 1024;
ALTER TABLE settings ADD COLUMN allow_loopback_http_redirects INTEGER NOT NULL DEFAULT 1;
ALTER TABLE settings ADD COLUMN max_logo_bytes INTEGER NOT NULL DEFAULT 524288;
