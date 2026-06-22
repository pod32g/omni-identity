ALTER TABLE settings ADD COLUMN log_level TEXT NOT NULL DEFAULT 'info';
ALTER TABLE settings ADD COLUMN log_http_requests TEXT NOT NULL DEFAULT 'errors';
