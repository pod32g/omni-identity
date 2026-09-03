-- Per-device login policy and admin-approved enrollment.
-- owner_only: only the device's owner may sign in on it (device-bound logins
-- approved by another user are refused).
ALTER TABLE devices ADD COLUMN owner_only INTEGER NOT NULL DEFAULT 0;
-- require_device_approval: new enrollments start pending until an admin
-- approves them; pending devices cannot obtain credentials.
ALTER TABLE settings ADD COLUMN require_device_approval INTEGER NOT NULL DEFAULT 0;
