-- Device key backend and posture (docs/DEVICE-IDENTITY-ARCHITECTURE.md).
-- key_backend: where the client says its key lives (file, dpapi, tpm,
-- secure-enclave); tpm and secure-enclave earn the "hardware" trust level.
-- posture: the facts the client last reported (JSON), posture_at when.
ALTER TABLE devices ADD COLUMN key_backend TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN posture TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN posture_at TIMESTAMP NULL;
