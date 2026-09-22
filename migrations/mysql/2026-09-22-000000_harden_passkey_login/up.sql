CREATE TABLE webauthn_challenges (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    state TEXT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX webauthn_challenges_expiry_idx ON webauthn_challenges (expires_at);
ALTER TABLE webauthn_credentials ADD COLUMN credential_id_hash VARCHAR(64);
CREATE UNIQUE INDEX webauthn_credentials_id_hash_uq ON webauthn_credentials (credential_id_hash);
CREATE INDEX webauthn_credentials_user_idx ON webauthn_credentials (user_uuid);
