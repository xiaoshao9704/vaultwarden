-- Development-only down migration. Production rollback restores the pre-upgrade backup.
DROP INDEX webauthn_credentials_user_idx ON webauthn_credentials;
DROP INDEX webauthn_credentials_id_hash_uq ON webauthn_credentials;
ALTER TABLE webauthn_credentials DROP COLUMN credential_id_hash;
DROP TABLE webauthn_challenges;
