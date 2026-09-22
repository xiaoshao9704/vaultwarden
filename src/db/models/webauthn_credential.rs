use derive_more::{AsRef, Deref, Display, From};
use diesel::prelude::*;
use macros::UuidFromParam;
use webauthn_rs::prelude::Passkey;

use super::UserId;
use crate::{
    api::{ApiResult, EmptyResult},
    db::{DbConn, schema::webauthn_credentials},
    error::MapResult,
};

// Single-server deployment gate. This is NOT a distributed lock: see the release
// limitations before using several Vaultwarden processes against one database.
static ACCOUNT_KEY_MUTATION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(num_derive::FromPrimitive, Serialize)]
pub enum WebauthnCredentialPrfStatus {
    Enabled = 0,
    Disabled = 1,
    NotSupported = 2,
}

#[derive(Debug, Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = webauthn_credentials)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
pub struct WebauthnCredential {
    pub uuid: WebauthnCredentialId,
    pub user_uuid: UserId,
    pub name: String,
    pub credential: String,
    pub supports_prf: bool,
    pub encrypted_user_key: Option<String>,
    pub encrypted_public_key: Option<String>,
    pub encrypted_private_key: Option<String>,
    // Nullable only for rows imported from an earlier experimental version of PR #7370.
    pub credential_id_hash: Option<String>,
}

impl WebauthnCredential {
    pub async fn lock_account_key_mutation() -> tokio::sync::MutexGuard<'static, ()> {
        ACCOUNT_KEY_MUTATION.lock().await
    }

    pub fn new(
        user_uuid: UserId,
        name: String,
        credential: String,
        supports_prf: bool,
        encrypted_user_key: Option<String>,
        encrypted_public_key: Option<String>,
        encrypted_private_key: Option<String>,
    ) -> ApiResult<Self> {
        let parsed: Passkey = serde_json::from_str(&credential)?;
        let digest = ring::digest::digest(&ring::digest::SHA256, parsed.cred_id().as_slice());
        let credential_id_hash = Some(data_encoding::HEXLOWER.encode(digest.as_ref()));
        Ok(Self {
            uuid: WebauthnCredentialId(crate::util::get_uuid()),
            user_uuid,
            name,
            credential,
            supports_prf,
            encrypted_user_key,
            encrypted_public_key,
            encrypted_private_key,
            credential_id_hash,
        })
    }

    pub fn get_prf_status(&self) -> WebauthnCredentialPrfStatus {
        if !self.supports_prf {
            return WebauthnCredentialPrfStatus::NotSupported;
        }
        let keys = [&self.encrypted_user_key, &self.encrypted_public_key, &self.encrypted_private_key];
        if keys.iter().all(|key| key.as_deref().is_some_and(|value| !value.is_empty())) {
            WebauthnCredentialPrfStatus::Enabled
        } else {
            WebauthnCredentialPrfStatus::Disabled
        }
    }

    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::insert_into(webauthn_credentials::table)
                .values(self)
                .execute(conn)
                .map_res("Error saving WebAuthn credential (credential IDs must be unique)")
        }}
    }

    pub async fn find_all_by_user_checked(user_uuid: &UserId, conn: &DbConn) -> ApiResult<Vec<Self>> {
        db_run! { conn: {
            Ok(webauthn_credentials::table
                .filter(webauthn_credentials::user_uuid.eq(user_uuid))
                .load::<Self>(conn)?)
        }}
    }

    // Retain the PR's existing /sync API signature. Authentication and registration
    // use the checked variant so a database failure cannot masquerade as no keys.
    pub async fn find_all_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        Self::find_all_by_user_checked(user_uuid, conn).await.unwrap_or_default()
    }

    pub async fn has_any_by_user(user_uuid: &UserId, conn: &DbConn) -> ApiResult<bool> {
        db_run! { conn: {
            Ok(diesel::select(diesel::dsl::exists(
                webauthn_credentials::table.filter(webauthn_credentials::user_uuid.eq(user_uuid)),
            )).get_result::<bool>(conn)?)
        }}
    }

    pub async fn has_legacy_credentials(conn: &DbConn) -> ApiResult<bool> {
        db_run! { conn: {
            Ok(diesel::select(diesel::dsl::exists(
                webauthn_credentials::table.filter(webauthn_credentials::credential_id_hash.is_null()),
            )).get_result::<bool>(conn)?)
        }}
    }

    pub async fn delete_by_uuid_and_user(
        uuid: &WebauthnCredentialId,
        user_uuid: &UserId,
        conn: &DbConn,
    ) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(webauthn_credentials::table
                .filter(webauthn_credentials::uuid.eq(uuid))
                .filter(webauthn_credentials::user_uuid.eq(user_uuid)))
                .execute(conn).map_res("Error removing WebAuthn credential")
        }}
    }

    pub async fn compare_and_swap_credential(
        uuid: &WebauthnCredentialId,
        user_uuid: &UserId,
        old: &str,
        new: &str,
        conn: &DbConn,
    ) -> ApiResult<bool> {
        db_run! { conn: {
            let updated = diesel::update(webauthn_credentials::table
                .filter(webauthn_credentials::uuid.eq(uuid))
                .filter(webauthn_credentials::user_uuid.eq(user_uuid))
                .filter(webauthn_credentials::credential.eq(old)))
                .set(webauthn_credentials::credential.eq(new))
                .execute(conn)?;
            Ok(updated == 1)
        }}
    }

    pub async fn delete_all_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(webauthn_credentials::table
                .filter(webauthn_credentials::user_uuid.eq(user_uuid)))
                .execute(conn).map_res("Error deleting WebAuthn credentials")
        }}
    }
}

#[derive(
    Clone,
    Debug,
    AsRef,
    Deref,
    DieselNewType,
    Display,
    From,
    FromForm,
    Hash,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    UuidFromParam,
)]
pub struct WebauthnCredentialId(String);
