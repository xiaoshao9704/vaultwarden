use std::sync::LazyLock;

use rocket::{http::Status, serde::json::Json};
use serde_json::Value;
use webauthn_rs::{
    Webauthn, WebauthnBuilder,
    prelude::{Passkey, PasskeyRegistration},
};
use webauthn_rs_proto::UserVerificationPolicy;

use crate::{
    CONFIG,
    api::{ApiResult, JsonResult, PasswordOrOtpData, core::two_factor::webauthn::RegisterPublicKeyCredentialCopy},
    auth::Headers,
    db::{
        DbConn,
        models::{TwoFactor, TwoFactorType, WebauthnCredential, WebauthnCredentialId, WebauthnCredentialPrfStatus},
    },
};

pub static WEBAUTHN_PASSWORDLESS: LazyLock<Webauthn> = LazyLock::new(|| {
    let domain = CONFIG.domain();
    let origin = url::Url::parse(&CONFIG.domain_origin()).expect("Invalid WebAuthn origin");
    let rp_id = url::Url::parse(&domain).ok().and_then(|u| u.domain().map(str::to_owned)).unwrap_or_default();
    let mut builder = WebauthnBuilder::new(&rp_id, &origin)
        .expect("Creating WebAuthn builder failed")
        .rp_name(&domain)
        .timeout(tokio::time::Duration::from_secs(120));
    // Preserve the PR's exact official extension allowlist. Do not use a wildcard.
    for value in
        ["chrome-extension://nngceckbapebfimnlniiiahkandclblb", "chrome-extension://jbkfoedolllekgbhcbcoahefnbanhhlh"]
    {
        let origin = url::Url::parse(value).expect("Invalid extension origin");
        builder = builder.append_allowed_origin(&origin);
    }
    builder.build().expect("Building WebAuthn failed")
});

fn passkey_login_enabled() -> bool {
    CONFIG.passkey_login_allowed() && !(CONFIG.sso_enabled() && CONFIG.sso_only())
}

pub fn routes() -> Vec<rocket::Route> {
    routes![get_webauthn, post_webauthn, post_webauthn_attestation_options, post_webauthn_delete]
}

pub fn webauthn_prf_option(wac: &WebauthnCredential, pascal_case: bool) -> Option<Value> {
    if !passkey_login_enabled() || !matches!(wac.get_prf_status(), WebauthnCredentialPrfStatus::Enabled) {
        return None;
    }
    let passkey: Passkey = serde_json::from_str(&wac.credential).ok()?;
    if pascal_case {
        Some(json!({
            "CredentialId": passkey.cred_id().to_owned(), "Transports": [],
            "EncryptedPrivateKey": wac.encrypted_private_key.as_ref()?,
            "EncryptedUserKey": wac.encrypted_user_key.as_ref()?,
        }))
    } else {
        Some(json!({
            "credentialId": passkey.cred_id().to_owned(), "transports": [],
            "encryptedPrivateKey": wac.encrypted_private_key.as_ref()?,
            "encryptedUserKey": wac.encrypted_user_key.as_ref()?,
        }))
    }
}

#[get("/webauthn")]
async fn get_webauthn(headers: Headers, conn: DbConn) -> JsonResult {
    // Still list existing credentials when login is disabled. Hiding them breaks
    // key-management callers and prevents users from removing disabled credentials.
    let data = WebauthnCredential::find_all_by_user_checked(&headers.user.uuid, &conn)
        .await?
        .into_iter()
        .map(|wac| {
            json!({
                "id": wac.uuid, "name": wac.name, "prfStatus": wac.get_prf_status() as u8,
                "encryptedUserKey": wac.encrypted_user_key,
                "encryptedPublicKey": wac.encrypted_public_key,
                "object": "webauthnCredential",
            })
        })
        .collect::<Value>();
    Ok(Json(json!({"object": "list", "data": data, "continuationToken": null})))
}

#[derive(Serialize, Deserialize)]
struct RegistrationChallenge {
    expires_at: i64,
    security_stamp: String,
    state: PasskeyRegistration,
}

fn challenge_is_live(expires_at: i64, now: i64) -> bool {
    expires_at > now
}

#[post("/webauthn/attestation-options", data = "<data>")]
async fn post_webauthn_attestation_options(
    data: Json<PasswordOrOtpData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    if !passkey_login_enabled() {
        err!("Passkey login is not available")
    }
    let user = headers.user;
    data.into_inner().validate(&user, false, &conn).await?;
    if WebauthnCredential::has_legacy_credentials(&conn).await? {
        err!("Remove credentials created by the earlier experimental PR before enrolling new passkeys")
    }
    let all = WebauthnCredential::find_all_by_user_checked(&user.uuid, &conn).await?;
    let mut excluded = Vec::with_capacity(all.len());
    for record in all {
        let key: Passkey = serde_json::from_str(&record.credential)?;
        excluded.push(key.cred_id().to_owned());
    }
    let uuid = uuid::Uuid::parse_str(&user.uuid).map_err(|_| crate::error::Error::new("Invalid user UUID", ""))?;
    let (mut challenge, state) =
        WEBAUTHN_PASSWORDLESS.start_passkey_registration(uuid, &user.email, user.display_name(), Some(excluded))?;
    if let Some(selection) = challenge.public_key.authenticator_selection.as_mut() {
        selection.user_verification = UserVerificationPolicy::Required;
        selection.require_resident_key = true;
        selection.resident_key = Some(webauthn_rs_proto::ResidentKeyRequirement::Required);
    }
    // Keep the library-generated algorithm list in sync with its server-side state.
    // Retain the PR's extension shape needed by the Bitwarden client.
    if let Some(extensions) = challenge.public_key.extensions.as_mut() {
        extensions.cred_props = None;
        extensions.uvm = None;
        extensions.cred_protect = None;
        extensions.hmac_create_secret = None;
        extensions.min_pin_length = None;
    }
    let state = RegistrationChallenge {
        expires_at: chrono::Utc::now().timestamp() + 120,
        security_stamp: user.security_stamp.clone(),
        state,
    };
    TwoFactor::new(user.uuid, TwoFactorType::WebauthnPasskeyRegisterChallenge, serde_json::to_string(&state)?)
        .save(&conn)
        .await?;
    let mut options = serde_json::to_value(challenge.public_key)?;
    options["status"] = "ok".into();
    options["errorMessage"] = "".into();
    Ok(Json(json!({"options": options, "object": "webauthnCredentialCreateOptions"})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebAuthnLoginCredentialCreateRequest {
    device_response: RegisterPublicKeyCredentialCopy,
    name: String,
    supports_prf: bool,
    encrypted_user_key: Option<String>,
    encrypted_public_key: Option<String>,
    encrypted_private_key: Option<String>,
}

fn valid_prf_material(supports_prf: bool, keys: [Option<&str>; 3]) -> bool {
    keys.iter().all(Option::is_none) || (supports_prf && keys.iter().all(|k| k.is_some_and(|value| !value.is_empty())))
}

#[post("/webauthn", data = "<data>")]
async fn post_webauthn(
    data: Json<WebAuthnLoginCredentialCreateRequest>,
    headers: Headers,
    conn: DbConn,
) -> ApiResult<Status> {
    if !passkey_login_enabled() {
        err!("Passkey login is not available")
    }
    let data = data.into_inner();
    // Serialize registration and key rotation inside this one Vaultwarden process.
    // Revalidate after acquiring the lock: Headers may have been built before a rotation.
    let _key_mutation = WebauthnCredential::lock_account_key_mutation().await;
    let Some(user) = crate::db::models::User::find_by_uuid(&headers.user.uuid, &conn).await else {
        err!("User not found")
    };
    if !user.enabled || user.security_stamp != headers.user.security_stamp {
        err!("Account changed; authenticate again before registering a passkey")
    }
    let name = data.name.trim().to_owned();
    if name.is_empty() || name.chars().count() > 128 {
        err!("Passkey name must contain 1 to 128 characters")
    }
    if !valid_prf_material(
        data.supports_prf,
        [
            data.encrypted_user_key.as_deref(),
            data.encrypted_public_key.as_deref(),
            data.encrypted_private_key.as_deref(),
        ],
    ) {
        err!("PRF encrypted key material must be absent or complete and non-empty")
    }
    if WebauthnCredential::has_legacy_credentials(&conn).await? {
        err!("Remove credentials created by the earlier experimental PR before enrolling new passkeys")
    }
    let kind = TwoFactorType::WebauthnPasskeyRegisterChallenge as i32;
    let Some(saved) = TwoFactor::find_by_user_and_type(&user.uuid, kind, &conn).await else {
        err!("Registration challenge not found. Please start again.")
    };
    let state: RegistrationChallenge = serde_json::from_str(&saved.data)?;
    if !saved.consume_passkey_registration(&conn).await? {
        err!("Registration challenge was already consumed. Please start again.")
    }
    if !challenge_is_live(state.expires_at, chrono::Utc::now().timestamp()) {
        err!("Registration challenge expired. Please start again.")
    }
    if state.security_stamp != user.security_stamp {
        err!("Account keys changed after the registration challenge was created. Please start again.")
    }
    let credential = WEBAUTHN_PASSWORDLESS.finish_passkey_registration(&data.device_response.into(), &state.state)?;
    WebauthnCredential::new(
        user.uuid,
        name,
        serde_json::to_string(&credential)?,
        data.supports_prf,
        data.encrypted_user_key,
        data.encrypted_public_key,
        data.encrypted_private_key,
    )?
    .save(&conn)
    .await?;
    Ok(Status::Ok)
}

#[post("/webauthn/<uuid>/delete", data = "<data>")]
async fn post_webauthn_delete(
    data: Json<PasswordOrOtpData>,
    uuid: &str,
    headers: Headers,
    conn: DbConn,
) -> ApiResult<Status> {
    // Revocation remains available even when new enrollment/login is disabled.
    let user = headers.user;
    data.into_inner().validate(&user, false, &conn).await?;
    WebauthnCredential::delete_by_uuid_and_user(&WebauthnCredentialId::from(uuid.to_owned()), &user.uuid, &conn)
        .await?;
    Ok(Status::Ok)
}

#[cfg(test)]
mod passkey_hardening_tests {
    use super::{challenge_is_live, valid_prf_material};

    #[test]
    fn challenge_expiry_is_strict() {
        assert!(challenge_is_live(101, 100));
        assert!(!challenge_is_live(100, 100));
        assert!(!challenge_is_live(99, 100));
    }
    #[test]
    fn prf_material_must_be_consistent() {
        assert!(valid_prf_material(false, [None, None, None]));
        assert!(valid_prf_material(true, [None, None, None]));
        assert!(valid_prf_material(true, [Some("a"), Some("b"), Some("c")]));
        assert!(!valid_prf_material(false, [Some("a"), Some("b"), Some("c")]));
        assert!(!valid_prf_material(true, [Some("a"), None, Some("c")]));
        assert!(!valid_prf_material(true, [Some("a"), Some(""), Some("c")]));
    }
}
