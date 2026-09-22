//! Short-lived, single-use passwordless authentication state.
//! Candidate implementation: run Rust and database integration tests before release.
use diesel::prelude::*;

use crate::{
    api::{ApiResult, EmptyResult},
    db::{DbConn, schema::webauthn_challenges},
    error::MapResult,
};

pub struct WebauthnChallenge;

impl WebauthnChallenge {
    pub async fn save(id: &str, state: &str, expires_at: i64, conn: &DbConn) -> EmptyResult {
        let now = chrono::Utc::now().timestamp();
        db_run! { conn: {
            // Opportunistic cleanup: expired rows never authenticate, even if cleanup fails.
            diesel::delete(webauthn_challenges::table.filter(webauthn_challenges::expires_at.le(now)))
                .execute(conn)?;
            diesel::insert_into(webauthn_challenges::table)
                .values((
                    webauthn_challenges::id.eq(id),
                    webauthn_challenges::state.eq(state),
                    webauthn_challenges::expires_at.eq(expires_at),
                ))
                .execute(conn)
                .map_res("Error saving passwordless challenge")
        }}
    }

    pub async fn take(id: &str, conn: &DbConn) -> ApiResult<Option<String>> {
        db_run! { conn: {
            let now = chrono::Utc::now().timestamp();
            let state = webauthn_challenges::table
                .filter(webauthn_challenges::id.eq(id))
                .filter(webauthn_challenges::expires_at.gt(now))
                .select(webauthn_challenges::state)
                .first::<String>(conn)
                .optional()?;
            let Some(state) = state else { return Ok(None); };

            // DELETE is the linearization point. Two concurrent reads are harmless:
            // only the request that actually deletes one row receives the state.
            // Recheck the wall clock after SELECT, not just when the request started.
            let deleted = diesel::delete(
                webauthn_challenges::table
                    .filter(webauthn_challenges::id.eq(id))
                    .filter(webauthn_challenges::state.eq(&state))
                    .filter(webauthn_challenges::expires_at.gt(chrono::Utc::now().timestamp())),
            )
            .execute(conn)?;
            Ok((deleted == 1).then_some(state))
        }}
    }
}
