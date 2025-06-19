use crate::app_state::AppState;
use crate::middleware::client_cert_auth::ClientCertData;
use axum::Extension;
use axum::extract::State;
use axum::response::IntoResponse;
use chrono::{DateTime, Utc};
use jsonwebtoken_aws_lc::{Algorithm, Header, encode};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: DateTime<Utc>,
    nbf: DateTime<Utc>,
    iat: DateTime<Utc>,
}

pub(super) async fn get_token(
    Extension(client_cert_data): Extension<ClientCertData>,
    State(app_state): State<AppState>,
) -> impl IntoResponse {
    let header = Header {
        alg: Algorithm::RS256,
        ..Default::default()
    };

    let claims = Claims {
        sub: client_cert_data.serial_number,
        exp: Utc::now() + Duration::from_secs(3600),
        nbf: Utc::now(),
        iat: Utc::now(),
    };

    let token = encode(&header, &claims, &app_state.jwt_private_key);
    token.unwrap()
}
