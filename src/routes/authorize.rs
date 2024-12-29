use crate::server_state::ServerState;
use axum::extract::{Query, State};
use axum::http::Response;
use axum::response::IntoResponse;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct AuthRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
}

pub async fn get_authorize(
    State(state): State<Arc<Mutex<ServerState>>>,
    Query(params): Query<AuthRequest>,
) -> impl IntoResponse {
    if params.response_type != "code" {
        return Response::builder()
            .status(400)
            .body::<String>("Invalid response type".into())
            .unwrap();
    }

    let auth_code = Uuid::new_v4().to_string();
    {
        let mut state = state.lock().await;
        state
            .auth_codes
            .insert(auth_code.clone(), params.client_id.clone());
        state
            .clients
            .insert(params.client_id.clone(), params.redirect_uri.clone());
    }

    let redirect_uri = format!("{}?code={}", params.redirect_uri, auth_code);
    Response::builder()
        .status(302)
        .header("Location", redirect_uri)
        .body("".into())
        .unwrap()
}
