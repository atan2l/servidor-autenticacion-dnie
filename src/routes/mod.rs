use crate::routes::authorize::get_authorize;
use crate::server_state::ServerState;
use axum::routing::get;
use axum::Router;
use std::sync::Arc;
use tokio::sync::Mutex;

pub mod authorize;
pub mod token;

pub fn create_routes() -> Router<Arc<Mutex<ServerState>>> {
    Router::new().route("/authorize", get(get_authorize))
}
