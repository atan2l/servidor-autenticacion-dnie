use crate::routes::token::get_token;
use axum::routing::get;
use axum::Router;

pub mod token;

pub fn create_routes() -> Router {
    Router::new().route("/token", get(get_token))
}
