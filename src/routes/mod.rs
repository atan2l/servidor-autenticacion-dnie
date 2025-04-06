use crate::routes::test::get_test;
use crate::routes::token::get_token;
use axum::routing::get;
use axum::Router;

mod test;
mod token;

pub fn create_routes() -> Router {
    Router::new()
        .route("/token", get(get_token))
        .route("/test", get(get_test))
}
