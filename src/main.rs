mod auth;

use axum::routing::get;
use axum::Router;
use std::net::SocketAddr;
use axum_server::tls_rustls::RustlsConfig;

#[tokio::main]
async fn main() {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));
    let config = RustlsConfig::from_pem_file("localhost.crt", "localhost.key").await.unwrap();

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap()
}
