mod auth;

use axum::routing::get;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from_pem_file("localhost.crt").unwrap()],
            PrivateKeyDer::from_pem_file("localhost.key").unwrap(),
        )
        .unwrap();
    let config = RustlsConfig::from_config(Arc::new(config));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap()
}
