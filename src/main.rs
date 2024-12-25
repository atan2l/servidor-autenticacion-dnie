mod auth;

use axum::routing::get;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::read;
use std::net::SocketAddr;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    let root_cert_store = create_root_cert_store().into();
    let client_cert_verifier = WebPkiClientVerifier::builder(root_cert_store)
        .build()
        .unwrap();
    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(
            vec![CertificateDer::from_pem_file("certs/localhost.crt").unwrap()],
            PrivateKeyDer::from_pem_file("certs/localhost.key").unwrap(),
        )
        .unwrap();
    let config = RustlsConfig::from_config(Arc::new(config));

    let app = Router::new().route("/", get(|| async { "Hello, World!" }));
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap()
}

fn create_root_cert_store() -> RootCertStore {
    let mut root_cert_store = RootCertStore::empty();
    root_cert_store
        .add(CertificateDer::from(read("certs/ACRaiz2.crt").unwrap()))
        .unwrap();
    root_cert_store
        .add(CertificateDer::from(read("certs/AC005.crt").unwrap()))
        .unwrap();

    root_cert_store
}
