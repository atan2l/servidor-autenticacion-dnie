use axum::routing::get;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use rustls::crypto::aws_lc_rs::cipher_suite::{
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
};
use rustls::crypto::aws_lc_rs::default_provider;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::server::WebPkiClientVerifier;
use rustls::version::TLS12;
use rustls::{KeyLogFile, RootCertStore, ServerConfig, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::read;
use std::net::SocketAddr;
use std::sync::Arc;
use webpki::aws_lc_rs::{
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
};

static SUPPORTED_SIG_ALGOS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        RSA_PKCS1_2048_8192_SHA512,
        RSA_PKCS1_2048_8192_SHA384,
        RSA_PKCS1_2048_8192_SHA256,
    ],
    mapping: &[
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[RSA_PKCS1_2048_8192_SHA512],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[RSA_PKCS1_2048_8192_SHA384],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[RSA_PKCS1_2048_8192_SHA256],
        ),
    ],
};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    let mut crypto_provider = default_provider();
    crypto_provider.cipher_suites = vec![
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    ];
    crypto_provider.signature_verification_algorithms = SUPPORTED_SIG_ALGOS;
    let crypto_provider = Arc::new(crypto_provider);

    let root_cert_store = create_root_cert_store().into();
    let client_cert_verifier = WebPkiClientVerifier::builder_with_provider(
        root_cert_store,
        crypto_provider.clone(),
    )
    .build()
    .unwrap();

    let mut config = ServerConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(&[&TLS12])
        .unwrap()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(
            vec![CertificateDer::from_pem_file("certs/localhost.crt").unwrap()],
            PrivateKeyDer::from_pem_file("certs/localhost.key").unwrap(),
        )
        .unwrap();
    config.key_log = Arc::new(KeyLogFile::new());
    let config = RustlsConfig::from_config(config.into());

    let app = Router::new().route("/", get(|| async { "No se me escapa el DNIe" }));
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap()
}

fn create_root_cert_store() -> RootCertStore {
    let mut root_cert_store = RootCertStore::empty();
    root_cert_store
        .add(CertificateDer::from(read("certs/AC004.crt").unwrap()))
        .unwrap();
    root_cert_store
        .add(CertificateDer::from(read("certs/AC005.crt").unwrap()))
        .unwrap();
    root_cert_store
        .add(CertificateDer::from(read("certs/AC006.crt").unwrap()))
        .unwrap();
    root_cert_store
        .add(CertificateDer::from(read("certs/ACRaiz2.crt").unwrap()))
        .unwrap();

    root_cert_store
}
