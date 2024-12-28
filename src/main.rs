use axum::routing::get;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use rustls::crypto::aws_lc_rs::cipher_suite::{
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
};
use rustls::crypto::aws_lc_rs::default_provider;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::WebPkiClientVerifier;
use rustls::version::TLS12;
use rustls::{RootCertStore, ServerConfig, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::{read, read_dir};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use webpki::aws_lc_rs::{
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().unwrap();

    let crypto_provider = create_crypto_provider();
    let root_cert_store = create_root_cert_store();
    let client_cert_verifier =
        create_client_cert_verifier(root_cert_store, crypto_provider.clone());
    let server_config = create_server_config(crypto_provider, client_cert_verifier);

    let config = RustlsConfig::from_config(server_config);
    let app = Router::new().route("/", get(|| async { "Hello, world!" }));
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap()
}

fn create_crypto_provider() -> Arc<CryptoProvider> {
    let mut crypto_provider = default_provider();
    crypto_provider.cipher_suites = vec![
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    ];
    crypto_provider.signature_verification_algorithms = SUPPORTED_SIG_ALGORITHMS;
    Arc::new(crypto_provider)
}

fn create_client_cert_verifier(
    root_cert_store: Arc<RootCertStore>,
    crypto_provider: Arc<CryptoProvider>,
) -> Arc<dyn ClientCertVerifier> {
    WebPkiClientVerifier::builder_with_provider(root_cert_store, crypto_provider)
        .build()
        .unwrap()
}

fn create_server_config(
    crypto_provider: Arc<CryptoProvider>,
    client_cert_verifier: Arc<dyn ClientCertVerifier>,
) -> Arc<ServerConfig> {
    let server_cert_path = dotenvy::var("DNIE_AUTH_SERVER_CERT")
        .expect("DNIE_AUTH_SERVER_CERT environment variable not set.");
    let server_key_path = dotenvy::var("DNIE_AUTH_SERVER_KEY")
        .expect("DNIE_AUTH_SERVER_KEY environment variable not set.");

    let server_certificate = if let Some(ext) = PathBuf::from(&server_cert_path)
        .extension()
        .and_then(|e| e.to_str())
    {
        load_certificate(ext, &PathBuf::from(&server_cert_path))
    } else {
        panic!("Server certificate file has no valid extension.");
    };

    let server_key = if let Some(ext) = PathBuf::from(&server_key_path)
        .extension()
        .and_then(|e| e.to_str())
    {
        if ext == "key" {
            PrivateKeyDer::from_pem_file(&server_key_path)
                .expect("Failed to parse server key file.")
        } else {
            unreachable!();
        }
    } else {
        panic!("Server key file has no valid extension.");
    };

    let config = ServerConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(&[&TLS12])
        .unwrap()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(vec![server_certificate], server_key)
        .unwrap();

    Arc::new(config)
}

fn create_root_cert_store() -> Arc<RootCertStore> {
    let certs_dir =
        dotenvy::var("DNIE_CERTS_DIR").expect("DNIE_CERTS_DIR environment variable not set.");
    let cert_files = read_dir(certs_dir).expect("Failed to read DNIE_CERTS_DIR.");
    let mut root_cert_store = RootCertStore::empty();

    for cert in cert_files.flatten() {
        if let Some(ext) = cert.path().extension().and_then(|e| e.to_str()) {
            if SUPPORTED_CERT_EXTENSIONS.contains(&ext) {
                add_certificate(&mut root_cert_store, ext, cert.path());
            }
        }
    }

    Arc::new(root_cert_store)
}

fn add_certificate(root_cert_store: &mut RootCertStore, ext: &str, path: PathBuf) {
    match ext {
        "pem" => {
            root_cert_store
                .add(load_certificate(ext, &path))
                .expect("Failed to add PEM certificate to root store.");
        }
        "der" => {
            root_cert_store
                .add(load_certificate(ext, &path))
                .expect("Failed to add DER certificate to root store.");
        }
        _ => unreachable!(),
    }
}

fn load_certificate<'a>(ext: &str, path: &PathBuf) -> CertificateDer<'a> {
    match ext {
        "pem" => CertificateDer::from_pem_file(path).expect("Failed to parse PEM file."),
        "der" => CertificateDer::from(read(path).expect("Failed to read DER file.")),
        _ => unreachable!(),
    }
}

static SUPPORTED_SIG_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
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

const SUPPORTED_CERT_EXTENSIONS: [&str; 2] = ["pem", "der"];
