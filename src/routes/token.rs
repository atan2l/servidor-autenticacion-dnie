use crate::middleware::client_cert_auth::ClientCertData;
use axum::response::IntoResponse;
use axum::Extension;
use biscuit::jwa::{ContentEncryptionAlgorithm, EncryptionOptions, KeyManagementAlgorithm, SignatureAlgorithm};
use biscuit::jwk::{AlgorithmParameters, CommonParameters, RSAKeyParameters, JWK};
use biscuit::jws::{Compact, RegisteredHeader, Secret};
use biscuit::{jwe, ClaimsSet, Empty, RegisteredClaims, SingleOrMultiple, Timestamp, JWE};
use chrono::{Duration, Utc};
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};
use std::fs::read;
use uuid::Uuid;
use x509_parser::num_bigint::BigUint;

#[derive(Serialize, Deserialize)]
struct PrivateClaims {
    given_name: String,
    family_name: String,
    country: String,
}

pub async fn get_token(
    Extension(client_cert_data): Extension<ClientCertData>,
) -> impl IntoResponse {
    let now = Utc::now();
    let claims = ClaimsSet::<PrivateClaims> {
        registered: RegisteredClaims {
            issuer: Some("auth_server".to_string()),
            audience: Some(SingleOrMultiple::Single("app_server".to_string())),
            subject: Some(client_cert_data.serial_number),
            issued_at: Some(Timestamp::from(now.timestamp())),
            expiry: Some(Timestamp::from(now + Duration::minutes(15))),
            not_before: Some(Timestamp::from(now.timestamp())),
            id: Some(Uuid::new_v4().to_string()),
        },
        private: PrivateClaims {
            given_name: client_cert_data.given_name,
            family_name: client_cert_data.surname,
            country: client_cert_data.country,
        },
    };

    let signing_secret = Secret::rsa_keypair_from_file("temp/auth_server_private.der").unwrap();
    let token = Compact::new_decoded(
        From::from(RegisteredHeader {
            algorithm: SignatureAlgorithm::RS256,
            ..Default::default()
        }),
        claims,
    );
    let token = token.into_encoded(&signing_secret).unwrap();
    
    let jwk = get_jwk_from_public_key();
    let token = JWE::new_decrypted(
        From::from(jwe::RegisteredHeader {
            cek_algorithm: KeyManagementAlgorithm::RSA_OAEP,
            enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
            media_type: Some("JOSE".to_string()),
            content_type: Some("JOSE".to_string()),
            ..Default::default()
        }),
        token,
    );
    
    let nonce_counter = BigUint::from_bytes_le(&[0; 96 / 8]);
    let mut nonce_bytes = nonce_counter.to_bytes_le();
    nonce_bytes.resize(96, 0);
    let options = EncryptionOptions::AES_GCM {
        nonce: nonce_bytes
    };
    
    let token_r = token.into_encrypted(&jwk, &options);
    if let Ok(token) = token_r {
        return token.unwrap_encrypted().to_string()
    }
    else {
        println!("{}", &token_r.err().unwrap());
    }
    panic!()
}

fn get_jwk_from_public_key() -> JWK<Empty> {
    // Needs extra rsa dependency because the app server key is a key, not a X509 cert :)
    let key_file = read("temp/app_server_public.der").unwrap();
    let result = RsaPublicKey::from_public_key_der(&key_file);
    if result.is_err() {
        println!("{}", &result.err().unwrap());
        panic!()
    }
    let public_key = result.unwrap();
    let key_params = RSAKeyParameters {
        n: BigUint::from_bytes_be(&public_key.n().to_bytes_be()),
        e: BigUint::from_bytes_be(&public_key.e().to_bytes_be()),
        ..RSAKeyParameters::default()
    };
    JWK {
        common: CommonParameters::default(),
        algorithm: AlgorithmParameters::RSA(key_params),
        additional: Empty::default(),
    }
}
