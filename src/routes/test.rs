use crate::middleware::client_cert_auth::ClientCertData;
use axum::response::IntoResponse;
use axum::Extension;

pub(super) async fn get_test(Extension(client_cert_data): Extension<ClientCertData>) -> impl IntoResponse {
    format!(
        "givenName={}, surname={}, C={}, serial number={}",
        client_cert_data.given_name,
        client_cert_data.surname,
        client_cert_data.country,
        client_cert_data.serial_number
    )
}
