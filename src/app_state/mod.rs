use jsonwebtoken_aws_lc::EncodingKey;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) jwt_private_key: EncodingKey,
}
