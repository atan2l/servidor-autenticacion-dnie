use std::collections::HashMap;

#[derive(Default)]
pub struct ServerState {
    pub auth_codes: HashMap<String, String>,
    pub clients: HashMap<String, String>
}
