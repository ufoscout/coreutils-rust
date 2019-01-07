use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Auth {
    pub id: i64,
    pub username: String,
    pub roles: Vec<String>,
}

#[derive(Clone)]
pub struct Role {
    pub name: String,
    pub permissions: Vec<String>,
}

pub trait Owned {
    fn get_owner_id(&self) -> i64;
}
