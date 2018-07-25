
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Auth {
    pub id: i64,
    pub username: String,
    pub roles: Vec<String>
}

#[derive(Clone)]
pub struct Role {
    pub id: i64,
    pub name: String,
    pub permissions: Vec<String>
}