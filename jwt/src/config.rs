#[derive(Debug)]
pub struct JwtConfig {
    pub secret: String,
    pub signature_algorithm: String,
    pub token_validity_minutes: u32
}