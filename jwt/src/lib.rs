pub mod config;

use chrono::prelude::Local;
use err_derive::Error;
use serde_derive::{Deserialize, Serialize};

pub fn new(jwt_config: &config::JwtConfig) -> JwtService {
    let alg = alg_from_str(&jwt_config.signature_algorithm);

    JwtService {
        secret: jwt_config.secret.clone(),
        token_validity_seconds: i64::from(jwt_config.token_validity_minutes) * 60,
        header_default: jsonwebtoken::Header {
            alg,
            ..jsonwebtoken::Header::default()
        },
        validation_default: jsonwebtoken::Validation::new(alg),
    }
}

fn alg_from_str(s: &str) -> jsonwebtoken::Algorithm {
    match s {
        "HS256" => jsonwebtoken::Algorithm::HS256,
        "HS384" => jsonwebtoken::Algorithm::HS384,
        "HS512" => jsonwebtoken::Algorithm::HS512,
        "RS256" => jsonwebtoken::Algorithm::RS256,
        "RS384" => jsonwebtoken::Algorithm::RS384,
        "RS512" => jsonwebtoken::Algorithm::RS512,
        _ => panic!("Unknown JWT signature algorithm: [{}]", s),
    }
}

pub struct JwtService {
    secret: String,
    token_validity_seconds: i64,
    header_default: jsonwebtoken::Header,
    validation_default: jsonwebtoken::Validation,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Token<T> {
    payload: T,

    // The subject of the token
    sub: String,
    // The expiration date of the token
    exp: i64,
    // The issued at field
    iat: i64,
    // The token id
    //jti: String,
}

#[derive(Error, Debug)]
pub enum JwtError {
    #[error(display = "InvalidTokenError: [{}]", message)]
    InvalidTokenError { message: String },
    #[error(display = "ExpiredTokenError: [{}]", message)]
    ExpiredTokenError { message: String },
    #[error(display = "GenerateTokenError: [{}]", message)]
    GenerateTokenError { message: String },
}

impl JwtService {
    pub fn generate_from_payload<T: serde::ser::Serialize>(
        &self,
        payload: &T,
    ) -> Result<String, JwtError> {
        let issued_at = Local::now().timestamp();
        let token = Token {
            payload,
            sub: "".to_string(),
            exp: issued_at + self.token_validity_seconds,
            iat: issued_at,
        };
        self.generate_from_token(&token)
    }

    pub fn generate_from_token<T: serde::ser::Serialize>(
        &self,
        token: &Token<T>,
    ) -> Result<String, JwtError> {
        let result = jsonwebtoken::encode(&self.header_default, &token, &self.secret.as_ref());
        match result {
            Ok(t) => Ok(t),
            Err(e) => {
                //let err = e.to_string();
                Err(JwtError::GenerateTokenError {
                    message: e.to_string(),
                })
            }
        }
    }

    pub fn parse_payload<T: serde::de::DeserializeOwned>(
        &self,
        jwt_string: &str,
    ) -> Result<T, JwtError> {
        let result = self.parse_token(jwt_string);
        match result {
            Ok(t) => Ok(t.payload),
            Err(e) => Err(e),
        }
    }

    pub fn parse_token<T: serde::de::DeserializeOwned>(
        &self,
        jwt_string: &str,
    ) -> Result<Token<T>, JwtError> {
        let result: Result<jsonwebtoken::TokenData<Token<T>>, jsonwebtoken::errors::Error> =
            jsonwebtoken::decode(jwt_string, &self.secret.as_ref(), &self.validation_default);
        match result {
            Ok(t) => Ok(t.claims),
            Err(e) => match *e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    Err(JwtError::ExpiredTokenError {
                        message: e.to_string(),
                    })
                }
                _ => Err(JwtError::InvalidTokenError {
                    message: e.to_string(),
                }),
            },
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn should_create_jwt_string_from_token() {
        let jwt = new();

        let payload = MyTestClaym {
            id: Local::now().timestamp(),
            name: "Red".to_string(),
        };

        let token = super::Token {
            payload,
            sub: "".to_string(),
            exp: Local::now().timestamp() + 3600,
            iat: Local::now().timestamp(),
        };

        let jwt_string = jwt.generate_from_token(&token).unwrap();
        println!("Jwt string: [{}]", jwt_string);
    }

    #[test]
    fn should_create_jwt_string_from_payload() {
        let jwt = new();

        let payload = MyTestClaym {
            id: Local::now().timestamp(),
            name: "Red".to_string(),
        };

        let jwt_string = jwt.generate_from_payload(&payload).unwrap();
        println!("Jwt string: [{}]", jwt_string);
    }

    #[test]
    fn should_parse_the_token() {
        let jwt = new();

        let payload = MyTestClaym {
            id: Local::now().timestamp(),
            name: "Red".to_string(),
        };

        let jwt_string = jwt.generate_from_payload(&payload).unwrap();
        let parsed: MyTestClaym = jwt.parse_payload(&jwt_string).unwrap();

        assert_eq!(payload.id, parsed.id);
        assert_eq!(payload.name, parsed.name);
    }

    #[test]
    fn should_parse_the_expiration_date() {
        let jwt = new();

        let payload = MyTestClaym {
            id: Local::now().timestamp(),
            name: "Red".to_string(),
        };

        let time_before = Local::now().timestamp();
        let jwt_string = jwt.generate_from_payload(&payload).unwrap();
        let time_after = Local::now().timestamp();

        let token: super::Token<MyTestClaym> = jwt.parse_token(&jwt_string).unwrap();

        assert_eq!(payload.id, token.payload.id);
        assert_eq!(&payload.name, &token.payload.name);

        let issued_at = token.iat;
        let expiration = token.exp;
        let timeout = (60 as i64) * 60;

        assert!(issued_at >= time_before);
        assert!(issued_at <= time_after);
        assert_eq!(issued_at + timeout, expiration);
    }

    #[test]
    fn should_fail_parsing_tampered_token() {
        let jwt = new();

        let payload = MyTestClaym {
            id: Local::now().timestamp(),
            name: "Red".to_string(),
        };

        let mut jwt_string = jwt.generate_from_payload(&payload).unwrap();
        jwt_string.push_str("1");

        let result: Result<super::Token<MyTestClaym>, super::JwtError> =
            jwt.parse_token(&jwt_string);
        let mut is_invalid = false;
        match result {
            Ok(r) => println!("Ok: {:?}", r),
            Err(e) => match e {
                super::JwtError::InvalidTokenError { message: mes } => {
                    println!("Error message: {:?}", &mes);
                    is_invalid = true;
                }
                _ => println!("Other kind of error: {:?}", e),
            },
        };
        assert!(is_invalid)
    }

    #[test]
    fn should_fail_parsing_expired_token() {
        let jwt = new();

        let token = super::Token {
            payload: MyTestClaym {
                id: Local::now().timestamp(),
                name: "Red".to_string(),
            },
            sub: "".to_string(),
            exp: Local::now().timestamp() - 10,
            iat: Local::now().timestamp() - 100,
        };

        let jwt_string = jwt.generate_from_token(&token).unwrap();

        let result: Result<MyTestClaym, super::JwtError> = jwt.parse_payload(&jwt_string);
        let mut is_expired = false;
        match result {
            Ok(r) => println!("Ok: {:?}", r),
            Err(e) => match e {
                super::JwtError::ExpiredTokenError { message: mes } => {
                    println!("Expired: {:?}", &mes);
                    is_expired = true;
                }
                _ => println!("Other kind of error: {:?}", e),
            },
        };
        assert!(is_expired)
    }

    fn new() -> super::JwtService {
        super::new(&super::config::JwtConfig {
            secret: "mySecret".to_string(),
            signature_algorithm: "HS512".to_string(),
            token_validity_minutes: 60,
        })
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct MyTestClaym {
        id: i64,
        name: String,
    }
}
