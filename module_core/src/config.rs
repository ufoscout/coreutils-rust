#[derive(Debug)]
pub struct CoreConfig {
    pub logger: coreutils_logger::config::LoggerConfig,
    pub jwt: coreutils_jwt::config::JwtConfig,
}

pub fn new(conf: &config_rs::Config) -> CoreConfig {
    CoreConfig {
        logger: coreutils_logger::config::LoggerConfig {
            root_level: conf.get_str("core.logger.root_level").unwrap(),
            level: conf.get_str("core.logger.level").unwrap(),
            output_system_enabled: conf.get_bool("core.logger.output_system_enabled").unwrap(),
            output_file_enabled: conf.get_bool("core.logger.output_file_enabled").unwrap(),
            output_file_name: conf.get_str("core.logger.output_file_name").unwrap(),
        },
        jwt: coreutils_jwt::config::JwtConfig {
            secret: conf.get_str("core.jwt.secret").unwrap(),
            signature_algorithm: conf.get_str("core.jwt.signatureAlgorithm").unwrap(),
            token_validity_minutes: conf.get_int("core.jwt.tokenValidityMinutes").unwrap() as u32,
        },
    }
}

#[cfg(test)]
mod test {}
