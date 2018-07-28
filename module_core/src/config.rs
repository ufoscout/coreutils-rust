extern crate config as rs_config;
extern crate coreutils_jwt as jwt;
extern crate coreutils_logger as logger;

#[derive(Debug)]
pub struct CoreConfig {
    pub logger: logger::config::LoggerConfig,
    pub jwt: jwt::config::JwtConfig,
}

pub fn new(conf: rs_config::Config) -> CoreConfig {
    CoreConfig {
        logger: logger::config::LoggerConfig {
            root_level: conf.get_str("core.logger.root_level").unwrap(),
            level: conf.get_str("core.logger.level").unwrap(),
            output_system_enabled: conf.get_bool("core.logger.output_system_enabled").unwrap(),
            output_file_enabled: conf.get_bool("core.logger.output_file_enabled").unwrap(),
            output_file_name: conf.get_str("core.logger.output_file_name").unwrap()
        },
        jwt: jwt::config::JwtConfig{
            secret: conf.get_str("core.jwt.secret").unwrap(),
            signature_algorithm: conf.get_str("core.jwt.signatureAlgorithm").unwrap(),
            token_validity_minutes: conf.get_int("core.jwt.tokenValidityMinutes").unwrap() as u32
        }
    }
}

#[cfg(test)]
mod test {

}