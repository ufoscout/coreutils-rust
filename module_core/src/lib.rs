pub mod config;

use log::info;
use std::sync::Arc;
use coreutils_module::ModuleError;

#[derive(Clone)]
pub struct CoreModule {
    pub config: Arc<config::CoreConfig>,
    pub json: Arc<coreutils_json::JsonService>,
    pub jwt: Arc<coreutils_jwt::JwtService>,
}

impl CoreModule {
    pub fn new(config: config::CoreConfig) -> CoreModule {
        println!("Creating CoreModule with configuration:\n{:#?}", config);
        info!("Creating CoreModule with configuration:\n{:#?}", config);

        let jwt = coreutils_jwt::JwtService::new(&config.jwt);

        CoreModule {
            config: Arc::new(config),
            json: Arc::new(coreutils_json::new()),
            jwt: Arc::new(jwt),
        }
    }
}

impl coreutils_module::Module for CoreModule {

    fn start(&mut self) -> Result<(), ModuleError> {
        info!("Core start");
        Ok(())
    }
}
