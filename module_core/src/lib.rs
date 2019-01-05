pub mod config;

use log::info;
use std::sync::Arc;

pub fn new(config: config::CoreConfig) -> CoreModule {
    println!("Creating CoreModule with configuration:\n{:#?}", config);
    info!("Creating CoreModule with configuration:\n{:#?}", config);

    let jwt = coreutils_jwt::new(&config.jwt);

    CoreModule {
        config: Arc::new(config),
        json: Arc::new(coreutils_json::new()),
        jwt: Arc::new(jwt),
    }
}

pub struct CoreModule {
    pub config: Arc<config::CoreConfig>,
    pub json: Arc<coreutils_json::JsonService>,
    pub jwt: Arc<coreutils_jwt::JwtService>,
}

impl coreutils_module::Module for CoreModule {
    fn init(&self) {
        info!("Core init");
    }

    fn start(&self) {
        info!("Core start")
    }
}
