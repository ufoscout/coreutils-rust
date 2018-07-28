extern crate coreutils_json as json;
extern crate coreutils_jwt as jwt;
extern crate coreutils_module as module;
#[macro_use] extern crate log;

pub mod config;

use std::sync::Arc;

pub fn new(config: config::CoreConfig) -> CoreModule {

    println!("Creating CoreModule with configuration:\n{:#?}", config);
    info!("Creating CoreModule with configuration:\n{:#?}", config);

    let jwt = jwt::new(&config.jwt);

    CoreModule{
        config: Arc::new(config),
        json: Arc::new(json::new()),
        jwt: Arc::new(jwt)
    }
}

pub struct CoreModule {
    pub config: Arc<config::CoreConfig>,
    pub json: Arc<json::JsonService>,
    pub jwt: Arc<jwt::JwtService>,
}

impl module::Module for CoreModule {

    fn init(&self) {
        info!("Core init");
    }

    fn start(&self) {
        info!("Core start")
    }

}