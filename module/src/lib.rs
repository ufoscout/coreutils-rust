#[macro_use] extern crate log;

pub trait Module: Sync + Send {
    fn init(&self);
    fn start(&self);
}

pub fn start(modules: &Vec<&dyn Module>) {
    info!("Begin modules 'init' phase");
    for module in modules {
        module.init();
    }
    info!("Begin modules 'start' phase");
    for module in modules {
        module.start();
    }
}

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

#[cfg(test)]
mod test {

    use std::sync::Mutex;

    lazy_static! {
        static ref MODULE_TEST_ARRAY_VALUES: Mutex<Vec<String>> = Mutex::new(vec![]);
    }

    #[test]
    fn should_init_all_then_start_all() {

        let mod1 = SimpleMod { name: "one".to_string() };
        let mod2 = SimpleMod { name: "two".to_string() };

        let modules: Vec<&dyn super::Module> = vec![&mod1, &mod2];

        super::start(&modules);

        assert_eq!(4, MODULE_TEST_ARRAY_VALUES.lock().unwrap().len());
        assert_eq!(&"one-init".to_string(), MODULE_TEST_ARRAY_VALUES.lock().unwrap().get(0).unwrap());
        assert_eq!(&"two-init".to_string(), MODULE_TEST_ARRAY_VALUES.lock().unwrap().get(1).unwrap());
        assert_eq!(&"one-start".to_string(), MODULE_TEST_ARRAY_VALUES.lock().unwrap().get(2).unwrap());
        assert_eq!(&"two-start".to_string(), MODULE_TEST_ARRAY_VALUES.lock().unwrap().get(3).unwrap());

    }

    struct SimpleMod {
        name: String
    }

    impl super::Module for SimpleMod {
        fn init(&self) {
            let mut owned = self.name.to_owned();
            owned.push_str(&"-init");
            MODULE_TEST_ARRAY_VALUES.lock().unwrap().push(owned)
        }
        fn start(&self) {
            let mut owned = self.name.to_owned();
            owned.push_str(&"-start");
            MODULE_TEST_ARRAY_VALUES.lock().unwrap().push(owned)
        }
    }
}