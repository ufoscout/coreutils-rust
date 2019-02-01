
use testcontainers::{clients, Container, Docker, Image, WaitForMessage};

use postgres::{Connection, TlsMode};

// Todo: remove this as it will be part of testcontainers itself

#[derive(Debug)]
pub struct Postgres {
    arguments: PostgresArgs,
}

#[derive(Default, Debug, Clone)]
pub struct PostgresArgs {}

impl IntoIterator for PostgresArgs {
    type Item = String;
    type IntoIter = ::std::vec::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        vec![].into_iter()
    }
}

impl Default for Postgres {
    fn default() -> Self {
        Self {
            arguments: PostgresArgs::default(),
        }
    }
}

impl Image for Postgres {
    type Args = PostgresArgs;

    fn descriptor(&self) -> String {
        "postgres:11-alpine".to_string()
    }

    fn wait_until_ready<D: Docker>(&self, container: &Container<D, Self>) {
        container
            .logs()
            .stderr
            .wait_for_message("database system is ready to accept connections")
            .unwrap();
    }

    fn args(&self) -> Self::Args {
        self.arguments.clone()
    }

    fn with_args(self, arguments: Self::Args) -> Self {
        Self { arguments, ..self }
    }
}

#[test]
fn postgres_one_plus_one() {
    let docker = clients::Cli::default();
    let node = docker.run(Postgres::default());

    let conn = Connection::connect(
        format!(
            "postgres://postgres:postgres@127.0.0.1:{}/postgres",
            node.get_host_port(5432).unwrap()
        ),
        TlsMode::None,
    )
        .unwrap();
    let rows = conn.query("SELECT 1+1 AS result;", &[]).unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows.get(0).get::<_, i32>("result"), 2);
}
