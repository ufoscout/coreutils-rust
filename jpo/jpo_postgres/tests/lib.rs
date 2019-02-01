use testcontainers::*;
use jpo::{Jpo, Model};
use coreutils_jpo_postgres::*;
use postgres::{Connection, TlsMode};
use serde_derive::{Deserialize, Serialize};

mod tc;

#[test]
fn postgres_basic_crud() {
    let docker = clients::Cli::default();
    let node = docker.run(tc::postgres::Postgres::default());

    let conn = Connection::connect(
        format!(
            "postgres://postgres:postgres@127.0.0.1:{}/postgres",
            node.get_host_port(5432).unwrap()
        ),
        TlsMode::None,
    )
        .unwrap();

    conn.execute("create table TEST_TABLE (
                            ID bigserial primary key,
                            VERSION int not null,
                            DATA JSONB
                        )", &[]).unwrap();

    let jpo= JpoPg::new::<TestData>(conn, "TEST_TABLE");

    let model = Model::new(TestData {
            first_name: "my_first_name".to_owned(),
            last_name: "my_last_name".to_owned(),
        });

    let saved_model = jpo.save(&model);
    assert!(saved_model.id.is_some());

    assert!(model.id.is_none());


    let found_model = jpo.find_by_id(saved_model.id.unwrap()).unwrap();
    assert_eq!(saved_model.id, found_model.id);
    assert_eq!(saved_model.version, found_model.version);
    assert_eq!(saved_model.data.first_name, found_model.data.first_name);
    assert_eq!(saved_model.data.last_name, found_model.data.last_name);


}

type TestModel = Model<TestData>;

#[derive(Clone, Serialize, Deserialize)]
struct TestData {
    first_name: String,
    last_name: String,
}