//! The ObjectWrite Gateway's PostgreSQL startup contract, against a real
//! database.
//!
//! Nothing exercised this end to end before, which is how a release shipped a
//! daemon whose startup ended in an unconditional refusal: every contract test
//! read the SQL as text. This installs the reviewed schema and the reviewed
//! login script into a disposable schema, connects as the gateway's own role,
//! and requires the daemon's own startup path to succeed.

use cats_control_plane::store::{
    DsnSource, ObjectWriteGatewayClient, Store, OBJECT_WRITE_GATEWAY_POSTGRES_ROLE,
};
use postgres::NoTls;

const ROLE_INSTALLER: &str = include_str!("../../deploy/postgres/object-write-gateway-role-v1.sql");

fn schema_of(dsn: &str) -> String {
    let marker = "search_path%3D";
    let start = dsn
        .find(marker)
        .expect("isolated DSN carries a search_path")
        + marker.len();
    let rest = &dsn[start..];
    let end = rest.find('%').unwrap_or(rest.len());
    rest[..end].to_owned()
}

fn base_of(dsn: &str) -> String {
    dsn.split_once('?')
        .map(|(base, _)| base.to_owned())
        .unwrap_or_else(|| dsn.to_owned())
}

/// Applies the reviewed operator script the way an operator does: psql
/// variables substituted, and the transaction executed as one statement batch.
fn install_gateway_role(base: &str, schema: &str, password: &str) {
    let mut admin = postgres::Client::connect(base, NoTls).expect("connect disposable PostgreSQL");
    let database: String = admin
        .query_one("SELECT current_database()::TEXT", &[])
        .expect("read current database")
        .get(0);
    let sql = ROLE_INSTALLER
        .replace("\\set ON_ERROR_STOP on", "")
        .replace(":\"control_database\"", &format!("\"{database}\""))
        .replace(":\"control_schema\"", &format!("\"{schema}\""));
    admin.batch_execute(&sql).expect("install gateway role");
    admin
        .batch_execute(&format!(
            "ALTER ROLE {OBJECT_WRITE_GATEWAY_POSTGRES_ROLE} LOGIN PASSWORD '{password}'"
        ))
        .expect("set gateway login password");
}

fn gateway_dsn(base: &str, schema: &str, password: &str) -> String {
    let rest = base
        .split_once("://")
        .map(|(_, rest)| rest)
        .expect("base DSN has a scheme");
    let host_and_path = rest.split_once('@').map_or(rest, |(_, tail)| tail);
    format!(
        "postgres://{OBJECT_WRITE_GATEWAY_POSTGRES_ROLE}:{password}@{host_and_path}\
         ?options=-csearch_path%3D{schema}"
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn the_gateway_starts_against_the_reviewed_schema_and_login() {
    let dsn = cats_control_plane::testsupport::isolated_control_store_url();
    let schema = schema_of(&dsn);
    let base = base_of(&dsn);
    // Bootstrapping the control schema installs the gateway's routines.
    let store = Store::connect_from_async(DsnSource::Literal(dsn.clone()), None)
        .await
        .expect("bootstrap the control schema");
    drop(store);

    let password = format!("p{}", uuid::Uuid::new_v4().simple());
    let installer_base = base.clone();
    let installer_schema = schema.clone();
    let installer_password = password.clone();
    tokio::task::spawn_blocking(move || {
        install_gateway_role(&installer_base, &installer_schema, &installer_password)
    })
    .await
    .expect("install the gateway role");

    let client = ObjectWriteGatewayClient::connect_from_async(
        DsnSource::Literal(gateway_dsn(&base, &schema, &password)),
        None,
        schema.clone(),
    )
    .await
    .expect("the gateway must start once its twelfth routine is installed and granted");
    drop(client);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_gateway_refuses_to_start_when_the_qualification_lock_is_not_granted() {
    let dsn = cats_control_plane::testsupport::isolated_control_store_url();
    let schema = schema_of(&dsn);
    let base = base_of(&dsn);
    let store = Store::connect_from_async(DsnSource::Literal(dsn.clone()), None)
        .await
        .expect("bootstrap the control schema");
    drop(store);

    let password = format!("p{}", uuid::Uuid::new_v4().simple());
    let installer_base = base.clone();
    let installer_schema = schema.clone();
    let installer_password = password.clone();
    tokio::task::spawn_blocking(move || {
        install_gateway_role(&installer_base, &installer_schema, &installer_password);
        // Calibration: withdraw exactly the E13 grant. The attested capability
        // is read from pg_catalog, so it must now report false and refuse.
        let mut admin =
            postgres::Client::connect(&installer_base, NoTls).expect("connect disposable");
        admin
            .batch_execute(&format!(
                "REVOKE EXECUTE ON FUNCTION \"{installer_schema}\"\
                 .control_object_write_gateway_qualification_lock_v1(\
                 BYTEA,BIGINT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,\
                 TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT) FROM {OBJECT_WRITE_GATEWAY_POSTGRES_ROLE}"
            ))
            .expect("revoke the E13 grant");
    })
    .await
    .expect("install then withdraw the grant");

    let error = match ObjectWriteGatewayClient::connect_from_async(
        DsnSource::Literal(gateway_dsn(&base, &schema, &password)),
        None,
        schema.clone(),
    )
    .await
    {
        Ok(_) => panic!("a withdrawn E13 grant must refuse startup"),
        Err(error) => error,
    };
    assert!(
        format!("{error}").contains("startup contract mismatch"),
        "unexpected refusal: {error}"
    );
}
