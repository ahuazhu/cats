use super::*;

use native_tls::{Certificate, TlsConnector};
use postgres_native_tls::MakeTlsConnector;
use sha2::{Digest as _, Sha256};
use std::time::Duration;

impl Store {
    /// Connect to the control database and bring its schema to this build's
    /// version. The URL may carry `options=-csearch_path=...` so tests can
    /// isolate in a per-test schema; reconnects preserve it because they
    /// re-parse the same URL.
    pub fn connect(url: &str, ca_file: Option<&str>) -> Result<Self> {
        Self::connect_from(&DsnSource::Literal(url.to_string()), ca_file)
    }

    /// Connect from a source that is consulted again after every disconnect.
    pub fn connect_from(dsn: &DsnSource, ca_file: Option<&str>) -> Result<Self> {
        let client = off_runtime(|| {
            let mut client = connect_client(dsn, ca_file)?;
            ensure_schema(&mut client)?;
            Ok::<_, ApiError>(client)
        })?;
        Ok(Self {
            client: Mutex::new(Some(client)),
            dsn: dsn.clone(),
            ca_file: ca_file.map(str::to_string),
            #[cfg(test)]
            commit_response_loss_once: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            request_commit_response_loss_once: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            commit_response_loss_delay_ms: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Verify a pre-existing Control schema without installing or repairing
    /// any object. Reset and release preflight callers must bind the DSN's
    /// search path to the exact explicit target and use this read-only path;
    /// ordinary `connect_from` remains the sole fresh-schema installer.
    pub fn verify_existing_schema(
        dsn: &DsnSource,
        ca_file: Option<&str>,
        expected_schema: &str,
    ) -> Result<()> {
        let mut schema_characters = expected_schema.chars();
        if expected_schema.len() > 63
            || !schema_characters
                .next()
                .is_some_and(|value| value == '_' || value.is_ascii_lowercase())
            || !schema_characters
                .all(|value| value == '_' || value.is_ascii_lowercase() || value.is_ascii_digit())
        {
            return Err(ApiError::invalid(
                "expected Control schema must match [a-z_][a-z0-9_]{0,62}",
            ));
        }
        off_runtime(|| {
            let mut client = connect_client(dsn, ca_file)?;
            client
                .batch_execute("SET statement_timeout = '5s'; SET lock_timeout = '2s'")
                .map_err(internal)?;
            let mut transaction = client.transaction().map_err(internal)?;
            transaction
                .batch_execute("SET TRANSACTION READ ONLY")
                .map_err(internal)?;
            let actual_schema: String = transaction
                .query_one("SELECT COALESCE(current_schema(), '')", &[])
                .map_err(internal)?
                .get(0);
            if actual_schema != expected_schema {
                return Err(ApiError::failed_precondition(format!(
                    "Control DSN selects schema {actual_schema}, expected exact schema {expected_schema}"
                )));
            }
            transaction
                .query_one(
                    "SELECT pg_advisory_xact_lock_shared(hashtext(current_schema()), 420103)",
                    &[],
                )
                .map_err(internal)?;
            if !relation_exists(&mut transaction, "control_schema_version")? {
                return Err(ApiError::failed_precondition(format!(
                    "Control schema {expected_schema} has no release stamp; refusing installation"
                )));
            }
            let stamped = transaction
                .query_opt(
                    "SELECT version FROM control_schema_version WHERE singleton",
                    &[],
                )
                .map_err(internal)?
                .ok_or_else(|| {
                    ApiError::failed_precondition(
                        "control-plane schema stamp is missing its singleton row; recreate it",
                    )
                })?
                .get::<_, i64>(0);
            if stamped != SCHEMA_VERSION {
                return Err(ApiError::failed_precondition(format!(
                    "control-plane database is at schema version {stamped}, this build requires exact clean-slate version {SCHEMA_VERSION}; recreate it"
                )));
            }
            verify_current_schema(&mut transaction)?;
            transaction.commit().map_err(internal)
        })
    }
}

pub(super) fn connect_client(dsn: &DsnSource, ca_file: Option<&str>) -> Result<Client> {
    let mut builder = TlsConnector::builder();
    if let Some(path) = ca_file {
        let pem = std::fs::read(path)
            .map_err(|error| internal(format!("read control-store CA file: {error}")))?;
        let certificates = pem_certificates(&pem)?;
        if certificates.is_empty() {
            return Err(internal(format!(
                "control-store CA file {path:?} contains no certificates"
            )));
        }
        for certificate in certificates {
            builder.add_root_certificate(certificate);
        }
    }
    let connector = builder
        .build()
        .map_err(|error| internal(format!("build control-store TLS client: {error}")))?;
    let url = dsn.resolve()?;
    let mut config: postgres::Config = url
        .parse()
        .map_err(|error| internal(format!("parse control-store URL: {error}")))?;
    config.connect_timeout(Duration::from_secs(5));
    let client = config
        .connect(MakeTlsConnector::new(connector))
        .map_err(|error| ApiError::unavailable(connect_failure(error)))?;
    Ok(client)
}

/// Describe a failed connect using the server's own words. `postgres::Error`
/// renders a server-side failure as just "db error"; the reason is only
/// reachable through `as_db_error`, and losing it has cost real diagnosis
/// time before (a rotated password surfacing as an unexplained "db error").
fn connect_failure(error: postgres::Error) -> String {
    match error.as_db_error() {
        Some(database_error) => {
            let detail = database_error
                .detail()
                .map(|value| format!("; {value}"))
                .unwrap_or_default();
            format!(
                "connect control store: {}{detail}",
                database_error.message()
            )
        }
        None => format!("connect control store: {error}"),
    }
}

fn pem_certificates(pem: &[u8]) -> Result<Vec<Certificate>> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";
    let mut certificates = Vec::new();
    let mut rest = pem;
    while let Some(start) = find_bytes(rest, BEGIN) {
        let candidate = &rest[start..];
        let Some(end) = find_bytes(candidate, END) else {
            return Err(internal(
                "control-store CA file has an unterminated certificate",
            ));
        };
        let end = end + END.len();
        certificates.push(
            Certificate::from_pem(&candidate[..end]).map_err(|error| {
                internal(format!("parse control-store CA certificate: {error}"))
            })?,
        );
        rest = &candidate[end..];
    }
    Ok(certificates)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn ensure_schema(client: &mut Client) -> Result<()> {
    client
        .batch_execute("SET statement_timeout = '5s'; SET lock_timeout = '2s'")
        .map_err(internal)?;
    let isolated_test_bootstrap: bool = client
        .query_one(
            "SELECT COALESCE(
                current_setting('cats.test_schema_bootstrap', TRUE) = 'on',
                FALSE
             )",
            &[],
        )
        .map_err(internal)?
        .get(0);
    // The clean-slate cutover has one schema shape. DDL and its stamp commit in
    // the same transaction; a current stamp is verified but never repaired.
    // The xact-scoped lock lets two first replicas converge without leaving a
    // session lock behind after any error.
    let mut transaction = client.transaction().map_err(internal)?;
    // Integration tests link the ordinary library, so the isolated-schema
    // helper carries an exact custom GUC instead of relying on cfg(test).
    // SET LOCAL restores the production 5s/2s session limits at transaction
    // end, and no other marker value changes production behavior. Four
    // workspace test threads can queue behind the intentionally global DDL
    // lock while a concurrent Linux gate loads the host, so the test-only
    // budget covers the complete bounded queue rather than one schema install.
    if isolated_test_bootstrap {
        transaction
            .batch_execute(
                "SET LOCAL statement_timeout = '120s'; \
                 SET LOCAL lock_timeout = '120s'",
            )
            .map_err(internal)?;
    }
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtext(current_schema()), 420103)",
            &[],
        )
        .map_err(internal)?;

    if relation_exists(&mut transaction, "control_schema_version")? {
        let stamped = transaction
            .query_opt(
                "SELECT version FROM control_schema_version WHERE singleton",
                &[],
            )
            .map_err(|error| internal(format!("verify authority foreign key catalog: {error:?}")))?
            .ok_or_else(|| {
                ApiError::failed_precondition(
                    "control-plane schema stamp is missing its singleton row; recreate it",
                )
            })?
            .get::<_, i64>(0);
        if stamped != SCHEMA_VERSION {
            return Err(ApiError::failed_precondition(format!(
                "control-plane database is at schema version {stamped}, this build requires exact clean-slate version {SCHEMA_VERSION}; recreate it"
            )));
        }
        verify_current_schema(&mut transaction)?;
    } else {
        if CONTROL_TABLES.iter().try_fold(false, |found, table| {
            relation_exists(&mut transaction, table).map(|exists| found || exists)
        })? {
            return Err(ApiError::failed_precondition(
                "control-plane schema is nonempty but unstamped; recreate it",
            ));
        }
        // Different isolated test schemas do not share the production
        // per-schema lock, so serialize only their catalog-heavy initial DDL.
        if isolated_test_bootstrap {
            transaction
                .query_one("SELECT pg_advisory_xact_lock(420111, 1)", &[])
                .map_err(internal)?;
        }
        transaction.batch_execute(SCHEMA).map_err(internal)?;
        install_host_fence_provider_functions(&mut transaction)?;
        install_object_write_gateway_functions(&mut transaction)?;
        transaction
            .execute(
                "INSERT INTO control_schema_version (singleton, version) VALUES (TRUE, $1)",
                &[&SCHEMA_VERSION],
            )
            .map_err(internal)?;
        verify_current_schema(&mut transaction)?;
    }
    transaction.commit().map_err(internal)
}

fn relation_exists(transaction: &mut postgres::Transaction<'_>, relation: &str) -> Result<bool> {
    transaction
        .query_one(
            "SELECT EXISTS (
                SELECT 1
                  FROM pg_class c
                  JOIN pg_namespace n ON n.oid = c.relnamespace
                 WHERE n.nspname = current_schema()
                   AND c.relname = $1
                   AND c.relkind IN ('r', 'p')
             )",
            &[&relation],
        )
        .map(|row| row.get(0))
        .map_err(internal)
}

fn column_exists(
    transaction: &mut postgres::Transaction<'_>,
    relation: &str,
    column: &str,
) -> Result<bool> {
    transaction
        .query_one(
            "SELECT EXISTS (
                SELECT 1
                  FROM information_schema.columns
                 WHERE table_schema=current_schema()
                   AND table_name=$1
                   AND column_name=$2
             )",
            &[&relation, &column],
        )
        .map(|row| row.get(0))
        .map_err(internal)
}

fn verify_current_schema(transaction: &mut postgres::Transaction<'_>) -> Result<()> {
    for table in CONTROL_TABLES {
        if !relation_exists(transaction, table)? {
            return Err(ApiError::failed_precondition(format!(
                "control-plane schema version {SCHEMA_VERSION} is partial: missing table {table}; recreate it"
            )));
        }
    }
    for table in FORBIDDEN_LEGACY_CONTROL_TABLES {
        if relation_exists(transaction, table)? {
            return Err(ApiError::failed_precondition(format!(
                "control-plane schema version {SCHEMA_VERSION} still contains legacy authority table {table}; recreate it"
            )));
        }
    }
    for (table, column) in FORBIDDEN_LEGACY_CONTROL_COLUMNS {
        if column_exists(transaction, table, column)? {
            return Err(ApiError::failed_precondition(format!(
                "control-plane schema version {SCHEMA_VERSION} still contains legacy authority column {table}.{column}; recreate it"
            )));
        }
    }

    // These probes also make a manually stamped shape with a missing authority
    // projection fail at startup instead of being repaired or discovered by a
    // writer later.
    for probe in AUTHORITY_SCHEMA_PROBES {
        transaction.query(*probe, &[]).map_err(|error| {
            ApiError::failed_precondition(format!(
                "control-plane schema version {SCHEMA_VERSION} does not match this build: {error}; recreate it"
            ))
        })?;
    }
    verify_authority_catalog(transaction)?;
    verify_host_fence_provider_function_catalog(transaction)?;
    verify_object_write_gateway_function_catalog(transaction)?;
    Ok(())
}

fn quote_identifier(identifier: &str) -> Result<String> {
    if identifier.is_empty() || identifier.as_bytes().contains(&0) {
        return Err(ApiError::failed_precondition(
            "control schema has an invalid PostgreSQL identifier",
        ));
    }
    Ok(format!("\"{}\"", identifier.replace('"', "\"\"")))
}

fn quote_literal(value: &str) -> Result<String> {
    if value.as_bytes().contains(&0) {
        return Err(ApiError::failed_precondition(
            "control schema has an invalid PostgreSQL literal",
        ));
    }
    Ok(format!("'{}'", value.replace('\'', "''")))
}

fn install_host_fence_provider_functions(
    transaction: &mut postgres::Transaction<'_>,
) -> Result<()> {
    let schema: String = transaction
        .query_one("SELECT current_schema()::TEXT", &[])
        .map_err(internal)?
        .try_get(0)
        .map_err(internal)?;
    let schema_identifier = quote_identifier(&schema)?;
    let schema_literal = quote_literal(&schema)?;
    let functions = HOST_FENCE_PROVIDER_FUNCTIONS
        .replace("__CATS_SCHEMA_IDENT__", &schema_identifier)
        .replace("__CATS_SCHEMA_LITERAL__", &schema_literal);
    transaction.batch_execute(&functions).map_err(|error| {
        let detail = error
            .as_db_error()
            .map(|database| {
                format!(
                    "{}{}",
                    database.message(),
                    database
                        .position()
                        .map(|position| format!(" at {position:?}"))
                        .unwrap_or_default()
                )
            })
            .unwrap_or_else(|| error.to_string());
        internal(format!(
            "install Host-fence provider PostgreSQL functions: {detail}"
        ))
    })
}

const OBJECT_WRITE_GATEWAY_FUNCTIONS: &str = include_str!("object_write_gateway_functions.sql");

#[derive(Clone, Copy)]
struct ObjectWriteGatewayFunction {
    name: &'static str,
    identity_arguments: &'static str,
    result: &'static str,
    security_definer: bool,
    strict: bool,
    volatility: &'static str,
    language: &'static str,
    gateway_execute: bool,
}

const OBJECT_WRITE_GATEWAY_FUNCTION_CATALOG: &[ObjectWriteGatewayFunction] = &[
    ObjectWriteGatewayFunction {
        name: "control_object_write_gateway_accept_v1",
        identity_arguments: "requested_request_id text",
        result: "TABLE(record_json text, authority_json text, accepted boolean)",
        security_definer: true,
        strict: false,
        volatility: "v",
        language: "plpgsql",
        gateway_execute: true,
    },
    ObjectWriteGatewayFunction {
        name: "control_object_write_gateway_begin_ingress_v1",
        identity_arguments: "requested_attachment jsonb, requested_descriptor jsonb",
        result: "TABLE(record_json text, authority_json text, accepted boolean)",
        security_definer: true,
        strict: false,
        volatility: "v",
        language: "plpgsql",
        gateway_execute: true,
    },
    ObjectWriteGatewayFunction {
        name: "control_object_write_gateway_frame_v1",
        identity_arguments: "value bytea",
        result: "bytea",
        security_definer: false,
        strict: true,
        volatility: "i",
        language: "sql",
        gateway_execute: false,
    },
    ObjectWriteGatewayFunction {
        name: "control_object_write_gateway_provider_issued_v1",
        identity_arguments: "requested_request_id text",
        result: "TABLE(record_json text, authority_json text)",
        security_definer: true,
        strict: false,
        volatility: "v",
        language: "plpgsql",
        gateway_execute: true,
    },
    ObjectWriteGatewayFunction {
        name: "control_object_write_gateway_qualification_head_canonical_v1",
        identity_arguments: "value jsonb",
        result: "bytea",
        security_definer: false,
        strict: true,
        volatility: "i",
        language: "plpgsql",
        gateway_execute: false,
    },
    ObjectWriteGatewayFunction {
        name: "control_object_write_gateway_qualification_lock_v1",
        identity_arguments: "p_request_canonical bytea, p_version bigint, p_mutation_class text, p_request_id text, p_writer_authority_id text, p_credential_id text, p_credential_public_key_spki_sha256 text, p_provider_attempt_id text, p_fault_kind text, p_qualification_id text, p_fault_id text, p_fault_catalog_sha256 text, p_provider text, p_partition text, p_account_id text, p_region text, p_object_store_scope_id text, p_canonical_logical_key text, p_content_sha256 text, p_content_length bigint",
        result: "TABLE(request_canonical bytea, authorization_canonical bytea, authorization_version bigint, authorization_mutation_class text, qualification_id text, workspace_id text, deployment_id text, release_id text, source_commit_sha text, control_schema_version bigint, qualification_catalog_sha256 text, admission_binding_sha256 text, admission_revision bigint, authorized_at_unix_ms bigint, qualification_expires_at_unix_ms bigint)",
        security_definer: true,
        strict: false,
        volatility: "v",
        language: "plpgsql",
        gateway_execute: true,
    },
    ObjectWriteGatewayFunction {
        name: "control_object_write_gateway_qualification_response_lost_v1",
        identity_arguments:
            "p_request_canonical bytea, p_successful_put_canonical bytea",
        result: "TABLE(found boolean, attempt_canonical bytea, authorization_canonical bytea, response_loss_canonical bytea)",
        security_definer: true,
        strict: false,
        volatility: "v",
        language: "plpgsql",
        gateway_execute: true,
    },
    ObjectWriteGatewayFunction {
        name: "control_object_write_gateway_recover_accepted_v1",
        identity_arguments: "requested_after_request_id text",
        result: "TABLE(request_id text, state text, record_json text, authority_json text)",
        security_definer: true,
        strict: false,
        volatility: "s",
        language: "plpgsql",
        gateway_execute: true,
    },
    ObjectWriteGatewayFunction {
        name: "control_object_write_gateway_recover_ingress_v1",
        identity_arguments: "requested_after_request_id text",
        result: "TABLE(request_id text, state text, record_json text)",
        security_definer: true,
        strict: false,
        volatility: "s",
        language: "plpgsql",
        gateway_execute: true,
    },
    ObjectWriteGatewayFunction {
        name: "control_object_write_gateway_register_v1",
        identity_arguments: "requested_node_credential_id text, requested_node_public_key_sha256 text, requested_attachment jsonb, requested_registration jsonb",
        result: "jsonb",
        security_definer: true,
        strict: false,
        volatility: "v",
        language: "plpgsql",
        gateway_execute: true,
    },
    ObjectWriteGatewayFunction {
        name: "control_object_write_gateway_spool_durable_v1",
        identity_arguments: "requested_request_id text, requested_spool jsonb",
        result: "TABLE(record_json text, authority_json text, accepted boolean)",
        security_definer: true,
        strict: false,
        volatility: "v",
        language: "plpgsql",
        gateway_execute: true,
    },
    ObjectWriteGatewayFunction {
        name: "control_object_write_gateway_spool_removed_v1",
        identity_arguments: "requested_request_id text, requested_removal_receipt_id text",
        result: "TABLE(record_json text, authority_json text)",
        security_definer: true,
        strict: false,
        volatility: "v",
        language: "plpgsql",
        gateway_execute: true,
    },
    ObjectWriteGatewayFunction {
        name: "control_object_write_gateway_startup_v1",
        identity_arguments: "",
        result: "TABLE(protocol_version bigint, schema_version bigint, schema_name text, expected_role text, routine_count bigint, contract_sha256 text, catalog_sha256 text, qualification_lock_available boolean)",
        security_definer: true,
        strict: false,
        volatility: "v",
        language: "plpgsql",
        gateway_execute: true,
    },
    ObjectWriteGatewayFunction {
        name: "control_object_write_gateway_terminal_v1",
        identity_arguments: "requested_request_id text, requested_outcome_canonical bytea",
        result: "TABLE(record_json text, authority_json text)",
        security_definer: true,
        strict: false,
        volatility: "v",
        language: "plpgsql",
        gateway_execute: true,
    },
];

fn object_write_gateway_function_body(name: &str) -> Result<&'static str> {
    let declaration = format!("CREATE OR REPLACE FUNCTION __CATS_SCHEMA_IDENT__.{name}(");
    let function = OBJECT_WRITE_GATEWAY_FUNCTIONS
        .find(&declaration)
        .ok_or_else(|| internal(format!("missing object-write function source for {name}")))?;
    let source = &OBJECT_WRITE_GATEWAY_FUNCTIONS[function..];
    let body_start = source
        .find("AS $function$")
        .map(|offset| offset + "AS $function$".len())
        .ok_or_else(|| internal(format!("missing object-write function body for {name}")))?;
    let body = &source[body_start..];
    let body_end = body.find("$function$;").ok_or_else(|| {
        internal(format!(
            "unterminated object-write function body for {name}"
        ))
    })?;
    Ok(&body[..body_end])
}

fn sha256_text(value: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(value.as_bytes()))
}

pub(super) fn object_write_gateway_contract_sha256() -> Result<String> {
    let mut lines = Vec::new();
    for function in OBJECT_WRITE_GATEWAY_FUNCTION_CATALOG
        .iter()
        .filter(|function| function.gateway_execute)
    {
        lines.push(format!(
            "{}\0{}\0{}",
            function.name, function.identity_arguments, function.result
        ));
    }
    Ok(sha256_text(&format!(
        "cats.control-object-write-gateway-contract.v1\n{}",
        lines.join("\n")
    )))
}

pub(super) fn object_write_gateway_catalog_sha256() -> Result<String> {
    let mut lines = Vec::new();
    for function in OBJECT_WRITE_GATEWAY_FUNCTION_CATALOG {
        let body_sha256 = sha256_text(object_write_gateway_function_body(function.name)?)
            .strip_prefix("sha256:")
            .ok_or_else(|| internal("object-write function digest lost its prefix"))?
            .to_string();
        lines.push(format!(
            "{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}search_path=pg_catalog, pg_temp\u{1}true\u{1}true\u{1}{}\u{1}{}",
            function.name,
            function.identity_arguments,
            function.result,
            function.security_definer,
            function.strict,
            function.volatility,
            function.language,
            function.gateway_execute,
            body_sha256,
        ));
    }
    Ok(sha256_text(&lines.join("\n")))
}

pub(super) fn object_write_gateway_catalog_function_names() -> Vec<&'static str> {
    OBJECT_WRITE_GATEWAY_FUNCTION_CATALOG
        .iter()
        .map(|function| function.name)
        .collect()
}

pub(super) fn object_write_gateway_catalog_function_count() -> usize {
    OBJECT_WRITE_GATEWAY_FUNCTION_CATALOG.len()
}

fn install_object_write_gateway_functions(
    transaction: &mut postgres::Transaction<'_>,
) -> Result<()> {
    let schema: String = transaction
        .query_one("SELECT current_schema()::TEXT", &[])
        .map_err(internal)?
        .try_get(0)
        .map_err(internal)?;
    let schema_identifier = quote_identifier(&schema)?;
    let schema_literal = quote_literal(&schema)?;
    let contract_sha256 = object_write_gateway_contract_sha256()?;
    let contract_hex = contract_sha256
        .strip_prefix("sha256:")
        .ok_or_else(|| internal("object-write contract digest lost its prefix"))?;
    let functions = OBJECT_WRITE_GATEWAY_FUNCTIONS
        .replace("__CATS_SCHEMA_IDENT__", &schema_identifier)
        .replace("__CATS_SCHEMA_LITERAL__", &schema_literal)
        .replace(
            "__CATS_OBJECT_WRITE_GATEWAY_CONTRACT_SHA256_VALUE__",
            contract_hex,
        );
    transaction.batch_execute(&functions).map_err(|error| {
        let detail = error
            .as_db_error()
            .map(|database| {
                format!(
                    "{}{}",
                    database.message(),
                    database
                        .position()
                        .map(|position| format!(" at {position:?}"))
                        .unwrap_or_default()
                )
            })
            .unwrap_or_else(|| error.to_string());
        internal(format!(
            "install object-write gateway PostgreSQL functions: {detail}"
        ))
    })?;
    transaction
        .batch_execute(&format!(
            "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA {schema_identifier} FROM PUBLIC"
        ))
        .map_err(|error| {
            internal(format!(
                "close object-write gateway PUBLIC function surface: {error}"
            ))
        })
}

fn verify_object_write_gateway_function_catalog(
    transaction: &mut postgres::Transaction<'_>,
) -> Result<()> {
    let contract_sha256 = object_write_gateway_contract_sha256()?;
    let contract_hex = contract_sha256
        .strip_prefix("sha256:")
        .ok_or_else(|| internal("object-write contract digest lost its prefix"))?;
    let names: Vec<&str> = OBJECT_WRITE_GATEWAY_FUNCTION_CATALOG
        .iter()
        .map(|function| function.name)
        .collect();
    let count: i64 = transaction
        .query_one(
            "SELECT COUNT(*)
               FROM pg_proc function
               JOIN pg_namespace namespace ON namespace.oid=function.pronamespace
              WHERE namespace.nspname=current_schema()
                AND function.proname=ANY($1::TEXT[])",
            &[&names],
        )
        .map_err(internal)?
        .get(0);
    if usize::try_from(count).ok() != Some(OBJECT_WRITE_GATEWAY_FUNCTION_CATALOG.len()) {
        return Err(partial_catalog_object(
            "object-write gateway exact function inventory",
        ));
    }
    for function in OBJECT_WRITE_GATEWAY_FUNCTION_CATALOG {
        let body_sha256 = sha256_text(object_write_gateway_function_body(function.name)?)
            .strip_prefix("sha256:")
            .ok_or_else(|| internal("object-write function digest lost its prefix"))?
            .to_string();
        let present: bool = transaction
            .query_one(
                "SELECT EXISTS (
                    SELECT 1
                      FROM pg_proc function
                      JOIN pg_namespace namespace
                        ON namespace.oid=function.pronamespace
                      JOIN pg_language language ON language.oid=function.prolang
                     WHERE namespace.nspname=current_schema()
                       AND function.proname=$1
                       AND pg_get_function_identity_arguments(function.oid)=$2
                       AND pg_get_function_result(function.oid)=$3
                       AND function.prosecdef=$4
                       AND function.proisstrict=$5
                       AND function.provolatile::TEXT=$6
                       AND language.lanname=$7
                       AND function.proconfig =
                           ARRAY['search_path=pg_catalog, pg_temp']::TEXT[]
                       AND function.proowner=namespace.nspowner
                       AND encode(sha256(convert_to(
                           replace(replace(replace(
                               function.prosrc,
                               chr(34) || current_schema() || chr(34),
                               '__CATS_SCHEMA_IDENT__'
                           ), quote_literal(current_schema()),
                              '__CATS_SCHEMA_LITERAL__'),
                              $8, '__CATS_OBJECT_WRITE_GATEWAY_CONTRACT_SHA256_VALUE__'
                           ), 'UTF8')), 'hex')=$9
                       AND NOT EXISTS (
                           SELECT 1
                             FROM aclexplode(COALESCE(
                                  function.proacl,
                                  acldefault('f', function.proowner)
                             )) privilege
                            WHERE privilege.grantee=0
                              AND privilege.privilege_type='EXECUTE'
                       )
                )",
                &[
                    &function.name,
                    &function.identity_arguments,
                    &function.result,
                    &function.security_definer,
                    &function.strict,
                    &function.volatility,
                    &function.language,
                    &contract_hex,
                    &body_sha256,
                ],
            )
            .map_err(internal)?
            .get(0);
        if !present {
            return Err(partial_catalog_object(function.name));
        }
    }
    let public_execute_is_closed: bool = transaction
        .query_one(
            "SELECT NOT EXISTS (
                SELECT 1
                  FROM pg_proc function
                  JOIN pg_namespace namespace
                    ON namespace.oid=function.pronamespace
                  CROSS JOIN LATERAL aclexplode(COALESCE(
                      function.proacl,
                      acldefault('f', function.proowner)
                  )) privilege
                 WHERE namespace.nspname=current_schema()
                   AND privilege.grantee=0
                   AND privilege.privilege_type='EXECUTE'
            )",
            &[],
        )
        .map_err(internal)?
        .get(0);
    if !public_execute_is_closed {
        return Err(partial_catalog_object(
            "object-write gateway PUBLIC function privilege closure",
        ));
    }
    Ok(())
}

/// The provider process is intentionally limited to a small, immutable
/// function surface.  Verify the properties which make those functions a
/// privilege boundary on every stamped-schema startup; a missing REVOKE or a
/// changed owner must never be silently repaired.
fn verify_host_fence_provider_function_catalog(
    transaction: &mut postgres::Transaction<'_>,
) -> Result<()> {
    let public_execute_is_closed: bool = transaction
        .query_one(
            "SELECT NOT EXISTS (
                SELECT 1
                  FROM pg_proc function
                  JOIN pg_namespace namespace
                    ON namespace.oid=function.pronamespace
                  CROSS JOIN LATERAL aclexplode(COALESCE(
                      function.proacl, acldefault('f', function.proowner)
                  )) privilege
                 WHERE namespace.nspname=current_schema()
                   AND privilege.grantee=0
                   AND privilege.privilege_type='EXECUTE'
            )",
            &[],
        )
        .map_err(internal)?
        .get(0);
    if !public_execute_is_closed {
        return Err(partial_catalog_object(
            "schema-wide PUBLIC function EXECUTE closure",
        ));
    }
    const FUNCTIONS: &[(&str, i16, bool, &str, &str)] = &[
        (
            "control_host_fence_provider_frame_v1",
            1,
            false,
            "sql",
            "b5fef9cc3b79242c39d03d8873917ff435dc0800879c258810e877a8c95a86a0",
        ),
        (
            "control_host_fence_provider_startup_v1",
            0,
            true,
            "plpgsql",
            "37c3f7be861f1951bb868ae6556eaf732cb3b3f7943d4932d0e056a5493414fb",
        ),
        (
            "control_host_fence_provider_claim_v1",
            7,
            true,
            "plpgsql",
            "ca7e243833c40c8748da7e7956cc56615d9f90939018fc4c5799cb82ede61d02",
        ),
        (
            "control_host_fence_provider_renew_v1",
            4,
            true,
            "plpgsql",
            "2cc610961a74fd2e7d74a09920a8d4f984463dba2b88909961d656e0ab1a1e93",
        ),
        (
            "control_host_fence_provider_object_cutoff_v1",
            2,
            true,
            "plpgsql",
            "c5e6a02bd09a6df2283af80b7408e864d2b3441f4cba6ff1e568c3ce2335865e",
        ),
        (
            "control_host_fence_provider_complete_v1",
            4,
            true,
            "plpgsql",
            "7114b4a93c12928948245529aab9d31d8c6e177e23b4e54978c3825a7dd17659",
        ),
        (
            "control_host_fence_provider_read_v1",
            2,
            true,
            "plpgsql",
            "764f366828187b24e75552a4f7ec057d2c195a62c893b126c20d8c0577c3ac9c",
        ),
    ];
    for (name, arguments, security_definer, language, body_sha256) in FUNCTIONS {
        let present: bool = transaction
            .query_one(
                "SELECT EXISTS (
                    SELECT 1
                      FROM pg_proc function
                      JOIN pg_namespace namespace
                        ON namespace.oid=function.pronamespace
                      JOIN pg_language language ON language.oid=function.prolang
                     WHERE namespace.nspname=current_schema()
                       AND function.proname=$1
                       AND function.pronargs=$2
                       AND function.prosecdef=$3
                       AND language.lanname=$4
                       AND encode(sha256(convert_to(
                           replace(replace(
                               function.prosrc,
                               chr(34) || current_schema() || chr(34),
                               '__CATS_SCHEMA_IDENT__'
                           ),
                           quote_literal(current_schema()),
                           '__CATS_SCHEMA_LITERAL__'
                       ), 'UTF8')), 'hex')=$5
                       AND function.proconfig =
                           ARRAY['search_path=pg_catalog, pg_temp']::TEXT[]
                       AND function.proowner=(
                           SELECT schema.nspowner
                             FROM pg_namespace schema
                            WHERE schema.nspname=current_schema()
                       )
                       AND NOT EXISTS (
                           SELECT 1
                             FROM aclexplode(COALESCE(
                                  function.proacl,
                                  acldefault('f', function.proowner)
                             )) privilege
                            WHERE privilege.grantee=0
                              AND privilege.privilege_type='EXECUTE'
                       )
                )",
                &[name, arguments, security_definer, language, body_sha256],
            )
            .map_err(internal)?
            .get(0);
        if !present {
            return Err(partial_catalog_object(name));
        }
    }
    let parent_guard_is_safe: bool = transaction
        .query_one(
            "SELECT EXISTS (
                SELECT 1
                  FROM pg_proc function
                  JOIN pg_namespace namespace
                    ON namespace.oid=function.pronamespace
                  JOIN pg_language language ON language.oid=function.prolang
                 WHERE namespace.nspname=current_schema()
                   AND function.proname='object_write_credential_parent_guard'
                   AND function.pronargs=0 AND function.prosecdef
                   AND language.lanname='plpgsql'
                   AND function.proowner=namespace.nspowner
                   AND function.proconfig = ARRAY[
                       'search_path=' || current_schema() || ', pg_catalog, pg_temp'
                   ]::TEXT[]
                   AND NOT EXISTS (
                       SELECT 1
                         FROM aclexplode(COALESCE(
                              function.proacl,
                              acldefault('f', function.proowner)
                         )) privilege
                        WHERE privilege.grantee=0
                          AND privilege.privilege_type='EXECUTE'
                   )
            )",
            &[],
        )
        .map_err(internal)?
        .get(0);
    if !parent_guard_is_safe {
        return Err(partial_catalog_object(
            "object_write_credential_parent_guard privilege boundary",
        ));
    }
    Ok(())
}

/// Column probes cannot detect a stamped schema whose database-enforced
/// lineage/immutability barriers were dropped. Verify the A23 catalog objects
/// structurally at every startup; a current stamp is never permission to
/// recreate or repair one of them.
fn verify_authority_catalog(transaction: &mut postgres::Transaction<'_>) -> Result<()> {
    for (table, constraint, columns) in REQUIRED_PRIMARY_KEYS {
        let present: bool = transaction
            .query_one(
                "SELECT EXISTS (
                    SELECT 1
                      FROM pg_constraint c
                      JOIN pg_class source ON source.oid=c.conrelid
                      JOIN pg_namespace source_namespace
                        ON source_namespace.oid=source.relnamespace
                      JOIN pg_index i ON i.indexrelid=c.conindid
                      JOIN pg_class index_relation
                        ON index_relation.oid=i.indexrelid
                      JOIN pg_am access_method
                        ON access_method.oid=index_relation.relam
                     WHERE source_namespace.nspname=current_schema()
                       AND source.relname=$1 AND c.conname=$2
                       AND index_relation.relname=$2
                       AND c.contype='p' AND c.convalidated
                       AND NOT c.condeferrable AND NOT c.condeferred
                       AND i.indisprimary AND i.indisunique
                       AND i.indisvalid AND i.indisready
                       AND i.indnkeyatts=array_length(string_to_array($3, ','), 1)
                       AND i.indnatts=i.indnkeyatts
                       AND i.indexprs IS NULL AND i.indpred IS NULL
                       AND access_method.amname='btree'
                       AND ARRAY(
                           SELECT attribute.attname::TEXT
                             FROM unnest(c.conkey) WITH ORDINALITY AS key(attnum, ordinal)
                             JOIN pg_attribute attribute
                               ON attribute.attrelid=c.conrelid
                              AND attribute.attnum=key.attnum
                            ORDER BY key.ordinal
                       ) = string_to_array($3, ',')
                 )",
                &[table, constraint, columns],
            )
            .map_err(|error| internal(format!("verify authority primary-key catalog: {error:?}")))?
            .get(0);
        if !present {
            return Err(partial_catalog_object(constraint));
        }
    }
    for (table, constraint, definition) in REQUIRED_CHECK_CONSTRAINTS {
        let present: bool = transaction
            .query_one(
                "SELECT EXISTS (
                    SELECT 1
                      FROM pg_constraint c
                      JOIN pg_class source ON source.oid=c.conrelid
                      JOIN pg_namespace source_namespace
                        ON source_namespace.oid=source.relnamespace
                     WHERE source_namespace.nspname=current_schema()
                       AND source.relname=$1 AND c.conname=$2
                       AND c.contype='c' AND c.convalidated
                       AND NOT c.connoinherit
                       AND pg_get_constraintdef(c.oid, FALSE)=$3
                 )",
                &[table, constraint, definition],
            )
            .map_err(|error| {
                internal(format!(
                    "verify authority check-constraint catalog: {error:?}"
                ))
            })?
            .get(0);
        if !present {
            return Err(partial_catalog_object(constraint));
        }
    }
    for (table, constraint, definition) in REQUIRED_FOREIGN_KEYS {
        let present: bool = transaction
            .query_one(
                "SELECT EXISTS (
                    SELECT 1
                      FROM pg_constraint c
                      JOIN pg_class source ON source.oid=c.conrelid
                      JOIN pg_namespace source_namespace
                        ON source_namespace.oid=source.relnamespace
                      JOIN pg_class target ON target.oid=c.confrelid
                      JOIN pg_namespace target_namespace
                        ON target_namespace.oid=target.relnamespace
                     WHERE source_namespace.nspname=current_schema()
                       AND target_namespace.nspname=current_schema()
                       AND source.relname=$1 AND c.conname=$2
                       AND c.contype='f' AND c.convalidated
                       AND NOT c.condeferrable AND NOT c.condeferred
                       AND pg_get_constraintdef(c.oid, FALSE)=$3
                 )",
                &[table, constraint, definition],
            )
            .map_err(|error| internal(format!("verify authority foreign-key catalog: {error:?}")))?
            .get(0);
        if !present {
            return Err(partial_catalog_object(constraint));
        }
    }
    for (table, constraint, target, source_columns, target_columns, update_action, delete_action) in
        REQUIRED_DEFERRED_FOREIGN_KEYS
    {
        let present: bool = transaction
            .query_one(
                "SELECT EXISTS (
                    SELECT 1
                      FROM pg_constraint c
                      JOIN pg_class source ON source.oid=c.conrelid
                      JOIN pg_namespace n ON n.oid=source.relnamespace
                      JOIN pg_class target ON target.oid=c.confrelid
                      JOIN pg_namespace target_namespace
                        ON target_namespace.oid=target.relnamespace
                     WHERE n.nspname=current_schema()
                       AND source.relname=$1 AND c.conname=$2
                       AND target_namespace.nspname=current_schema()
                       AND target.relname=$3 AND c.contype='f'
                       AND c.condeferrable AND c.condeferred AND c.convalidated
                       AND ARRAY(
                           SELECT attribute.attname::TEXT
                             FROM unnest(c.conkey) WITH ORDINALITY AS key(attnum, ordinal)
                             JOIN pg_attribute attribute
                               ON attribute.attrelid=c.conrelid
                              AND attribute.attnum=key.attnum
                            ORDER BY key.ordinal
                       ) = string_to_array($4, ',')
                       AND ARRAY(
                           SELECT attribute.attname::TEXT
                             FROM unnest(c.confkey) WITH ORDINALITY AS key(attnum, ordinal)
                             JOIN pg_attribute attribute
                               ON attribute.attrelid=c.confrelid
                              AND attribute.attnum=key.attnum
                            ORDER BY key.ordinal
                       ) = string_to_array($5, ',')
                       AND c.confupdtype::TEXT=$6 AND c.confdeltype::TEXT=$7
                 )",
                &[
                    table,
                    constraint,
                    target,
                    source_columns,
                    target_columns,
                    update_action,
                    delete_action,
                ],
            )
            .map_err(|error| internal(format!("verify authority index catalog: {error:?}")))?
            .get(0);
        if !present {
            return Err(partial_catalog_object(constraint));
        }
    }
    for (table, index, columns, predicate) in REQUIRED_UNIQUE_INDEXES {
        let present: bool = transaction
            .query_one(
                "SELECT EXISTS (
                    SELECT 1
                      FROM pg_index i
                      JOIN pg_class source ON source.oid=i.indrelid
                      JOIN pg_namespace n ON n.oid=source.relnamespace
                      JOIN pg_class index_relation ON index_relation.oid=i.indexrelid
                     WHERE n.nspname=current_schema()
                       AND source.relname=$1 AND index_relation.relname=$2
                       AND i.indisunique AND i.indisvalid AND i.indisready
                       AND ARRAY(
                           SELECT attribute.attname::TEXT
                             FROM unnest(i.indkey) WITH ORDINALITY AS key(attnum, ordinal)
                             JOIN pg_attribute attribute
                               ON attribute.attrelid=i.indrelid
                              AND attribute.attnum=key.attnum
                            WHERE key.ordinal <= i.indnkeyatts
                            ORDER BY key.ordinal
                       ) = string_to_array($3, ',')
                       AND (($4::TEXT IS NULL AND i.indpred IS NULL)
                            OR pg_get_expr(i.indpred, i.indrelid)=$4)
                 )",
                &[table, index, columns, predicate],
            )
            .map_err(|error| internal(format!("verify authority trigger catalog: {error:?}")))?
            .get(0);
        if !present {
            return Err(partial_catalog_object(index));
        }
    }
    for (table, index, first, second, third, fourth, predicate) in REQUIRED_ORDERED_PARTIAL_INDEXES
    {
        let present: bool = transaction
            .query_one(
                "SELECT EXISTS (
                    SELECT 1
                      FROM pg_index i
                      JOIN pg_class source ON source.oid=i.indrelid
                      JOIN pg_namespace source_namespace
                        ON source_namespace.oid=source.relnamespace
                      JOIN pg_class index_relation
                        ON index_relation.oid=i.indexrelid
                      JOIN pg_am access_method
                        ON access_method.oid=index_relation.relam
                     WHERE source_namespace.nspname=current_schema()
                       AND source.relname=$1 AND index_relation.relname=$2
                       AND NOT i.indisunique AND i.indisvalid AND i.indisready
                       AND i.indnkeyatts=4 AND i.indnatts=4
                       AND i.indoption::TEXT='0 0 0 0'
                       AND i.indexprs IS NULL AND i.indpred IS NOT NULL
                       AND access_method.amname='btree'
                       AND i.indcollation[0]=(
                           SELECT attribute.attcollation
                             FROM pg_attribute attribute
                            WHERE attribute.attrelid=i.indrelid
                              AND attribute.attname='volume_id'
                       )
                       AND i.indcollation[1]=(
                           SELECT attribute.attcollation
                             FROM pg_attribute attribute
                            WHERE attribute.attrelid=i.indrelid
                              AND attribute.attname=$4
                       )
                       AND i.indcollation[2]=0
                       AND i.indcollation[3]='pg_catalog.\"C\"'::regcollation
                       AND pg_get_indexdef(i.indexrelid, 1, FALSE)=$3
                       AND pg_get_indexdef(i.indexrelid, 2, FALSE)=$4
                       AND pg_get_indexdef(i.indexrelid, 3, FALSE)=$5
                       AND pg_get_indexdef(i.indexrelid, 4, FALSE)=$6
                       AND pg_get_expr(i.indpred, i.indrelid)=$7
                 )",
                &[table, index, first, second, third, fourth, predicate],
            )
            .map_err(|error| {
                internal(format!(
                    "verify authority ordered partial-index catalog: {error:?}"
                ))
            })?
            .get(0);
        if !present {
            return Err(partial_catalog_object(index));
        }
    }
    for (index, first_key, expression_key, predicate) in REQUIRED_VOLUME_OWNER_INDEXES {
        let present: bool = transaction
            .query_one(
                "SELECT EXISTS (
                    SELECT 1
                      FROM pg_index i
                      JOIN pg_class source ON source.oid=i.indrelid
                      JOIN pg_namespace source_namespace
                        ON source_namespace.oid=source.relnamespace
                      JOIN pg_class index_relation
                        ON index_relation.oid=i.indexrelid
                      JOIN pg_am access_method
                        ON access_method.oid=index_relation.relam
                     WHERE source_namespace.nspname=current_schema()
                       AND source.relname='volume_records'
                       AND index_relation.relname=$1
                       AND NOT i.indisunique AND i.indisvalid AND i.indisready
                       AND i.indnkeyatts=2 AND i.indnatts=2
                       AND i.indoption::TEXT='0 0'
                       AND access_method.amname='btree'
                       AND (($3 AND i.indexprs IS NOT NULL)
                            OR (NOT $3 AND i.indexprs IS NULL))
                       AND i.indpred IS NOT NULL
                       AND pg_get_indexdef(i.indexrelid, 1, FALSE)=$2
                       AND pg_get_indexdef(i.indexrelid, 2, FALSE)='volume_id'
                       AND i.indcollation[1]='pg_catalog.\"C\"'::regcollation
                       AND pg_get_expr(i.indpred, i.indrelid)=$4
                 )",
                &[index, first_key, expression_key, predicate],
            )
            .map_err(|error| {
                internal(format!(
                    "verify authority Volume owner-index catalog: {error:?}"
                ))
            })?
            .get(0);
        if !present {
            return Err(partial_catalog_object(index));
        }
    }
    for (table, index, access_method, operator_class, expression, collation) in
        REQUIRED_EXPRESSION_INDEXES
    {
        let present: bool = transaction
            .query_one(
                "SELECT EXISTS (
                    SELECT 1
                      FROM pg_index i
                      JOIN pg_class source ON source.oid=i.indrelid
                      JOIN pg_namespace source_namespace
                        ON source_namespace.oid=source.relnamespace
                      JOIN pg_class index_relation
                        ON index_relation.oid=i.indexrelid
                      JOIN pg_am access_method
                        ON access_method.oid=index_relation.relam
                      JOIN pg_opclass operator_class
                        ON operator_class.oid=i.indclass[0]
                      JOIN pg_namespace operator_namespace
                        ON operator_namespace.oid=operator_class.opcnamespace
                     WHERE source_namespace.nspname=current_schema()
                       AND source.relname=$1 AND index_relation.relname=$2
                       AND NOT i.indisunique AND i.indisvalid AND i.indisready
                       AND i.indnkeyatts=1 AND i.indnatts=1
                       AND i.indkey::TEXT='0' AND i.indoption::TEXT='0'
                       AND i.indpred IS NULL AND i.indexprs IS NOT NULL
                       AND access_method.amname=$3
                       AND operator_namespace.nspname='pg_catalog'
                       AND operator_class.opcname=$4
                       AND pg_get_expr(i.indexprs, i.indrelid)=$5
                       AND (($6::TEXT IS NULL AND i.indcollation[0]=0)
                            OR ($6::TEXT IS NOT NULL
                                AND i.indcollation[0]=to_regcollation($6)))
                 )",
                &[
                    table,
                    index,
                    access_method,
                    operator_class,
                    expression,
                    collation,
                ],
            )
            .map_err(|error| {
                internal(format!(
                    "verify authority expression-index catalog: {error:?}"
                ))
            })?
            .get(0);
        if !present {
            return Err(partial_catalog_object(index));
        }
    }
    for (index, first_key, second_key, predicate) in REQUIRED_RUNTIME_OPERATION_LOOKUP_INDEXES {
        let present: bool = transaction
            .query_one(
                "SELECT EXISTS (
                    SELECT 1
                      FROM pg_index i
                      JOIN pg_class source ON source.oid=i.indrelid
                      JOIN pg_namespace source_namespace
                        ON source_namespace.oid=source.relnamespace
                      JOIN pg_class index_relation
                        ON index_relation.oid=i.indexrelid
                      JOIN pg_am access_method
                        ON access_method.oid=index_relation.relam
                     WHERE source_namespace.nspname=current_schema()
                       AND source.relname='runtime_operations'
                       AND index_relation.relname=$1
                       AND NOT i.indisunique AND i.indisvalid AND i.indisready
                       AND i.indnkeyatts=2 AND i.indnatts=2
                       AND i.indoption::TEXT='0 0'
                       AND access_method.amname='btree'
                       AND i.indcollation[0]='pg_catalog.\"C\"'::regcollation
                       AND i.indcollation[1]='pg_catalog.\"C\"'::regcollation
                       AND pg_get_indexdef(i.indexrelid, 1, FALSE)=$2
                       AND pg_get_indexdef(i.indexrelid, 2, FALSE)=$3
                       AND (($4::TEXT IS NULL AND i.indpred IS NULL)
                            OR pg_get_expr(i.indpred, i.indrelid)=$4)
                 )",
                &[index, first_key, second_key, predicate],
            )
            .map_err(|error| {
                internal(format!(
                    "verify authority runtime Operation lookup-index catalog: {error:?}"
                ))
            })?
            .get(0);
        if !present {
            return Err(partial_catalog_object(index));
        }
    }
    for (table, index, first_key, second_key, predicate) in REQUIRED_PRODUCT_READ_LOOKUP_INDEXES {
        let present: bool = transaction
            .query_one(
                "SELECT EXISTS (
                    SELECT 1
                      FROM pg_index i
                      JOIN pg_class source ON source.oid=i.indrelid
                      JOIN pg_namespace source_namespace
                        ON source_namespace.oid=source.relnamespace
                      JOIN pg_class index_relation
                        ON index_relation.oid=i.indexrelid
                      JOIN pg_am access_method
                        ON access_method.oid=index_relation.relam
                     WHERE source_namespace.nspname=current_schema()
                       AND source.relname=$1
                       AND index_relation.relname=$2
                       AND NOT i.indisunique AND i.indisvalid AND i.indisready
                       AND i.indnkeyatts=2 AND i.indnatts=2
                       AND i.indoption::TEXT='0 0'
                       AND access_method.amname='btree'
                       AND i.indcollation[0]='pg_catalog.\"C\"'::regcollation
                       AND i.indcollation[1]='pg_catalog.\"C\"'::regcollation
                       AND pg_get_indexdef(i.indexrelid, 1, FALSE)=$3
                       AND pg_get_indexdef(i.indexrelid, 2, FALSE)=$4
                       AND (($5::TEXT IS NULL AND i.indpred IS NULL)
                            OR pg_get_expr(i.indpred, i.indrelid)=$5)
                 )",
                &[table, index, first_key, second_key, predicate],
            )
            .map_err(|error| {
                internal(format!(
                    "verify authority product read lookup-index catalog: {error:?}"
                ))
            })?
            .get(0);
        if !present {
            return Err(partial_catalog_object(index));
        }
    }
    for (table, index, column) in REQUIRED_ARRAY_MEMBERSHIP_INDEXES {
        let present: bool = transaction
            .query_one(
                "SELECT EXISTS (
                    SELECT 1
                      FROM pg_index i
                      JOIN pg_class source ON source.oid=i.indrelid
                      JOIN pg_namespace source_namespace
                        ON source_namespace.oid=source.relnamespace
                      JOIN pg_class index_relation
                        ON index_relation.oid=i.indexrelid
                      JOIN pg_am access_method
                        ON access_method.oid=index_relation.relam
                      JOIN pg_attribute attribute
                        ON attribute.attrelid=source.oid
                       AND attribute.attname=$3 AND NOT attribute.attisdropped
                      JOIN pg_opclass operator_class
                        ON operator_class.oid=i.indclass[0]
                      JOIN pg_namespace operator_namespace
                        ON operator_namespace.oid=operator_class.opcnamespace
                     WHERE source_namespace.nspname=current_schema()
                       AND source.relname=$1 AND index_relation.relname=$2
                       AND NOT i.indisunique AND i.indisvalid AND i.indisready
                       AND i.indnkeyatts=1 AND i.indnatts=1
                       AND i.indkey[0]=attribute.attnum
                       AND i.indoption::TEXT='0'
                       AND i.indpred IS NULL AND i.indexprs IS NULL
                       AND access_method.amname='gin'
                       AND operator_namespace.nspname='pg_catalog'
                       AND operator_class.opcname='array_ops'
                       AND pg_get_indexdef(i.indexrelid, 1, FALSE)=$3
                 )",
                &[table, index, column],
            )
            .map_err(|error| {
                internal(format!(
                    "verify authority array membership-index catalog: {error:?}"
                ))
            })?
            .get(0);
        if !present {
            return Err(partial_catalog_object(index));
        }
    }
    for (table, trigger, function, trigger_type, body_sha256) in REQUIRED_IMMUTABILITY_TRIGGERS {
        let body = transaction
            .query_opt(
                "SELECT function.prosrc
                   FROM pg_trigger trigger
                   JOIN pg_class source ON source.oid=trigger.tgrelid
                   JOIN pg_namespace source_namespace
                     ON source_namespace.oid=source.relnamespace
                   JOIN pg_proc function ON function.oid=trigger.tgfoid
                   JOIN pg_namespace function_namespace
                     ON function_namespace.oid=function.pronamespace
                   JOIN pg_language language ON language.oid=function.prolang
                  WHERE source_namespace.nspname=current_schema()
                    AND function_namespace.nspname=current_schema()
                    AND source.relname=$1 AND trigger.tgname=$2
                    AND function.proname=$3 AND NOT trigger.tgisinternal
                    AND trigger.tgenabled='O' AND trigger.tgtype=$4
                    AND trigger.tgattr::TEXT='' AND trigger.tgqual IS NULL
                    AND trigger.tgnargs=0 AND function.pronargs=0
                    AND function.prorettype='trigger'::regtype
                    AND language.lanname='plpgsql'",
                &[table, trigger, function, trigger_type],
            )
            .map_err(internal)?
            .map(|row| row.get::<_, String>(0));
        let actual_body_sha256 = body.map(|body| hex::encode(Sha256::digest(body.as_bytes())));
        if actual_body_sha256.as_deref() != Some(*body_sha256) {
            return Err(partial_catalog_object(trigger));
        }
    }
    Ok(())
}

fn partial_catalog_object(name: &str) -> ApiError {
    ApiError::failed_precondition(format!(
        "control-plane schema version {SCHEMA_VERSION} is missing or changed authority catalog object {name}; recreate it"
    ))
}

/// The Control Store owns the exact clean-slate release stamp. Version 19 has
/// no migration or compatibility reader/writer for an earlier authority shape.
pub(super) const SCHEMA_VERSION: i64 = 19;

const CONTROL_TABLES: &[&str] = &[
    "control_schema_version",
    "accounts",
    "workspaces",
    "nodes",
    "node_heartbeats",
    "cats",
    "persistent_disks",
    "disk_bindings",
    "account_membership_shadow",
    "workspace_grants",
    "workspace_tokens",
    "signup_grant_eligibility",
    "account_invitations",
    "workos_event_receipts",
    "oci_deployments",
    "volume_records",
    "host_fence_events",
    "volume_authorizations",
    "delete_completion_receipts",
    "cat_records",
    "endpoint_records",
    "disk_records",
    "disk_snapshot_records",
    "cat_runtime_configs",
    "hostname_endpoint_lookups",
    "runtime_operations",
    "lifecycle_volume_receipts",
    "host_fence_provider_queue_v1",
    "api_idempotency_results",
    "production_mutation_admission_commands",
    "production_mutation_admission",
    "node_identities",
    "route_operations",
    "agent_registration_attempts",
    "current_agent_sessions",
    "route_node_ring_acks",
    "runtime_inventory_receive_states",
    "runtime_full_inventory_attestations",
    "runtime_current_cat_telemetry",
    "runtime_node_placement_policies",
    "runtime_node_authority_apply_records",
    "runtime_node_credential_lineage",
    "runtime_provisioner_deployment_identity",
    "runtime_provisioner_trust_revisions",
    "runtime_provisioner_credential_lineage",
    "object_write_authorities",
    "object_write_credentials",
    "object_write_attempts",
    "route_v2_gateway_identity_authority",
    "route_v2_gateway_identity_revisions",
    "route_v2_gateway_credential_lineage",
    "route_v2_gateway_current_credentials",
    "route_v2_signing_authority",
    "route_v2_signer_revisions",
    "route_v2_signer_key_lineage",
    // Route v2 signer lineage and the Stage B operator-delivery authority.
    "route_v2_public_key_ring_revisions",
    "route_v2_signer_retirements",
    "route_v2_rotation_operator_authority",
    "route_v2_rotation_operator_credentials",
    "route_v2_signing_command_receipts",
    "route_v2_public_ring_deliveries",
];

// Version 19 is an empty-database cutover, not an additive migration. A
// manually stamped database that still exposes any former product or Desired
// authority must fail closed instead of letting old and atomic writers coexist.
const FORBIDDEN_LEGACY_CONTROL_TABLES: &[&str] = &[
    "route_grant_rollout_state",
    "disks",
    "mount_bindings",
    "operations",
    "idempotency",
    "endpoints",
    "routes",
    "cat_work_sources",
    "cat_work_leases",
    "desired_runtime_specs",
    "hostname_desired_lookups",
    "runtime_desired_read_states",
    "runtime_observation_receive_states",
    "runtime_current_cat_observations",
    "runtime_admission_inventory_states",
    "trusted_host_fence_recovery_attempts_v1",
    "trusted_host_fence_recovery_attempt_cats_v1",
];

const FORBIDDEN_LEGACY_CONTROL_COLUMNS: &[(&str, &str)] = &[
    ("oci_deployments", "operation_id"),
    ("volume_records", "transition_desired_revision"),
    ("volume_authorizations", "desired_revision"),
    ("runtime_full_inventory_attestations", "full_observation"),
    ("runtime_full_inventory_attestations", "observation_id"),
    ("runtime_full_inventory_attestations", "heartbeat_sequence"),
    ("runtime_full_inventory_attestations", "assigned_snapshot"),
];

type RequiredDeferredForeignKey = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);

pub(super) const REQUIRED_CHECK_CONSTRAINTS: &[(&str, &str, &str)] = &[
    (
        "disk_records",
        "disk_records_initialization_commit_receipt_bytes_check",
        "CHECK (((initialization_commit_receipt_bytes IS NULL) OR ((octet_length(initialization_commit_receipt_bytes) >= 1) AND (octet_length(initialization_commit_receipt_bytes) <= 2097152))))",
    ),
    (
        "disk_records",
        "disk_records_initialization_commit_receipt_digest_check",
        "CHECK (((initialization_commit_receipt_digest IS NULL) OR (initialization_commit_receipt_digest ~ '^sha256:[0-9a-f]{64}$'::text)))",
    ),
    (
        "volume_authorizations",
        "volume_authorizations_lifecycle_request_fingerprint_check",
        "CHECK (((lifecycle_request_fingerprint IS NULL) OR (lifecycle_request_fingerprint ~ '^sha256:[0-9a-f]{64}$'::text)))",
    ),
    (
        "volume_authorizations",
        "volume_authorizations_persistent_dispositions_digest_check",
        "CHECK (((persistent_dispositions_digest IS NULL) OR (persistent_dispositions_digest ~ '^sha256:[0-9a-f]{64}$'::text)))",
    ),
    (
        "volume_authorizations",
        "volume_authorizations_strong_stop_receipt_digest_check",
        "CHECK (((strong_stop_receipt_digest IS NULL) OR (strong_stop_receipt_digest ~ '^sha256:[0-9a-f]{64}$'::text)))",
    ),
    (
        "volume_authorizations",
        "volume_authorizations_execution_absence_proof_digest_check",
        "CHECK (((execution_absence_proof_digest IS NULL) OR (execution_absence_proof_digest ~ '^sha256:[0-9a-f]{64}$'::text)))",
    ),
    (
        "volume_authorizations",
        "volume_authorizations_inventory_attestation_digest_check",
        "CHECK (((inventory_attestation_digest IS NULL) OR (inventory_attestation_digest ~ '^sha256:[0-9a-f]{64}$'::text)))",
    ),
    (
        "volume_authorizations",
        "volume_authorizations_host_lost_result_digest_check",
        "CHECK (((host_lost_result_digest IS NULL) OR (host_lost_result_digest ~ '^sha256:[0-9a-f]{64}$'::text)))",
    ),
    (
        "volume_authorizations",
        "volume_authorizations_kind_shape_check",
        "CHECK ((((kind = 'takeover'::text) AND (host_fence_event_id IS NOT NULL) AND (lease_duration_ms IS NOT NULL) AND (lease_duration_ms > 0) AND (lifecycle_operation_id IS NOT NULL) AND (lifecycle_request_fingerprint IS NOT NULL) AND (delete_id IS NULL) AND (disk_id IS NOT NULL) AND (cat_id IS NOT NULL) AND (expected_attachment_id IS NOT NULL) AND (expected_attachment_epoch IS NOT NULL) AND (expected_attachment_epoch > 0) AND (disposition IS NULL) AND (persistent_dispositions_digest IS NULL) AND (isolation_basis_kind IS NULL) AND (strong_stop_receipt_digest IS NULL) AND (strong_stop_agent_session_epoch IS NULL) AND (execution_absence_proof_digest IS NULL) AND (inventory_attestation_digest IS NULL) AND (interrupted_operation_id IS NOT NULL) AND (host_lost_result_digest IS NOT NULL)) OR ((kind = 'disposable_root_delete'::text) AND (lease_duration_ms IS NULL) AND (lifecycle_operation_id IS NOT NULL) AND (lifecycle_request_fingerprint IS NOT NULL) AND (delete_id IS NOT NULL) AND (disk_id IS NOT NULL) AND (cat_id IS NOT NULL) AND (expected_attachment_id IS NOT NULL) AND (expected_attachment_epoch IS NOT NULL) AND (expected_attachment_epoch > 0) AND (disposition = 'discard_with_cat'::text) AND (persistent_dispositions_digest IS NOT NULL) AND (((isolation_basis_kind = 'lifecycle_strong_stop'::text) AND (host_fence_event_id IS NULL) AND (strong_stop_receipt_digest IS NOT NULL) AND (strong_stop_agent_session_epoch IS NOT NULL) AND (strong_stop_agent_session_epoch > 0) AND (execution_absence_proof_digest IS NOT NULL) AND (inventory_attestation_digest IS NOT NULL) AND (interrupted_operation_id IS NULL) AND (host_lost_result_digest IS NULL)) OR ((isolation_basis_kind = 'host_fence_event'::text) AND (host_fence_event_id IS NOT NULL) AND (strong_stop_receipt_digest IS NULL) AND (strong_stop_agent_session_epoch IS NULL) AND (execution_absence_proof_digest IS NULL) AND (inventory_attestation_digest IS NULL) AND (interrupted_operation_id IS NOT NULL) AND (host_lost_result_digest IS NOT NULL))))))",
    ),
    (
        "cat_records",
        "cat_records_stable_state_check",
        "CHECK ((stable_state = ANY (ARRAY['running'::text, 'suspended'::text, 'warm'::text, 'cold'::text])))",
    ),
    (
        "cat_records",
        "cat_records_runtime_incarnation_check",
        "CHECK ((runtime_incarnation ~ '^[0-9a-f]{32}$'::text))",
    ),
    (
        "cat_records",
        "cat_records_runtime_config_digest_check",
        "CHECK ((current_runtime_config_sha256 ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "cat_records",
        "cat_records_deleted_at_check",
        "CHECK ((deleted_at >= created_at))",
    ),
    (
        "cat_records",
        "cat_records_runtime_ready_shape_check",
        "CHECK (((((stable_state = 'running'::text) AND (effective_runtime_ready_operation_id IS NOT NULL) AND (runtime_incarnation IS NOT NULL)) OR ((stable_state = 'suspended'::text) AND (effective_runtime_ready_operation_id IS NULL) AND (runtime_incarnation IS NOT NULL)) OR ((stable_state = ANY (ARRAY['warm'::text, 'cold'::text])) AND (effective_runtime_ready_operation_id IS NULL) AND (runtime_incarnation IS NULL)) OR ((stable_state IS NULL) AND (effective_runtime_ready_operation_id IS NULL) AND (runtime_incarnation IS NULL))) IS TRUE))",
    ),
    (
        "cat_records",
        "cat_records_deleted_shape_check",
        "CHECK (((deleted_at IS NULL) OR ((stable_state IS NULL) AND (effective_runtime_ready_operation_id IS NULL) AND (runtime_incarnation IS NULL))))",
    ),
    (
        "cat_runtime_configs",
        "cat_runtime_configs_bytes_check",
        "CHECK (((octet_length(canonical_config_bytes) >= 1) AND (octet_length(canonical_config_bytes) <= 1048576)))",
    ),
    (
        "cat_runtime_configs",
        "cat_runtime_configs_digest_check",
        "CHECK ((canonical_config_sha256 ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "cat_runtime_configs",
        "cat_runtime_configs_placement_vcpus_check",
        "CHECK (((placement_vcpus >= 1) AND (placement_vcpus <= '4294967295'::bigint)))",
    ),
    (
        "cat_runtime_configs",
        "cat_runtime_configs_placement_memory_check",
        "CHECK ((placement_memory_bytes > 0))",
    ),
    (
        "cat_runtime_configs",
        "cat_runtime_configs_placement_ipv4_pool_base_check",
        "CHECK (((placement_ipv4_pool_base >= 0) AND (placement_ipv4_pool_base <= '4294901760'::bigint)))",
    ),
    (
        "cat_runtime_configs",
        "cat_runtime_configs_placement_ipv4_slot_check",
        "CHECK (((placement_ipv4_slot >= 1) AND (placement_ipv4_slot <= 16383)))",
    ),
    (
        "cat_runtime_configs",
        "cat_runtime_configs_placement_disk_ids_check",
        "CHECK ((((cardinality(placement_disk_ids) >= 1) AND (cardinality(placement_disk_ids) <= 64)) AND (array_position(placement_disk_ids, NULL::text) IS NULL)))",
    ),
    (
        "cat_runtime_configs",
        "cat_runtime_configs_placement_volume_ids_check",
        "CHECK ((((cardinality(placement_volume_ids) >= 1) AND (cardinality(placement_volume_ids) <= 64)) AND (array_position(placement_volume_ids, NULL::text) IS NULL)))",
    ),
    (
        "cat_runtime_configs",
        "cat_runtime_configs_placement_volume_cardinality_check",
        "CHECK ((cardinality(placement_disk_ids) = cardinality(placement_volume_ids)))",
    ),
    (
        "cat_runtime_configs",
        "cat_runtime_configs_created_at_check",
        "CHECK ((created_at_unix_ms >= 0))",
    ),
    (
        "runtime_operations",
        "runtime_operations_placement_epoch_check",
        "CHECK ((placement_epoch > 0))",
    ),
    (
        "runtime_operations",
        "runtime_operations_command_kind_check",
        "CHECK ((command_kind = ANY (ARRAY['start'::text, 'suspend'::text, 'warm'::text, 'cold'::text, 'stop'::text, 'delete'::text])))",
    ),
    (
        "runtime_operations",
        "runtime_operations_request_bytes_check",
        "CHECK (((octet_length(canonical_request_bytes) >= 1) AND (octet_length(canonical_request_bytes) <= 1048576)))",
    ),
    (
        "runtime_operations",
        "runtime_operations_request_digest_check",
        "CHECK ((canonical_request_sha256 ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "runtime_operations",
        "runtime_operations_runtime_config_digest_check",
        "CHECK ((runtime_config_sha256 ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "runtime_operations",
        "runtime_operations_predecessor_kind_check",
        "CHECK ((predecessor_kind = ANY (ARRAY['genesis'::text, 'same_node'::text, 'cross_node_cold_handoff'::text, 'host_fence_recovery'::text])))",
    ),
    (
        "runtime_operations",
        "runtime_operations_predecessor_digest_check",
        "CHECK ((expected_predecessor_result_sha256 ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "runtime_operations",
        "runtime_operations_state_check",
        "CHECK ((state = ANY (ARRAY['unresolved'::text, 'terminal'::text])))",
    ),
    (
        "runtime_operations",
        "runtime_operations_terminal_source_check",
        "CHECK ((terminal_source = ANY (ARRAY['node_result'::text, 'host_lost'::text])))",
    ),
    (
        "runtime_operations",
        "runtime_operations_terminal_result_kind_check",
        "CHECK ((terminal_result_kind = ANY (ARRAY['runtime_ready'::text, 'start_failed'::text, 'suspended'::text, 'suspend_declined'::text, 'suspend_failed'::text, 'warm'::text, 'warm_failed'::text, 'cold'::text, 'killed'::text, 'deleted'::text, 'needs_intervention'::text, 'host_lost'::text])))",
    ),
    (
        "runtime_operations",
        "runtime_operations_result_bytes_check",
        "CHECK (((canonical_result_bytes IS NULL) OR ((octet_length(canonical_result_bytes) >= 1) AND (octet_length(canonical_result_bytes) <= 1048576))))",
    ),
    (
        "runtime_operations",
        "runtime_operations_result_digest_check",
        "CHECK ((canonical_result_sha256 ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "runtime_operations",
        "runtime_operations_created_at_check",
        "CHECK ((created_at_unix_ms >= 0))",
    ),
    (
        "runtime_operations",
        "runtime_operations_terminal_at_check",
        "CHECK ((terminal_at_unix_ms >= created_at_unix_ms))",
    ),
    (
        "runtime_operations",
        "runtime_operations_predecessor_shape_check",
        "CHECK ((((predecessor_kind = 'genesis'::text) AND (expected_predecessor_operation_id IS NULL) AND (expected_predecessor_result_kind IS NULL) AND (expected_predecessor_result_sha256 IS NULL)) OR ((predecessor_kind <> 'genesis'::text) AND (expected_predecessor_operation_id IS NOT NULL) AND (expected_predecessor_result_kind IS NOT NULL) AND (expected_predecessor_result_sha256 IS NOT NULL))))",
    ),
    (
        "runtime_operations",
        "runtime_operations_typed_predecessor_check",
        "CHECK ((((predecessor_kind <> 'cross_node_cold_handoff'::text) OR (expected_predecessor_result_kind = 'cold'::text)) AND ((predecessor_kind <> 'host_fence_recovery'::text) OR (expected_predecessor_result_kind = 'host_lost'::text))))",
    ),
    (
        "runtime_operations",
        "runtime_operations_terminal_shape_check",
        "CHECK ((((state = 'unresolved'::text) AND (terminal_source IS NULL) AND (terminal_result_kind IS NULL) AND (canonical_result_bytes IS NULL) AND (canonical_result_sha256 IS NULL) AND (terminal_at_unix_ms IS NULL)) OR ((state = 'terminal'::text) AND (terminal_source IS NOT NULL) AND (terminal_result_kind IS NOT NULL) AND (canonical_result_bytes IS NOT NULL) AND (canonical_result_sha256 IS NOT NULL) AND (terminal_at_unix_ms IS NOT NULL))))",
    ),
    (
        "runtime_operations",
        "runtime_operations_terminal_source_shape_check",
        "CHECK ((((terminal_source IS NULL) AND (terminal_result_kind IS NULL)) OR ((terminal_source = 'host_lost'::text) AND (terminal_result_kind = 'host_lost'::text)) OR ((terminal_source = 'node_result'::text) AND (terminal_result_kind <> 'host_lost'::text))))",
    ),
    (
        "runtime_operations",
        "runtime_operations_command_result_check",
        "CHECK (((terminal_source IS DISTINCT FROM 'node_result'::text) OR ((command_kind = 'start'::text) AND (terminal_result_kind = ANY (ARRAY['runtime_ready'::text, 'start_failed'::text]))) OR ((command_kind = 'suspend'::text) AND (terminal_result_kind = ANY (ARRAY['suspended'::text, 'suspend_declined'::text, 'suspend_failed'::text]))) OR ((command_kind = 'warm'::text) AND (terminal_result_kind = ANY (ARRAY['warm'::text, 'warm_failed'::text, 'needs_intervention'::text]))) OR ((command_kind = 'cold'::text) AND (terminal_result_kind = ANY (ARRAY['cold'::text, 'needs_intervention'::text]))) OR ((command_kind = 'stop'::text) AND (terminal_result_kind = 'killed'::text)) OR ((command_kind = 'delete'::text) AND (terminal_result_kind = ANY (ARRAY['deleted'::text, 'needs_intervention'::text])))))",
    ),
    (
        "lifecycle_volume_receipts",
        "lifecycle_volume_receipts_bytes_check",
        "CHECK (((octet_length(canonical_receipt_bytes) >= 1) AND (octet_length(canonical_receipt_bytes) <= 1048576)))",
    ),
    (
        "lifecycle_volume_receipts",
        "lifecycle_volume_receipts_command_shape_check",
        "CHECK ((((source_command_kind = 'start'::text) AND (receipt_kind = 'start_grant'::text) AND (delete_id IS NULL)) OR ((source_command_kind = 'cold'::text) AND (receipt_kind = ANY (ARRAY['normal_release'::text, 'already_unowned'::text])) AND (receipt_sequence = 0) AND (delete_id IS NULL)) OR ((source_command_kind = 'delete'::text) AND (receipt_sequence = 0) AND (delete_id IS NOT NULL))))",
    ),
    (
        "lifecycle_volume_receipts",
        "lifecycle_volume_receipts_sequence_check",
        "CHECK ((receipt_sequence >= 0))",
    ),
    (
        "endpoint_records",
        "endpoint_records_binding_shape_check",
        "CHECK ((((binding_state = 'bound'::text) AND (hostname IS NOT NULL) AND (protocol = 'http'::text) AND ((target_port >= 1) AND (target_port <= 65535))) OR ((binding_state = 'unbound'::text) AND (hostname IS NULL) AND (protocol IS NULL) AND (target_port IS NULL) AND (effective_serving_operation_id IS NULL))))",
    ),
    (
        "route_operations",
        "route_operations_predecessor_shape_check",
        "CHECK ((((expected_predecessor_operation_id IS NULL) AND (expected_predecessor_result_kind IS NULL) AND (expected_predecessor_result_sha256 IS NULL)) OR ((expected_predecessor_operation_id IS NOT NULL) AND (expected_predecessor_result_kind IS NOT NULL) AND (expected_predecessor_result_sha256 IS NOT NULL))))",
    ),
    (
        "route_operations",
        "route_operations_terminal_shape_check",
        "CHECK ((((state = 'unresolved'::text) AND (terminal_source IS NULL) AND (terminal_result_kind IS NULL) AND (canonical_result_bytes IS NULL) AND (canonical_result_sha256 IS NULL) AND (terminal_at_unix_ms IS NULL)) OR ((state = 'terminal'::text) AND (terminal_source IS NOT NULL) AND (terminal_result_kind IS NOT NULL) AND (canonical_result_bytes IS NOT NULL) AND (canonical_result_sha256 IS NOT NULL) AND (terminal_at_unix_ms IS NOT NULL))))",
    ),
    (
        "route_operations",
        "route_operations_command_result_check",
        "CHECK (((terminal_source IS NULL) OR ((terminal_source = 'control_invalidation'::text) AND (terminal_result_kind = 'invalidated'::text)) OR ((terminal_source = 'node_result'::text) AND (operation_kind = 'enable'::text) AND (terminal_result_kind = ANY (ARRAY['serving'::text, 'rejected'::text]))) OR ((terminal_source = 'node_result'::text) AND (operation_kind = 'disable'::text) AND (terminal_result_kind = ANY (ARRAY['closed'::text, 'rejected'::text])))))",
    ),
    (
        "route_node_ring_acks",
        "route_node_ring_acks_bytes_check",
        "CHECK (((octet_length(canonical_ack_bytes) >= 1) AND (octet_length(canonical_ack_bytes) <= 1048576)))",
    ),
    (
        "route_node_ring_acks",
        "route_node_ring_acks_loaded_kids_check",
        "CHECK ((jsonb_typeof(loaded_kids) = 'array'::text))",
    ),
    (
        "route_v2_rotation_operator_authority",
        "route_v2_rotation_operator_singleton_ck",
        "CHECK (singleton)",
    ),
    (
        "route_v2_rotation_operator_authority",
        "route_v2_rotation_operator_release_sha_ck",
        "CHECK ((release_commit_sha ~ '^[0-9a-f]{40}$'::text))",
    ),
    (
        "route_v2_rotation_operator_authority",
        "route_v2_rotation_operator_trust_sha_ck",
        "CHECK ((trust_sha256 ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "route_v2_rotation_operator_authority",
        "route_v2_rotation_operator_threshold_ck",
        "CHECK (((threshold >= 1) AND (threshold <= 8)))",
    ),
    (
        "route_v2_rotation_operator_authority",
        "route_v2_rotation_operator_trust_bytes_ck",
        "CHECK (((octet_length(trust_bytes) >= 1) AND (octet_length(trust_bytes) <= 16384)))",
    ),
    (
        "route_v2_rotation_operator_authority",
        "route_v2_rotation_operator_committed_at_ck",
        "CHECK ((first_committed_at_unix_ms >= 0))",
    ),
    (
        "route_v2_rotation_operator_credentials",
        "route_v2_rotation_operator_ordinal_ck",
        "CHECK (((credential_ordinal >= 0) AND (credential_ordinal <= 7)))",
    ),
    (
        "route_v2_rotation_operator_credentials",
        "route_v2_rotation_operator_spki_sha_ck",
        "CHECK ((public_key_spki_sha256 ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "route_v2_rotation_operator_credentials",
        "route_v2_rotation_operator_credential_committed_at_ck",
        "CHECK ((first_committed_at_unix_ms >= 0))",
    ),
    (
        "route_v2_signing_command_receipts",
        "route_v2_signing_command_id_ck",
        "CHECK ((command_id ~ '^[0-9a-f]{32}$'::text))",
    ),
    (
        "route_v2_signing_command_receipts",
        "route_v2_signing_command_release_sha_ck",
        "CHECK ((release_commit_sha ~ '^[0-9a-f]{40}$'::text))",
    ),
    (
        "route_v2_signing_command_receipts",
        "route_v2_signing_command_credential_set_sha_ck",
        "CHECK ((credential_set_sha256 ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "route_v2_signing_command_receipts",
        "route_v2_signing_command_exact_sha_ck",
        "CHECK ((exact_command_sha256 ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "route_v2_signing_command_receipts",
        "route_v2_signing_command_exact_bytes_ck",
        "CHECK (((octet_length(exact_command_bytes) >= 1) AND (octet_length(exact_command_bytes) <= 65536)))",
    ),
    (
        "route_v2_signing_command_receipts",
        "route_v2_signing_command_kind_ck",
        "CHECK ((command_kind = ANY (ARRAY['publish_overlap'::text, 'switch_active'::text, 'publish_new_only'::text, 'retire'::text, 'disable'::text, 'activate'::text])))",
    ),
    (
        "route_v2_signing_command_receipts",
        "route_v2_signing_command_expected_revision_ck",
        "CHECK ((expected_signer_revision > 0))",
    ),
    (
        "route_v2_signing_command_receipts",
        "route_v2_signing_command_expected_sha_ck",
        "CHECK ((expected_signer_reference_sha256 ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "route_v2_signing_command_receipts",
        "route_v2_signing_command_terminal_outcome_ck",
        "CHECK ((terminal_outcome = ANY (ARRAY['applied'::text, 'authority_precondition_failed'::text])))",
    ),
    (
        "route_v2_signing_command_receipts",
        "route_v2_signing_command_result_revision_ck",
        "CHECK ((resulting_signer_revision > 0))",
    ),
    (
        "route_v2_signing_command_receipts",
        "route_v2_signing_command_result_ring_ck",
        "CHECK ((resulting_ring_version > 0))",
    ),
    (
        "route_v2_signing_command_receipts",
        "route_v2_signing_command_result_bytes_ck",
        "CHECK (((octet_length(exact_result_bytes) >= 1) AND (octet_length(exact_result_bytes) <= 16384)))",
    ),
    (
        "route_v2_signing_command_receipts",
        "route_v2_signing_command_committed_at_ck",
        "CHECK ((committed_at_unix_ms >= 0))",
    ),
    (
        "route_v2_signing_command_receipts",
        "route_v2_signing_command_result_projection_ck",
        "CHECK ((((terminal_outcome = 'applied'::text) AND (resulting_signer_revision IS NOT NULL) AND (resulting_ring_version IS NOT NULL)) OR ((terminal_outcome = 'authority_precondition_failed'::text) AND (resulting_signer_revision IS NULL) AND (resulting_ring_version IS NULL))))",
    ),
    (
        "route_v2_public_ring_deliveries",
        "route_v2_public_ring_delivery_version_ck",
        "CHECK ((ring_version > 1))",
    ),
    (
        "route_v2_public_ring_deliveries",
        "route_v2_public_ring_delivery_digest_ck",
        "CHECK ((key_ring_digest ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "route_v2_public_ring_deliveries",
        "route_v2_public_ring_delivery_previous_version_ck",
        "CHECK ((expected_previous_ring_version > 0))",
    ),
    (
        "route_v2_public_ring_deliveries",
        "route_v2_public_ring_delivery_previous_digest_ck",
        "CHECK ((expected_previous_key_ring_digest ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "route_v2_public_ring_deliveries",
        "route_v2_public_ring_delivery_release_sha_ck",
        "CHECK ((source_release_commit_sha ~ '^[0-9a-f]{40}$'::text))",
    ),
    (
        "route_v2_public_ring_deliveries",
        "route_v2_public_ring_delivery_envelope_sha_ck",
        "CHECK ((exact_signed_envelope_sha256 ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "route_v2_public_ring_deliveries",
        "route_v2_public_ring_delivery_envelope_bytes_ck",
        "CHECK (((octet_length(exact_signed_envelope_bytes) >= 1) AND (octet_length(exact_signed_envelope_bytes) <= 65536)))",
    ),
    (
        "route_v2_public_ring_deliveries",
        "route_v2_public_ring_delivery_committed_at_ck",
        "CHECK ((committed_at_unix_ms >= 0))",
    ),
    (
        "route_v2_public_ring_deliveries",
        "route_v2_public_ring_delivery_adjacency_ck",
        "CHECK ((expected_previous_ring_version = (ring_version - 1)))",
    ),
    (
        "route_v2_signing_authority",
        "route_v2_signing_authority_singleton_ck",
        "CHECK (singleton)",
    ),
    (
        "route_v2_signing_authority",
        "route_v2_signing_authority_revision_ck",
        "CHECK ((current_signer_revision > 0))",
    ),
    (
        "route_v2_signing_authority",
        "route_v2_signing_authority_digest_ck",
        "CHECK ((current_signer_reference_sha256 ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "route_v2_signing_authority",
        "route_v2_signing_authority_state_ck",
        "CHECK ((signer_state = ANY (ARRAY['active'::text, 'disabled'::text])))",
    ),
    (
        "route_v2_signing_authority",
        "route_v2_signing_authority_active_kid_ck",
        "CHECK (((active_kid = ''::text) OR (active_kid ~ '^[0-9a-f]{64}$'::text)))",
    ),
    (
        "route_v2_signing_authority",
        "route_v2_signing_authority_ring_version_ck",
        "CHECK ((public_key_ring_version > 0))",
    ),
    (
        "route_v2_signing_authority",
        "route_v2_signing_authority_ring_digest_ck",
        "CHECK ((public_key_ring_digest ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "route_v2_signing_authority",
        "route_v2_signing_authority_selection_ck",
        "CHECK ((((signer_state = 'active'::text) AND (active_kid <> ''::text) AND (secret_reference_id <> ''::text)) OR ((signer_state = 'disabled'::text) AND (active_kid = ''::text) AND (secret_reference_id = ''::text))))",
    ),
    (
        "route_v2_signing_authority",
        "route_v2_signing_authority_first_time_ck",
        "CHECK ((first_committed_at_unix_ms >= 0))",
    ),
    (
        "route_v2_signer_revisions",
        "route_v2_signer_revision_revision_ck",
        "CHECK ((signer_revision > 0))",
    ),
    (
        "route_v2_signer_revisions",
        "route_v2_signer_revision_digest_ck",
        "CHECK ((signer_reference_sha256 ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "route_v2_signer_revisions",
        "route_v2_signer_revision_bytes_ck",
        "CHECK (((octet_length(signer_reference_bytes) >= 1) AND (octet_length(signer_reference_bytes) <= 16384)))",
    ),
    (
        "route_v2_signer_revisions",
        "route_v2_signer_revision_previous_revision_ck",
        "CHECK ((expected_previous_signer_revision > 0))",
    ),
    (
        "route_v2_signer_revisions",
        "route_v2_signer_revision_previous_digest_ck",
        "CHECK ((expected_previous_signer_reference_sha256 ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "route_v2_signer_revisions",
        "route_v2_signer_revision_lineage_ck",
        "CHECK ((((signer_revision = 1) AND (expected_previous_signer_revision IS NULL) AND (expected_previous_signer_reference_sha256 IS NULL)) OR ((signer_revision > 1) AND (expected_previous_signer_revision = (signer_revision - 1)) AND (expected_previous_signer_reference_sha256 IS NOT NULL))))",
    ),
    (
        "route_v2_signer_revisions",
        "route_v2_signer_revision_state_ck",
        "CHECK ((signer_state = ANY (ARRAY['active'::text, 'disabled'::text])))",
    ),
    (
        "route_v2_signer_revisions",
        "route_v2_signer_revision_active_kid_ck",
        "CHECK (((active_kid = ''::text) OR (active_kid ~ '^[0-9a-f]{64}$'::text)))",
    ),
    (
        "route_v2_signer_revisions",
        "route_v2_signer_revision_ring_version_ck",
        "CHECK ((public_key_ring_version > 0))",
    ),
    (
        "route_v2_signer_revisions",
        "route_v2_signer_revision_ring_digest_ck",
        "CHECK ((public_key_ring_digest ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "route_v2_signer_revisions",
        "route_v2_signer_revision_selection_ck",
        "CHECK ((((signer_state = 'active'::text) AND (active_kid <> ''::text) AND (secret_reference_id <> ''::text)) OR ((signer_state = 'disabled'::text) AND (active_kid = ''::text) AND (secret_reference_id = ''::text))))",
    ),
    (
        "route_v2_signer_revisions",
        "route_v2_signer_revision_committed_time_ck",
        "CHECK ((committed_at_unix_ms >= 0))",
    ),
    (
        "route_v2_signer_key_lineage",
        "route_v2_signer_key_lineage_kid_ck",
        "CHECK ((kid ~ '^[0-9a-f]{64}$'::text))",
    ),
    (
        "route_v2_signer_key_lineage",
        "route_v2_signer_key_lineage_first_revision_ck",
        "CHECK ((first_signer_revision > 0))",
    ),
    (
        "route_v2_signer_key_lineage",
        "route_v2_signer_key_lineage_state_ck",
        "CHECK ((state = ANY (ARRAY['active'::text, 'retired'::text])))",
    ),
    (
        "route_v2_signer_key_lineage",
        "route_v2_signer_key_lineage_first_time_ck",
        "CHECK ((first_committed_at_unix_ms >= 0))",
    ),
    (
        "route_v2_signer_key_lineage",
        "route_v2_signer_key_lineage_retired_time_ck",
        "CHECK (((retired_at_unix_ms IS NULL) OR (retired_at_unix_ms >= first_committed_at_unix_ms)))",
    ),
    (
        "route_v2_signer_key_lineage",
        "route_v2_signer_key_lineage_state_time_ck",
        "CHECK ((((state = 'active'::text) AND (retired_at_unix_ms IS NULL)) OR ((state = 'retired'::text) AND (retired_at_unix_ms IS NOT NULL))))",
    ),
    (
        "route_v2_public_key_ring_revisions",
        "route_v2_public_ring_version_ck",
        "CHECK ((ring_version > 0))",
    ),
    (
        "route_v2_public_key_ring_revisions",
        "route_v2_public_ring_digest_ck",
        "CHECK ((key_ring_digest ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "route_v2_public_key_ring_revisions",
        "route_v2_public_ring_bytes_ck",
        "CHECK (((octet_length(exact_bytes) >= 1) AND (octet_length(exact_bytes) <= 16384)))",
    ),
    (
        "route_v2_public_key_ring_revisions",
        "route_v2_public_ring_previous_version_ck",
        "CHECK ((expected_previous_ring_version > 0))",
    ),
    (
        "route_v2_public_key_ring_revisions",
        "route_v2_public_ring_previous_digest_ck",
        "CHECK ((expected_previous_key_ring_digest ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "route_v2_public_key_ring_revisions",
        "route_v2_public_ring_lineage_ck",
        "CHECK ((((ring_version = 1) AND (expected_previous_ring_version IS NULL) AND (expected_previous_key_ring_digest IS NULL)) OR ((ring_version > 1) AND (expected_previous_ring_version = (ring_version - 1)) AND (expected_previous_key_ring_digest IS NOT NULL))))",
    ),
    (
        "route_v2_public_key_ring_revisions",
        "route_v2_public_ring_published_time_ck",
        "CHECK ((published_at_unix_ms >= 0))",
    ),
    (
        "route_v2_signer_retirements",
        "route_v2_signer_retirement_kid_ck",
        "CHECK ((kid ~ '^[0-9a-f]{64}$'::text))",
    ),
    (
        "route_v2_signer_retirements",
        "route_v2_signer_retirement_revision_ck",
        "CHECK ((retirement_signer_revision > 0))",
    ),
    (
        "route_v2_signer_retirements",
        "route_v2_signer_retirement_time_ck",
        "CHECK ((last_old_issue_at_unix_ms >= 0))",
    ),
    (
        "route_v2_signer_retirements",
        "route_v2_signer_retirement_source_ck",
        "CHECK ((source = ANY (ARRAY['normal'::text, 'emergency'::text])))",
    ),
    (
        "route_v2_signer_retirements",
        "route_v2_signer_retirement_state_ck",
        "CHECK ((state = ANY (ARRAY['pending'::text, 'ring_removed'::text, 'retired'::text])))",
    ),
    (
        "route_v2_signer_retirements",
        "route_v2_signer_retirement_removed_version_ck",
        "CHECK ((ring_removed_version > 0))",
    ),
    (
        "route_v2_signer_retirements",
        "route_v2_signer_retirement_finished_revision_ck",
        "CHECK ((retired_signer_revision > 0))",
    ),
    (
        "route_v2_signer_retirements",
        "route_v2_signer_retirement_finished_time_ck",
        "CHECK ((retired_at_unix_ms >= last_old_issue_at_unix_ms))",
    ),
    (
        "route_v2_signer_retirements",
        "route_v2_signer_retirement_state_projection_ck",
        "CHECK ((((state = 'pending'::text) AND (ring_removed_version IS NULL) AND (retired_signer_revision IS NULL) AND (retired_at_unix_ms IS NULL)) OR ((state = 'ring_removed'::text) AND (ring_removed_version IS NOT NULL) AND (retired_signer_revision IS NULL) AND (retired_at_unix_ms IS NULL)) OR ((state = 'retired'::text) AND (ring_removed_version IS NOT NULL) AND (retired_signer_revision IS NOT NULL) AND (retired_at_unix_ms IS NOT NULL))))",
    ),
    (
        "route_v2_gateway_identity_authority",
        "route_v2_gateway_authority_singleton_ck",
        "CHECK (singleton)",
    ),
    (
        "route_v2_gateway_identity_authority",
        "route_v2_gateway_authority_revision_ck",
        "CHECK ((current_policy_revision > 0))",
    ),
    (
        "route_v2_gateway_identity_authority",
        "route_v2_gateway_authority_digest_ck",
        "CHECK ((current_policy_sha256 ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "route_v2_gateway_identity_authority",
        "route_v2_gateway_authority_first_time_ck",
        "CHECK ((first_committed_at_unix_ms >= 0))",
    ),
    (
        "route_v2_gateway_identity_revisions",
        "route_v2_gateway_revision_revision_ck",
        "CHECK ((policy_revision > 0))",
    ),
    (
        "route_v2_gateway_identity_revisions",
        "route_v2_gateway_revision_digest_ck",
        "CHECK ((policy_sha256 ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "route_v2_gateway_identity_revisions",
        "route_v2_gateway_revision_bytes_ck",
        "CHECK (((octet_length(policy_bytes) >= 1) AND (octet_length(policy_bytes) <= 65536)))",
    ),
    (
        "route_v2_gateway_identity_revisions",
        "route_v2_gateway_revision_previous_revision_ck",
        "CHECK ((expected_previous_policy_revision > 0))",
    ),
    (
        "route_v2_gateway_identity_revisions",
        "route_v2_gateway_revision_previous_digest_ck",
        "CHECK ((expected_previous_policy_sha256 ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "route_v2_gateway_identity_revisions",
        "route_v2_gateway_revision_committed_time_ck",
        "CHECK ((committed_at_unix_ms >= 0))",
    ),
    (
        "route_v2_gateway_identity_revisions",
        "route_v2_gateway_revision_lineage_ck",
        "CHECK ((((policy_revision = 1) AND (expected_previous_policy_revision IS NULL) AND (expected_previous_policy_sha256 IS NULL)) OR ((policy_revision > 1) AND (expected_previous_policy_revision = (policy_revision - 1)) AND (expected_previous_policy_sha256 IS NOT NULL))))",
    ),
    (
        "route_v2_gateway_credential_lineage",
        "route_v2_gateway_credential_digest_ck",
        "CHECK ((public_key_spki_sha256 ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "route_v2_gateway_credential_lineage",
        "route_v2_gateway_credential_state_ck",
        "CHECK ((state = ANY (ARRAY['active'::text, 'revoked'::text])))",
    ),
    (
        "route_v2_gateway_credential_lineage",
        "route_v2_gateway_credential_first_revision_ck",
        "CHECK ((first_policy_revision > 0))",
    ),
    (
        "route_v2_gateway_credential_lineage",
        "route_v2_gateway_credential_first_time_ck",
        "CHECK ((first_committed_at_unix_ms >= 0))",
    ),
    (
        "route_v2_gateway_credential_lineage",
        "route_v2_gateway_credential_revoked_time_ck",
        "CHECK (((revoked_at_unix_ms IS NULL) OR (revoked_at_unix_ms >= first_committed_at_unix_ms)))",
    ),
    (
        "route_v2_gateway_credential_lineage",
        "route_v2_gateway_credential_state_time_ck",
        "CHECK ((((state = 'active'::text) AND (revoked_at_unix_ms IS NULL)) OR ((state = 'revoked'::text) AND (revoked_at_unix_ms IS NOT NULL))))",
    ),
    (
        "route_v2_gateway_current_credentials",
        "route_v2_gateway_current_revision_ck",
        "CHECK ((policy_revision > 0))",
    ),
    (
        "route_v2_gateway_current_credentials",
        "route_v2_gateway_current_policy_digest_ck",
        "CHECK ((policy_sha256 ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "route_v2_gateway_current_credentials",
        "route_v2_gateway_current_spki_digest_ck",
        "CHECK ((public_key_spki_sha256 ~ '^sha256:[0-9a-f]{64}$'::text))",
    ),
    (
        "route_v2_gateway_current_credentials",
        "route_v2_gateway_current_scope_ck",
        "CHECK ((jsonb_typeof(scope) = 'object'::text))",
    ),
    (
        "route_v2_gateway_current_credentials",
        "route_v2_gateway_current_state_ck",
        "CHECK ((lineage_state = 'active'::text))",
    ),
    (
        "runtime_node_placement_policies",
        "runtime_node_placement_policies_node_transport_target_check",
        "CHECK ((node_transport_target ~ '^https://[a-z0-9.-]+:[1-9][0-9]{0,4}$'::text))",
    ),
    (
        "volume_records",
        "volume_records_owner_present_check",
        "CHECK (((lease_owner IS NULL) = (owner_binding IS NULL)))",
    ),
    (
        "volume_records",
        "volume_records_owner_node_present_check",
        "CHECK (((owner_binding IS NULL) = (owner_node_id IS NULL)))",
    ),
    (
        "volume_records",
        "volume_records_owner_binding_check",
        "CHECK (((owner_binding IS NULL) OR (owner_binding = jsonb_build_object('volume_id', volume_id, 'owner_node_id', owner_node_id, 'attachment_id', lease_owner, 'attachment_epoch', lease_epoch))))",
    ),
    (
        "volume_records",
        "volume_records_transition_shape_check",
        "CHECK (((((last_transition_kind IS NULL) AND (last_transition_id IS NULL) AND (transition_source_kind IS NULL) AND (transition_operation_id IS NULL) AND (transition_request_fingerprint IS NULL) AND (transition_placement_epoch IS NULL) AND (transition_lease_duration_ms IS NULL)) OR ((last_transition_kind = 'normal_acquire'::text) AND (last_transition_id IS NOT NULL) AND (transition_source_kind IS NOT NULL) AND (transition_placement_epoch > 0) AND (transition_lease_duration_ms > 0) AND (((transition_source_kind = 'independent'::text) AND (transition_operation_id IS NULL) AND (transition_request_fingerprint IS NULL)) OR ((transition_source_kind = 'lifecycle'::text) AND (transition_operation_id IS NOT NULL) AND (transition_request_fingerprint IS NOT NULL)))) OR ((last_transition_kind = ANY (ARRAY['release'::text, 'takeover'::text, 'begin_delete'::text, 'begin_disposable_delete'::text])) AND (last_transition_id IS NOT NULL) AND (transition_source_kind IS NOT NULL) AND (transition_placement_epoch IS NULL) AND (transition_lease_duration_ms IS NULL) AND (((transition_source_kind = 'independent'::text) AND (transition_operation_id IS NULL) AND (transition_request_fingerprint IS NULL)) OR ((transition_source_kind = 'lifecycle'::text) AND (transition_operation_id IS NOT NULL) AND (transition_request_fingerprint IS NOT NULL))))) IS TRUE))",
    ),
];

const REQUIRED_PRIMARY_KEYS: &[(&str, &str, &str)] = &[
    (
        "route_v2_rotation_operator_authority",
        "route_v2_rotation_operator_authority_pkey",
        "singleton",
    ),
    (
        "route_v2_rotation_operator_credentials",
        "route_v2_rotation_operator_credentials_pkey",
        "credential_id",
    ),
    (
        "route_v2_signing_command_receipts",
        "route_v2_signing_command_receipts_pkey",
        "authority_id,command_id",
    ),
    (
        "route_v2_public_ring_deliveries",
        "route_v2_public_ring_deliveries_pkey",
        "deployment_id,ring_version",
    ),
    (
        "cat_runtime_configs",
        "cat_runtime_configs_pkey",
        "config_id",
    ),
    (
        "hostname_endpoint_lookups",
        "hostname_endpoint_lookups_pkey",
        "hostname",
    ),
    (
        "runtime_operations",
        "runtime_operations_pkey",
        "operation_id",
    ),
    (
        "lifecycle_volume_receipts",
        "lifecycle_volume_receipts_pkey",
        "operation_id,volume_id,receipt_kind,receipt_sequence",
    ),
    ("route_operations", "route_operations_pkey", "operation_id"),
    (
        "route_node_ring_acks",
        "route_node_ring_acks_pkey",
        "node_id",
    ),
    (
        "runtime_full_inventory_attestations",
        "runtime_full_inventory_attestations_pkey",
        "node_id",
    ),
    (
        "host_fence_provider_queue_v1",
        "host_fence_provider_queue_v1_pkey",
        "fence_attempt_id",
    ),
    ("volume_records", "volume_records_pkey", "volume_id"),
    (
        "production_mutation_admission_commands",
        "production_mutation_admission_commands_pkey",
        "command_id",
    ),
    (
        "production_mutation_admission",
        "production_mutation_admission_pkey",
        "singleton",
    ),
    (
        "route_v2_signing_authority",
        "route_v2_signing_authority_pkey",
        "singleton",
    ),
    (
        "route_v2_signer_revisions",
        "route_v2_signer_revisions_pkey",
        "deployment_id,signer_revision",
    ),
    (
        "route_v2_signer_key_lineage",
        "route_v2_signer_key_lineage_pkey",
        "kid",
    ),
    (
        "route_v2_public_key_ring_revisions",
        "route_v2_public_key_ring_revisions_pkey",
        "deployment_id,ring_version",
    ),
    (
        "route_v2_signer_retirements",
        "route_v2_signer_retirements_pkey",
        "deployment_id,kid",
    ),
    (
        "route_v2_gateway_identity_authority",
        "route_v2_gateway_identity_authority_pkey",
        "singleton",
    ),
    (
        "route_v2_gateway_identity_revisions",
        "route_v2_gateway_identity_revisions_pkey",
        "authority_id,policy_revision",
    ),
    (
        "route_v2_gateway_credential_lineage",
        "route_v2_gateway_credential_lineage_pkey",
        "credential_id",
    ),
    (
        "route_v2_gateway_current_credentials",
        "route_v2_gateway_current_credentials_pkey",
        "credential_id",
    ),
];

pub(super) const REQUIRED_FOREIGN_KEYS: &[(&str, &str, &str)] = &[
    (
        "volume_records",
        "volume_records_lifecycle_transition_operation_fkey",
        "FOREIGN KEY (transition_operation_id, transition_request_fingerprint) REFERENCES runtime_operations(operation_id, canonical_request_sha256) ON UPDATE RESTRICT ON DELETE RESTRICT",
    ),
    (
        "runtime_operations",
        "runtime_operations_workspace_cat_fkey",
        "FOREIGN KEY (workspace_id, cat_id) REFERENCES cat_records(workspace_id, cat_id) ON UPDATE RESTRICT ON DELETE RESTRICT",
    ),
    (
        "runtime_operations",
        "runtime_operations_exact_runtime_config_fkey",
        "FOREIGN KEY (workspace_id, cat_id, runtime_config_id, runtime_config_sha256) REFERENCES cat_runtime_configs(workspace_id, cat_id, config_id, canonical_config_sha256) ON UPDATE RESTRICT ON DELETE RESTRICT",
    ),
    (
        "lifecycle_volume_receipts",
        "lifecycle_volume_receipts_exact_operation_fkey",
        "FOREIGN KEY (operation_id, request_fingerprint, workspace_id, cat_id, node_id, placement_epoch, runtime_config_id, runtime_config_sha256, source_command_kind) REFERENCES runtime_operations(operation_id, canonical_request_sha256, workspace_id, cat_id, node_id, placement_epoch, runtime_config_id, runtime_config_sha256, command_kind) ON UPDATE RESTRICT ON DELETE RESTRICT",
    ),
    (
        "route_operations",
        "route_operations_endpoint_fkey",
        "FOREIGN KEY (workspace_id, cat_id, endpoint_id) REFERENCES endpoint_records(workspace_id, cat_id, endpoint_id) ON UPDATE RESTRICT ON DELETE RESTRICT",
    ),
    (
        "route_operations",
        "route_operations_source_lifecycle_fkey",
        "FOREIGN KEY (cat_id, source_lifecycle_operation_id) REFERENCES runtime_operations(cat_id, operation_id) ON UPDATE RESTRICT ON DELETE RESTRICT",
    ),
    (
        "route_operations",
        "route_operations_node_fkey",
        "FOREIGN KEY (node_id) REFERENCES node_identities(node_id) ON UPDATE RESTRICT ON DELETE RESTRICT",
    ),
    (
        "route_v2_rotation_operator_credentials",
        "route_v2_rotation_operator_credential_authority_fkey",
        "FOREIGN KEY (authority_id) REFERENCES route_v2_rotation_operator_authority(authority_id) ON UPDATE RESTRICT ON DELETE RESTRICT",
    ),
    (
        "route_v2_signing_command_receipts",
        "route_v2_signing_command_operator_fkey",
        "FOREIGN KEY (authority_id) REFERENCES route_v2_rotation_operator_authority(authority_id) ON UPDATE RESTRICT ON DELETE RESTRICT",
    ),
    (
        "route_v2_signing_command_receipts",
        "route_v2_signing_command_target_fkey",
        "FOREIGN KEY (target_deployment_id) REFERENCES route_v2_signing_authority(deployment_id) ON UPDATE RESTRICT ON DELETE RESTRICT",
    ),
    (
        "route_v2_public_ring_deliveries",
        "route_v2_public_ring_delivery_ring_fkey",
        "FOREIGN KEY (deployment_id, ring_version, key_ring_digest) REFERENCES route_v2_public_key_ring_revisions(deployment_id, ring_version, key_ring_digest) ON UPDATE RESTRICT ON DELETE RESTRICT",
    ),
    (
        "route_v2_public_ring_deliveries",
        "route_v2_public_ring_delivery_command_fkey",
        "FOREIGN KEY (source_authority_id, source_command_id) REFERENCES route_v2_signing_command_receipts(authority_id, command_id) ON UPDATE RESTRICT ON DELETE RESTRICT",
    ),
];

const REQUIRED_DEFERRED_FOREIGN_KEYS: &[RequiredDeferredForeignKey] = &[
    (
        "cat_runtime_configs",
        "cat_runtime_configs_workspace_cat_fkey",
        "cat_records",
        "workspace_id,cat_id",
        "workspace_id,cat_id",
        "r",
        "r",
    ),
    (
        "cat_records",
        "cat_records_current_runtime_config_fkey",
        "cat_runtime_configs",
        "workspace_id,cat_id,current_runtime_config_id,current_runtime_config_sha256",
        "workspace_id,cat_id,config_id,canonical_config_sha256",
        "r",
        "r",
    ),
    (
        "hostname_endpoint_lookups",
        "hostname_endpoint_lookup_endpoint_fkey",
        "endpoint_records",
        "workspace_id,cat_id,endpoint_id,hostname",
        "workspace_id,cat_id,endpoint_id,hostname",
        "a",
        "a",
    ),
    (
        "runtime_operations",
        "runtime_operations_exact_predecessor_fkey",
        "runtime_operations",
        "cat_id,expected_predecessor_operation_id,expected_predecessor_result_kind,expected_predecessor_result_sha256",
        "cat_id,operation_id,terminal_result_kind,canonical_result_sha256",
        "a",
        "a",
    ),
    (
        "route_operations",
        "route_operations_exact_predecessor_fkey",
        "route_operations",
        "endpoint_id,expected_predecessor_operation_id,expected_predecessor_result_kind,expected_predecessor_result_sha256",
        "endpoint_id,operation_id,terminal_result_kind,canonical_result_sha256",
        "a",
        "a",
    ),
    (
        "endpoint_records",
        "endpoint_records_route_head_operation_fkey",
        "route_operations",
        "workspace_id,cat_id,endpoint_id,route_head_operation_id",
        "workspace_id,cat_id,endpoint_id,operation_id",
        "r",
        "r",
    ),
    (
        "endpoint_records",
        "endpoint_records_effective_serving_operation_fkey",
        "route_operations",
        "workspace_id,cat_id,endpoint_id,effective_serving_operation_id",
        "workspace_id,cat_id,endpoint_id,operation_id",
        "r",
        "r",
    ),
    (
        "route_node_ring_acks",
        "route_node_ring_acks_exact_session_fkey",
        "agent_registration_attempts",
        "node_id,node_boot_id,agent_instance_id,admission_session_epoch",
        "node_id,node_boot_id,agent_instance_id,agent_session_epoch",
        "r",
        "r",
    ),
    (
        "production_mutation_admission",
        "production_mutation_admission_exact_command_fkey",
        "production_mutation_admission_commands",
        "last_command_id,revision,mode,binding_sha256",
        "command_id,resulting_revision,resulting_mode,binding_sha256",
        "r",
        "r",
    ),
    (
        "route_v2_signing_authority",
        "route_v2_signing_authority_current_revision_fkey",
        "route_v2_signer_revisions",
        "deployment_id,current_signer_revision,current_signer_reference_sha256,signer_state,active_kid,public_key_ring_version,public_key_ring_digest,secret_reference_id",
        "deployment_id,signer_revision,signer_reference_sha256,signer_state,active_kid,public_key_ring_version,public_key_ring_digest,secret_reference_id",
        "r",
        "r",
    ),
    (
        "route_v2_signer_revisions",
        "route_v2_signer_revisions_authority_fkey",
        "route_v2_signing_authority",
        "deployment_id",
        "deployment_id",
        "r",
        "r",
    ),
    (
        "route_v2_signer_revisions",
        "route_v2_signer_revision_previous_fkey",
        "route_v2_signer_revisions",
        "deployment_id,expected_previous_signer_revision,expected_previous_signer_reference_sha256",
        "deployment_id,signer_revision,signer_reference_sha256",
        "r",
        "r",
    ),
    (
        "route_v2_signer_key_lineage",
        "route_v2_signer_key_lineage_first_revision_fkey",
        "route_v2_signer_revisions",
        "deployment_id,first_signer_revision",
        "deployment_id,signer_revision",
        "r",
        "r",
    ),
    (
        "route_v2_signer_key_lineage",
        "route_v2_signer_key_lineage_authority_fkey",
        "route_v2_signing_authority",
        "deployment_id",
        "deployment_id",
        "r",
        "r",
    ),
    (
        "route_v2_signer_retirements",
        "route_v2_signer_retirement_key_fkey",
        "route_v2_signer_key_lineage",
        "kid",
        "kid",
        "r",
        "r",
    ),
    (
        "route_v2_signer_retirements",
        "route_v2_signer_retirement_start_revision_fkey",
        "route_v2_signer_revisions",
        "deployment_id,retirement_signer_revision",
        "deployment_id,signer_revision",
        "r",
        "r",
    ),
    (
        "route_v2_signer_retirements",
        "route_v2_signer_retirement_removed_ring_fkey",
        "route_v2_public_key_ring_revisions",
        "deployment_id,ring_removed_version",
        "deployment_id,ring_version",
        "r",
        "r",
    ),
    (
        "route_v2_signer_retirements",
        "route_v2_signer_retirement_finish_revision_fkey",
        "route_v2_signer_revisions",
        "deployment_id,retired_signer_revision",
        "deployment_id,signer_revision",
        "r",
        "r",
    ),
    (
        "route_v2_public_key_ring_revisions",
        "route_v2_public_ring_authority_fkey",
        "route_v2_signing_authority",
        "deployment_id",
        "deployment_id",
        "r",
        "r",
    ),
    (
        "route_v2_public_key_ring_revisions",
        "route_v2_public_ring_previous_fkey",
        "route_v2_public_key_ring_revisions",
        "deployment_id,expected_previous_ring_version,expected_previous_key_ring_digest",
        "deployment_id,ring_version,key_ring_digest",
        "r",
        "r",
    ),
    (
        "route_v2_signing_authority",
        "route_v2_signing_authority_current_ring_fkey",
        "route_v2_public_key_ring_revisions",
        "deployment_id,public_key_ring_version,public_key_ring_digest",
        "deployment_id,ring_version,key_ring_digest",
        "r",
        "r",
    ),
    (
        "route_v2_signer_revisions",
        "route_v2_signer_revision_ring_fkey",
        "route_v2_public_key_ring_revisions",
        "deployment_id,public_key_ring_version,public_key_ring_digest",
        "deployment_id,ring_version,key_ring_digest",
        "r",
        "r",
    ),
    (
        "route_v2_signer_retirements",
        "route_v2_signer_retirement_authority_fkey",
        "route_v2_signing_authority",
        "deployment_id",
        "deployment_id",
        "r",
        "r",
    ),
    (
        "node_identities",
        "node_identity_current_public_key_lineage",
        "runtime_node_credential_lineage",
        "node_id,credential_id,credential_public_key_spki_sha256,credential_lineage_state",
        "node_id,credential_id,public_key_spki_sha256,state",
        "a",
        "a",
    ),
    (
        "runtime_node_credential_lineage",
        "runtime_node_credential_lineage_node_id_fkey",
        "node_identities",
        "node_id",
        "node_id",
        "r",
        "r",
    ),
    (
        "runtime_provisioner_deployment_identity",
        "runtime_provisioner_current_trust_revision",
        "runtime_provisioner_trust_revisions",
        "deployment_id,current_trust_revision,current_active_set_sha256",
        "deployment_id,trust_revision,active_set_sha256",
        "r",
        "r",
    ),
    (
        "runtime_provisioner_trust_revisions",
        "runtime_provisioner_trust_revisions_deployment_id_fkey",
        "runtime_provisioner_deployment_identity",
        "deployment_id",
        "deployment_id",
        "r",
        "r",
    ),
    (
        "route_v2_gateway_identity_authority",
        "route_v2_gateway_current_policy_revision",
        "route_v2_gateway_identity_revisions",
        "authority_id,fleet_id,current_policy_revision,current_policy_sha256",
        "authority_id,fleet_id,policy_revision,policy_sha256",
        "r",
        "r",
    ),
    (
        "route_v2_gateway_identity_revisions",
        "route_v2_gateway_revisions_authority_fkey",
        "route_v2_gateway_identity_authority",
        "authority_id,fleet_id",
        "authority_id,fleet_id",
        "r",
        "r",
    ),
    (
        "route_v2_gateway_current_credentials",
        "route_v2_gateway_current_policy_fkey",
        "route_v2_gateway_identity_authority",
        "authority_id,fleet_id,policy_revision,policy_sha256",
        "authority_id,fleet_id,current_policy_revision,current_policy_sha256",
        "a",
        "a",
    ),
    (
        "route_v2_gateway_credential_lineage",
        "route_v2_gateway_credential_first_revision_fkey",
        "route_v2_gateway_identity_revisions",
        "authority_id,first_policy_revision",
        "authority_id,policy_revision",
        "r",
        "r",
    ),
    (
        "route_v2_gateway_current_credentials",
        "route_v2_gateway_current_lineage_fkey",
        "route_v2_gateway_credential_lineage",
        "credential_id,authority_id,public_key_spki_sha256,lineage_state",
        "credential_id,authority_id,public_key_spki_sha256,state",
        "a",
        "a",
    ),
];

const REQUIRED_UNIQUE_INDEXES: &[(&str, &str, &str, Option<&str>)] = &[
    (
        "route_v2_rotation_operator_authority",
        "route_v2_rotation_operator_authority_id_key",
        "authority_id",
        None,
    ),
    (
        "route_v2_rotation_operator_authority",
        "route_v2_rotation_operator_identity_key",
        "authority_id,route_deployment_id,release_commit_sha,trust_sha256",
        None,
    ),
    (
        "route_v2_rotation_operator_credentials",
        "route_v2_rotation_operator_spki_key",
        "public_key_spki",
        None,
    ),
    (
        "route_v2_rotation_operator_credentials",
        "route_v2_rotation_operator_spki_sha_key",
        "public_key_spki_sha256",
        None,
    ),
    (
        "route_v2_rotation_operator_credentials",
        "route_v2_rotation_operator_ordinal_key",
        "authority_id,credential_ordinal",
        None,
    ),
    (
        "route_v2_public_ring_deliveries",
        "route_v2_public_ring_delivery_envelope_sha_key",
        "exact_signed_envelope_sha256",
        None,
    ),
    (
        "route_v2_public_ring_deliveries",
        "route_v2_public_ring_delivery_predecessor_key",
        "deployment_id,expected_previous_ring_version,expected_previous_key_ring_digest",
        None,
    ),
    (
        "production_mutation_admission_commands",
        "production_mutation_admission_commands_state_key",
        "command_id,resulting_revision,resulting_mode,binding_sha256",
        None,
    ),
    (
        "production_mutation_admission",
        "production_mutation_admission_last_command_key",
        "last_command_id",
        None,
    ),
    (
        "node_identities",
        "node_identity_one_provisioned_per_host",
        "host_provider,host_partition,host_account_id,host_region,immutable_host_id",
        Some("(state = 'provisioned'::text)"),
    ),
    (
        "object_write_authorities",
        "object_write_one_open_authority_per_host",
        "host_provider,host_partition,host_account_id,host_region,immutable_host_id",
        Some("(state = 'open'::text)"),
    ),
    (
        "cat_records",
        "cat_records_cat_creation_id_key",
        "cat_creation_id",
        None,
    ),
    (
        "cat_records",
        "cat_records_lifecycle_head_operation_key",
        "lifecycle_head_operation_id",
        Some("(lifecycle_head_operation_id IS NOT NULL)"),
    ),
    (
        "cat_records",
        "cat_records_effective_runtime_ready_operation_key",
        "effective_runtime_ready_operation_id",
        Some("(effective_runtime_ready_operation_id IS NOT NULL)"),
    ),
    (
        "cat_runtime_configs",
        "cat_runtime_configs_exact_key",
        "workspace_id,cat_id,config_id,canonical_config_sha256",
        None,
    ),
    (
        "runtime_operations",
        "runtime_operations_cat_operation_key",
        "cat_id,operation_id",
        None,
    ),
    (
        "runtime_operations",
        "runtime_operations_predecessor_result_key",
        "cat_id,operation_id,terminal_result_kind,canonical_result_sha256",
        None,
    ),
    (
        "runtime_operations",
        "runtime_operations_receipt_scope_key",
        "operation_id,canonical_request_sha256,workspace_id,cat_id,node_id,placement_epoch,runtime_config_id,runtime_config_sha256,command_kind",
        None,
    ),
    (
        "runtime_operations",
        "runtime_operations_request_scope_key",
        "operation_id,canonical_request_sha256",
        None,
    ),
    (
        "runtime_operations",
        "runtime_operations_one_unresolved_per_cat",
        "cat_id",
        Some("(state = 'unresolved'::text)"),
    ),
    (
        "runtime_operations",
        "runtime_operations_one_genesis_per_cat",
        "cat_id",
        Some("(expected_predecessor_operation_id IS NULL)"),
    ),
    (
        "runtime_operations",
        "runtime_operations_one_successor_per_predecessor",
        "cat_id,expected_predecessor_operation_id",
        Some("(expected_predecessor_operation_id IS NOT NULL)"),
    ),
    (
        "lifecycle_volume_receipts",
        "lifecycle_volume_receipts_operation_disk_unique",
        "operation_id,disk_id,receipt_kind,receipt_sequence",
        None,
    ),
    (
        "endpoint_records",
        "endpoint_records_route_head_operation_key",
        "route_head_operation_id",
        Some("(route_head_operation_id IS NOT NULL)"),
    ),
    (
        "endpoint_records",
        "endpoint_records_effective_serving_operation_key",
        "effective_serving_operation_id",
        Some("(effective_serving_operation_id IS NOT NULL)"),
    ),
    (
        "route_operations",
        "route_operations_endpoint_operation_key",
        "endpoint_id,operation_id",
        None,
    ),
    (
        "route_operations",
        "route_operations_predecessor_result_key",
        "endpoint_id,operation_id,terminal_result_kind,canonical_result_sha256",
        None,
    ),
    (
        "route_operations",
        "route_operations_one_unresolved_per_endpoint",
        "endpoint_id",
        Some("(state = 'unresolved'::text)"),
    ),
    (
        "route_operations",
        "route_operations_one_genesis_per_endpoint",
        "endpoint_id",
        Some("(expected_predecessor_operation_id IS NULL)"),
    ),
    (
        "route_operations",
        "route_operations_one_successor_per_predecessor",
        "endpoint_id,expected_predecessor_operation_id",
        Some("(expected_predecessor_operation_id IS NOT NULL)"),
    ),
    (
        "agent_registration_attempts",
        "agent_registration_attempts_exact_session_binding_key",
        "node_id,node_boot_id,agent_instance_id,agent_session_epoch",
        None,
    ),
    (
        "current_agent_sessions",
        "current_agent_sessions_exact_binding_key",
        "node_id,node_boot_id,agent_instance_id,agent_session_epoch",
        None,
    ),
    (
        "route_node_ring_acks",
        "route_node_ring_acks_session_sequence_key",
        "node_id,admission_session_epoch,ack_sequence",
        None,
    ),
    (
        "route_node_ring_acks",
        "route_node_ring_acks_session_ack_id_key",
        "node_id,admission_session_epoch,ack_id",
        None,
    ),
    (
        "disk_records",
        "disk_records_initialization_token_unique",
        "initialization_token",
        Some("(role_kind = 'persistent'::text)"),
    ),
    (
        "disk_records",
        "disk_records_filesystem_uuid_unique",
        "filesystem_uuid",
        Some("(role_kind = 'persistent'::text)"),
    ),
    (
        "route_v2_signing_authority",
        "route_v2_signing_authority_deployment_id_key",
        "deployment_id",
        None,
    ),
    (
        "route_v2_signing_authority",
        "route_v2_signing_authority_current_key",
        "deployment_id,current_signer_revision,current_signer_reference_sha256,signer_state,active_kid,public_key_ring_version,public_key_ring_digest,secret_reference_id",
        None,
    ),
    (
        "route_v2_signer_revisions",
        "route_v2_signer_revisions_exact_key",
        "deployment_id,signer_revision,signer_reference_sha256,signer_state,active_kid,public_key_ring_version,public_key_ring_digest,secret_reference_id",
        None,
    ),
    (
        "route_v2_signer_revisions",
        "route_v2_signer_revisions_reference_key",
        "deployment_id,signer_revision,signer_reference_sha256",
        None,
    ),
    (
        "route_v2_signer_key_lineage",
        "route_v2_signer_key_lineage_public_key_spki_key",
        "public_key_spki",
        None,
    ),
    (
        "route_v2_signer_key_lineage",
        "route_v2_signer_key_lineage_secret_reference_id_key",
        "secret_reference_id",
        None,
    ),
    (
        "route_v2_public_key_ring_revisions",
        "route_v2_public_key_ring_revisions_exact_key",
        "deployment_id,ring_version,key_ring_digest",
        None,
    ),
    (
        "route_v2_signer_retirements",
        "route_v2_signer_one_pending_normal_retirement",
        "deployment_id",
        Some("((source = 'normal'::text) AND (state <> 'retired'::text))"),
    ),
    (
        "route_v2_signer_retirements",
        "route_v2_signer_retirements_completion_key",
        "deployment_id,kid,secret_reference_id,retired_signer_revision",
        None,
    ),
    (
        "host_fence_events",
        "runtime_node_one_active_host_fence_event",
        "node_id",
        Some("(state = 'active'::text)"),
    ),
    (
        "host_fence_events",
        "runtime_one_terminal_host_fence_event_v1",
        "provider,host_partition,host_account_id,host_region,immutable_host_id,node_id,expected_node_boot_id,expected_agent_session_epoch",
        Some("(state = 'terminal_v1'::text)"),
    ),
    (
        "runtime_node_credential_lineage",
        "runtime_node_one_active_credential",
        "node_id",
        Some("(state = 'active'::text)"),
    ),
    (
        "runtime_node_credential_lineage",
        "runtime_node_credential_lineage_public_key_spki_sha256_key",
        "public_key_spki_sha256",
        None,
    ),
    (
        "runtime_node_authority_apply_records",
        "runtime_node_authority_apply_records_pkey",
        "apply_id",
        None,
    ),
    (
        "runtime_provisioner_credential_lineage",
        "runtime_provisioner_credential_lineage_public_key_spki_key",
        "public_key_spki",
        None,
    ),
    (
        "runtime_provisioner_credential_lineage",
        "runtime_provisioner_credential_linea_public_key_spki_sha256_key",
        "public_key_spki_sha256",
        None,
    ),
    (
        "runtime_provisioner_trust_revisions",
        "runtime_provisioner_trust_revisions_pkey",
        "deployment_id,trust_revision",
        None,
    ),
    (
        "route_v2_gateway_identity_authority",
        "route_v2_gateway_identity_authority_authority_id_key",
        "authority_id",
        None,
    ),
    (
        "route_v2_gateway_identity_authority",
        "route_v2_gateway_identity_authority_authority_id_fleet_id_key",
        "authority_id,fleet_id",
        None,
    ),
    (
        "route_v2_gateway_identity_authority",
        "route_v2_gateway_identity_authority_current_key",
        "authority_id,fleet_id,current_policy_revision,current_policy_sha256",
        None,
    ),
    (
        "route_v2_gateway_identity_revisions",
        "route_v2_gateway_identity_revisions_exact_key",
        "authority_id,fleet_id,policy_revision,policy_sha256",
        None,
    ),
    (
        "route_v2_gateway_credential_lineage",
        "route_v2_gateway_credential_lineage_spki_key",
        "public_key_spki",
        None,
    ),
    (
        "route_v2_gateway_credential_lineage",
        "route_v2_gateway_credential_lineage_spki_sha256_key",
        "public_key_spki_sha256",
        None,
    ),
    (
        "route_v2_gateway_credential_lineage",
        "route_v2_gateway_credential_lineage_exact_key",
        "credential_id,authority_id,public_key_spki_sha256,state",
        None,
    ),
    (
        "host_fence_provider_queue_v1",
        "host_fence_provider_queue_claim_token_unique",
        "claim_attempt_token",
        Some("(claim_attempt_token IS NOT NULL)"),
    ),
    (
        "host_fence_provider_queue_v1",
        "host_fence_provider_queue_renew_token_unique",
        "renew_attempt_token",
        Some("(renew_attempt_token IS NOT NULL)"),
    ),
];

type RequiredExpressionIndex = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    Option<&'static str>,
);

const REQUIRED_EXPRESSION_INDEXES: &[RequiredExpressionIndex] = &[
    (
        "volume_records",
        "volume_records_record_volume",
        "btree",
        "text_ops",
        "(record ->> 'volume_id'::text)",
        Some("pg_catalog.\"default\""),
    ),
    (
        "volume_records",
        "volume_records_delete",
        "btree",
        "text_ops",
        "COALESCE(delete_id, ''::text)",
        Some("pg_catalog.\"default\""),
    ),
    (
        "volume_records",
        "volume_records_record_delete",
        "btree",
        "text_ops",
        "((record -> 'admin_state'::text) ->> 'delete_id'::text)",
        Some("pg_catalog.\"default\""),
    ),
    (
        "volume_authorizations",
        "volume_authorizations_record_authorization",
        "gin",
        "jsonb_path_ops",
        "(record -> 'authorization'::text)",
        None,
    ),
    (
        "delete_completion_receipts",
        "delete_completion_receipts_record_delete",
        "btree",
        "text_ops",
        "(record ->> 'delete_id'::text)",
        Some("pg_catalog.\"default\""),
    ),
    (
        "delete_completion_receipts",
        "delete_completion_receipts_record_disk",
        "btree",
        "text_ops",
        "(record ->> 'disk_id'::text)",
        Some("pg_catalog.\"default\""),
    ),
    (
        "delete_completion_receipts",
        "delete_completion_receipts_record_volume",
        "btree",
        "text_ops",
        "(record ->> 'volume_id'::text)",
        Some("pg_catalog.\"default\""),
    ),
    (
        "delete_completion_receipts",
        "delete_completion_receipts_record_request_delete",
        "btree",
        "text_ops",
        "((record -> 'request'::text) ->> 'delete_id'::text)",
        Some("pg_catalog.\"default\""),
    ),
    (
        "delete_completion_receipts",
        "delete_completion_receipts_record_request_disk",
        "btree",
        "text_ops",
        "((record -> 'request'::text) ->> 'disk_id'::text)",
        Some("pg_catalog.\"default\""),
    ),
    (
        "delete_completion_receipts",
        "delete_completion_receipts_record_request_volume",
        "btree",
        "text_ops",
        "((record -> 'request'::text) ->> 'volume_id'::text)",
        Some("pg_catalog.\"default\""),
    ),
    (
        "disk_records",
        "disk_records_record_root_cat",
        "btree",
        "text_ops",
        "((record -> 'role'::text) ->> 'cat_id'::text)",
        Some("pg_catalog.\"default\""),
    ),
    (
        "disk_records",
        "disk_records_record_volume",
        "btree",
        "text_ops",
        "(record ->> 'volume_id'::text)",
        Some("pg_catalog.\"default\""),
    ),
];

const REQUIRED_RUNTIME_OPERATION_LOOKUP_INDEXES: &[(&str, &str, &str, Option<&str>)] = &[(
    "runtime_operations_workspace_lookup",
    "workspace_id",
    "operation_id",
    None,
)];

type RequiredProductReadLookupIndex = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    Option<&'static str>,
);

const REQUIRED_PRODUCT_READ_LOOKUP_INDEXES: &[RequiredProductReadLookupIndex] = &[
    (
        "cat_runtime_configs",
        "cat_runtime_configs_network_history",
        "placement_network_id",
        "config_id",
        None,
    ),
    (
        "cat_records",
        "cat_records_lookup_scalar_scalar",
        "workspace_id",
        "cat_id",
        None,
    ),
    (
        "cat_records",
        "cat_records_lookup_scalar_record",
        "workspace_id",
        "((record ->> 'cat_id'::text))",
        Some(
            "((cat_id COLLATE \"C\") IS DISTINCT FROM ((record ->> 'cat_id'::text) COLLATE \"C\"))",
        ),
    ),
    (
        "cat_records",
        "cat_records_lookup_record_scalar",
        "((record ->> 'workspace_id'::text))",
        "cat_id",
        Some(
            "((workspace_id COLLATE \"C\") IS DISTINCT FROM ((record ->> 'workspace_id'::text) COLLATE \"C\"))",
        ),
    ),
    (
        "cat_records",
        "cat_records_lookup_record_record",
        "((record ->> 'workspace_id'::text))",
        "((record ->> 'cat_id'::text))",
        Some(
            "(((workspace_id COLLATE \"C\") IS DISTINCT FROM ((record ->> 'workspace_id'::text) COLLATE \"C\")) AND ((cat_id COLLATE \"C\") IS DISTINCT FROM ((record ->> 'cat_id'::text) COLLATE \"C\")))",
        ),
    ),
    (
        "disk_records",
        "disk_records_lookup_scalar_scalar",
        "workspace_id",
        "disk_id",
        None,
    ),
    (
        "disk_records",
        "disk_records_lookup_scalar_record",
        "workspace_id",
        "((record ->> 'disk_id'::text))",
        Some(
            "((disk_id COLLATE \"C\") IS DISTINCT FROM ((record ->> 'disk_id'::text) COLLATE \"C\"))",
        ),
    ),
    (
        "disk_records",
        "disk_records_lookup_record_scalar",
        "((record ->> 'workspace_id'::text))",
        "disk_id",
        Some(
            "((workspace_id COLLATE \"C\") IS DISTINCT FROM ((record ->> 'workspace_id'::text) COLLATE \"C\"))",
        ),
    ),
    (
        "disk_records",
        "disk_records_lookup_record_record",
        "((record ->> 'workspace_id'::text))",
        "((record ->> 'disk_id'::text))",
        Some(
            "(((workspace_id COLLATE \"C\") IS DISTINCT FROM ((record ->> 'workspace_id'::text) COLLATE \"C\")) AND ((disk_id COLLATE \"C\") IS DISTINCT FROM ((record ->> 'disk_id'::text) COLLATE \"C\")))",
        ),
    ),
];

const REQUIRED_ARRAY_MEMBERSHIP_INDEXES: &[(&str, &str, &str)] = &[
    (
        "cat_runtime_configs",
        "cat_runtime_configs_disk_membership",
        "placement_disk_ids",
    ),
    (
        "cat_runtime_configs",
        "cat_runtime_configs_volume_membership",
        "placement_volume_ids",
    ),
];

type RequiredOrderedPartialIndex = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);

const REQUIRED_ORDERED_PARTIAL_INDEXES: &[RequiredOrderedPartialIndex] = &[(
    "volume_authorizations",
    "volume_authorizations_disposable_scope",
    "volume_id",
    "lifecycle_operation_id",
    "placement_epoch",
    "authorization_id",
    "(kind = 'disposable_root_delete'::text)",
)];

const REQUIRED_VOLUME_OWNER_INDEXES: &[(&str, &str, bool, &str)] = &[
    (
        "volume_records_owner_node",
        "owner_node_id",
        false,
        "(owner_node_id IS NOT NULL)",
    ),
    (
        "volume_records_owner_binding_node",
        "((owner_binding ->> 'owner_node_id'::text))",
        true,
        "(owner_binding IS NOT NULL)",
    ),
];

// PostgreSQL `pg_trigger.tgtype` bits: ROW=1, BEFORE=2, DELETE=8,
// UPDATE=16. Exact masks reject statement-level, AFTER, extra-event and
// `UPDATE OF`/WHEN weakened variants even when their names/functions match.
const BEFORE_ROW_DELETE: i16 = 1 | 2 | 8;
const BEFORE_ROW_UPDATE: i16 = 1 | 2 | 16;
const BEFORE_ROW_UPDATE_DELETE: i16 = 1 | 2 | 8 | 16;
const REQUIRED_IMMUTABILITY_TRIGGERS: &[(&str, &str, &str, i16, &str)] = &[
    (
        "route_v2_rotation_operator_authority",
        "route_v2_rotation_operator_authority_is_immutable",
        "control_route_v2_rotation_record_is_immutable",
        BEFORE_ROW_UPDATE_DELETE,
        "8089e0f2c469819e8b3228e1d263d543114b56f81d80b944954bd9b99f5d9f6b",
    ),
    (
        "route_v2_rotation_operator_credentials",
        "route_v2_rotation_operator_credential_is_immutable",
        "control_route_v2_rotation_record_is_immutable",
        BEFORE_ROW_UPDATE_DELETE,
        "8089e0f2c469819e8b3228e1d263d543114b56f81d80b944954bd9b99f5d9f6b",
    ),
    (
        "route_v2_signing_command_receipts",
        "route_v2_signing_command_receipt_is_immutable",
        "control_route_v2_rotation_record_is_immutable",
        BEFORE_ROW_UPDATE_DELETE,
        "8089e0f2c469819e8b3228e1d263d543114b56f81d80b944954bd9b99f5d9f6b",
    ),
    (
        "route_v2_public_ring_deliveries",
        "route_v2_public_ring_delivery_is_immutable",
        "control_route_v2_rotation_record_is_immutable",
        BEFORE_ROW_UPDATE_DELETE,
        "8089e0f2c469819e8b3228e1d263d543114b56f81d80b944954bd9b99f5d9f6b",
    ),
    (
        "production_mutation_admission_commands",
        "production_mutation_admission_command_is_immutable",
        "control_production_mutation_admission_command_is_immutable",
        BEFORE_ROW_UPDATE_DELETE,
        "8b1d09afb32bb828dd3869a742d7cdce06e4ef367f85b83932fd8f469d26aea2",
    ),
    (
        "production_mutation_admission",
        "production_mutation_admission_successor",
        "control_production_mutation_admission_successor",
        BEFORE_ROW_UPDATE,
        "ec2504cf1e185105fe156688a2026b7d7779725d366e0741ec7f48b0b86bed6a",
    ),
    (
        "production_mutation_admission",
        "production_mutation_admission_cannot_delete",
        "control_production_mutation_admission_cannot_delete",
        BEFORE_ROW_DELETE,
        "9651671a2ac23952c11607ca1b45394534c5855e2bbf7929fe3b96924801a9d1",
    ),
    (
        "runtime_node_credential_lineage",
        "runtime_node_credential_lineage_update",
        "control_runtime_node_credential_lineage_update",
        BEFORE_ROW_UPDATE,
        "b59ca8cd4bb9bd032340d29c9c230f4ba5f1957089bcc0be7d3b16d1530a9fbf",
    ),
    (
        "runtime_node_credential_lineage",
        "runtime_node_credential_lineage_cannot_delete",
        "control_runtime_node_credential_lineage_cannot_delete",
        BEFORE_ROW_DELETE,
        "47aadab1d6b9584e1a8313d38655be3eaee3ec5865e64938f5ebf20c3c02f205",
    ),
    (
        "runtime_node_placement_policies",
        "runtime_node_policy_update",
        "control_runtime_node_policy_update",
        BEFORE_ROW_UPDATE,
        "e5aecb0d77f3125308bf95f772cfab57b03ddce8d8c9859a69f88003ac7b30a7",
    ),
    (
        "runtime_node_placement_policies",
        "runtime_node_policy_cannot_delete",
        "control_runtime_node_policy_cannot_delete",
        BEFORE_ROW_DELETE,
        "8eeafd5c331ab500bda261e135b6c061f13987386898edde3f74c3c4dc009a2c",
    ),
    (
        "runtime_node_authority_apply_records",
        "runtime_node_apply_is_immutable",
        "control_runtime_node_apply_is_immutable",
        BEFORE_ROW_UPDATE_DELETE,
        "31366c6d9612212b3e9fae15ec31c217c3708c5fb166431980e3f60fd28f80d8",
    ),
    (
        "runtime_provisioner_trust_revisions",
        "runtime_provisioner_revision_is_immutable",
        "control_runtime_provisioner_revision_is_immutable",
        BEFORE_ROW_UPDATE_DELETE,
        "28c3a0a59fed38ccb79d2ce366bde142919d64eaa4164e2ffc6e2a5250313431",
    ),
    (
        "runtime_provisioner_credential_lineage",
        "runtime_provisioner_credential_update",
        "control_runtime_provisioner_credential_update",
        BEFORE_ROW_UPDATE,
        "297646e468dd86f20c46c4212f47b5bbe94c99288ee34c87a301e06308367a9a",
    ),
    (
        "runtime_provisioner_credential_lineage",
        "runtime_provisioner_credential_cannot_delete",
        "control_runtime_provisioner_credential_cannot_delete",
        BEFORE_ROW_DELETE,
        "4f3a0c1a80e7678486cad830a1be9427fb8e546c47ff21f4c387e9817f0bf4b6",
    ),
    (
        "runtime_provisioner_deployment_identity",
        "runtime_provisioner_pointer_update",
        "control_runtime_provisioner_pointer_update",
        BEFORE_ROW_UPDATE,
        "883fd6c3ff7394370a112afc7292e2e64503f37c05ec452c382f0e97ae45b24c",
    ),
    (
        "runtime_provisioner_deployment_identity",
        "runtime_provisioner_pointer_cannot_delete",
        "control_runtime_provisioner_pointer_cannot_delete",
        BEFORE_ROW_DELETE,
        "3ba58cdd898c1ded0023c8732a3ca155cc17caf6bba93d8346dcc43c2dbd9e76",
    ),
    (
        "route_v2_signer_revisions",
        "route_v2_signer_revision_is_immutable",
        "control_route_v2_signer_revision_is_immutable",
        BEFORE_ROW_UPDATE_DELETE,
        "8b0be4bcd5c553e9a341b7c865b72c9d471ddb323677a1f7e57b2ab5f221a2bc",
    ),
    (
        "route_v2_signer_key_lineage",
        "route_v2_signer_key_lineage_update",
        "control_route_v2_signer_key_lineage_update",
        BEFORE_ROW_UPDATE,
        "6aa312c3de5125a6caeabe30fde0ed30e51b852cf51181584bcd49aed2cc90d9",
    ),
    (
        "route_v2_signer_key_lineage",
        "route_v2_signer_key_lineage_cannot_delete",
        "control_route_v2_signer_key_lineage_cannot_delete",
        BEFORE_ROW_DELETE,
        "f5e2468ec0b2a0ae7446a73b0625623fba9278ca53f6279de52795d451e1be7f",
    ),
    (
        "route_v2_signing_authority",
        "route_v2_signing_authority_update",
        "control_route_v2_signing_authority_update",
        BEFORE_ROW_UPDATE,
        "bc4e33c4752b5f6f5fb6978b00cebcc985e05d512df7bd8e144426663f3cb330",
    ),
    (
        "route_v2_signing_authority",
        "route_v2_signing_authority_cannot_delete",
        "control_route_v2_signing_authority_cannot_delete",
        BEFORE_ROW_DELETE,
        "d689c869eaa0b1d0ad50a0b5e9b81be3a093cf63d1b64cbb0057b89cd4b17286",
    ),
    (
        "route_v2_public_key_ring_revisions",
        "route_v2_public_ring_revision_is_immutable",
        "control_route_v2_public_ring_revision_is_immutable",
        BEFORE_ROW_UPDATE_DELETE,
        "b40956e9b07de061ab8df10884916356d00d7c33e6c80214a02627b40fc52674",
    ),
    (
        "route_v2_signer_retirements",
        "route_v2_signer_retirement_update",
        "control_route_v2_signer_retirement_update",
        BEFORE_ROW_UPDATE,
        "9906634c8a56358d36814abc3f41730283864650b85d12bb19b5f99bdc69b19c",
    ),
    (
        "route_v2_signer_retirements",
        "route_v2_signer_retirement_cannot_delete",
        "control_route_v2_signer_retirement_cannot_delete",
        BEFORE_ROW_DELETE,
        "56fabcb6c34fc9913bdc1293b3b80c90612749431aef62bb5d2e71fd17406c18",
    ),
    (
        "route_v2_gateway_identity_revisions",
        "route_v2_gateway_revision_is_immutable",
        "control_route_v2_gateway_revision_is_immutable",
        BEFORE_ROW_UPDATE_DELETE,
        "0361b1936fe77f8af0dc9dbfef74403fc35082cd9fcc7faa58b9aceb9046c86f",
    ),
    (
        "route_v2_gateway_credential_lineage",
        "route_v2_gateway_credential_update",
        "control_route_v2_gateway_credential_update",
        BEFORE_ROW_UPDATE,
        "1fcef7a6e0026d0c3ee3715baa8011a1c751ccc6b1ce371005dc6881b9d5006f",
    ),
    (
        "route_v2_gateway_credential_lineage",
        "route_v2_gateway_credential_cannot_delete",
        "control_route_v2_gateway_credential_cannot_delete",
        BEFORE_ROW_DELETE,
        "9f5496d7d7edd5410512a78d46de6b79c9c015f53153880eb982aa70e6ac0bd5",
    ),
    (
        "route_v2_gateway_identity_authority",
        "route_v2_gateway_pointer_update",
        "control_route_v2_gateway_pointer_update",
        BEFORE_ROW_UPDATE,
        "b4b6b423ba8bd5cbdd225e3bc5edcf17c64330d303c61099832bbc374ae55bfe",
    ),
    (
        "route_v2_gateway_identity_authority",
        "route_v2_gateway_pointer_cannot_delete",
        "control_route_v2_gateway_pointer_cannot_delete",
        BEFORE_ROW_DELETE,
        "95487da8f6a12df1ef2329176b8661fa2318dd5d9240e95550b15bb8e4e5d98d",
    ),
    (
        "node_identities",
        "node_identity_lineage_is_immutable",
        "control_node_identity_lineage_is_immutable",
        BEFORE_ROW_UPDATE,
        "519b3ceb50adb00acb363cc3707c97f3e8aef5621a3f06c015bf2259d6bdcca3",
    ),
    (
        "node_identities",
        "node_identity_cannot_be_deleted",
        "control_node_identity_cannot_be_deleted",
        BEFORE_ROW_DELETE,
        "3930793dad74a3088892fdf5b2391255f8ebd1b2b675e21369cbda0543bef264",
    ),
    (
        "host_fence_provider_queue_v1",
        "host_fence_provider_queue_transition_is_forward_only",
        "control_host_fence_provider_queue_transition_guard",
        BEFORE_ROW_UPDATE,
        "5909f78bfdb0b59bc0792677073c6657987c3888dfed6ddc558a1dcffdc45317",
    ),
    (
        "host_fence_provider_queue_v1",
        "host_fence_provider_queue_cannot_delete",
        "control_host_fence_provider_queue_cannot_delete",
        BEFORE_ROW_DELETE,
        "f9f88a4724e414eb226d429fdfb1dca313868b2ea5a9d69d467f63a85696d8aa",
    ),
    (
        "runtime_operations",
        "runtime_operation_transition_is_forward_only",
        "control_runtime_operation_transition_guard",
        BEFORE_ROW_UPDATE,
        "fc00b66725065b4fc6a527a4982bc0108785cec0ac5f1668d1673aadc733c8b3",
    ),
    (
        "runtime_operations",
        "runtime_operation_cannot_delete",
        "control_runtime_operation_cannot_delete",
        BEFORE_ROW_DELETE,
        "68ea71ec0b39c400451864589c88683ca6ba80a579b86f76f4e41810e5e26d5d",
    ),
    (
        "cat_records",
        "cat_record_identity_is_immutable",
        "control_cat_record_identity_guard",
        BEFORE_ROW_UPDATE,
        "64400971bfff2fc539de2e0588a277498a64c0d8c3c3ee2cedaf8533994f7079",
    ),
    (
        "cat_records",
        "cat_record_cannot_delete",
        "control_cat_record_cannot_delete",
        BEFORE_ROW_DELETE,
        "9d2b2b4b4e98d5a50531d17a2dc70d6884c2082806fe0afcb746e435f3924d86",
    ),
    (
        "cat_runtime_configs",
        "cat_runtime_config_cannot_update",
        "control_cat_runtime_config_is_immutable",
        BEFORE_ROW_UPDATE,
        "e1b1cb5cf748c57734477d4c98f51932c488cf9142ebaa982fdc96721ef2d992",
    ),
    (
        "cat_runtime_configs",
        "cat_runtime_config_cannot_delete",
        "control_cat_runtime_config_is_immutable",
        BEFORE_ROW_DELETE,
        "e1b1cb5cf748c57734477d4c98f51932c488cf9142ebaa982fdc96721ef2d992",
    ),
    (
        "lifecycle_volume_receipts",
        "lifecycle_volume_receipt_cannot_update",
        "control_lifecycle_volume_receipt_is_immutable",
        BEFORE_ROW_UPDATE,
        "165ed66d83baa7d13ee78747798ab6257f3cb46adfe094c461cb449d3fda4897",
    ),
    (
        "lifecycle_volume_receipts",
        "lifecycle_volume_receipt_cannot_delete",
        "control_lifecycle_volume_receipt_is_immutable",
        BEFORE_ROW_DELETE,
        "165ed66d83baa7d13ee78747798ab6257f3cb46adfe094c461cb449d3fda4897",
    ),
    (
        "endpoint_records",
        "endpoint_record_transition_is_forward_only",
        "control_endpoint_record_transition_guard",
        BEFORE_ROW_UPDATE,
        "3699f12957510bf43e8288421ad81b3dab84770ef450bd22f846986a7c06bccd",
    ),
    (
        "endpoint_records",
        "endpoint_record_cannot_delete",
        "control_endpoint_record_cannot_delete",
        BEFORE_ROW_DELETE,
        "f00d56f121c90d16475177f52897d957b34674bdb886d5c5bc989855e03d2aff",
    ),
    (
        "route_operations",
        "route_operation_transition_is_forward_only",
        "control_route_operation_transition_guard",
        BEFORE_ROW_UPDATE,
        "ef530d845e69aa356bb6b04783b559bc6b54590ea6ee4c5aa3db68083aa9b360",
    ),
    (
        "route_operations",
        "route_operation_cannot_delete",
        "control_route_operation_cannot_delete",
        BEFORE_ROW_DELETE,
        "00896b3e808767ba3109b67715f8a6f61c2d94908249c49d2d544ee7abbb2af6",
    ),
    (
        "route_node_ring_acks",
        "route_node_ring_ack_transition_is_forward_only",
        "control_route_node_ring_ack_transition_guard",
        BEFORE_ROW_UPDATE,
        "5cd74190ddd7fb8ae82dbf0f46c0b394b414d9259da05243bf3c51c9455de484",
    ),
    (
        "route_node_ring_acks",
        "route_node_ring_ack_cannot_delete",
        "control_route_node_ring_ack_cannot_delete",
        BEFORE_ROW_DELETE,
        "ffe9feb77c44c36ef51b7707f4ecc765e963acf6c23a088ffadfd9e72761ca11",
    ),
];

const AUTHORITY_SCHEMA_PROBES: &[&str] = &[
    "SELECT id, cat_id, app, image_digest, attempt_id, phase,
            manifest_digest, service, active, error_json, created_at, updated_at
       FROM oci_deployments WHERE FALSE",
    "SELECT volume_id, record, size_bytes, durability, admin_state, delete_id,
            head_generation, head_root_hash, head_root_object_id, lease_owner,
            lease_epoch, lease_expires_at, last_transition_kind,
            last_transition_id, transition_source_kind,
            transition_operation_id, transition_request_fingerprint,
            transition_placement_epoch, transition_lease_duration_ms,
            owner_binding, owner_node_id
       FROM volume_records WHERE FALSE",
    "SELECT event_id, record, canonical_record, provider, host_partition, host_account_id,
            host_region, immutable_host_id, node_id,
            expected_node_boot_id, expected_agent_session_epoch,
            fence_attempt_id, isolation_state, observed_at, state,
            destroyed_at, provider_evidence_sha256, committed_at
       FROM host_fence_events WHERE FALSE",
    "SELECT authorization_id, record, kind, authorized_node_id,
            host_fence_event_id, volume_id,
            state, placement_epoch, lease_duration_ms,
            lifecycle_operation_id, lifecycle_request_fingerprint,
            delete_id, disk_id, cat_id, expected_attachment_id,
            expected_attachment_epoch, disposition,
            persistent_dispositions_digest, isolation_basis_kind,
            strong_stop_receipt_digest, strong_stop_agent_session_epoch,
            execution_absence_proof_digest, inventory_attestation_digest,
            interrupted_operation_id, host_lost_result_digest,
            expected_head_generation, expected_head_root_hash,
            expected_head_root_object_id,
            not_after, consumed_at
       FROM volume_authorizations WHERE FALSE",
    "SELECT delete_id, record, kind, disk_id, volume_id, authorization_id,
            prior_attachment_id, deleting_epoch, head_generation,
            head_root_hash, head_root_object_id, completed_at
       FROM delete_completion_receipts WHERE FALSE",
    "SELECT cat_id, record, workspace_id, name, cat_creation_id,
            lifecycle_head_operation_id, stable_state,
            effective_runtime_ready_operation_id, runtime_incarnation,
            current_runtime_config_id, current_runtime_config_sha256,
            created_at, deleted_at
       FROM cat_records WHERE FALSE",
    "SELECT endpoint_id, record, workspace_id, cat_id, name,
            binding_state, hostname, protocol, target_port, route_epoch,
            route_head_operation_id, effective_serving_operation_id,
            created_at, updated_at_unix_ms
       FROM endpoint_records WHERE FALSE",
    "SELECT disk_id, record, workspace_id, name, volume_id, size_bytes,
            durability, created_at, admin_state, delete_id, role_kind,
            root_cat_id, initialization_kind, initialization_token,
            filesystem_uuid, expected_blank_generation,
            expected_blank_root_hash, expected_blank_root_object_id,
            initialized_generation, initialized_root_hash,
            initialized_root_object_id, initialized_at,
            initialization_commit_receipt_bytes,
            initialization_commit_receipt_digest
       FROM disk_records WHERE FALSE",
    "SELECT snapshot_id, record, disk_id, volume_id, size_bytes,
            head_generation, head_root_hash, head_root_object_id, created_at
       FROM disk_snapshot_records WHERE FALSE",
    "SELECT config_id, workspace_id, cat_id, canonical_config_bytes,
            canonical_config_sha256, placement_vcpus,
            placement_memory_bytes, placement_network_id,
            placement_ipv4_pool_base, placement_ipv4_slot, placement_disk_ids,
            placement_volume_ids, created_at_unix_ms
       FROM cat_runtime_configs WHERE FALSE",
    "SELECT hostname, workspace_id, cat_id, endpoint_id
       FROM hostname_endpoint_lookups WHERE FALSE",
    "SELECT operation_id, workspace_id, cat_id, node_id, placement_epoch,
            command_kind, canonical_request_bytes, canonical_request_sha256,
            runtime_config_id, runtime_config_sha256,
            expected_predecessor_operation_id, predecessor_kind,
            expected_predecessor_result_kind,
            expected_predecessor_result_sha256, state, terminal_source,
            terminal_result_kind, canonical_result_bytes,
            canonical_result_sha256, created_at_unix_ms,
            terminal_at_unix_ms
       FROM runtime_operations WHERE FALSE",
    "SELECT operation_id, request_fingerprint, workspace_id, cat_id,
            node_id, placement_epoch, runtime_config_id,
            runtime_config_sha256, source_command_kind, delete_id,
            disk_id, volume_id, disk_role, receipt_kind, receipt_sequence,
            canonical_receipt_bytes, receipt_digest, created_at_unix_ms
       FROM lifecycle_volume_receipts WHERE FALSE",
    "SELECT fence_attempt_id, request_bytes, request_sha256,
            provider, host_partition, host_account_id, host_region,
            immutable_host_id, node_id, expected_node_boot_id,
            expected_agent_session_epoch, writer_authority_id,
            workload_principal_id, object_store_scope_id,
            network_quarantine_boundary_id, state, worker_id,
            claim_attempt_token, claim_duration_ms, claim_generation,
            claim_lease_expires_at_unix_ms, renew_attempt_token,
            renew_duration_ms, renew_generation, renewed_from_unix_ms,
            renewed_to_unix_ms, evidence_bytes, evidence_sha256,
            enqueued_at_unix_ms, completed_at_unix_ms
       FROM host_fence_provider_queue_v1 WHERE FALSE",
    "SELECT authenticated_workspace_id, canonical_route, idempotency_key,
            request_fingerprint, http_status, content_type, response_body,
            created_at
       FROM api_idempotency_results WHERE FALSE",
    "SELECT command_id, command, request_sha256, principal, principal_kind,
            operator_credential_id, operator_public_key_spki_sha256,
            operator_trust_bundle_sha256, operator_aws_partition,
            operator_account_id, operator_role_arn, operator_principal_arn,
            issued_at_unix_ms, expires_at_unix_ms, expected_revision,
            mutation_kind, target_mode, binding_kind, binding_sha256,
            qualification_id, reset_id, deployment_id, release_id,
            source_commit_sha, control_schema_version, source_manifest_sha256,
            source_bundle_sha256, build_receipt_sha256,
            release_manifest_sha256, worker_bundle_sha256,
            qualification_manifest_sha256, qualification_catalog_sha256,
            proof_set_sha256, fresh_targets_sha256,
            reset_complete_receipt_sha256, fleet_closed_receipt_sha256,
            route_v2_rotation_qualification_receipt_sha256,
            route_v2_rotation_qualification_node_ack_sets_sha256,
            route_v2_rotation_qualification_transcript_sha256,
            usage_terminal_receipt_sha256, old_host_coverage_sha256,
            kernel_nbd_qualification_bundle_sha256,
            vhost_user_qualification_bundle_sha256,
            qualification_cell_manifest_sha256,
            qualification_aws_partition, qualification_aws_account_id,
            qualification_aws_region, qualification_cell_id,
            qualification_cell_namespace, qualification_cats_account_id,
            qualification_workspace_id, qualification_mutation_classes,
            qualification_expires_at_unix_ms, outcome, outcome_kind,
            resulting_revision, resulting_mode, committed_at_unix_ms
       FROM production_mutation_admission_commands WHERE FALSE",
    "SELECT singleton, revision, mode, binding, binding_sha256, binding_kind,
            qualification_id, reset_id, deployment_id, release_id,
            source_commit_sha, control_schema_version, source_manifest_sha256,
            source_bundle_sha256, build_receipt_sha256,
            release_manifest_sha256, worker_bundle_sha256,
            qualification_manifest_sha256, qualification_catalog_sha256,
            proof_set_sha256, fresh_targets_sha256,
            reset_complete_receipt_sha256, fleet_closed_receipt_sha256,
            route_v2_rotation_qualification_receipt_sha256,
            route_v2_rotation_qualification_node_ack_sets_sha256,
            route_v2_rotation_qualification_transcript_sha256,
            usage_terminal_receipt_sha256, old_host_coverage_sha256,
            kernel_nbd_qualification_bundle_sha256,
            vhost_user_qualification_bundle_sha256,
            qualification_cell_manifest_sha256,
            qualification_aws_partition, qualification_aws_account_id,
            qualification_aws_region, qualification_cell_id,
            qualification_cell_namespace, qualification_cats_account_id,
            qualification_workspace_id, qualification_mutation_classes,
            qualification_expires_at_unix_ms, last_command_id,
            updated_at_unix_ms
       FROM production_mutation_admission WHERE FALSE",
    "SELECT node_id, record, host_provider, host_partition, host_account_id,
            host_region, immutable_host_id, credential_id,
            credential_kind, credential_public_key_spki_sha256,
            credential_provider, credential_principal,
            credential_lineage_state, state_path_id, state
       FROM node_identities WHERE FALSE",
    "SELECT operation_id, workspace_id, cat_id, endpoint_id,
            operation_kind, canonical_request_bytes,
            canonical_request_sha256, expected_predecessor_operation_id,
            expected_predecessor_result_kind,
            expected_predecessor_result_sha256, hostname, protocol,
            target_port, route_epoch, source_lifecycle_operation_id,
            runtime_incarnation, node_id, placement_epoch, node_boot_id,
            agent_instance_id, admission_session_epoch, state,
            terminal_source, terminal_result_kind, canonical_result_bytes,
            canonical_result_sha256, created_at_unix_ms,
            terminal_at_unix_ms
       FROM route_operations WHERE FALSE",
    "SELECT node_id, registration_attempt_id, attempt_record,
            immutable_host_id, node_boot_id, agent_instance_id,
            guest_config_digest, expected_agent_session_epoch,
            session_record, agent_session_epoch, lease_deadline_unix_ms
       FROM agent_registration_attempts WHERE FALSE",
    "SELECT node_id, record, immutable_host_id, node_boot_id,
            agent_instance_id, agent_session_epoch, registration_attempt_id,
            guest_config_digest, lease_deadline_unix_ms
       FROM current_agent_sessions WHERE FALSE",
    "SELECT node_id, canonical_ack_bytes, canonical_ack_sha256, ack_id,
            ack_sequence, node_boot_id, agent_instance_id,
            admission_session_epoch, ring_version, key_ring_digest,
            loaded_kids, accepted_at_unix_ms
       FROM route_node_ring_acks WHERE FALSE",
    "SELECT node_id, report, acceptance, node_boot_id,
            agent_instance_id, agent_session_epoch, report_sequence,
            report_id, accepted_at_unix_ms
       FROM runtime_inventory_receive_states WHERE FALSE",
    "SELECT node_id, attestation, full_report,
            node_boot_id, agent_instance_id, agent_session_epoch,
            inventory_epoch, scan_id, inventory_digest, source_report_id,
            source_sequence, accepted_at_unix_ms
       FROM runtime_full_inventory_attestations WHERE FALSE",
    "SELECT node_id, cat_id, telemetry_record, node_boot_id,
            agent_instance_id, agent_session_epoch, inventory_epoch,
            source_report_id, report_sequence, accepted_at_unix_ms,
            source_kind
       FROM runtime_current_cat_telemetry WHERE FALSE",
    "SELECT node_id, record, policy_revision, scheduling_state,
            allocatable_vcpus, allocatable_memory_bytes,
            guest_config_digest, block_frontend, guest_ipv4_network_address,
            node_transport_target
       FROM runtime_node_placement_policies WHERE FALSE",
    "SELECT apply_id, request, request_sha256, principal, principal_kind,
            node_id, outcome, outcome_kind, committed_at_unix_ms
       FROM runtime_node_authority_apply_records WHERE FALSE",
    "SELECT credential_id, node_id, public_key_spki_sha256, state,
            first_committed_at_unix_ms, retired_at_unix_ms
       FROM runtime_node_credential_lineage WHERE FALSE",
    "SELECT singleton, deployment_id, current_trust_revision,
            current_active_set_sha256, first_committed_at_unix_ms
       FROM runtime_provisioner_deployment_identity WHERE FALSE",
    "SELECT deployment_id, trust_revision, active_set_sha256,
            expected_previous_trust_revision,
            expected_previous_active_set_sha256, committed_at_unix_ms
       FROM runtime_provisioner_trust_revisions WHERE FALSE",
    "SELECT credential_id, deployment_id, public_key_spki,
            public_key_spki_sha256, state, first_committed_at_unix_ms,
            retired_at_unix_ms
       FROM runtime_provisioner_credential_lineage WHERE FALSE",
    "SELECT writer_authority_id, record, host_provider, host_partition,
            host_account_id, host_region, immutable_host_id, node_id,
            object_provider, object_partition, object_account_id,
            object_region, workload_principal_id, object_store_scope_id,
            state, max_accepted_sequence, terminal_prefix_sequence,
            terminal_prefix_sha256, fence_attempt_id,
            cutoff_effective_at_unix_ms, cutoff_sequence, cutoff_receipt
       FROM object_write_authorities WHERE FALSE",
    "SELECT credential_id, record, public_key_spki,
            public_key_spki_sha256, writer_authority_id, host_provider,
            host_partition, host_account_id, host_region,
            immutable_host_id, node_id, node_boot_id, agent_instance_id,
            agent_session_epoch, volume_id, attachment_id,
            attachment_epoch, private_artifact_id,
            private_file_fsync_receipt_id,
            private_directory_fsync_receipt_id, registered_at_unix_ms,
            state, retirement_kind, retirement_transition_id,
            retirement_receipt_id, retired_at_unix_ms
       FROM object_write_credentials WHERE FALSE",
    "SELECT request_id, record, writer_authority_id, credential_id,
            volume_id, key_kind, object_provider, object_partition,
            object_account_id, object_region, object_store_scope_id,
            object_key, content_sha256, content_length,
            receiving_started_at_unix_ms, state, spool_id,
            spool_file_fsync_receipt_id, spool_directory_fsync_receipt_id,
            spool_durable_at_unix_ms, rejection_kind,
            rejection_receipt_id, rejected_at_unix_ms,
            accepted_sequence, accepted_at_unix_ms, provider_attempt_id,
            provider_issued_at_unix_ms, qualification_request_canonical,
            qualification_authorization_canonical,
            qualification_successful_put_canonical,
            qualification_response_loss_canonical,
            qualification_response_lost_attempt_canonical,
            qualification_response_loss_sha256,
            qualification_injection_receipt_id,
            qualification_injected_at_unix_ms,
            qualification_visibility_head_canonical,
            qualification_unproven_intent_canonical,
            qualification_unproven_sealed_request_canonical,
            qualification_unproven_receipt_canonical,
            qualification_unproven_attempt_canonical,
            qualification_unproven_resolution_receipt_id,
            terminal_kind, put_receipt_id,
            put_completed_at_unix_ms, visibility_receipt_id,
            visible_at_unix_ms, failure_receipt_id, failed_at_unix_ms,
            qualification_unproven_reason,
            qualification_head_evidence_canonical,
            qualification_unproven_at_unix_ms,
            spool_removal_receipt_id, spool_removed_at_unix_ms
       FROM object_write_attempts WHERE FALSE",
    "SELECT singleton, deployment_id, current_signer_revision,
            current_signer_reference_sha256, signer_state, active_kid,
            public_key_ring_version, public_key_ring_digest,
            secret_reference_id, first_committed_at_unix_ms
       FROM route_v2_signing_authority WHERE FALSE",
    "SELECT deployment_id, signer_revision, signer_reference_sha256,
            signer_reference_bytes, expected_previous_signer_revision,
            expected_previous_signer_reference_sha256, signer_state,
            active_kid, public_key_ring_version, public_key_ring_digest,
            secret_reference_id, committed_at_unix_ms
       FROM route_v2_signer_revisions WHERE FALSE",
    "SELECT kid, deployment_id, public_key_spki, secret_reference_id,
            first_signer_revision, state, first_committed_at_unix_ms,
            retired_at_unix_ms
       FROM route_v2_signer_key_lineage WHERE FALSE",
    "SELECT deployment_id, ring_version, key_ring_digest, exact_bytes,
            expected_previous_ring_version, expected_previous_key_ring_digest,
            published_at_unix_ms
       FROM route_v2_public_key_ring_revisions WHERE FALSE",
    "SELECT deployment_id, kid, secret_reference_id,
            retirement_signer_revision, last_old_issue_at_unix_ms,
            source, state, ring_removed_version, retired_signer_revision,
            retired_at_unix_ms
       FROM route_v2_signer_retirements WHERE FALSE",
    "SELECT singleton, authority_id, route_deployment_id,
            release_commit_sha, trust_sha256, threshold, trust_bytes,
            first_committed_at_unix_ms
       FROM route_v2_rotation_operator_authority WHERE FALSE",
    "SELECT credential_id, authority_id, credential_ordinal,
            public_key_spki, public_key_spki_sha256,
            first_committed_at_unix_ms
       FROM route_v2_rotation_operator_credentials WHERE FALSE",
    "SELECT authority_id, command_id, release_commit_sha,
            credential_set_sha256, exact_command_sha256,
            exact_command_bytes, command_kind, target_deployment_id,
            expected_signer_revision, expected_signer_reference_sha256,
            terminal_outcome, resulting_signer_revision,
            resulting_ring_version, exact_result_bytes,
            committed_at_unix_ms
       FROM route_v2_signing_command_receipts WHERE FALSE",
    "SELECT deployment_id, ring_version, key_ring_digest,
            expected_previous_ring_version,
            expected_previous_key_ring_digest, source_authority_id,
            source_command_id, source_release_commit_sha,
            exact_signed_envelope_sha256, exact_signed_envelope_bytes,
            committed_at_unix_ms
       FROM route_v2_public_ring_deliveries WHERE FALSE",
    "SELECT singleton, authority_id, fleet_id, current_policy_revision,
            current_policy_sha256, first_committed_at_unix_ms
       FROM route_v2_gateway_identity_authority WHERE FALSE",
    "SELECT authority_id, fleet_id, policy_revision, policy_sha256,
            policy_bytes, expected_previous_policy_revision,
            expected_previous_policy_sha256, committed_at_unix_ms
       FROM route_v2_gateway_identity_revisions WHERE FALSE",
    "SELECT credential_id, authority_id, public_key_spki,
            public_key_spki_sha256, state, first_policy_revision,
            first_committed_at_unix_ms,
            revoked_at_unix_ms
       FROM route_v2_gateway_credential_lineage WHERE FALSE",
    "SELECT credential_id, authority_id, fleet_id, policy_revision,
            policy_sha256, public_key_spki_sha256, scope, lineage_state
       FROM route_v2_gateway_current_credentials WHERE FALSE",
];

const HOST_FENCE_PROVIDER_FUNCTIONS: &str = r#"
-- A PostgreSQL role cannot be denied a privilege inherited through PUBLIC.
-- Remove that default from the release schema before granting the provider's
-- exact six-function surface in the deployment role script. Schema owners
-- retain implicit authority; trigger invocation does not require EXECUTE.
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA __CATS_SCHEMA_IDENT__ FROM PUBLIC;

-- This deferred parent/child invariant is reached by the provider's
-- SECURITY DEFINER cutoff function. It therefore needs the same fixed owner
-- and schema-safe lookup context; the provider role still receives no direct
-- privilege on either object-write table.
ALTER FUNCTION __CATS_SCHEMA_IDENT__.object_write_credential_parent_guard()
    SECURITY DEFINER;
ALTER FUNCTION __CATS_SCHEMA_IDENT__.object_write_credential_parent_guard()
    SET search_path = __CATS_SCHEMA_IDENT__, pg_catalog, pg_temp;
REVOKE ALL ON FUNCTION
    __CATS_SCHEMA_IDENT__.object_write_credential_parent_guard() FROM PUBLIC;

CREATE OR REPLACE FUNCTION __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(value BYTEA)
RETURNS BYTEA
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT pg_catalog.int8send(pg_catalog.octet_length(value)::BIGINT) || value
$function$;
REVOKE ALL ON FUNCTION
    __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(BYTEA) FROM PUBLIC;

CREATE OR REPLACE FUNCTION __CATS_SCHEMA_IDENT__.control_host_fence_provider_startup_v1()
RETURNS TABLE(protocol_version BIGINT, schema_name TEXT, expected_role TEXT)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF session_user::TEXT IS DISTINCT FROM 'cats_host_fence_provider' THEN
        RAISE EXCEPTION 'Host-fence provider PostgreSQL role mismatch'
            USING ERRCODE = '42501';
    END IF;
    RETURN QUERY SELECT 1::BIGINT, __CATS_SCHEMA_LITERAL__::TEXT,
        'cats_host_fence_provider'::TEXT;
END;
$function$;
REVOKE ALL ON FUNCTION
    __CATS_SCHEMA_IDENT__.control_host_fence_provider_startup_v1() FROM PUBLIC;

CREATE OR REPLACE FUNCTION __CATS_SCHEMA_IDENT__.control_host_fence_provider_claim_v1(
    expected_provider TEXT,
    expected_partition TEXT,
    expected_account_id TEXT,
    expected_region TEXT,
    requested_worker_id TEXT,
    requested_claim_attempt_token TEXT,
    requested_lease_duration_ms BIGINT
)
RETURNS TABLE(
    request_bytes BYTEA,
    request_sha256 TEXT,
    worker_id TEXT,
    claim_attempt_token TEXT,
    claim_generation BIGINT,
    claim_lease_expires_at_unix_ms BIGINT
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    now_ms BIGINT;
BEGIN
    IF session_user::TEXT IS DISTINCT FROM 'cats_host_fence_provider' THEN
        RAISE EXCEPTION 'Host-fence provider PostgreSQL role mismatch'
            USING ERRCODE = '42501';
    END IF;
    IF requested_lease_duration_ms NOT BETWEEN 1 AND 60000
       OR requested_claim_attempt_token !~ '^[0-9a-f]{32}$'
       OR requested_worker_id !~ '^[A-Za-z0-9._:-]{1,128}$' THEN
        RAISE EXCEPTION 'invalid Host-fence provider claim'
            USING ERRCODE = '22023';
    END IF;
    -- Lost-response replay of the still-current claim never leases a second
    -- row or extends the original DB-time deadline.
    RETURN QUERY
        SELECT queue.request_bytes, queue.request_sha256, queue.worker_id,
               queue.claim_attempt_token, queue.claim_generation,
               queue.claim_lease_expires_at_unix_ms
          FROM __CATS_SCHEMA_IDENT__.host_fence_provider_queue_v1 queue
         WHERE queue.provider = expected_provider
           AND queue.host_partition = expected_partition
           AND queue.host_account_id = expected_account_id
           AND queue.host_region = expected_region
           AND queue.state = 'claimed'
           AND queue.worker_id = requested_worker_id
           AND queue.claim_attempt_token = requested_claim_attempt_token
           AND queue.claim_duration_ms = requested_lease_duration_ms
           AND queue.claim_lease_expires_at_unix_ms > floor(
               extract(epoch FROM pg_catalog.clock_timestamp()) * 1000
           )::BIGINT
         FOR UPDATE;
    IF FOUND THEN
        RETURN;
    END IF;
    IF EXISTS (
        SELECT 1
          FROM __CATS_SCHEMA_IDENT__.host_fence_provider_queue_v1 queue
         WHERE queue.claim_attempt_token = requested_claim_attempt_token
    ) THEN
        RAISE EXCEPTION 'Host-fence provider claim replay is stale or changed'
            USING ERRCODE = '55000';
    END IF;

    now_ms := floor(
        extract(epoch FROM pg_catalog.clock_timestamp()) * 1000
    )::BIGINT;
    IF now_ms > 9223372036854775807 - requested_lease_duration_ms THEN
        RAISE EXCEPTION 'Host-fence provider lease overflow'
            USING ERRCODE = '22003';
    END IF;

    RETURN QUERY
        WITH candidate AS (
            SELECT queue.fence_attempt_id
              FROM __CATS_SCHEMA_IDENT__.host_fence_provider_queue_v1 queue
             WHERE queue.provider = expected_provider
               AND queue.host_partition = expected_partition
               AND queue.host_account_id = expected_account_id
               AND queue.host_region = expected_region
               AND (queue.state = 'pending' OR
                    (queue.state = 'claimed' AND
                     queue.claim_lease_expires_at_unix_ms <= now_ms))
             ORDER BY queue.enqueued_at_unix_ms,
                      queue.fence_attempt_id COLLATE "C"
             FOR UPDATE SKIP LOCKED
             LIMIT 1
        )
        UPDATE __CATS_SCHEMA_IDENT__.host_fence_provider_queue_v1 queue
           SET state = 'claimed',
               worker_id = requested_worker_id,
               claim_attempt_token = requested_claim_attempt_token,
               claim_duration_ms = requested_lease_duration_ms,
               claim_generation = queue.claim_generation + 1,
               claim_lease_expires_at_unix_ms =
                   now_ms + requested_lease_duration_ms,
               renew_attempt_token = NULL,
               renew_duration_ms = NULL,
               renew_generation = 0,
               renewed_from_unix_ms = NULL,
               renewed_to_unix_ms = NULL
          FROM candidate
         WHERE queue.fence_attempt_id = candidate.fence_attempt_id
        RETURNING queue.request_bytes, queue.request_sha256, queue.worker_id,
                  queue.claim_attempt_token, queue.claim_generation,
                  queue.claim_lease_expires_at_unix_ms;
END;
$function$;
REVOKE ALL ON FUNCTION
    __CATS_SCHEMA_IDENT__.control_host_fence_provider_claim_v1(
        TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT
    ) FROM PUBLIC;

CREATE OR REPLACE FUNCTION __CATS_SCHEMA_IDENT__.control_host_fence_provider_renew_v1(
    requested_fence_attempt_id TEXT,
    requested_claim_attempt_token TEXT,
    requested_renew_attempt_token TEXT,
    requested_lease_duration_ms BIGINT
)
RETURNS BIGINT
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    now_ms BIGINT;
    existing_expiry BIGINT;
    resulting_expiry BIGINT;
BEGIN
    IF session_user::TEXT IS DISTINCT FROM 'cats_host_fence_provider' THEN
        RAISE EXCEPTION 'Host-fence provider PostgreSQL role mismatch'
            USING ERRCODE = '42501';
    END IF;
    IF requested_lease_duration_ms NOT BETWEEN 1 AND 60000
       OR requested_claim_attempt_token !~ '^[0-9a-f]{32}$'
       OR requested_renew_attempt_token !~ '^[0-9a-f]{32}$' THEN
        RAISE EXCEPTION 'invalid Host-fence provider renewal'
            USING ERRCODE = '22023';
    END IF;
    SELECT queue.claim_lease_expires_at_unix_ms
      INTO existing_expiry
      FROM __CATS_SCHEMA_IDENT__.host_fence_provider_queue_v1 queue
     WHERE queue.fence_attempt_id = requested_fence_attempt_id
       AND queue.state = 'claimed'
       AND queue.claim_attempt_token = requested_claim_attempt_token
       AND queue.renew_attempt_token = requested_renew_attempt_token
       AND queue.renew_duration_ms = requested_lease_duration_ms
     FOR UPDATE;
    IF FOUND THEN
        RETURN existing_expiry;
    END IF;

    now_ms := floor(
        extract(epoch FROM pg_catalog.clock_timestamp()) * 1000
    )::BIGINT;
    IF now_ms > 9223372036854775807 - requested_lease_duration_ms THEN
        RAISE EXCEPTION 'Host-fence provider lease overflow'
            USING ERRCODE = '22003';
    END IF;
    resulting_expiry := now_ms + requested_lease_duration_ms;
    UPDATE __CATS_SCHEMA_IDENT__.host_fence_provider_queue_v1 queue
       SET claim_lease_expires_at_unix_ms = resulting_expiry,
           renew_attempt_token = requested_renew_attempt_token,
           renew_duration_ms = requested_lease_duration_ms,
           renew_generation = queue.renew_generation + 1,
           renewed_from_unix_ms = now_ms,
           renewed_to_unix_ms = resulting_expiry
     WHERE queue.fence_attempt_id = requested_fence_attempt_id
       AND queue.state = 'claimed'
       AND queue.claim_attempt_token = requested_claim_attempt_token
       AND queue.claim_lease_expires_at_unix_ms > now_ms
       AND resulting_expiry > queue.claim_lease_expires_at_unix_ms
    RETURNING queue.claim_lease_expires_at_unix_ms INTO existing_expiry;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Host-fence provider claim is stale or expired'
            USING ERRCODE = '55000';
    END IF;
    RETURN existing_expiry;
END;
$function$;
REVOKE ALL ON FUNCTION
    __CATS_SCHEMA_IDENT__.control_host_fence_provider_renew_v1(
        TEXT,TEXT,TEXT,BIGINT
    ) FROM PUBLIC;

CREATE OR REPLACE FUNCTION __CATS_SCHEMA_IDENT__.control_host_fence_provider_read_v1(
    requested_fence_attempt_id TEXT,
    requested_claim_attempt_token TEXT
)
RETURNS TABLE(
    request_bytes BYTEA,
    request_sha256 TEXT,
    enqueued_at_unix_ms BIGINT,
    state TEXT,
    worker_id TEXT,
    claim_attempt_token TEXT,
    claim_generation BIGINT,
    claim_lease_expires_at_unix_ms BIGINT,
    evidence_bytes BYTEA,
    evidence_sha256 TEXT,
    completed_at_unix_ms BIGINT
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF session_user::TEXT IS DISTINCT FROM 'cats_host_fence_provider' THEN
        RAISE EXCEPTION 'Host-fence provider PostgreSQL role mismatch'
            USING ERRCODE = '42501';
    END IF;
    RETURN QUERY
        SELECT queue.request_bytes, queue.request_sha256,
               queue.enqueued_at_unix_ms, queue.state, queue.worker_id,
               queue.claim_attempt_token, queue.claim_generation,
               queue.claim_lease_expires_at_unix_ms, queue.evidence_bytes,
               queue.evidence_sha256, queue.completed_at_unix_ms
          FROM __CATS_SCHEMA_IDENT__.host_fence_provider_queue_v1 queue
         WHERE queue.fence_attempt_id = requested_fence_attempt_id
           AND queue.state IN ('claimed', 'terminal')
           AND queue.claim_attempt_token = requested_claim_attempt_token;
END;
$function$;
REVOKE ALL ON FUNCTION
    __CATS_SCHEMA_IDENT__.control_host_fence_provider_read_v1(TEXT,TEXT) FROM PUBLIC;

CREATE OR REPLACE FUNCTION __CATS_SCHEMA_IDENT__.control_host_fence_provider_object_cutoff_v1(
    requested_fence_attempt_id TEXT,
    requested_claim_attempt_token TEXT
)
RETURNS TABLE(result_kind TEXT, cutoff_receipt JSONB)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    now_ms BIGINT;
    queue_row RECORD;
    authority_row RECORD;
    attempt_row RECORD;
    expected_sequence BIGINT;
    prefix_sequence BIGINT;
    prefix_sha256 TEXT;
    authorization_sha256 TEXT;
    ambiguity_sha256 TEXT;
    ambiguity_canonical BYTEA;
    hash_input BYTEA;
    receipt JSONB;
    cutoff_receipt_id TEXT;
    terminal_receipt_id TEXT;
    visibility_receipt_id TEXT;
BEGIN
    IF session_user::TEXT IS DISTINCT FROM 'cats_host_fence_provider' THEN
        RAISE EXCEPTION 'Host-fence provider PostgreSQL role mismatch'
            USING ERRCODE = '42501';
    END IF;
    now_ms := floor(
        extract(epoch FROM pg_catalog.clock_timestamp()) * 1000
    )::BIGINT;
    SELECT queue.writer_authority_id, queue.provider, queue.host_partition,
           queue.host_account_id, queue.host_region, queue.immutable_host_id,
           queue.node_id, queue.workload_principal_id,
           queue.object_store_scope_id,
           queue.claim_lease_expires_at_unix_ms
      INTO queue_row
      FROM __CATS_SCHEMA_IDENT__.host_fence_provider_queue_v1 queue
     WHERE queue.fence_attempt_id = requested_fence_attempt_id
       AND queue.state = 'claimed'
       AND queue.claim_attempt_token = requested_claim_attempt_token
       AND queue.claim_lease_expires_at_unix_ms > now_ms
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Host-fence provider claim is stale or expired'
            USING ERRCODE = '55000';
    END IF;

    SELECT authority.record, authority.state, authority.writer_authority_id,
           authority.host_provider, authority.host_partition,
           authority.host_account_id, authority.host_region,
           authority.immutable_host_id, authority.node_id,
           authority.workload_principal_id, authority.object_store_scope_id,
           authority.fence_attempt_id, authority.cutoff_effective_at_unix_ms,
           authority.cutoff_sequence, authority.max_accepted_sequence,
           authority.terminal_prefix_sequence,
           authority.terminal_prefix_sha256, authority.cutoff_receipt
      INTO authority_row
      FROM __CATS_SCHEMA_IDENT__.object_write_authorities authority
     WHERE authority.writer_authority_id = queue_row.writer_authority_id
     FOR UPDATE;
    IF NOT FOUND OR
       (authority_row.host_provider, authority_row.host_partition,
        authority_row.host_account_id, authority_row.host_region,
        authority_row.immutable_host_id, authority_row.node_id,
        authority_row.workload_principal_id,
        authority_row.object_store_scope_id,
        authority_row.fence_attempt_id)
       IS DISTINCT FROM
       (queue_row.provider, queue_row.host_partition,
        queue_row.host_account_id, queue_row.host_region,
        queue_row.immutable_host_id, queue_row.node_id,
        queue_row.workload_principal_id, queue_row.object_store_scope_id,
        requested_fence_attempt_id) THEN
        RAISE EXCEPTION 'Host-fence queue/object-writer binding mismatch'
            USING ERRCODE = '55000';
    END IF;
    now_ms := floor(
        extract(epoch FROM pg_catalog.clock_timestamp()) * 1000
    )::BIGINT;
    IF queue_row.claim_lease_expires_at_unix_ms <= now_ms THEN
        RAISE EXCEPTION 'Host-fence provider claim expired during object cutoff'
            USING ERRCODE = '55000';
    END IF;
    IF authority_row.state = 'cutoff_complete' THEN
        RETURN QUERY SELECT 'complete'::TEXT, authority_row.cutoff_receipt;
        RETURN;
    END IF;
    IF authority_row.state <> 'cutoff_pending'
       OR authority_row.cutoff_sequence <> authority_row.max_accepted_sequence THEN
        RAISE EXCEPTION 'object-writer cutoff is not pending for this attempt'
            USING ERRCODE = '55000';
    END IF;

    prefix_sequence := authority_row.terminal_prefix_sequence;
    prefix_sha256 := authority_row.terminal_prefix_sha256;
    expected_sequence := prefix_sequence + 1;
    FOR attempt_row IN
        SELECT attempt.accepted_sequence, attempt.request_id,
               attempt.object_key, attempt.content_sha256,
               attempt.content_length, attempt.terminal_kind,
               attempt.put_receipt_id, attempt.put_completed_at_unix_ms,
               attempt.visibility_receipt_id, attempt.visible_at_unix_ms,
               attempt.failure_receipt_id, attempt.failed_at_unix_ms,
               attempt.qualification_authorization_canonical,
               attempt.qualification_response_loss_canonical,
               attempt.qualification_injection_receipt_id,
               attempt.qualification_visibility_head_canonical,
               attempt.qualification_unproven_reason,
               attempt.qualification_head_evidence_canonical,
               attempt.qualification_unproven_receipt_canonical,
               attempt.record
          FROM __CATS_SCHEMA_IDENT__.object_write_attempts attempt
         WHERE attempt.writer_authority_id = queue_row.writer_authority_id
           AND attempt.accepted_sequence > prefix_sequence
           AND attempt.accepted_sequence <= authority_row.cutoff_sequence
           AND attempt.state IN (
               'terminal_visible', 'permanent',
               'qualification_unproven_visible', 'spool_removed'
           )
         ORDER BY attempt.accepted_sequence
         LIMIT 256
    LOOP
        IF attempt_row.accepted_sequence <> expected_sequence THEN
            EXIT;
        END IF;
        hash_input :=
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.convert_to('cats.object-write-terminal-prefix.v1', 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.convert_to(prefix_sha256, 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.int8send(attempt_row.accepted_sequence)) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.convert_to(attempt_row.request_id, 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.convert_to(attempt_row.object_key, 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.convert_to(attempt_row.content_sha256, 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.int8send(attempt_row.content_length));
        IF attempt_row.terminal_kind = 'succeeded_visible' THEN
            hash_input := hash_input ||
                __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                    pg_catalog.convert_to('succeeded-visible', 'UTF8')) ||
                __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                    pg_catalog.convert_to(attempt_row.put_receipt_id, 'UTF8')) ||
                __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                    pg_catalog.int8send(attempt_row.put_completed_at_unix_ms)) ||
                __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                    pg_catalog.convert_to(attempt_row.visibility_receipt_id, 'UTF8')) ||
                __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                    pg_catalog.int8send(attempt_row.visible_at_unix_ms));
            IF attempt_row.record #> '{state,outcome,qualification_ambiguity}'
                    IS DISTINCT FROM 'null'::JSONB THEN
                authorization_sha256 := 'sha256:' || pg_catalog.encode(
                    pg_catalog.sha256(
                        __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                            pg_catalog.convert_to(
                                'cats.object-write-qualification-authorization.v1', 'UTF8')) ||
                        __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                            attempt_row.qualification_authorization_canonical)
                    ), 'hex');
                ambiguity_canonical := pg_catalog.convert_to(
                    '{"version":1,"response_loss":' || pg_catalog.convert_from(
                        attempt_row.qualification_response_loss_canonical, 'UTF8') ||
                    ',"head":' || pg_catalog.convert_from(
                        attempt_row.qualification_visibility_head_canonical, 'UTF8') || '}',
                    'UTF8');
                ambiguity_sha256 := 'sha256:' || pg_catalog.encode(
                    pg_catalog.sha256(ambiguity_canonical), 'hex');
                hash_input := hash_input ||
                    __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                        pg_catalog.convert_to('qualification-ambiguity', 'UTF8')) ||
                    __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                        pg_catalog.convert_to(authorization_sha256, 'UTF8')) ||
                    __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                        pg_catalog.convert_to(
                            attempt_row.qualification_injection_receipt_id, 'UTF8')) ||
                    __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                        pg_catalog.convert_to(ambiguity_sha256, 'UTF8'));
            END IF;
        ELSIF attempt_row.terminal_kind = 'permanently_failed' THEN
            hash_input := hash_input ||
                __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                    pg_catalog.convert_to('permanently-failed', 'UTF8')) ||
                __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                    pg_catalog.convert_to(attempt_row.failure_receipt_id, 'UTF8')) ||
                __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                    pg_catalog.int8send(attempt_row.failed_at_unix_ms));
        ELSIF attempt_row.terminal_kind = 'qualification_unproven_visible' THEN
            IF attempt_row.qualification_unproven_reason
                    IS DISTINCT FROM 'response_loss_receipt_absent' THEN
                RAISE EXCEPTION 'unproven object-write projection is invalid'
                    USING ERRCODE = '55000';
            END IF;
            hash_input := hash_input ||
                __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                    pg_catalog.convert_to('qualification-unproven-visible', 'UTF8')) ||
                __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                    attempt_row.qualification_unproven_receipt_canonical);
        ELSE
            RAISE EXCEPTION 'terminal object-write projection is invalid'
                USING ERRCODE = '55000';
        END IF;
        prefix_sha256 := 'sha256:' ||
            pg_catalog.encode(pg_catalog.sha256(hash_input), 'hex');
        prefix_sequence := attempt_row.accepted_sequence;
        expected_sequence := prefix_sequence + 1;
    END LOOP;

    now_ms := floor(
        extract(epoch FROM pg_catalog.clock_timestamp()) * 1000
    )::BIGINT;
    IF queue_row.claim_lease_expires_at_unix_ms <= now_ms THEN
        RAISE EXCEPTION 'Host-fence provider claim expired during object cutoff'
            USING ERRCODE = '55000';
    END IF;

    authority_row.record := pg_catalog.jsonb_set(
        pg_catalog.jsonb_set(
            authority_row.record,
            '{terminal_prefix_sequence}', pg_catalog.to_jsonb(prefix_sequence), FALSE
        ),
        '{terminal_prefix_sha256}', pg_catalog.to_jsonb(prefix_sha256), FALSE
    );
    IF prefix_sequence = authority_row.cutoff_sequence THEN
        hash_input :=
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.convert_to('cats.object-write-barrier-receipt.v1', 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.convert_to('cutoff', 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.convert_to(authority_row.writer_authority_id, 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.convert_to(requested_fence_attempt_id, 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.int8send(authority_row.cutoff_effective_at_unix_ms)) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.int8send(authority_row.cutoff_sequence)) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.convert_to(prefix_sha256, 'UTF8'));
        cutoff_receipt_id := 'owcut1_' ||
            pg_catalog.encode(pg_catalog.sha256(hash_input), 'hex');
        hash_input :=
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.convert_to('cats.object-write-barrier-receipt.v1', 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.convert_to('terminal-prefix', 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.convert_to(authority_row.writer_authority_id, 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.convert_to(requested_fence_attempt_id, 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.int8send(authority_row.cutoff_effective_at_unix_ms)) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.int8send(authority_row.cutoff_sequence)) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.convert_to(prefix_sha256, 'UTF8'));
        terminal_receipt_id := 'owterm1_' ||
            pg_catalog.encode(pg_catalog.sha256(hash_input), 'hex');
        hash_input :=
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.convert_to('cats.object-write-barrier-receipt.v1', 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.convert_to('successful-visible', 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.convert_to(authority_row.writer_authority_id, 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.convert_to(requested_fence_attempt_id, 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.int8send(authority_row.cutoff_effective_at_unix_ms)) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.int8send(authority_row.cutoff_sequence)) ||
            __CATS_SCHEMA_IDENT__.control_host_fence_provider_frame_v1(
                pg_catalog.convert_to(prefix_sha256, 'UTF8'));
        visibility_receipt_id := 'owvis1_' ||
            pg_catalog.encode(pg_catalog.sha256(hash_input), 'hex');
        receipt := pg_catalog.jsonb_build_object(
            'writer_authority_id', authority_row.writer_authority_id,
            'fence_attempt_id', requested_fence_attempt_id,
            'cutoff_receipt_id', cutoff_receipt_id,
            'cutoff_effective_at_unix_ms', authority_row.cutoff_effective_at_unix_ms,
            'cutoff_sequence', authority_row.cutoff_sequence,
            'accepted_put_terminal_receipt_id', terminal_receipt_id,
            'accepted_puts_terminal_at_unix_ms', now_ms,
            'terminal_sequence', prefix_sequence,
            'terminal_prefix_sha256', prefix_sha256,
            'successful_put_visibility_receipt_id', visibility_receipt_id,
            'successful_puts_visible_at_unix_ms', now_ms
        );
        authority_row.record := pg_catalog.jsonb_set(
            authority_row.record, '{state}',
            pg_catalog.jsonb_build_object(
                'kind', 'cutoff_complete', 'receipt', receipt
            ), FALSE
        );
        UPDATE __CATS_SCHEMA_IDENT__.object_write_authorities authority
           SET record = authority_row.record,
               state = 'cutoff_complete',
               terminal_prefix_sequence = prefix_sequence,
               terminal_prefix_sha256 = prefix_sha256,
               cutoff_receipt = receipt
         WHERE authority.writer_authority_id = authority_row.writer_authority_id;
        RETURN QUERY SELECT 'complete'::TEXT, receipt;
    ELSE
        UPDATE __CATS_SCHEMA_IDENT__.object_write_authorities authority
           SET record = authority_row.record,
               terminal_prefix_sequence = prefix_sequence,
               terminal_prefix_sha256 = prefix_sha256
         WHERE authority.writer_authority_id = authority_row.writer_authority_id;
        RETURN QUERY SELECT 'pending'::TEXT, NULL::JSONB;
    END IF;
END;
$function$;
REVOKE ALL ON FUNCTION
    __CATS_SCHEMA_IDENT__.control_host_fence_provider_object_cutoff_v1(TEXT,TEXT)
    FROM PUBLIC;

CREATE OR REPLACE FUNCTION __CATS_SCHEMA_IDENT__.control_host_fence_provider_complete_v1(
    requested_fence_attempt_id TEXT,
    requested_claim_attempt_token TEXT,
    requested_evidence_bytes BYTEA,
    requested_evidence_sha256 TEXT
)
RETURNS TABLE(evidence_bytes BYTEA, evidence_sha256 TEXT, completed_at_unix_ms BIGINT)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    now_ms BIGINT;
    queue_row RECORD;
    authority_receipt JSONB;
    evidence_record JSONB;
    derived_digest TEXT;
    evidence_completed_at BIGINT;
BEGIN
    IF session_user::TEXT IS DISTINCT FROM 'cats_host_fence_provider' THEN
        RAISE EXCEPTION 'Host-fence provider PostgreSQL role mismatch'
            USING ERRCODE = '42501';
    END IF;
    IF pg_catalog.octet_length(requested_evidence_bytes) NOT BETWEEN 2 AND 4194304
       OR requested_evidence_sha256 !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid Host-fence provider evidence envelope'
            USING ERRCODE = '22023';
    END IF;
    derived_digest := 'sha256:' || pg_catalog.encode(
        pg_catalog.sha256(
            pg_catalog.convert_to('cats.trusted-host-fence-event.v1', 'UTF8') ||
            pg_catalog.decode('00', 'hex') || requested_evidence_bytes
        ), 'hex'
    );
    IF derived_digest <> requested_evidence_sha256 THEN
        RAISE EXCEPTION 'Host-fence provider evidence digest mismatch'
            USING ERRCODE = '22023';
    END IF;
    BEGIN
        evidence_record := pg_catalog.convert_from(requested_evidence_bytes, 'UTF8')::JSONB;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Host-fence provider evidence is not JSON'
            USING ERRCODE = '22023';
    END;
    SELECT queue.* INTO queue_row
      FROM __CATS_SCHEMA_IDENT__.host_fence_provider_queue_v1 queue
     WHERE queue.fence_attempt_id = requested_fence_attempt_id
     FOR UPDATE;
    IF NOT FOUND OR queue_row.claim_attempt_token <> requested_claim_attempt_token THEN
        RAISE EXCEPTION 'Host-fence provider claim is stale'
            USING ERRCODE = '55000';
    END IF;
    IF queue_row.state = 'terminal' THEN
        IF queue_row.evidence_bytes = requested_evidence_bytes
           AND queue_row.evidence_sha256 = requested_evidence_sha256 THEN
            RETURN QUERY SELECT queue_row.evidence_bytes,
                queue_row.evidence_sha256, queue_row.completed_at_unix_ms;
            RETURN;
        END IF;
        RAISE EXCEPTION 'terminal Host-fence evidence replay changed bytes'
            USING ERRCODE = '55000';
    END IF;
    now_ms := floor(
        extract(epoch FROM pg_catalog.clock_timestamp()) * 1000
    )::BIGINT;
    IF queue_row.state <> 'claimed'
       OR queue_row.claim_lease_expires_at_unix_ms <= now_ms THEN
        RAISE EXCEPTION 'Host-fence provider claim is expired'
            USING ERRCODE = '55000';
    END IF;
    SELECT authority.cutoff_receipt INTO authority_receipt
      FROM __CATS_SCHEMA_IDENT__.object_write_authorities authority
     WHERE authority.writer_authority_id = queue_row.writer_authority_id
       AND authority.state = 'cutoff_complete'
       AND authority.fence_attempt_id = requested_fence_attempt_id
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'object-writer cutoff is not complete'
            USING ERRCODE = '55000';
    END IF;
    now_ms := floor(
        extract(epoch FROM pg_catalog.clock_timestamp()) * 1000
    )::BIGINT;
    IF queue_row.claim_lease_expires_at_unix_ms <= now_ms THEN
        RAISE EXCEPTION 'Host-fence provider claim expired during completion'
            USING ERRCODE = '55000';
    END IF;
    evidence_completed_at := (evidence_record ->> 'completed_at_unix_ms')::BIGINT;
    IF (evidence_record ->> 'version')::BIGINT IS DISTINCT FROM 1
       OR evidence_record #>> '{binding,fence_attempt_id}' IS DISTINCT FROM
            requested_fence_attempt_id
       OR evidence_record #>> '{binding,provider_scope,provider}' IS DISTINCT FROM
            queue_row.provider
       OR evidence_record #>> '{binding,provider_scope,partition}' IS DISTINCT FROM
            queue_row.host_partition
       OR evidence_record #>> '{binding,provider_scope,account_id}' IS DISTINCT FROM
            queue_row.host_account_id
       OR evidence_record #>> '{binding,provider_scope,region}' IS DISTINCT FROM
            queue_row.host_region
       OR evidence_record #>> '{binding,immutable_host_id}' IS DISTINCT FROM
            queue_row.immutable_host_id
       OR evidence_record #>> '{binding,node_id}' IS DISTINCT FROM queue_row.node_id
       OR evidence_record #>> '{binding,expected_node_boot_id}' IS DISTINCT FROM
            queue_row.expected_node_boot_id
       OR (evidence_record #>> '{binding,expected_agent_session_epoch}')::BIGINT
            IS DISTINCT FROM
            queue_row.expected_agent_session_epoch
       OR evidence_record #>> '{object_write_cutoff,kind}' IS DISTINCT FROM
            'principal_cutoff_with_accepted_put_terminal_barrier'
       OR evidence_record #>> '{object_write_cutoff,binding,fence_attempt_id}'
            IS DISTINCT FROM
            requested_fence_attempt_id
       OR evidence_record #>> '{object_write_cutoff,binding,provider_scope,provider}'
            IS DISTINCT FROM
            queue_row.provider
       OR evidence_record #>> '{object_write_cutoff,binding,provider_scope,partition}'
            IS DISTINCT FROM
            queue_row.host_partition
       OR evidence_record #>> '{object_write_cutoff,binding,provider_scope,account_id}'
            IS DISTINCT FROM
            queue_row.host_account_id
       OR evidence_record #>> '{object_write_cutoff,binding,provider_scope,region}'
            IS DISTINCT FROM
            queue_row.host_region
       OR evidence_record #>> '{object_write_cutoff,binding,immutable_host_id}'
            IS DISTINCT FROM
            queue_row.immutable_host_id
       OR evidence_record #>> '{object_write_cutoff,binding,node_id}' IS DISTINCT FROM
            queue_row.node_id
       OR evidence_record #>> '{object_write_cutoff,object_writer,writer_authority_id}'
            IS DISTINCT FROM
            queue_row.writer_authority_id
       OR evidence_record #>> '{object_write_cutoff,object_writer,provider_scope,provider}'
            IS DISTINCT FROM
            queue_row.provider
       OR evidence_record #>> '{object_write_cutoff,object_writer,provider_scope,partition}'
            IS DISTINCT FROM
            queue_row.host_partition
       OR evidence_record #>> '{object_write_cutoff,object_writer,provider_scope,account_id}'
            IS DISTINCT FROM
            queue_row.host_account_id
       OR evidence_record #>> '{object_write_cutoff,object_writer,provider_scope,region}'
            IS DISTINCT FROM
            queue_row.host_region
       OR evidence_record #>> '{object_write_cutoff,object_writer,workload_principal_id}'
            IS DISTINCT FROM
            queue_row.workload_principal_id
       OR evidence_record #>> '{object_write_cutoff,object_writer,object_store_scope_id}'
            IS DISTINCT FROM
            queue_row.object_store_scope_id
       OR evidence_record #>> '{object_write_cutoff,cutoff_receipt_id}' IS DISTINCT FROM
            authority_receipt ->> 'cutoff_receipt_id'
       OR (evidence_record #>> '{object_write_cutoff,cutoff_effective_at_unix_ms}')::BIGINT
            IS DISTINCT FROM
            (authority_receipt ->> 'cutoff_effective_at_unix_ms')::BIGINT
       OR (evidence_record #>> '{object_write_cutoff,cutoff_sequence}')::BIGINT
            IS DISTINCT FROM
            (authority_receipt ->> 'cutoff_sequence')::BIGINT
       OR evidence_record #>> '{object_write_cutoff,accepted_put_terminal_receipt_id}'
            IS DISTINCT FROM
            authority_receipt ->> 'accepted_put_terminal_receipt_id'
       OR (evidence_record #>> '{object_write_cutoff,accepted_puts_terminal_at_unix_ms}')::BIGINT
            IS DISTINCT FROM
            (authority_receipt ->> 'accepted_puts_terminal_at_unix_ms')::BIGINT
       OR (evidence_record #>> '{object_write_cutoff,terminal_sequence}')::BIGINT
            IS DISTINCT FROM
            (authority_receipt ->> 'terminal_sequence')::BIGINT
       OR evidence_record #>> '{object_write_cutoff,terminal_prefix_sha256}'
            IS DISTINCT FROM
            authority_receipt ->> 'terminal_prefix_sha256'
       OR evidence_record #>> '{object_write_cutoff,successful_put_visibility_receipt_id}'
            IS DISTINCT FROM
            authority_receipt ->> 'successful_put_visibility_receipt_id'
       OR (evidence_record #>> '{object_write_cutoff,successful_puts_visible_at_unix_ms}')::BIGINT
            IS DISTINCT FROM
            (authority_receipt ->> 'successful_puts_visible_at_unix_ms')::BIGINT
       OR evidence_record #>> '{execution_cutoff,immutable_host_id}' IS DISTINCT FROM
            queue_row.immutable_host_id
       OR evidence_record #>> '{network_cutoff,immutable_host_id}' IS DISTINCT FROM
            queue_row.immutable_host_id
       OR evidence_record #>> '{network_cutoff,quarantine_policy_id}' IS DISTINCT FROM
            queue_row.network_quarantine_boundary_id
       OR evidence_completed_at IS DISTINCT FROM
            greatest(
                (evidence_record #>> '{execution_cutoff,observed_at_unix_ms}')::BIGINT,
                (evidence_record #>> '{network_cutoff,policy_observed_at_unix_ms}')::BIGINT,
                (evidence_record #>> '{network_cutoff,observed_at_unix_ms}')::BIGINT
            ) THEN
        RAISE EXCEPTION 'Host-fence provider evidence does not match the sealed request'
            USING ERRCODE = '55000';
    END IF;

    UPDATE __CATS_SCHEMA_IDENT__.host_fence_provider_queue_v1 queue
       SET state = 'terminal', evidence_bytes = requested_evidence_bytes,
           evidence_sha256 = requested_evidence_sha256,
           completed_at_unix_ms = evidence_completed_at
     WHERE queue.fence_attempt_id = requested_fence_attempt_id;
    RETURN QUERY SELECT requested_evidence_bytes,
        requested_evidence_sha256, evidence_completed_at;
END;
$function$;
REVOKE ALL ON FUNCTION
    __CATS_SCHEMA_IDENT__.control_host_fence_provider_complete_v1(
        TEXT,TEXT,BYTEA,TEXT
    ) FROM PUBLIC;
"#;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS control_schema_version (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    version BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('personal','organization')),
    workos_organization_id TEXT NOT NULL UNIQUE,
    billing_account_id TEXT NOT NULL UNIQUE,
    personal_owner_user_id TEXT UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('provisioning','active','disabled')),
    created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    slug TEXT NOT NULL,
    display_name TEXT NOT NULL,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    created_at BIGINT NOT NULL,
    UNIQUE (account_id, slug)
);
CREATE UNIQUE INDEX IF NOT EXISTS workspaces_one_default
ON workspaces(account_id) WHERE is_default;
-- The semantic Control/Node protocol is a clean product model.  These tables
-- are intentionally independent from the former runtime Operation and
-- inventory projections below; new protocol code reads and writes only this
-- set while the remaining release components are cut over.
CREATE TABLE IF NOT EXISTS nodes (
    node_id TEXT PRIMARY KEY,
    node_name TEXT NOT NULL CHECK (length(node_name) BETWEEN 1 AND 255),
    control_endpoint TEXT NOT NULL CHECK (length(control_endpoint) BETWEEN 1 AND 2048),
    vendor TEXT NOT NULL CHECK (length(vendor) BETWEEN 1 AND 63),
    region TEXT NOT NULL CHECK (length(region) BETWEEN 1 AND 127),
    zone TEXT NOT NULL CHECK (length(zone) BETWEEN 1 AND 127),
    instance_id TEXT NOT NULL CHECK (length(instance_id) BETWEEN 1 AND 255),
    machine_type TEXT NOT NULL CHECK (length(machine_type) BETWEEN 1 AND 127),
    node_version TEXT NOT NULL CHECK (length(node_version) BETWEEN 1 AND 127),
    status TEXT NOT NULL
        CHECK (status IN ('running','draining','offline','reset_required','deleted')),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    updated_at BIGINT NOT NULL CHECK (updated_at >= created_at),
    CONSTRAINT nodes_cloud_instance_unique UNIQUE (vendor, instance_id)
);
CREATE TABLE IF NOT EXISTS node_heartbeats (
    node_id TEXT PRIMARY KEY REFERENCES nodes(node_id),
    -- Written from clock_timestamp() by the heartbeat upsert.  Node time is
    -- retained separately and must never decide liveness.
    last_heartbeat_at BIGINT NOT NULL CHECK (last_heartbeat_at >= 0),
    node_reported_at BIGINT CHECK (node_reported_at >= 0),
    reported_status TEXT NOT NULL
        CHECK (reported_status IN ('running','draining','offline','reset_required','deleted')),
    total_cpu BIGINT NOT NULL CHECK (total_cpu > 0),
    cpu_utilized DOUBLE PRECISION NOT NULL
        CHECK (cpu_utilized >= 0 AND cpu_utilized <= total_cpu),
    total_memory BIGINT NOT NULL CHECK (total_memory > 0),
    memory_utilized BIGINT NOT NULL
        CHECK (memory_utilized >= 0 AND memory_utilized <= total_memory),
    running_cat_count BIGINT NOT NULL CHECK (running_cat_count >= 0),
    suspended_cat_count BIGINT NOT NULL CHECK (suspended_cat_count >= 0),
    warm_cat_count BIGINT NOT NULL CHECK (warm_cat_count >= 0)
);
CREATE TABLE IF NOT EXISTS cats (
    cat_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    cat_slug TEXT NOT NULL
        CHECK (cat_slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    state TEXT CHECK (state IN ('running','suspended','warm','cold','failure','destroyed')),
    current_action TEXT
        CHECK (current_action IN ('create','run','suspend','warm','cold','destroy')),
    current_action_started_at BIGINT CHECK (current_action_started_at >= 0),
    current_action_node_id TEXT REFERENCES nodes(node_id),
    node_id TEXT REFERENCES nodes(node_id),
    cpu_count BIGINT NOT NULL CHECK (cpu_count > 0),
    memory_bytes BIGINT NOT NULL CHECK (memory_bytes > 0),
    boot_image TEXT NOT NULL CHECK (length(boot_image) > 0),
    last_error_code TEXT,
    last_error_message TEXT,
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    updated_at BIGINT NOT NULL CHECK (updated_at >= created_at),
    destroyed_at BIGINT CHECK (destroyed_at >= created_at),
    CONSTRAINT cats_workspace_identity_unique UNIQUE (workspace_id, cat_id),
    CONSTRAINT cats_destroyed_shape_check CHECK (
        ((state = 'destroyed') IS TRUE) = (destroyed_at IS NOT NULL)
    ),
    CONSTRAINT cats_initial_create_shape_check CHECK (
        state IS NOT NULL OR current_action = 'create'
    ),
    CONSTRAINT cats_current_action_shape_check CHECK (
        (current_action IS NULL
            AND current_action_started_at IS NULL
            AND current_action_node_id IS NULL) OR
        (current_action IS NOT NULL
            AND current_action_started_at IS NOT NULL
            AND (current_action_node_id IS NOT NULL OR
                 (current_action = 'destroy' AND node_id IS NULL))
            AND state IS DISTINCT FROM 'destroyed')
    ),
    CONSTRAINT cats_placement_shape_check CHECK (
        (state IN ('running','suspended','warm') AND node_id IS NOT NULL) OR
        (state IN ('cold','destroyed') AND node_id IS NULL) OR
        state IN ('failure') OR
        state IS NULL
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS cats_current_slug_unique
ON cats(workspace_id, cat_slug) WHERE destroyed_at IS NULL;
CREATE INDEX IF NOT EXISTS cats_current_action_scan
ON cats(current_action_started_at) WHERE current_action IS NOT NULL;
CREATE INDEX IF NOT EXISTS cats_node_placement
ON cats(node_id) WHERE node_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS persistent_disks (
    disk_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    disk_slug TEXT NOT NULL
        CHECK (disk_slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    size_bytes BIGINT NOT NULL CHECK (size_bytes > 0),
    status TEXT NOT NULL CHECK (status IN ('normal','deleted')),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    deleted_at BIGINT CHECK (deleted_at >= created_at),
    CONSTRAINT persistent_disks_workspace_identity_unique
        UNIQUE (workspace_id, disk_id),
    CONSTRAINT persistent_disks_deleted_shape_check CHECK (
        (status = 'deleted') IS NOT DISTINCT FROM (deleted_at IS NOT NULL)
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS disks_current_slug_unique
ON persistent_disks(workspace_id, disk_slug) WHERE deleted_at IS NULL;
CREATE TABLE IF NOT EXISTS disk_bindings (
    binding_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    disk_id TEXT NOT NULL,
    cat_id TEXT NOT NULL,
    mount_path TEXT NOT NULL CHECK (
        mount_path LIKE '/%' AND
        mount_path NOT IN ('/','/boot','/proc','/sys','/dev','/run')
    ),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    CONSTRAINT disk_bindings_disk_unique UNIQUE (disk_id),
    CONSTRAINT disk_bindings_cat_mount_unique UNIQUE (cat_id, mount_path),
    CONSTRAINT disk_bindings_disk_workspace_fkey
        FOREIGN KEY (workspace_id, disk_id)
        REFERENCES persistent_disks(workspace_id, disk_id),
    CONSTRAINT disk_bindings_cat_workspace_fkey
        FOREIGN KEY (workspace_id, cat_id)
        REFERENCES cats(workspace_id, cat_id)
);
CREATE TABLE IF NOT EXISTS account_membership_shadow (
    workos_membership_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    workos_user_id TEXT NOT NULL,
    role_slug TEXT NOT NULL,
    status TEXT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE (account_id, workos_user_id)
);
CREATE TABLE IF NOT EXISTS workspace_grants (
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    workos_user_id TEXT NOT NULL,
    access_level TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (workspace_id, workos_user_id)
);
CREATE TABLE IF NOT EXISTS workspace_tokens (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    label TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at BIGINT NOT NULL,
    revoked_at BIGINT
);
CREATE INDEX IF NOT EXISTS workspace_tokens_active
ON workspace_tokens(token_hash) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS signup_grant_eligibility (
    workos_user_id TEXT NOT NULL,
    campaign TEXT NOT NULL,
    billing_account_id TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state IN ('pending','applied')),
    created_at BIGINT NOT NULL,
    applied_at BIGINT,
    PRIMARY KEY (workos_user_id, campaign)
);
CREATE TABLE IF NOT EXISTS account_invitations (
    workos_invitation_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    workos_organization_id TEXT NOT NULL,
    email TEXT NOT NULL,
    role_slug TEXT NOT NULL,
    state TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS workos_event_receipts (
    workos_event_id TEXT PRIMARY KEY,
    event_name TEXT NOT NULL,
    processed_at BIGINT NOT NULL
);
-- One row per (cat, app, pinned digest): the deployment's identity, so a
-- retried request finds the first attempt instead of starting a second one.
-- The UNIQUE constraint is the idempotency mechanism; handler code only reads
-- what the constraint decided. Registry credentials are deliberately absent --
-- they are transient pull credentials and must never be persisted, which is
-- also why an interrupted deploy cannot be resumed after a restart and is
-- converged to 'failed' instead.
--
-- 'superseded' is what a succeeded row becomes when a later digest is
-- activated for the same app. It matters because a Cat runs exactly one image
-- per app: without it, re-requesting an older digest would replay a record for
-- something no longer running, reporting success while the Guest kept serving
-- the newer image.
CREATE TABLE IF NOT EXISTS oci_deployments (
    id TEXT PRIMARY KEY,
    cat_id TEXT NOT NULL,
    app TEXT NOT NULL,
    image_digest TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    phase TEXT NOT NULL
        CHECK (phase IN ('running','succeeded','failed','superseded')),
    manifest_digest TEXT,
    service TEXT,
    active BOOLEAN NOT NULL DEFAULT FALSE,
    error_json TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE (cat_id, app, image_digest)
);
-- At most one activated deployment per (cat, app), enforced rather than
-- maintained by convention: a Cat has one `current` symlink and one systemd
-- unit per app, so two 'succeeded' rows for one app would describe a state the
-- Guest cannot be in. This also removes any need to order or de-duplicate when
-- reading what is deployed.
CREATE UNIQUE INDEX IF NOT EXISTS oci_deployments_one_current_per_app
    ON oci_deployments (cat_id, app) WHERE phase='succeeded';
CREATE TABLE IF NOT EXISTS volume_records (
    volume_id TEXT PRIMARY KEY,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    size_bytes BIGINT NOT NULL CHECK (size_bytes > 0),
    durability TEXT NOT NULL CHECK (durability IN ('strict', 'relaxed')),
    admin_state TEXT NOT NULL CHECK (admin_state IN ('active', 'deleting')),
    delete_id TEXT,
    head_generation BIGINT NOT NULL CHECK (head_generation >= 0),
    head_root_hash TEXT,
    head_root_object_id TEXT,
    lease_owner TEXT,
    lease_epoch BIGINT NOT NULL CHECK (lease_epoch >= 0),
    lease_expires_at BIGINT,
    last_transition_kind TEXT CHECK (
        last_transition_kind IN (
            'normal_acquire', 'release', 'takeover', 'begin_delete',
            'begin_disposable_delete'
        )
    ),
    last_transition_id TEXT,
    transition_source_kind TEXT CHECK (
        transition_source_kind IN ('independent', 'lifecycle')
    ),
    transition_operation_id TEXT,
    transition_request_fingerprint TEXT CHECK (
        transition_request_fingerprint ~ '^sha256:[0-9a-f]{64}$'
    ),
    transition_placement_epoch BIGINT,
    transition_lease_duration_ms BIGINT,
    owner_binding JSONB,
    owner_node_id TEXT,
    CHECK (
        (admin_state = 'active' AND delete_id IS NULL) OR
        (admin_state = 'deleting' AND delete_id IS NOT NULL)
    ),
    CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL)),
    CHECK (lease_owner IS NULL OR admin_state = 'active'),
    CHECK (lease_owner IS NULL OR (lease_epoch > 0 AND lease_expires_at > 0)),
    CONSTRAINT volume_records_owner_present_check
        CHECK ((lease_owner IS NULL) = (owner_binding IS NULL)),
    CONSTRAINT volume_records_owner_node_present_check
        CHECK ((owner_binding IS NULL) = (owner_node_id IS NULL)),
    CONSTRAINT volume_records_owner_binding_check CHECK (
        owner_binding IS NULL OR owner_binding = jsonb_build_object(
            'volume_id', volume_id,
            'owner_node_id', owner_node_id,
            'attachment_id', lease_owner,
            'attachment_epoch', lease_epoch
        )
    ),
    CHECK (admin_state <> 'deleting' OR (lease_owner IS NULL AND lease_epoch > 0)),
    CHECK (
        (head_generation = 0 AND head_root_hash IS NULL AND head_root_object_id IS NULL) OR
        (head_generation > 0 AND head_root_hash IS NOT NULL AND head_root_object_id IS NOT NULL)
    ),
    CONSTRAINT volume_records_transition_shape_check CHECK ((
        (last_transition_kind IS NULL AND last_transition_id IS NULL
            AND transition_source_kind IS NULL
            AND transition_operation_id IS NULL
            AND transition_request_fingerprint IS NULL
            AND transition_placement_epoch IS NULL
            AND transition_lease_duration_ms IS NULL) OR
        (last_transition_kind = 'normal_acquire' AND last_transition_id IS NOT NULL
            AND transition_source_kind IS NOT NULL
            AND transition_placement_epoch > 0
            AND transition_lease_duration_ms > 0
            AND (
                (transition_source_kind = 'independent'
                    AND transition_operation_id IS NULL
                    AND transition_request_fingerprint IS NULL) OR
                (transition_source_kind = 'lifecycle'
                    AND transition_operation_id IS NOT NULL
                    AND transition_request_fingerprint IS NOT NULL)
            )) OR
        (last_transition_kind IN (
                'release', 'takeover', 'begin_delete', 'begin_disposable_delete'
            ) AND last_transition_id IS NOT NULL
            AND transition_source_kind IS NOT NULL
            AND transition_placement_epoch IS NULL
            AND transition_lease_duration_ms IS NULL
            AND (
                (transition_source_kind = 'independent'
                    AND transition_operation_id IS NULL
                    AND transition_request_fingerprint IS NULL) OR
                (transition_source_kind = 'lifecycle'
                    AND transition_operation_id IS NOT NULL
                    AND transition_request_fingerprint IS NOT NULL)
            ))
    ) IS TRUE)
);
CREATE INDEX IF NOT EXISTS volume_records_owner_node
ON volume_records(owner_node_id, volume_id COLLATE \"C\")
WHERE owner_node_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS volume_records_owner_binding_node
ON volume_records((owner_binding->>'owner_node_id'), volume_id COLLATE \"C\")
WHERE owner_binding IS NOT NULL;
CREATE INDEX IF NOT EXISTS volume_records_record_volume
ON volume_records((record->>'volume_id'));
CREATE INDEX IF NOT EXISTS volume_records_delete
ON volume_records((COALESCE(delete_id, '')));
CREATE INDEX IF NOT EXISTS volume_records_record_delete
ON volume_records((record->'admin_state'->>'delete_id'));
CREATE TABLE IF NOT EXISTS host_fence_events (
    event_id TEXT PRIMARY KEY,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    canonical_record BYTEA CHECK (
        canonical_record IS NULL OR octet_length(canonical_record) BETWEEN 2 AND 4194304
    ),
    provider TEXT NOT NULL,
    host_partition TEXT,
    host_account_id TEXT,
    host_region TEXT,
    immutable_host_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    expected_node_boot_id TEXT NOT NULL,
    expected_agent_session_epoch BIGINT NOT NULL CHECK (expected_agent_session_epoch > 0),
    fence_attempt_id TEXT NOT NULL,
    isolation_state TEXT NOT NULL CHECK (isolation_state IN (
        'isolated', 'host_destroyed', 'trusted_provider_evidence_v1'
    )),
    observed_at BIGINT NOT NULL CHECK (observed_at >= 0),
    state TEXT NOT NULL CHECK (state IN ('active', 'rejoined', 'terminal_v1')),
    destroyed_at BIGINT,
    provider_evidence_sha256 TEXT
        CHECK (provider_evidence_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    committed_at BIGINT CHECK (committed_at >= 0),
    UNIQUE (event_id, state),
    CHECK (
        (state IN ('active', 'rejoined')
            AND host_partition IS NULL
            AND host_account_id IS NULL
            AND host_region IS NULL
            AND provider_evidence_sha256 IS NULL
            AND committed_at IS NULL
            AND canonical_record IS NULL
            AND (
                (isolation_state = 'isolated' AND destroyed_at IS NULL) OR
                (isolation_state = 'host_destroyed' AND destroyed_at IS NOT NULL)
            )) OR
        (state = 'terminal_v1'
            AND isolation_state = 'trusted_provider_evidence_v1'
            AND host_partition IS NOT NULL
            AND host_account_id IS NOT NULL
            AND host_region IS NOT NULL
            AND provider_evidence_sha256 IS NOT NULL
            AND committed_at IS NOT NULL
            AND canonical_record IS NOT NULL
            AND destroyed_at IS NULL)
    ),
    CHECK (isolation_state <> 'host_destroyed' OR state = 'active'),
    CHECK (state <> 'terminal_v1' OR committed_at >= observed_at)
);
CREATE UNIQUE INDEX IF NOT EXISTS runtime_node_one_active_host_fence_event
    ON host_fence_events(node_id) WHERE state = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS runtime_one_terminal_host_fence_event_v1
    ON host_fence_events(
        provider, host_partition, host_account_id, host_region,
        immutable_host_id, node_id, expected_node_boot_id,
        expected_agent_session_epoch
    ) WHERE state = 'terminal_v1';
-- `runtime_operations` is declared after the product/authority rows it uses,
-- so this Delete-Operation back-reference deliberately has no reverse FK.
-- The sole writer must lock and validate the current unresolved Delete row,
-- Cat chain head, canonical request fingerprint and proof tuple in the same
-- transaction which inserts this immutable authorization.
CREATE TABLE IF NOT EXISTS volume_authorizations (
    authorization_id TEXT PRIMARY KEY,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    kind TEXT NOT NULL CHECK (kind IN ('takeover', 'disposable_root_delete')),
    authorized_node_id TEXT NOT NULL,
    host_fence_event_id TEXT REFERENCES host_fence_events(event_id),
    volume_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('unconsumed', 'consumed')),
    -- Both arms bind exact lifecycle lineage. HostFenceRecovery is not yet a
    -- production writer, but its persisted shape is already clean-slate: an
    -- external fence plus the interrupted Operation's HostLost result grants
    -- one target placement/volume/head takeover, never a Desired revision.
    placement_epoch BIGINT NOT NULL CHECK (placement_epoch > 0),
    lease_duration_ms BIGINT,
    lifecycle_operation_id TEXT,
    lifecycle_request_fingerprint TEXT,
    delete_id TEXT,
    disk_id TEXT,
    cat_id TEXT,
    expected_attachment_id TEXT,
    expected_attachment_epoch BIGINT,
    disposition TEXT,
    persistent_dispositions_digest TEXT,
    isolation_basis_kind TEXT,
    strong_stop_receipt_digest TEXT,
    strong_stop_agent_session_epoch BIGINT,
    execution_absence_proof_digest TEXT,
    inventory_attestation_digest TEXT,
    interrupted_operation_id TEXT,
    host_lost_result_digest TEXT,
    expected_head_generation BIGINT NOT NULL CHECK (expected_head_generation >= 0),
    expected_head_root_hash TEXT,
    expected_head_root_object_id TEXT,
    not_after BIGINT NOT NULL CHECK (not_after >= 0),
    consumed_at BIGINT,
    CONSTRAINT volume_authorizations_lifecycle_request_fingerprint_check
        CHECK (lifecycle_request_fingerprint IS NULL OR
            lifecycle_request_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT volume_authorizations_persistent_dispositions_digest_check
        CHECK (persistent_dispositions_digest IS NULL OR
            persistent_dispositions_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT volume_authorizations_strong_stop_receipt_digest_check
        CHECK (strong_stop_receipt_digest IS NULL OR
            strong_stop_receipt_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT volume_authorizations_execution_absence_proof_digest_check
        CHECK (execution_absence_proof_digest IS NULL OR
            execution_absence_proof_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT volume_authorizations_inventory_attestation_digest_check
        CHECK (inventory_attestation_digest IS NULL OR
            inventory_attestation_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT volume_authorizations_host_lost_result_digest_check
        CHECK (host_lost_result_digest IS NULL OR
            host_lost_result_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT volume_authorizations_kind_shape_check CHECK (
        (kind = 'takeover'
            AND host_fence_event_id IS NOT NULL
            AND lease_duration_ms IS NOT NULL
            AND lease_duration_ms > 0
            AND lifecycle_operation_id IS NOT NULL
            AND lifecycle_request_fingerprint IS NOT NULL
            AND delete_id IS NULL
            AND disk_id IS NOT NULL
            AND cat_id IS NOT NULL
            AND expected_attachment_id IS NOT NULL
            AND expected_attachment_epoch IS NOT NULL
            AND expected_attachment_epoch > 0
            AND disposition IS NULL
            AND persistent_dispositions_digest IS NULL
            AND isolation_basis_kind IS NULL
            AND strong_stop_receipt_digest IS NULL
            AND strong_stop_agent_session_epoch IS NULL
            AND execution_absence_proof_digest IS NULL
            AND inventory_attestation_digest IS NULL
            AND interrupted_operation_id IS NOT NULL
            AND host_lost_result_digest IS NOT NULL) OR
        (kind = 'disposable_root_delete'
            AND lease_duration_ms IS NULL
            AND lifecycle_operation_id IS NOT NULL
            AND lifecycle_request_fingerprint IS NOT NULL
            AND delete_id IS NOT NULL
            AND disk_id IS NOT NULL
            AND cat_id IS NOT NULL
            AND expected_attachment_id IS NOT NULL
            AND expected_attachment_epoch IS NOT NULL
            AND expected_attachment_epoch > 0
            AND disposition = 'discard_with_cat'
            AND persistent_dispositions_digest IS NOT NULL
            AND (
                (isolation_basis_kind = 'lifecycle_strong_stop'
                    AND host_fence_event_id IS NULL
                    AND strong_stop_receipt_digest IS NOT NULL
                    AND strong_stop_agent_session_epoch IS NOT NULL
                    AND strong_stop_agent_session_epoch > 0
                    AND execution_absence_proof_digest IS NOT NULL
                    AND inventory_attestation_digest IS NOT NULL
                    AND interrupted_operation_id IS NULL
                    AND host_lost_result_digest IS NULL) OR
                (isolation_basis_kind = 'host_fence_event'
                    AND host_fence_event_id IS NOT NULL
                    AND strong_stop_receipt_digest IS NULL
                    AND strong_stop_agent_session_epoch IS NULL
                    AND execution_absence_proof_digest IS NULL
                    AND inventory_attestation_digest IS NULL
                    AND interrupted_operation_id IS NOT NULL
                    AND host_lost_result_digest IS NOT NULL)
            ))
    ),
    CHECK (
        (expected_head_generation = 0
            AND expected_head_root_hash IS NULL
            AND expected_head_root_object_id IS NULL) OR
        (expected_head_generation > 0
            AND expected_head_root_hash ~ '^sha256:[0-9a-f]{64}$'
            AND expected_head_root_object_id IS NOT NULL)
    ),
    CHECK ((state = 'consumed') = (consumed_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS volume_authorizations_event
ON volume_authorizations(host_fence_event_id) WHERE host_fence_event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS volume_authorizations_volume
ON volume_authorizations(volume_id);
CREATE INDEX IF NOT EXISTS volume_authorizations_disposable_scope
ON volume_authorizations(
    volume_id, lifecycle_operation_id, placement_epoch,
    authorization_id COLLATE \"C\"
) WHERE kind='disposable_root_delete';
CREATE INDEX IF NOT EXISTS volume_authorizations_record_authorization
ON volume_authorizations USING GIN ((record->'authorization') jsonb_path_ops);
CREATE TABLE IF NOT EXISTS delete_completion_receipts (
    delete_id TEXT PRIMARY KEY,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    kind TEXT NOT NULL CHECK (kind IN ('normal', 'disposable_root')),
    disk_id TEXT NOT NULL,
    volume_id TEXT NOT NULL UNIQUE,
    authorization_id TEXT,
    prior_attachment_id TEXT,
    deleting_epoch BIGINT NOT NULL CHECK (deleting_epoch > 0),
    head_generation BIGINT NOT NULL CHECK (head_generation >= 0),
    head_root_hash TEXT,
    head_root_object_id TEXT,
    completed_at BIGINT NOT NULL CHECK (completed_at >= 0),
    CHECK (
        (kind = 'normal' AND authorization_id IS NULL AND prior_attachment_id IS NULL) OR
        (kind = 'disposable_root' AND authorization_id IS NOT NULL AND prior_attachment_id IS NOT NULL)
    ),
    CHECK (
        (head_generation = 0 AND head_root_hash IS NULL AND head_root_object_id IS NULL) OR
        (head_generation > 0 AND head_root_hash IS NOT NULL AND head_root_object_id IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS delete_completion_receipts_disk
ON delete_completion_receipts(disk_id);
CREATE INDEX IF NOT EXISTS delete_completion_receipts_record_delete
ON delete_completion_receipts((record->>'delete_id'));
CREATE INDEX IF NOT EXISTS delete_completion_receipts_record_disk
ON delete_completion_receipts((record->>'disk_id'));
CREATE INDEX IF NOT EXISTS delete_completion_receipts_record_volume
ON delete_completion_receipts((record->>'volume_id'));
CREATE INDEX IF NOT EXISTS delete_completion_receipts_record_request_delete
ON delete_completion_receipts((record->'request'->>'delete_id'));
CREATE INDEX IF NOT EXISTS delete_completion_receipts_record_request_disk
ON delete_completion_receipts((record->'request'->>'disk_id'));
CREATE INDEX IF NOT EXISTS delete_completion_receipts_record_request_volume
ON delete_completion_receipts((record->'request'->>'volume_id'));
CREATE TABLE IF NOT EXISTS cat_records (
    cat_id TEXT PRIMARY KEY,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    name TEXT NOT NULL,
    cat_creation_id TEXT NOT NULL,
    lifecycle_head_operation_id TEXT,
    stable_state TEXT
        CONSTRAINT cat_records_stable_state_check
        CHECK (stable_state IN ('running', 'suspended', 'warm', 'cold')),
    effective_runtime_ready_operation_id TEXT,
    runtime_incarnation TEXT
        CONSTRAINT cat_records_runtime_incarnation_check
        CHECK (runtime_incarnation ~ '^[0-9a-f]{32}$'),
    current_runtime_config_id TEXT NOT NULL,
    current_runtime_config_sha256 TEXT NOT NULL
        CONSTRAINT cat_records_runtime_config_digest_check
        CHECK (current_runtime_config_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    deleted_at BIGINT
        CONSTRAINT cat_records_deleted_at_check
        CHECK (deleted_at >= created_at),
    CONSTRAINT cat_records_cat_creation_id_key UNIQUE (cat_creation_id),
    UNIQUE (workspace_id, name),
    UNIQUE (workspace_id, cat_id),
    CONSTRAINT cat_records_runtime_ready_shape_check CHECK ((
        (stable_state = 'running'
            AND effective_runtime_ready_operation_id IS NOT NULL
            AND runtime_incarnation IS NOT NULL) OR
        (stable_state = 'suspended'
            AND effective_runtime_ready_operation_id IS NULL
            AND runtime_incarnation IS NOT NULL) OR
        (stable_state IN ('warm', 'cold')
            AND effective_runtime_ready_operation_id IS NULL
            AND runtime_incarnation IS NULL) OR
        (stable_state IS NULL
            AND effective_runtime_ready_operation_id IS NULL
            AND runtime_incarnation IS NULL)
    ) IS TRUE),
    CONSTRAINT cat_records_deleted_shape_check CHECK (
        deleted_at IS NULL OR
        (stable_state IS NULL
            AND effective_runtime_ready_operation_id IS NULL
            AND runtime_incarnation IS NULL)
    )
);
-- These are the Cat-row transaction's current-chain projections. They do not
-- carry reverse foreign keys to runtime_operations: the fresh-schema create
-- order would form a Cat/Operation cycle, and an unresolved Operation is
-- deliberately not the terminal lifecycle head. The Store must update them
-- with exact Operation settlement in the same Cat-row transaction.
CREATE UNIQUE INDEX IF NOT EXISTS cat_records_lifecycle_head_operation_key
ON cat_records(lifecycle_head_operation_id)
WHERE lifecycle_head_operation_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS cat_records_effective_runtime_ready_operation_key
ON cat_records(effective_runtime_ready_operation_id)
WHERE effective_runtime_ready_operation_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS cat_records_lookup_scalar_scalar
ON cat_records(workspace_id COLLATE \"C\", cat_id COLLATE \"C\");
CREATE INDEX IF NOT EXISTS cat_records_lookup_scalar_record
ON cat_records(workspace_id COLLATE \"C\", (record->>'cat_id') COLLATE \"C\")
WHERE cat_id COLLATE \"C\" IS DISTINCT FROM (record->>'cat_id') COLLATE \"C\";
CREATE INDEX IF NOT EXISTS cat_records_lookup_record_scalar
ON cat_records((record->>'workspace_id') COLLATE \"C\", cat_id COLLATE \"C\")
WHERE workspace_id COLLATE \"C\" IS DISTINCT FROM (record->>'workspace_id') COLLATE \"C\";
CREATE INDEX IF NOT EXISTS cat_records_lookup_record_record
ON cat_records((record->>'workspace_id') COLLATE \"C\", (record->>'cat_id') COLLATE \"C\")
WHERE workspace_id COLLATE \"C\" IS DISTINCT FROM (record->>'workspace_id') COLLATE \"C\"
  AND cat_id COLLATE \"C\" IS DISTINCT FROM (record->>'cat_id') COLLATE \"C\";
CREATE TABLE IF NOT EXISTS endpoint_records (
    endpoint_id TEXT PRIMARY KEY,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    workspace_id TEXT NOT NULL,
    cat_id TEXT NOT NULL,
    name TEXT NOT NULL,
    binding_state TEXT NOT NULL
        CONSTRAINT endpoint_records_binding_state_check
        CHECK (binding_state IN ('bound', 'unbound')),
    hostname TEXT,
    protocol TEXT,
    target_port INTEGER,
    route_epoch BIGINT NOT NULL
        CONSTRAINT endpoint_records_route_epoch_check
        CHECK (route_epoch > 0),
    route_head_operation_id TEXT,
    effective_serving_operation_id TEXT,
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    updated_at_unix_ms BIGINT NOT NULL
        CONSTRAINT endpoint_records_updated_at_check
        CHECK (updated_at_unix_ms >= created_at),
    UNIQUE (cat_id, name),
    UNIQUE (workspace_id, cat_id, endpoint_id),
    UNIQUE (hostname),
    UNIQUE (workspace_id, cat_id, endpoint_id, hostname),
    FOREIGN KEY (workspace_id, cat_id)
        REFERENCES cat_records(workspace_id, cat_id),
    CONSTRAINT endpoint_records_binding_shape_check CHECK (
        (binding_state = 'bound'
            AND hostname IS NOT NULL
            AND protocol = 'http'
            AND target_port BETWEEN 1 AND 65535) OR
        (binding_state = 'unbound'
            AND hostname IS NULL
            AND protocol IS NULL
            AND target_port IS NULL
            AND effective_serving_operation_id IS NULL)
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS endpoint_records_route_head_operation_key
ON endpoint_records(route_head_operation_id)
WHERE route_head_operation_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS endpoint_records_effective_serving_operation_key
ON endpoint_records(effective_serving_operation_id)
WHERE effective_serving_operation_id IS NOT NULL;
CREATE OR REPLACE FUNCTION control_endpoint_record_transition_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (OLD.endpoint_id, OLD.record, OLD.workspace_id, OLD.cat_id,
        OLD.name, OLD.created_at)
       IS DISTINCT FROM
       (NEW.endpoint_id, NEW.record, NEW.workspace_id, NEW.cat_id,
        NEW.name, NEW.created_at)
       OR NEW.route_epoch < OLD.route_epoch
       OR NEW.route_epoch > OLD.route_epoch + 1
       OR NEW.updated_at_unix_ms < OLD.updated_at_unix_ms
    THEN
        RAISE EXCEPTION 'invalid Endpoint identity or route lineage transition';
    END IF;
    IF (OLD.binding_state, OLD.hostname, OLD.protocol, OLD.target_port)
       IS DISTINCT FROM
       (NEW.binding_state, NEW.hostname, NEW.protocol, NEW.target_port)
       AND (NEW.route_epoch <> OLD.route_epoch + 1
            OR NEW.route_head_operation_id IS DISTINCT FROM
                OLD.route_head_operation_id
            OR NEW.effective_serving_operation_id IS NOT NULL)
    THEN
        RAISE EXCEPTION 'Endpoint binding changes must burn one epoch, retain the history head and close Serving';
    END IF;
    IF NEW.route_epoch = OLD.route_epoch + 1
       AND NEW.effective_serving_operation_id IS NOT NULL
    THEN
        RAISE EXCEPTION 'an epoch burn must close effective Serving';
    END IF;
    IF NEW.route_head_operation_id IS NOT NULL
       AND NOT EXISTS (
            SELECT 1 FROM route_operations r
             WHERE r.operation_id=NEW.route_head_operation_id
               AND r.workspace_id=NEW.workspace_id
               AND r.cat_id=NEW.cat_id
               AND r.endpoint_id=NEW.endpoint_id
               AND r.state='terminal'
       )
    THEN
        RAISE EXCEPTION 'Endpoint route head must name an exact terminal Route Operation';
    END IF;
    IF NEW.effective_serving_operation_id IS NOT NULL
       AND NOT EXISTS (
            SELECT 1 FROM route_operations r
             WHERE r.operation_id=NEW.effective_serving_operation_id
               AND r.workspace_id=NEW.workspace_id
               AND r.cat_id=NEW.cat_id
               AND r.endpoint_id=NEW.endpoint_id
               AND r.state='terminal'
               AND r.terminal_result_kind='serving'
               AND r.hostname=NEW.hostname
               AND r.protocol=NEW.protocol
               AND r.target_port=NEW.target_port
               AND r.route_epoch=NEW.route_epoch
       )
    THEN
        RAISE EXCEPTION 'effective Serving pointer is not exact for the current Endpoint binding';
    END IF;
    RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION control_endpoint_record_cannot_delete()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Endpoint identity is retained as an unbound route lineage';
END;
$$;
CREATE TRIGGER endpoint_record_transition_is_forward_only
BEFORE UPDATE ON endpoint_records FOR EACH ROW
EXECUTE FUNCTION control_endpoint_record_transition_guard();
CREATE TRIGGER endpoint_record_cannot_delete
BEFORE DELETE ON endpoint_records FOR EACH ROW
EXECUTE FUNCTION control_endpoint_record_cannot_delete();
CREATE TABLE IF NOT EXISTS disk_records (
    disk_id TEXT PRIMARY KEY,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    name TEXT NOT NULL,
    volume_id TEXT NOT NULL UNIQUE REFERENCES volume_records(volume_id),
    size_bytes BIGINT NOT NULL CHECK (size_bytes > 0),
    durability TEXT NOT NULL CHECK (durability IN ('strict', 'relaxed')),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    admin_state TEXT NOT NULL CHECK (admin_state IN ('active', 'deleting')),
    delete_id TEXT,
    role_kind TEXT NOT NULL CHECK (role_kind IN ('root', 'persistent')),
    root_cat_id TEXT,
    initialization_kind TEXT CHECK (initialization_kind IN ('uninitialized', 'initialized')),
    initialization_token TEXT,
    filesystem_uuid TEXT,
    expected_blank_generation BIGINT,
    expected_blank_root_hash TEXT,
    expected_blank_root_object_id TEXT,
    initialized_generation BIGINT,
    initialized_root_hash TEXT,
    initialized_root_object_id TEXT,
    initialized_at BIGINT,
    initialization_commit_receipt_bytes BYTEA
        CONSTRAINT disk_records_initialization_commit_receipt_bytes_check
        CHECK (initialization_commit_receipt_bytes IS NULL OR
               octet_length(initialization_commit_receipt_bytes) BETWEEN 1 AND 2097152),
    initialization_commit_receipt_digest TEXT
        CONSTRAINT disk_records_initialization_commit_receipt_digest_check
        CHECK (initialization_commit_receipt_digest IS NULL OR
               initialization_commit_receipt_digest ~ '^sha256:[0-9a-f]{64}$'),
    UNIQUE (workspace_id, name),
    FOREIGN KEY (workspace_id, root_cat_id)
        REFERENCES cat_records(workspace_id, cat_id),
    CHECK (
        (admin_state = 'active' AND delete_id IS NULL) OR
        (admin_state = 'deleting' AND delete_id IS NOT NULL)
    ),
    CHECK ((
        (role_kind = 'root'
            AND name = disk_id
            AND root_cat_id IS NOT NULL
            AND initialization_kind IS NULL
            AND initialization_token IS NULL
            AND filesystem_uuid IS NULL
            AND expected_blank_generation IS NULL
            AND expected_blank_root_hash IS NULL
            AND expected_blank_root_object_id IS NULL
            AND initialized_generation IS NULL
            AND initialized_root_hash IS NULL
            AND initialized_root_object_id IS NULL
            AND initialized_at IS NULL
            AND initialization_commit_receipt_bytes IS NULL
            AND initialization_commit_receipt_digest IS NULL) OR
        (role_kind = 'persistent'
            AND root_cat_id IS NULL
            AND initialization_kind = 'uninitialized'
            AND initialization_token IS NOT NULL
            AND filesystem_uuid IS NOT NULL
            AND expected_blank_generation = 0
            AND expected_blank_root_hash IS NULL
            AND expected_blank_root_object_id IS NULL
            AND initialized_generation IS NULL
            AND initialized_root_hash IS NULL
            AND initialized_root_object_id IS NULL
            AND initialized_at IS NULL
            AND initialization_commit_receipt_bytes IS NULL
            AND initialization_commit_receipt_digest IS NULL) OR
        (role_kind = 'persistent'
            AND root_cat_id IS NULL
            AND initialization_kind = 'initialized'
            AND initialization_token IS NOT NULL
            AND filesystem_uuid IS NOT NULL
            AND expected_blank_generation = 0
            AND expected_blank_root_hash IS NULL
            AND expected_blank_root_object_id IS NULL
            AND initialized_generation > 0
            AND initialized_root_hash IS NOT NULL
            AND initialized_root_object_id IS NOT NULL
            AND initialized_at >= 0
            AND initialization_commit_receipt_bytes IS NOT NULL
            AND initialization_commit_receipt_digest IS NOT NULL)
    ) IS TRUE)
);
CREATE UNIQUE INDEX IF NOT EXISTS disk_records_one_root_per_cat
ON disk_records(root_cat_id) WHERE role_kind = 'root';
CREATE UNIQUE INDEX IF NOT EXISTS disk_records_initialization_token_unique
ON disk_records(initialization_token) WHERE role_kind = 'persistent';
CREATE UNIQUE INDEX IF NOT EXISTS disk_records_filesystem_uuid_unique
ON disk_records(filesystem_uuid) WHERE role_kind = 'persistent';
CREATE INDEX IF NOT EXISTS disk_records_record_root_cat
ON disk_records((record->'role'->>'cat_id'));
CREATE INDEX IF NOT EXISTS disk_records_record_volume
ON disk_records((record->>'volume_id'));
CREATE INDEX IF NOT EXISTS disk_records_lookup_scalar_scalar
ON disk_records(workspace_id COLLATE \"C\", disk_id COLLATE \"C\");
CREATE INDEX IF NOT EXISTS disk_records_lookup_scalar_record
ON disk_records(workspace_id COLLATE \"C\", (record->>'disk_id') COLLATE \"C\")
WHERE disk_id COLLATE \"C\" IS DISTINCT FROM (record->>'disk_id') COLLATE \"C\";
CREATE INDEX IF NOT EXISTS disk_records_lookup_record_scalar
ON disk_records((record->>'workspace_id') COLLATE \"C\", disk_id COLLATE \"C\")
WHERE workspace_id COLLATE \"C\" IS DISTINCT FROM (record->>'workspace_id') COLLATE \"C\";
CREATE INDEX IF NOT EXISTS disk_records_lookup_record_record
ON disk_records((record->>'workspace_id') COLLATE \"C\", (record->>'disk_id') COLLATE \"C\")
WHERE workspace_id COLLATE \"C\" IS DISTINCT FROM (record->>'workspace_id') COLLATE \"C\"
  AND disk_id COLLATE \"C\" IS DISTINCT FROM (record->>'disk_id') COLLATE \"C\";
CREATE TABLE IF NOT EXISTS disk_snapshot_records (
    snapshot_id TEXT PRIMARY KEY,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    disk_id TEXT NOT NULL REFERENCES disk_records(disk_id),
    volume_id TEXT NOT NULL REFERENCES volume_records(volume_id),
    size_bytes BIGINT NOT NULL CHECK (size_bytes > 0),
    head_generation BIGINT NOT NULL CHECK (head_generation >= 0),
    head_root_hash TEXT,
    head_root_object_id TEXT,
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    CHECK (
        (head_generation = 0 AND head_root_hash IS NULL AND head_root_object_id IS NULL) OR
        (head_generation > 0 AND head_root_hash IS NOT NULL AND head_root_object_id IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS disk_snapshot_records_disk
ON disk_snapshot_records(disk_id, snapshot_id);
CREATE INDEX IF NOT EXISTS disk_snapshot_records_volume
ON disk_snapshot_records(volume_id, snapshot_id);
CREATE INDEX IF NOT EXISTS disk_snapshot_records_record_disk
ON disk_snapshot_records((record->>'disk_id'), snapshot_id);
CREATE INDEX IF NOT EXISTS disk_snapshot_records_record_volume
ON disk_snapshot_records((record->>'volume_id'), snapshot_id);
CREATE TABLE IF NOT EXISTS cat_runtime_configs (
    config_id TEXT
        CONSTRAINT cat_runtime_configs_pkey PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    cat_id TEXT NOT NULL,
    canonical_config_bytes BYTEA NOT NULL
        CONSTRAINT cat_runtime_configs_bytes_check
        CHECK (octet_length(canonical_config_bytes) BETWEEN 1 AND 1048576),
    canonical_config_sha256 TEXT NOT NULL
        CONSTRAINT cat_runtime_configs_digest_check
        CHECK (canonical_config_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    placement_vcpus BIGINT NOT NULL
        CONSTRAINT cat_runtime_configs_placement_vcpus_check
        CHECK (placement_vcpus BETWEEN 1 AND 4294967295),
    placement_memory_bytes BIGINT NOT NULL
        CONSTRAINT cat_runtime_configs_placement_memory_check
        CHECK (placement_memory_bytes > 0),
    placement_network_id TEXT NOT NULL,
    placement_ipv4_pool_base BIGINT NOT NULL
        CONSTRAINT cat_runtime_configs_placement_ipv4_pool_base_check
        CHECK (placement_ipv4_pool_base BETWEEN 0 AND 4294901760),
    placement_ipv4_slot BIGINT NOT NULL
        CONSTRAINT cat_runtime_configs_placement_ipv4_slot_check
        CHECK (placement_ipv4_slot BETWEEN 1 AND 16383),
    placement_disk_ids TEXT[] NOT NULL
        CONSTRAINT cat_runtime_configs_placement_disk_ids_check
        CHECK (
            cardinality(placement_disk_ids) BETWEEN 1 AND 64
            AND array_position(placement_disk_ids, NULL) IS NULL
        ),
    placement_volume_ids TEXT[] NOT NULL
        CONSTRAINT cat_runtime_configs_placement_volume_ids_check
        CHECK (
            cardinality(placement_volume_ids) BETWEEN 1 AND 64
            AND array_position(placement_volume_ids, NULL) IS NULL
        ),
    CONSTRAINT cat_runtime_configs_placement_volume_cardinality_check
        CHECK (cardinality(placement_disk_ids) = cardinality(placement_volume_ids)),
    created_at_unix_ms BIGINT NOT NULL
        CONSTRAINT cat_runtime_configs_created_at_check
        CHECK (created_at_unix_ms >= 0),
    CONSTRAINT cat_runtime_configs_exact_key UNIQUE (
        workspace_id, cat_id, config_id, canonical_config_sha256
    ),
    CONSTRAINT cat_runtime_configs_workspace_cat_fkey
        FOREIGN KEY (workspace_id, cat_id)
        REFERENCES cat_records(workspace_id, cat_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE cat_records
    ADD CONSTRAINT cat_records_current_runtime_config_fkey
    FOREIGN KEY (
        workspace_id, cat_id,
        current_runtime_config_id, current_runtime_config_sha256
    ) REFERENCES cat_runtime_configs (
        workspace_id, cat_id, config_id, canonical_config_sha256
    ) ON UPDATE RESTRICT ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX IF NOT EXISTS cat_runtime_configs_cat_history
ON cat_runtime_configs(workspace_id, cat_id, created_at_unix_ms, config_id);
CREATE INDEX IF NOT EXISTS cat_runtime_configs_network_history
ON cat_runtime_configs(
    placement_network_id COLLATE \"C\", config_id COLLATE \"C\"
);
CREATE INDEX IF NOT EXISTS cat_runtime_configs_disk_membership
ON cat_runtime_configs USING GIN (placement_disk_ids);
CREATE INDEX IF NOT EXISTS cat_runtime_configs_volume_membership
ON cat_runtime_configs USING GIN (placement_volume_ids);
CREATE OR REPLACE FUNCTION control_cat_runtime_config_is_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'runtime configs are append-only immutable product history';
END;
$$;
CREATE TRIGGER cat_runtime_config_cannot_update
BEFORE UPDATE ON cat_runtime_configs FOR EACH ROW
EXECUTE FUNCTION control_cat_runtime_config_is_immutable();
CREATE TRIGGER cat_runtime_config_cannot_delete
BEFORE DELETE ON cat_runtime_configs FOR EACH ROW
EXECUTE FUNCTION control_cat_runtime_config_is_immutable();
CREATE TABLE IF NOT EXISTS hostname_endpoint_lookups (
    hostname TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    cat_id TEXT NOT NULL,
    endpoint_id TEXT NOT NULL UNIQUE,
    CONSTRAINT hostname_endpoint_lookup_endpoint_fkey
        FOREIGN KEY (workspace_id, cat_id, endpoint_id, hostname)
        REFERENCES endpoint_records(workspace_id, cat_id, endpoint_id, hostname)
        DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE IF NOT EXISTS runtime_operations (
    operation_id TEXT
        CONSTRAINT runtime_operations_pkey PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    cat_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    placement_epoch BIGINT NOT NULL
        CONSTRAINT runtime_operations_placement_epoch_check
        CHECK (placement_epoch > 0),
    command_kind TEXT NOT NULL
        CONSTRAINT runtime_operations_command_kind_check
        CHECK (command_kind IN (
            'start', 'suspend', 'warm', 'cold', 'stop', 'delete'
        )),
    canonical_request_bytes BYTEA NOT NULL
        CONSTRAINT runtime_operations_request_bytes_check
        CHECK (octet_length(canonical_request_bytes) BETWEEN 1 AND 1048576),
    canonical_request_sha256 TEXT NOT NULL
        CONSTRAINT runtime_operations_request_digest_check
        CHECK (canonical_request_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    runtime_config_id TEXT NOT NULL,
    runtime_config_sha256 TEXT NOT NULL
        CONSTRAINT runtime_operations_runtime_config_digest_check
        CHECK (runtime_config_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    expected_predecessor_operation_id TEXT,
    predecessor_kind TEXT NOT NULL
        CONSTRAINT runtime_operations_predecessor_kind_check
        CHECK (predecessor_kind IN (
            'genesis', 'same_node', 'cross_node_cold_handoff',
            'host_fence_recovery'
        )),
    expected_predecessor_result_kind TEXT,
    expected_predecessor_result_sha256 TEXT
        CONSTRAINT runtime_operations_predecessor_digest_check
        CHECK (expected_predecessor_result_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    state TEXT NOT NULL
        CONSTRAINT runtime_operations_state_check
        CHECK (state IN ('unresolved', 'terminal')),
    terminal_source TEXT
        CONSTRAINT runtime_operations_terminal_source_check
        CHECK (terminal_source IN ('node_result', 'host_lost')),
    terminal_result_kind TEXT
        CONSTRAINT runtime_operations_terminal_result_kind_check
        CHECK (terminal_result_kind IN (
            'runtime_ready', 'start_failed',
            'suspended', 'suspend_declined', 'suspend_failed',
            'warm', 'warm_failed', 'cold', 'killed', 'deleted',
            'needs_intervention', 'host_lost'
        )),
    canonical_result_bytes BYTEA
        CONSTRAINT runtime_operations_result_bytes_check
        CHECK (canonical_result_bytes IS NULL OR
               octet_length(canonical_result_bytes) BETWEEN 1 AND 1048576),
    canonical_result_sha256 TEXT
        CONSTRAINT runtime_operations_result_digest_check
        CHECK (canonical_result_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    created_at_unix_ms BIGINT NOT NULL
        CONSTRAINT runtime_operations_created_at_check
        CHECK (created_at_unix_ms >= 0),
    terminal_at_unix_ms BIGINT
        CONSTRAINT runtime_operations_terminal_at_check
        CHECK (terminal_at_unix_ms >= created_at_unix_ms),
    CONSTRAINT runtime_operations_workspace_cat_fkey
        FOREIGN KEY (workspace_id, cat_id)
        REFERENCES cat_records(workspace_id, cat_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT runtime_operations_exact_runtime_config_fkey
        FOREIGN KEY (
            workspace_id, cat_id, runtime_config_id, runtime_config_sha256
        ) REFERENCES cat_runtime_configs (
            workspace_id, cat_id, config_id, canonical_config_sha256
        ) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT runtime_operations_cat_operation_key
        UNIQUE (cat_id, operation_id),
    CONSTRAINT runtime_operations_predecessor_result_key
        UNIQUE (
            cat_id, operation_id, terminal_result_kind,
            canonical_result_sha256
        ),
    CONSTRAINT runtime_operations_receipt_scope_key UNIQUE (
        operation_id, canonical_request_sha256, workspace_id, cat_id,
        node_id, placement_epoch, runtime_config_id, runtime_config_sha256,
        command_kind
    ),
    CONSTRAINT runtime_operations_request_scope_key UNIQUE (
        operation_id, canonical_request_sha256
    ),
    CONSTRAINT runtime_operations_exact_predecessor_fkey
        FOREIGN KEY (
            cat_id, expected_predecessor_operation_id,
            expected_predecessor_result_kind,
            expected_predecessor_result_sha256
        ) REFERENCES runtime_operations (
            cat_id, operation_id, terminal_result_kind,
            canonical_result_sha256
        ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT runtime_operations_predecessor_shape_check CHECK (
        (predecessor_kind = 'genesis'
            AND expected_predecessor_operation_id IS NULL
            AND expected_predecessor_result_kind IS NULL
            AND expected_predecessor_result_sha256 IS NULL) OR
        (predecessor_kind <> 'genesis'
            AND expected_predecessor_operation_id IS NOT NULL
            AND expected_predecessor_result_kind IS NOT NULL
            AND expected_predecessor_result_sha256 IS NOT NULL)
    ),
    CONSTRAINT runtime_operations_typed_predecessor_check CHECK (
        (predecessor_kind <> 'cross_node_cold_handoff'
            OR expected_predecessor_result_kind = 'cold')
        AND (predecessor_kind <> 'host_fence_recovery'
            OR expected_predecessor_result_kind = 'host_lost')
    ),
    CONSTRAINT runtime_operations_terminal_shape_check CHECK (
        (state = 'unresolved'
            AND terminal_source IS NULL
            AND terminal_result_kind IS NULL
            AND canonical_result_bytes IS NULL
            AND canonical_result_sha256 IS NULL
            AND terminal_at_unix_ms IS NULL) OR
        (state = 'terminal'
            AND terminal_source IS NOT NULL
            AND terminal_result_kind IS NOT NULL
            AND canonical_result_bytes IS NOT NULL
            AND canonical_result_sha256 IS NOT NULL
            AND terminal_at_unix_ms IS NOT NULL)
    ),
    CONSTRAINT runtime_operations_terminal_source_shape_check CHECK (
        (terminal_source IS NULL AND terminal_result_kind IS NULL) OR
        (terminal_source = 'host_lost' AND terminal_result_kind = 'host_lost') OR
        (terminal_source = 'node_result' AND terminal_result_kind <> 'host_lost')
    ),
    CONSTRAINT runtime_operations_command_result_check CHECK (
        terminal_source IS DISTINCT FROM 'node_result' OR
        (command_kind = 'start'
            AND terminal_result_kind IN ('runtime_ready', 'start_failed')) OR
        (command_kind = 'suspend'
            AND terminal_result_kind IN (
                'suspended', 'suspend_declined', 'suspend_failed'
            )) OR
        (command_kind = 'warm'
            AND terminal_result_kind IN (
                'warm', 'warm_failed', 'needs_intervention'
            )) OR
        (command_kind = 'cold'
            AND terminal_result_kind IN (
                'cold', 'needs_intervention'
            )) OR
        (command_kind = 'stop' AND terminal_result_kind = 'killed') OR
        (command_kind = 'delete'
            AND terminal_result_kind IN (
                'deleted', 'needs_intervention'
            ))
    )
);
ALTER TABLE volume_records
    ADD CONSTRAINT volume_records_lifecycle_transition_operation_fkey
    FOREIGN KEY (transition_operation_id, transition_request_fingerprint)
    REFERENCES runtime_operations(operation_id, canonical_request_sha256)
    ON UPDATE RESTRICT ON DELETE RESTRICT;
CREATE UNIQUE INDEX IF NOT EXISTS runtime_operations_one_unresolved_per_cat
ON runtime_operations(cat_id) WHERE state = 'unresolved';
CREATE UNIQUE INDEX IF NOT EXISTS runtime_operations_one_genesis_per_cat
ON runtime_operations(cat_id)
WHERE expected_predecessor_operation_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS runtime_operations_one_successor_per_predecessor
ON runtime_operations(cat_id, expected_predecessor_operation_id)
WHERE expected_predecessor_operation_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS runtime_operations_workspace_lookup
ON runtime_operations(workspace_id COLLATE \"C\", operation_id COLLATE \"C\");
CREATE OR REPLACE FUNCTION control_runtime_operation_transition_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (OLD.operation_id, OLD.workspace_id, OLD.cat_id, OLD.node_id,
        OLD.placement_epoch, OLD.command_kind, OLD.canonical_request_bytes,
        OLD.canonical_request_sha256, OLD.runtime_config_id,
        OLD.runtime_config_sha256, OLD.expected_predecessor_operation_id,
        OLD.predecessor_kind, OLD.expected_predecessor_result_kind,
        OLD.expected_predecessor_result_sha256, OLD.created_at_unix_ms)
       IS DISTINCT FROM
       (NEW.operation_id, NEW.workspace_id, NEW.cat_id, NEW.node_id,
        NEW.placement_epoch, NEW.command_kind, NEW.canonical_request_bytes,
        NEW.canonical_request_sha256, NEW.runtime_config_id,
        NEW.runtime_config_sha256, NEW.expected_predecessor_operation_id,
        NEW.predecessor_kind, NEW.expected_predecessor_result_kind,
        NEW.expected_predecessor_result_sha256, NEW.created_at_unix_ms)
       OR OLD.state <> 'unresolved'
       OR NEW.state <> 'terminal'
    THEN
        RAISE EXCEPTION 'invalid runtime lifecycle Operation transition';
    END IF;
    RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION control_runtime_operation_cannot_delete()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'runtime lifecycle Operations cannot be deleted';
END;
$$;
CREATE TRIGGER runtime_operation_transition_is_forward_only
BEFORE UPDATE ON runtime_operations FOR EACH ROW
EXECUTE FUNCTION control_runtime_operation_transition_guard();
CREATE TRIGGER runtime_operation_cannot_delete
BEFORE DELETE ON runtime_operations FOR EACH ROW
EXECUTE FUNCTION control_runtime_operation_cannot_delete();
CREATE TABLE IF NOT EXISTS lifecycle_volume_receipts (
    operation_id TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL
        CONSTRAINT lifecycle_volume_receipts_request_digest_check
        CHECK (request_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    workspace_id TEXT NOT NULL,
    cat_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    placement_epoch BIGINT NOT NULL
        CONSTRAINT lifecycle_volume_receipts_placement_epoch_check
        CHECK (placement_epoch > 0),
    runtime_config_id TEXT NOT NULL,
    runtime_config_sha256 TEXT NOT NULL
        CONSTRAINT lifecycle_volume_receipts_runtime_config_digest_check
        CHECK (runtime_config_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    source_command_kind TEXT NOT NULL
        CONSTRAINT lifecycle_volume_receipts_command_kind_check
        CHECK (source_command_kind IN ('start', 'cold', 'delete')),
    delete_id TEXT,
    disk_id TEXT NOT NULL,
    volume_id TEXT NOT NULL,
    disk_role TEXT NOT NULL
        CONSTRAINT lifecycle_volume_receipts_disk_role_check
        CHECK (disk_role IN ('root', 'persistent')),
    receipt_kind TEXT NOT NULL
        CONSTRAINT lifecycle_volume_receipts_kind_check
        CHECK (receipt_kind IN (
            'start_grant', 'normal_release', 'already_unowned',
            'disposable_consumed', 'delete_completion'
        )),
    receipt_sequence BIGINT NOT NULL
        CONSTRAINT lifecycle_volume_receipts_sequence_check
        CHECK (receipt_sequence >= 0),
    canonical_receipt_bytes BYTEA NOT NULL
        CONSTRAINT lifecycle_volume_receipts_bytes_check
        CHECK (octet_length(canonical_receipt_bytes) BETWEEN 1 AND 1048576),
    receipt_digest TEXT NOT NULL
        CONSTRAINT lifecycle_volume_receipts_digest_check
        CHECK (receipt_digest ~ '^sha256:[0-9a-f]{64}$'),
    created_at_unix_ms BIGINT NOT NULL
        CONSTRAINT lifecycle_volume_receipts_created_at_check
        CHECK (created_at_unix_ms >= 0),
    CONSTRAINT lifecycle_volume_receipts_pkey
        PRIMARY KEY (operation_id, volume_id, receipt_kind, receipt_sequence),
    CONSTRAINT lifecycle_volume_receipts_exact_operation_fkey
        FOREIGN KEY (
            operation_id, request_fingerprint, workspace_id, cat_id,
            node_id, placement_epoch, runtime_config_id, runtime_config_sha256,
            source_command_kind
        ) REFERENCES runtime_operations (
            operation_id, canonical_request_sha256, workspace_id, cat_id,
            node_id, placement_epoch, runtime_config_id, runtime_config_sha256,
            command_kind
        ) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT lifecycle_volume_receipts_operation_disk_unique
        UNIQUE (operation_id, disk_id, receipt_kind, receipt_sequence),
    CONSTRAINT lifecycle_volume_receipts_command_shape_check CHECK (
        (source_command_kind = 'start'
            AND receipt_kind = 'start_grant'
            AND delete_id IS NULL) OR
        (source_command_kind = 'cold'
            AND receipt_kind IN ('normal_release', 'already_unowned')
            AND receipt_sequence = 0
            AND delete_id IS NULL) OR
        (source_command_kind = 'delete'
            AND receipt_sequence = 0
            AND delete_id IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS lifecycle_volume_receipts_stable_lookup
ON lifecycle_volume_receipts(operation_id, receipt_kind, receipt_sequence, volume_id);
CREATE INDEX IF NOT EXISTS lifecycle_volume_receipts_delete_lookup
ON lifecycle_volume_receipts(volume_id, delete_id, receipt_kind, operation_id);
CREATE OR REPLACE FUNCTION control_lifecycle_volume_receipt_is_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'lifecycle volume receipts are immutable command evidence';
END;
$$;
CREATE TRIGGER lifecycle_volume_receipt_cannot_update
BEFORE UPDATE ON lifecycle_volume_receipts FOR EACH ROW
EXECUTE FUNCTION control_lifecycle_volume_receipt_is_immutable();
CREATE TRIGGER lifecycle_volume_receipt_cannot_delete
BEFORE DELETE ON lifecycle_volume_receipts FOR EACH ROW
EXECUTE FUNCTION control_lifecycle_volume_receipt_is_immutable();
CREATE OR REPLACE FUNCTION control_cat_record_identity_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (OLD.cat_id, OLD.record, OLD.workspace_id, OLD.name,
        OLD.cat_creation_id, OLD.created_at)
       IS DISTINCT FROM
       (NEW.cat_id, NEW.record, NEW.workspace_id, NEW.name,
        NEW.cat_creation_id, NEW.created_at)
       OR (OLD.deleted_at IS NOT NULL AND
           (OLD.lifecycle_head_operation_id, OLD.stable_state,
            OLD.effective_runtime_ready_operation_id,
            OLD.runtime_incarnation, OLD.current_runtime_config_id,
            OLD.current_runtime_config_sha256, OLD.deleted_at)
           IS DISTINCT FROM
           (NEW.lifecycle_head_operation_id, NEW.stable_state,
            NEW.effective_runtime_ready_operation_id,
            NEW.runtime_incarnation, NEW.current_runtime_config_id,
            NEW.current_runtime_config_sha256, NEW.deleted_at))
    THEN
        RAISE EXCEPTION 'Cat identity and creation authority are immutable';
    END IF;
    IF (OLD.current_runtime_config_id, OLD.current_runtime_config_sha256)
       IS DISTINCT FROM
       (NEW.current_runtime_config_id, NEW.current_runtime_config_sha256)
       AND (OLD.stable_state IS DISTINCT FROM 'cold'
            OR NEW.stable_state IS DISTINCT FROM 'cold'
            OR EXISTS (
                SELECT 1 FROM runtime_operations
                 WHERE cat_id=OLD.cat_id AND state='unresolved'
            ))
    THEN
        RAISE EXCEPTION 'runtime config may advance only from terminal Cold with no unresolved Operation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION control_cat_record_cannot_delete()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Cat lifecycle membership is retired by tombstone, not deletion';
END;
$$;
CREATE TRIGGER cat_record_identity_is_immutable
BEFORE UPDATE ON cat_records FOR EACH ROW
EXECUTE FUNCTION control_cat_record_identity_guard();
CREATE TRIGGER cat_record_cannot_delete
BEFORE DELETE ON cat_records FOR EACH ROW
EXECUTE FUNCTION control_cat_record_cannot_delete();
CREATE TABLE IF NOT EXISTS api_idempotency_results (
    authenticated_workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    canonical_route TEXT NOT NULL CHECK (
        octet_length(canonical_route) BETWEEN 1 AND 512
        AND canonical_route ~ '^[ -~]+$'
    ),
    idempotency_key TEXT NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 512
        AND idempotency_key ~ '^[ -~]+$'
    ),
    request_fingerprint TEXT NOT NULL
        CHECK (request_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    http_status SMALLINT NOT NULL CHECK (http_status BETWEEN 200 AND 599),
    content_type TEXT CHECK (content_type = 'application/json'),
    response_body BYTEA NOT NULL CHECK (octet_length(response_body) <= 1048576),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (authenticated_workspace_id, canonical_route, idempotency_key)
);
-- ADR-0051/0052: immutable operator commands and the one production mutation
-- admission pointer.  The pointer is born Closed at revision 1.  Qualification
-- is a time-bounded, exact-workspace release test scope; it is not an Open
-- binding with missing proofs.  Repeated projections make the sum type and its
-- nullability closed in PostgreSQL as well as in the canonical JSON decoder.
CREATE TABLE IF NOT EXISTS production_mutation_admission_commands (
    command_id TEXT PRIMARY KEY
        CONSTRAINT production_mutation_admission_commands_id_ck
        CHECK (command_id ~ '^[0-9a-f]{32}$'),
    command JSONB NOT NULL
        CONSTRAINT production_mutation_admission_commands_command_ck
        CHECK (jsonb_typeof(command) = 'object'),
    request_sha256 TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_request_digest_ck
        CHECK (request_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    principal JSONB NOT NULL
        CONSTRAINT production_mutation_admission_commands_principal_ck
        CHECK (jsonb_typeof(principal) = 'object'),
    principal_kind TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_principal_kind_ck
        CHECK (principal_kind = 'production_cutover_operator'),
    operator_credential_id TEXT NOT NULL,
    operator_public_key_spki_sha256 TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_operator_key_ck
        CHECK (operator_public_key_spki_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    operator_trust_bundle_sha256 TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_operator_trust_ck
        CHECK (operator_trust_bundle_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    operator_aws_partition TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_operator_partition_ck
        CHECK (operator_aws_partition IN ('aws', 'aws-us-gov', 'aws-cn')),
    operator_account_id TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_operator_account_ck
        CHECK (operator_account_id ~ '^[0-9]{12}$'),
    operator_role_arn TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_operator_role_ck
        CHECK (octet_length(operator_role_arn) BETWEEN 1 AND 2048),
    operator_principal_arn TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_operator_principal_ck
        CHECK (octet_length(operator_principal_arn) BETWEEN 1 AND 2048),
    issued_at_unix_ms BIGINT NOT NULL
        CONSTRAINT production_mutation_admission_commands_issued_time_ck
        CHECK (issued_at_unix_ms >= 0),
    expires_at_unix_ms BIGINT NOT NULL
        CONSTRAINT production_mutation_admission_commands_expiry_time_ck
        CHECK (expires_at_unix_ms > issued_at_unix_ms
            AND expires_at_unix_ms - issued_at_unix_ms <= 300000),
    expected_revision BIGINT NOT NULL
        CONSTRAINT production_mutation_admission_commands_expected_revision_ck
        CHECK (expected_revision > 0),
    mutation_kind TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_mutation_kind_ck
        CHECK (mutation_kind IN (
            'begin_qualification', 'end_qualification', 'open', 'emergency_close'
        )),
    target_mode TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_target_mode_ck
        CHECK (target_mode IN ('closed', 'qualification', 'open')),
    binding_kind TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_binding_kind_ck
        CHECK (binding_kind IN ('qualification', 'open')),
    binding_sha256 TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_binding_digest_ck
        CHECK (binding_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    qualification_id TEXT NULL,
    reset_id TEXT NULL,
    deployment_id TEXT NOT NULL,
    release_id TEXT NOT NULL,
    source_commit_sha TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_source_commit_ck
        CHECK (source_commit_sha ~ '^[0-9a-f]{40}$'),
    control_schema_version BIGINT NOT NULL
        CONSTRAINT production_mutation_admission_commands_schema_ck
        CHECK (control_schema_version = 19),
    source_manifest_sha256 TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_source_manifest_ck
        CHECK (source_manifest_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    source_bundle_sha256 TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_source_bundle_ck
        CHECK (source_bundle_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    build_receipt_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_commands_build_receipt_ck
        CHECK (build_receipt_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    release_manifest_sha256 TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_release_manifest_ck
        CHECK (release_manifest_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    worker_bundle_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_commands_worker_bundle_ck
        CHECK (worker_bundle_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    qualification_manifest_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_commands_qualification_manifest_ck
        CHECK (qualification_manifest_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    qualification_catalog_sha256 TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_qualification_catalog_ck
        CHECK (qualification_catalog_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    proof_set_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_commands_proof_set_ck
        CHECK (proof_set_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    fresh_targets_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_commands_fresh_targets_ck
        CHECK (fresh_targets_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    reset_complete_receipt_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_commands_reset_complete_ck
        CHECK (reset_complete_receipt_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    fleet_closed_receipt_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_commands_fleet_closed_ck
        CHECK (fleet_closed_receipt_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    route_v2_rotation_qualification_receipt_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_commands_route_v2_qualification_ck
        CHECK (route_v2_rotation_qualification_receipt_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    route_v2_rotation_qualification_node_ack_sets_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_commands_route_v2_node_acks_ck
        CHECK (route_v2_rotation_qualification_node_ack_sets_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    route_v2_rotation_qualification_transcript_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_commands_route_v2_transcript_ck
        CHECK (route_v2_rotation_qualification_transcript_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    usage_terminal_receipt_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_commands_usage_terminal_ck
        CHECK (usage_terminal_receipt_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    old_host_coverage_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_commands_host_coverage_ck
        CHECK (old_host_coverage_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    kernel_nbd_qualification_bundle_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_commands_kernel_nbd_ck
        CHECK (kernel_nbd_qualification_bundle_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    vhost_user_qualification_bundle_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_commands_vhost_user_ck
        CHECK (vhost_user_qualification_bundle_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    qualification_cell_manifest_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_commands_qualification_cell_manifest_ck
        CHECK (qualification_cell_manifest_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    qualification_aws_partition TEXT NULL
        CONSTRAINT production_mutation_admission_commands_qualification_partition_ck
        CHECK (qualification_aws_partition IN ('aws', 'aws-us-gov', 'aws-cn')),
    qualification_aws_account_id TEXT NULL
        CONSTRAINT production_mutation_admission_commands_qualification_aws_account_ck
        CHECK (qualification_aws_account_id ~ '^[0-9]{12}$'),
    qualification_aws_region TEXT NULL
        CONSTRAINT production_mutation_admission_commands_qualification_region_ck
        CHECK (qualification_aws_region ~ '^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$'),
    qualification_cell_id TEXT NULL,
    qualification_cell_namespace TEXT NULL
        CONSTRAINT production_mutation_admission_commands_qualification_namespace_ck
        CHECK (qualification_cell_namespace ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    qualification_cats_account_id TEXT NULL,
    qualification_workspace_id TEXT NULL,
    qualification_mutation_classes JSONB NULL
        CONSTRAINT production_mutation_admission_commands_qualification_classes_ck
        CHECK (jsonb_typeof(qualification_mutation_classes) = 'array'
            AND qualification_mutation_classes =
                '[\"cat_create\",\"disk_create\",\"disk_delete\",\"object_write_ambiguity\",\"runtime_mutation\"]'::jsonb),
    qualification_expires_at_unix_ms BIGINT NULL
        CONSTRAINT production_mutation_admission_commands_qualification_expiry_ck
        CHECK (qualification_expires_at_unix_ms > 0),
    outcome JSONB NOT NULL
        CONSTRAINT production_mutation_admission_commands_outcome_ck
        CHECK (jsonb_typeof(outcome) = 'object'),
    outcome_kind TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_outcome_kind_ck
        CHECK (outcome_kind IN ('applied', 'authority_precondition_failed')),
    resulting_revision BIGINT NULL
        CONSTRAINT production_mutation_admission_commands_result_revision_ck
        CHECK (resulting_revision > 0),
    resulting_mode TEXT NULL
        CONSTRAINT production_mutation_admission_commands_result_mode_ck
        CHECK (resulting_mode IN ('closed', 'qualification', 'open')),
    committed_at_unix_ms BIGINT NOT NULL
        CONSTRAINT production_mutation_admission_commands_time_ck
        CHECK (committed_at_unix_ms >= 0),
    CONSTRAINT production_mutation_admission_commands_terminal_ck CHECK (
        (outcome_kind = 'applied'
            AND resulting_revision = expected_revision + 1
            AND resulting_mode = target_mode) OR
        (outcome_kind = 'authority_precondition_failed'
            AND resulting_revision IS NULL AND resulting_mode IS NULL)
    ),
    CONSTRAINT production_mutation_admission_commands_mutation_target_ck CHECK (
        (mutation_kind = 'begin_qualification'
            AND binding_kind = 'qualification' AND target_mode = 'qualification') OR
        (mutation_kind = 'end_qualification'
            AND binding_kind = 'qualification' AND target_mode = 'closed') OR
        (mutation_kind = 'open'
            AND binding_kind = 'open' AND target_mode = 'open') OR
        (mutation_kind = 'emergency_close' AND target_mode = 'closed')
    ),
    CONSTRAINT production_mutation_admission_commands_binding_closed_ck CHECK (
        (binding_kind = 'qualification'
            AND qualification_id IS NOT NULL AND reset_id IS NULL
            AND build_receipt_sha256 IS NOT NULL
            AND worker_bundle_sha256 IS NOT NULL
            AND qualification_manifest_sha256 IS NULL
            AND proof_set_sha256 IS NULL AND fresh_targets_sha256 IS NULL
            AND reset_complete_receipt_sha256 IS NULL
            AND fleet_closed_receipt_sha256 IS NULL
            AND route_v2_rotation_qualification_receipt_sha256 IS NULL
            AND route_v2_rotation_qualification_node_ack_sets_sha256 IS NULL
            AND route_v2_rotation_qualification_transcript_sha256 IS NULL
            AND usage_terminal_receipt_sha256 IS NULL
            AND old_host_coverage_sha256 IS NULL
            AND kernel_nbd_qualification_bundle_sha256 IS NULL
            AND vhost_user_qualification_bundle_sha256 IS NULL
            AND qualification_cell_manifest_sha256 IS NOT NULL
            AND qualification_aws_partition IS NOT NULL
            AND qualification_aws_account_id IS NOT NULL
            AND qualification_aws_region IS NOT NULL
            AND qualification_cell_id IS NOT NULL
            AND qualification_cell_namespace IS NOT NULL
            AND qualification_cats_account_id IS NOT NULL
            AND qualification_workspace_id IS NOT NULL
            AND qualification_mutation_classes IS NOT NULL
            AND qualification_expires_at_unix_ms IS NOT NULL) OR
        (binding_kind = 'open'
            AND qualification_id IS NULL AND reset_id IS NOT NULL
            AND build_receipt_sha256 IS NULL AND worker_bundle_sha256 IS NULL
            AND qualification_manifest_sha256 IS NOT NULL
            AND proof_set_sha256 IS NOT NULL AND fresh_targets_sha256 IS NOT NULL
            AND reset_complete_receipt_sha256 IS NOT NULL
            AND fleet_closed_receipt_sha256 IS NOT NULL
            AND route_v2_rotation_qualification_receipt_sha256 IS NOT NULL
            AND route_v2_rotation_qualification_node_ack_sets_sha256 IS NOT NULL
            AND route_v2_rotation_qualification_transcript_sha256 IS NOT NULL
            AND usage_terminal_receipt_sha256 IS NOT NULL
            AND old_host_coverage_sha256 IS NOT NULL
            AND kernel_nbd_qualification_bundle_sha256 IS NOT NULL
            AND vhost_user_qualification_bundle_sha256 IS NOT NULL
            AND qualification_cell_manifest_sha256 IS NULL
            AND qualification_aws_partition IS NULL
            AND qualification_aws_account_id IS NULL
            AND qualification_aws_region IS NULL
            AND qualification_cell_id IS NULL
            AND qualification_cell_namespace IS NULL
            AND qualification_cats_account_id IS NULL
            AND qualification_workspace_id IS NULL
            AND qualification_mutation_classes IS NULL
            AND qualification_expires_at_unix_ms IS NULL)
    ),
    CONSTRAINT production_mutation_admission_commands_state_key
        UNIQUE (command_id, resulting_revision, resulting_mode, binding_sha256)
);
CREATE TABLE IF NOT EXISTS production_mutation_admission (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE
        CONSTRAINT production_mutation_admission_singleton_ck CHECK (singleton),
    revision BIGINT NOT NULL
        CONSTRAINT production_mutation_admission_revision_ck CHECK (revision > 0),
    mode TEXT NOT NULL
        CONSTRAINT production_mutation_admission_mode_ck
        CHECK (mode IN ('closed', 'qualification', 'open')),
    binding JSONB NULL
        CONSTRAINT production_mutation_admission_binding_json_ck
        CHECK (jsonb_typeof(binding) = 'object'),
    binding_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_binding_digest_ck
        CHECK (binding_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    binding_kind TEXT NULL
        CONSTRAINT production_mutation_admission_binding_kind_ck
        CHECK (binding_kind IN ('qualification', 'open')),
    qualification_id TEXT NULL,
    reset_id TEXT NULL,
    deployment_id TEXT NULL,
    release_id TEXT NULL,
    source_commit_sha TEXT NULL
        CONSTRAINT production_mutation_admission_source_commit_ck
        CHECK (source_commit_sha ~ '^[0-9a-f]{40}$'),
    control_schema_version BIGINT NULL
        CONSTRAINT production_mutation_admission_schema_ck
        CHECK (control_schema_version = 19),
    source_manifest_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_source_manifest_ck
        CHECK (source_manifest_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    source_bundle_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_source_bundle_ck
        CHECK (source_bundle_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    build_receipt_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_build_receipt_ck
        CHECK (build_receipt_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    release_manifest_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_release_manifest_ck
        CHECK (release_manifest_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    worker_bundle_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_worker_bundle_ck
        CHECK (worker_bundle_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    qualification_manifest_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_qualification_manifest_ck
        CHECK (qualification_manifest_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    qualification_catalog_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_qualification_catalog_ck
        CHECK (qualification_catalog_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    proof_set_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_proof_set_ck
        CHECK (proof_set_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    fresh_targets_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_fresh_targets_ck
        CHECK (fresh_targets_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    reset_complete_receipt_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_reset_complete_ck
        CHECK (reset_complete_receipt_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    fleet_closed_receipt_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_fleet_closed_ck
        CHECK (fleet_closed_receipt_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    route_v2_rotation_qualification_receipt_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_route_v2_qualification_ck
        CHECK (route_v2_rotation_qualification_receipt_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    route_v2_rotation_qualification_node_ack_sets_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_route_v2_node_acks_ck
        CHECK (route_v2_rotation_qualification_node_ack_sets_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    route_v2_rotation_qualification_transcript_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_route_v2_transcript_ck
        CHECK (route_v2_rotation_qualification_transcript_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    usage_terminal_receipt_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_usage_terminal_ck
        CHECK (usage_terminal_receipt_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    old_host_coverage_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_host_coverage_ck
        CHECK (old_host_coverage_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    kernel_nbd_qualification_bundle_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_kernel_nbd_ck
        CHECK (kernel_nbd_qualification_bundle_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    vhost_user_qualification_bundle_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_vhost_user_ck
        CHECK (vhost_user_qualification_bundle_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    qualification_cell_manifest_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_qualification_cell_manifest_ck
        CHECK (qualification_cell_manifest_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    qualification_aws_partition TEXT NULL
        CONSTRAINT production_mutation_admission_qualification_partition_ck
        CHECK (qualification_aws_partition IN ('aws', 'aws-us-gov', 'aws-cn')),
    qualification_aws_account_id TEXT NULL
        CONSTRAINT production_mutation_admission_qualification_aws_account_ck
        CHECK (qualification_aws_account_id ~ '^[0-9]{12}$'),
    qualification_aws_region TEXT NULL
        CONSTRAINT production_mutation_admission_qualification_region_ck
        CHECK (qualification_aws_region ~ '^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$'),
    qualification_cell_id TEXT NULL,
    qualification_cell_namespace TEXT NULL
        CONSTRAINT production_mutation_admission_qualification_namespace_ck
        CHECK (qualification_cell_namespace ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    qualification_cats_account_id TEXT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    qualification_workspace_id TEXT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
    qualification_mutation_classes JSONB NULL
        CONSTRAINT production_mutation_admission_qualification_classes_ck
        CHECK (jsonb_typeof(qualification_mutation_classes) = 'array'
            AND qualification_mutation_classes =
                '[\"cat_create\",\"disk_create\",\"disk_delete\",\"object_write_ambiguity\",\"runtime_mutation\"]'::jsonb),
    qualification_expires_at_unix_ms BIGINT NULL
        CONSTRAINT production_mutation_admission_qualification_expiry_ck
        CHECK (qualification_expires_at_unix_ms > 0),
    last_command_id TEXT NULL
        CONSTRAINT production_mutation_admission_last_command_key UNIQUE,
    updated_at_unix_ms BIGINT NOT NULL
        CONSTRAINT production_mutation_admission_time_ck
        CHECK (updated_at_unix_ms >= 0),
    CONSTRAINT production_mutation_admission_initial_or_bound_ck CHECK (
        (binding IS NULL AND binding_sha256 IS NULL AND binding_kind IS NULL
            AND qualification_id IS NULL AND reset_id IS NULL
            AND deployment_id IS NULL AND release_id IS NULL
            AND source_commit_sha IS NULL AND control_schema_version IS NULL
            AND source_manifest_sha256 IS NULL AND source_bundle_sha256 IS NULL
            AND build_receipt_sha256 IS NULL
            AND release_manifest_sha256 IS NULL
            AND worker_bundle_sha256 IS NULL
            AND qualification_manifest_sha256 IS NULL
            AND qualification_catalog_sha256 IS NULL
            AND proof_set_sha256 IS NULL
            AND fresh_targets_sha256 IS NULL
            AND reset_complete_receipt_sha256 IS NULL
            AND fleet_closed_receipt_sha256 IS NULL
            AND route_v2_rotation_qualification_receipt_sha256 IS NULL
            AND route_v2_rotation_qualification_node_ack_sets_sha256 IS NULL
            AND route_v2_rotation_qualification_transcript_sha256 IS NULL
            AND usage_terminal_receipt_sha256 IS NULL
            AND old_host_coverage_sha256 IS NULL
            AND kernel_nbd_qualification_bundle_sha256 IS NULL
            AND vhost_user_qualification_bundle_sha256 IS NULL
            AND qualification_cell_manifest_sha256 IS NULL
            AND qualification_aws_partition IS NULL
            AND qualification_aws_account_id IS NULL
            AND qualification_aws_region IS NULL
            AND qualification_cell_id IS NULL
            AND qualification_cell_namespace IS NULL
            AND qualification_cats_account_id IS NULL
            AND qualification_workspace_id IS NULL
            AND qualification_mutation_classes IS NULL
            AND qualification_expires_at_unix_ms IS NULL
            AND mode = 'closed' AND revision = 1
            AND last_command_id IS NULL AND updated_at_unix_ms = 0) OR
        (binding IS NOT NULL AND binding_sha256 IS NOT NULL
            AND binding_kind = 'qualification'
            AND qualification_id IS NOT NULL AND reset_id IS NULL
            AND deployment_id IS NOT NULL
            AND release_id IS NOT NULL AND source_commit_sha IS NOT NULL
            AND control_schema_version IS NOT NULL
            AND source_manifest_sha256 IS NOT NULL
            AND source_bundle_sha256 IS NOT NULL
            AND build_receipt_sha256 IS NOT NULL
            AND release_manifest_sha256 IS NOT NULL
            AND worker_bundle_sha256 IS NOT NULL
            AND qualification_manifest_sha256 IS NULL
            AND qualification_catalog_sha256 IS NOT NULL
            AND proof_set_sha256 IS NULL AND fresh_targets_sha256 IS NULL
            AND reset_complete_receipt_sha256 IS NULL
            AND fleet_closed_receipt_sha256 IS NULL
            AND route_v2_rotation_qualification_receipt_sha256 IS NULL
            AND route_v2_rotation_qualification_node_ack_sets_sha256 IS NULL
            AND route_v2_rotation_qualification_transcript_sha256 IS NULL
            AND usage_terminal_receipt_sha256 IS NULL
            AND old_host_coverage_sha256 IS NULL
            AND kernel_nbd_qualification_bundle_sha256 IS NULL
            AND vhost_user_qualification_bundle_sha256 IS NULL
            AND qualification_cell_manifest_sha256 IS NOT NULL
            AND qualification_aws_partition IS NOT NULL
            AND qualification_aws_account_id IS NOT NULL
            AND qualification_aws_region IS NOT NULL
            AND qualification_cell_id IS NOT NULL
            AND qualification_cell_namespace IS NOT NULL
            AND qualification_cats_account_id IS NOT NULL
            AND qualification_workspace_id IS NOT NULL
            AND qualification_mutation_classes IS NOT NULL
            AND qualification_expires_at_unix_ms IS NOT NULL
            AND mode IN ('closed', 'qualification')
            AND last_command_id IS NOT NULL) OR
        (binding IS NOT NULL AND binding_sha256 IS NOT NULL
            AND binding_kind = 'open'
            AND qualification_id IS NULL AND reset_id IS NOT NULL
            AND deployment_id IS NOT NULL AND release_id IS NOT NULL
            AND source_commit_sha IS NOT NULL AND control_schema_version IS NOT NULL
            AND source_manifest_sha256 IS NOT NULL
            AND source_bundle_sha256 IS NOT NULL
            AND build_receipt_sha256 IS NULL
            AND release_manifest_sha256 IS NOT NULL
            AND worker_bundle_sha256 IS NULL
            AND qualification_manifest_sha256 IS NOT NULL
            AND qualification_catalog_sha256 IS NOT NULL
            AND proof_set_sha256 IS NOT NULL AND fresh_targets_sha256 IS NOT NULL
            AND reset_complete_receipt_sha256 IS NOT NULL
            AND fleet_closed_receipt_sha256 IS NOT NULL
            AND route_v2_rotation_qualification_receipt_sha256 IS NOT NULL
            AND route_v2_rotation_qualification_node_ack_sets_sha256 IS NOT NULL
            AND route_v2_rotation_qualification_transcript_sha256 IS NOT NULL
            AND usage_terminal_receipt_sha256 IS NOT NULL
            AND old_host_coverage_sha256 IS NOT NULL
            AND kernel_nbd_qualification_bundle_sha256 IS NOT NULL
            AND vhost_user_qualification_bundle_sha256 IS NOT NULL
            AND qualification_cell_manifest_sha256 IS NULL
            AND qualification_aws_partition IS NULL
            AND qualification_aws_account_id IS NULL
            AND qualification_aws_region IS NULL
            AND qualification_cell_id IS NULL
            AND qualification_cell_namespace IS NULL
            AND qualification_cats_account_id IS NULL
            AND qualification_workspace_id IS NULL
            AND qualification_mutation_classes IS NULL
            AND qualification_expires_at_unix_ms IS NULL
            AND mode IN ('closed', 'open')
            AND last_command_id IS NOT NULL)
    ),
    CONSTRAINT production_mutation_admission_exact_command_fkey
        FOREIGN KEY (last_command_id, revision, mode, binding_sha256)
        REFERENCES production_mutation_admission_commands(
            command_id, resulting_revision, resulting_mode, binding_sha256)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);
INSERT INTO production_mutation_admission (singleton, revision, mode, updated_at_unix_ms)
VALUES (TRUE, 1, 'closed', 0);
CREATE TABLE IF NOT EXISTS node_identities (
    node_id TEXT PRIMARY KEY,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    host_provider TEXT NOT NULL CHECK (
        octet_length(host_provider) BETWEEN 1 AND 128
        AND host_provider ~ '^[A-Za-z0-9._:-]+$'
    ),
    host_partition TEXT NOT NULL CHECK (
        octet_length(host_partition) BETWEEN 1 AND 128
        AND host_partition ~ '^[A-Za-z0-9._:-]+$'
    ),
    host_account_id TEXT NOT NULL CHECK (
        octet_length(host_account_id) BETWEEN 1 AND 128
        AND host_account_id ~ '^[A-Za-z0-9._:-]+$'
    ),
    host_region TEXT NOT NULL CHECK (
        octet_length(host_region) BETWEEN 1 AND 128
        AND host_region ~ '^[A-Za-z0-9._:-]+$'
    ),
    immutable_host_id TEXT NOT NULL,
    credential_id TEXT NOT NULL UNIQUE,
    credential_kind TEXT NOT NULL
        CHECK (credential_kind IN ('public_key', 'provider_principal')),
    credential_public_key_spki_sha256 TEXT,
    credential_provider TEXT,
    credential_principal TEXT,
    credential_lineage_state TEXT
        CHECK (credential_lineage_state IN ('active', 'retired')),
    state_path_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('provisioned', 'retired')),
    UNIQUE (
        host_provider, host_partition, host_account_id, host_region,
        immutable_host_id, state_path_id
    ),
    UNIQUE (
        node_id, host_provider, host_partition, host_account_id, host_region,
        immutable_host_id
    ),
    CHECK ((
        (credential_kind = 'public_key'
            AND credential_public_key_spki_sha256 IS NOT NULL
            AND credential_public_key_spki_sha256 ~ '^sha256:[0-9a-f]{64}$'
            AND credential_provider IS NULL
            AND credential_principal IS NULL
            AND credential_lineage_state IS NOT NULL
            AND ((state = 'provisioned' AND credential_lineage_state = 'active') OR
                 (state = 'retired' AND credential_lineage_state = 'retired'))) OR
        (credential_kind = 'provider_principal'
            AND credential_public_key_spki_sha256 IS NULL
            AND credential_provider IS NOT NULL
            AND credential_principal IS NOT NULL
            AND credential_lineage_state IS NULL)
    ) IS TRUE)
);
CREATE UNIQUE INDEX IF NOT EXISTS node_identity_one_provisioned_per_host
    ON node_identities(
        host_provider, host_partition, host_account_id, host_region,
        immutable_host_id
    ) WHERE state = 'provisioned';
CREATE TABLE IF NOT EXISTS route_operations (
    operation_id TEXT
        CONSTRAINT route_operations_pkey PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    cat_id TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    operation_kind TEXT NOT NULL
        CONSTRAINT route_operations_kind_check
        CHECK (operation_kind IN ('enable', 'disable')),
    canonical_request_bytes BYTEA NOT NULL
        CONSTRAINT route_operations_request_bytes_check
        CHECK (octet_length(canonical_request_bytes) BETWEEN 1 AND 1048576),
    canonical_request_sha256 TEXT NOT NULL
        CONSTRAINT route_operations_request_digest_check
        CHECK (canonical_request_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    expected_predecessor_operation_id TEXT,
    expected_predecessor_result_kind TEXT,
    expected_predecessor_result_sha256 TEXT
        CONSTRAINT route_operations_predecessor_digest_check
        CHECK (expected_predecessor_result_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    hostname TEXT NOT NULL,
    protocol TEXT NOT NULL
        CONSTRAINT route_operations_protocol_check
        CHECK (protocol = 'http'),
    target_port INTEGER NOT NULL
        CONSTRAINT route_operations_target_port_check
        CHECK (target_port BETWEEN 1 AND 65535),
    route_epoch BIGINT NOT NULL
        CONSTRAINT route_operations_route_epoch_check
        CHECK (route_epoch > 0),
    source_lifecycle_operation_id TEXT NOT NULL,
    runtime_incarnation TEXT NOT NULL
        CONSTRAINT route_operations_runtime_incarnation_check
        CHECK (runtime_incarnation ~ '^[0-9a-f]{32}$'),
    node_id TEXT NOT NULL,
    placement_epoch BIGINT NOT NULL
        CONSTRAINT route_operations_placement_epoch_check
        CHECK (placement_epoch > 0),
    node_boot_id TEXT NOT NULL,
    agent_instance_id TEXT NOT NULL
        CONSTRAINT route_operations_agent_instance_check
        CHECK (agent_instance_id ~ '^[0-9a-f]{32}$'),
    admission_session_epoch BIGINT NOT NULL
        CONSTRAINT route_operations_session_epoch_check
        CHECK (admission_session_epoch > 0),
    state TEXT NOT NULL
        CONSTRAINT route_operations_state_check
        CHECK (state IN ('unresolved', 'terminal')),
    terminal_source TEXT
        CONSTRAINT route_operations_terminal_source_check
        CHECK (terminal_source IN ('node_result', 'control_invalidation')),
    terminal_result_kind TEXT
        CONSTRAINT route_operations_terminal_result_kind_check
        CHECK (terminal_result_kind IN (
            'serving', 'closed', 'rejected', 'invalidated'
        )),
    canonical_result_bytes BYTEA
        CONSTRAINT route_operations_result_bytes_check
        CHECK (canonical_result_bytes IS NULL OR
               octet_length(canonical_result_bytes) BETWEEN 1 AND 1048576),
    canonical_result_sha256 TEXT
        CONSTRAINT route_operations_result_digest_check
        CHECK (canonical_result_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    created_at_unix_ms BIGINT NOT NULL
        CONSTRAINT route_operations_created_at_check
        CHECK (created_at_unix_ms >= 0),
    terminal_at_unix_ms BIGINT
        CONSTRAINT route_operations_terminal_at_check
        CHECK (terminal_at_unix_ms >= created_at_unix_ms),
    CONSTRAINT route_operations_endpoint_fkey
        FOREIGN KEY (workspace_id, cat_id, endpoint_id)
        REFERENCES endpoint_records(workspace_id, cat_id, endpoint_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT route_operations_source_lifecycle_fkey
        FOREIGN KEY (cat_id, source_lifecycle_operation_id)
        REFERENCES runtime_operations(cat_id, operation_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT route_operations_node_fkey
        FOREIGN KEY (node_id) REFERENCES node_identities(node_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT route_operations_endpoint_operation_key
        UNIQUE (endpoint_id, operation_id),
    CONSTRAINT route_operations_exact_endpoint_operation_key
        UNIQUE (workspace_id, cat_id, endpoint_id, operation_id),
    CONSTRAINT route_operations_predecessor_result_key
        UNIQUE (
            endpoint_id, operation_id, terminal_result_kind,
            canonical_result_sha256
        ),
    CONSTRAINT route_operations_exact_predecessor_fkey
        FOREIGN KEY (
            endpoint_id, expected_predecessor_operation_id,
            expected_predecessor_result_kind,
            expected_predecessor_result_sha256
        ) REFERENCES route_operations (
            endpoint_id, operation_id, terminal_result_kind,
            canonical_result_sha256
        ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT route_operations_predecessor_shape_check CHECK (
        (expected_predecessor_operation_id IS NULL
            AND expected_predecessor_result_kind IS NULL
            AND expected_predecessor_result_sha256 IS NULL) OR
        (expected_predecessor_operation_id IS NOT NULL
            AND expected_predecessor_result_kind IS NOT NULL
            AND expected_predecessor_result_sha256 IS NOT NULL)
    ),
    CONSTRAINT route_operations_terminal_shape_check CHECK (
        (state = 'unresolved'
            AND terminal_source IS NULL
            AND terminal_result_kind IS NULL
            AND canonical_result_bytes IS NULL
            AND canonical_result_sha256 IS NULL
            AND terminal_at_unix_ms IS NULL) OR
        (state = 'terminal'
            AND terminal_source IS NOT NULL
            AND terminal_result_kind IS NOT NULL
            AND canonical_result_bytes IS NOT NULL
            AND canonical_result_sha256 IS NOT NULL
            AND terminal_at_unix_ms IS NOT NULL)
    ),
    CONSTRAINT route_operations_command_result_check CHECK (
        terminal_source IS NULL OR
        (terminal_source = 'control_invalidation'
            AND terminal_result_kind = 'invalidated') OR
        (terminal_source = 'node_result'
            AND operation_kind = 'enable'
            AND terminal_result_kind IN ('serving', 'rejected')) OR
        (terminal_source = 'node_result'
            AND operation_kind = 'disable'
            AND terminal_result_kind IN ('closed', 'rejected'))
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS route_operations_one_unresolved_per_endpoint
ON route_operations(endpoint_id) WHERE state='unresolved';
CREATE UNIQUE INDEX IF NOT EXISTS route_operations_one_genesis_per_endpoint
ON route_operations(endpoint_id)
WHERE expected_predecessor_operation_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS route_operations_one_successor_per_predecessor
ON route_operations(endpoint_id, expected_predecessor_operation_id)
WHERE expected_predecessor_operation_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS route_operations_workspace_lookup
ON route_operations(workspace_id, operation_id);
CREATE INDEX IF NOT EXISTS route_operations_endpoint_history
ON route_operations(endpoint_id, created_at_unix_ms, operation_id);
ALTER TABLE endpoint_records
    ADD CONSTRAINT endpoint_records_route_head_operation_fkey
    FOREIGN KEY (workspace_id, cat_id, endpoint_id, route_head_operation_id)
    REFERENCES route_operations(workspace_id, cat_id, endpoint_id, operation_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE endpoint_records
    ADD CONSTRAINT endpoint_records_effective_serving_operation_fkey
    FOREIGN KEY (workspace_id, cat_id, endpoint_id, effective_serving_operation_id)
    REFERENCES route_operations(workspace_id, cat_id, endpoint_id, operation_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED;
CREATE OR REPLACE FUNCTION control_route_operation_transition_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (OLD.operation_id, OLD.workspace_id, OLD.cat_id, OLD.endpoint_id,
        OLD.operation_kind, OLD.canonical_request_bytes,
        OLD.canonical_request_sha256, OLD.expected_predecessor_operation_id,
        OLD.expected_predecessor_result_kind,
        OLD.expected_predecessor_result_sha256, OLD.hostname, OLD.protocol,
        OLD.target_port, OLD.route_epoch, OLD.source_lifecycle_operation_id,
        OLD.runtime_incarnation, OLD.node_id, OLD.placement_epoch,
        OLD.node_boot_id, OLD.agent_instance_id, OLD.admission_session_epoch,
        OLD.created_at_unix_ms)
       IS DISTINCT FROM
       (NEW.operation_id, NEW.workspace_id, NEW.cat_id, NEW.endpoint_id,
        NEW.operation_kind, NEW.canonical_request_bytes,
        NEW.canonical_request_sha256, NEW.expected_predecessor_operation_id,
        NEW.expected_predecessor_result_kind,
        NEW.expected_predecessor_result_sha256, NEW.hostname, NEW.protocol,
        NEW.target_port, NEW.route_epoch, NEW.source_lifecycle_operation_id,
        NEW.runtime_incarnation, NEW.node_id, NEW.placement_epoch,
        NEW.node_boot_id, NEW.agent_instance_id, NEW.admission_session_epoch,
        NEW.created_at_unix_ms)
       OR OLD.state <> 'unresolved'
       OR NEW.state <> 'terminal'
    THEN
        RAISE EXCEPTION 'invalid Route Operation transition';
    END IF;
    RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION control_route_operation_cannot_delete()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Route Operations are immutable history';
END;
$$;
CREATE TRIGGER route_operation_transition_is_forward_only
BEFORE UPDATE ON route_operations FOR EACH ROW
EXECUTE FUNCTION control_route_operation_transition_guard();
CREATE TRIGGER route_operation_cannot_delete
BEFORE DELETE ON route_operations FOR EACH ROW
EXECUTE FUNCTION control_route_operation_cannot_delete();
CREATE TABLE IF NOT EXISTS runtime_node_credential_lineage (
    credential_id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES node_identities(node_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    public_key_spki_sha256 TEXT NOT NULL UNIQUE
        CHECK (public_key_spki_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    state TEXT NOT NULL CHECK (state IN ('active', 'retired')),
    first_committed_at_unix_ms BIGINT NOT NULL CHECK (first_committed_at_unix_ms >= 0),
    retired_at_unix_ms BIGINT NULL CHECK (
        retired_at_unix_ms IS NULL OR
        retired_at_unix_ms >= first_committed_at_unix_ms),
    CHECK ((state = 'active' AND retired_at_unix_ms IS NULL) OR
           (state = 'retired' AND retired_at_unix_ms IS NOT NULL)),
    UNIQUE (node_id, credential_id),
    UNIQUE (node_id, credential_id, public_key_spki_sha256, state)
);
CREATE UNIQUE INDEX IF NOT EXISTS runtime_node_one_active_credential
    ON runtime_node_credential_lineage(node_id) WHERE state = 'active';
ALTER TABLE node_identities
    ADD CONSTRAINT node_identity_current_public_key_lineage
    FOREIGN KEY (
        node_id, credential_id, credential_public_key_spki_sha256,
        credential_lineage_state)
    REFERENCES runtime_node_credential_lineage(
        node_id, credential_id, public_key_spki_sha256, state)
    ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE IF NOT EXISTS object_write_authorities (
    writer_authority_id TEXT
        CONSTRAINT object_write_authorities_pkey PRIMARY KEY,
    record JSONB NOT NULL
        CONSTRAINT object_write_authorities_record_object_check
        CHECK (jsonb_typeof(record) = 'object'),
    host_provider TEXT NOT NULL,
    host_partition TEXT NOT NULL,
    host_account_id TEXT NOT NULL,
    host_region TEXT NOT NULL,
    immutable_host_id TEXT NOT NULL,
    node_id TEXT NOT NULL
        CONSTRAINT object_write_authorities_node_id_fkey
        REFERENCES node_identities(node_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    object_provider TEXT NOT NULL,
    object_partition TEXT NOT NULL,
    object_account_id TEXT NOT NULL,
    object_region TEXT NOT NULL,
    workload_principal_id TEXT NOT NULL,
    object_store_scope_id TEXT NOT NULL,
    state TEXT NOT NULL
        CONSTRAINT object_write_authorities_state_check CHECK (
        state IN ('open', 'cutoff_pending', 'cutoff_complete')
    ),
    max_accepted_sequence BIGINT NOT NULL
        CONSTRAINT object_write_authorities_max_sequence_check
        CHECK (max_accepted_sequence >= 0),
    terminal_prefix_sequence BIGINT NOT NULL
        CONSTRAINT object_write_authorities_terminal_prefix_sequence_check CHECK (
        terminal_prefix_sequence >= 0
        AND terminal_prefix_sequence <= max_accepted_sequence
    ),
    terminal_prefix_sha256 TEXT NOT NULL
        CONSTRAINT object_write_authorities_terminal_prefix_digest_check
        CHECK (terminal_prefix_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    fence_attempt_id TEXT,
    cutoff_effective_at_unix_ms BIGINT
        CONSTRAINT object_write_authorities_cutoff_time_check
        CHECK (cutoff_effective_at_unix_ms >= 0),
    cutoff_sequence BIGINT
        CONSTRAINT object_write_authorities_cutoff_sequence_check
        CHECK (cutoff_sequence >= 0),
    cutoff_receipt JSONB
        CONSTRAINT object_write_authorities_cutoff_receipt_check CHECK (
        cutoff_receipt IS NULL OR jsonb_typeof(cutoff_receipt) = 'object'
    ),
    CONSTRAINT object_write_authorities_host_lineage_key UNIQUE (
        host_provider, host_partition, host_account_id, host_region,
        immutable_host_id, writer_authority_id
    ),
    CONSTRAINT object_write_authorities_record_projection_check CHECK (
        record #>> '{writer,authority_id}' = writer_authority_id
        AND record #>> '{writer,host_provider_scope,provider}' = host_provider
        AND record #>> '{writer,host_provider_scope,partition}' = host_partition
        AND record #>> '{writer,host_provider_scope,account_id}' = host_account_id
        AND record #>> '{writer,host_provider_scope,region}' = host_region
        AND record #>> '{writer,immutable_host_id}' = immutable_host_id
        AND record #>> '{writer,node_id}' = node_id
        AND record #>> '{writer,object_provider_scope,provider}' = object_provider
        AND record #>> '{writer,object_provider_scope,partition}' = object_partition
        AND record #>> '{writer,object_provider_scope,account_id}' = object_account_id
        AND record #>> '{writer,object_provider_scope,region}' = object_region
        AND record #>> '{writer,workload_principal_id}' = workload_principal_id
        AND record #>> '{writer,object_store_scope_id}' = object_store_scope_id
        AND record #>> '{state,kind}' = state
        AND record #>> '{max_accepted_sequence}' = max_accepted_sequence::TEXT
        AND record #>> '{terminal_prefix_sequence}' = terminal_prefix_sequence::TEXT
        AND record #>> '{terminal_prefix_sha256}' = terminal_prefix_sha256
    ),
    CONSTRAINT object_write_authorities_state_shape_check CHECK (
        (state = 'open' AND fence_attempt_id IS NULL
            AND cutoff_effective_at_unix_ms IS NULL
            AND cutoff_sequence IS NULL AND cutoff_receipt IS NULL) OR
        (state = 'cutoff_pending' AND fence_attempt_id IS NOT NULL
            AND cutoff_effective_at_unix_ms IS NOT NULL
            AND cutoff_sequence = max_accepted_sequence
            AND record #>> '{state,fence_attempt_id}' = fence_attempt_id
            AND record #>> '{state,cutoff_effective_at_unix_ms}' =
                cutoff_effective_at_unix_ms::TEXT
            AND record #>> '{state,cutoff_sequence}' = cutoff_sequence::TEXT
            AND cutoff_receipt IS NULL) OR
        (state = 'cutoff_complete' AND fence_attempt_id IS NOT NULL
            AND cutoff_effective_at_unix_ms IS NOT NULL
            AND cutoff_sequence = max_accepted_sequence
            AND terminal_prefix_sequence = cutoff_sequence
            AND record #>> '{state,receipt,fence_attempt_id}' = fence_attempt_id
            AND record #>> '{state,receipt,cutoff_effective_at_unix_ms}' =
                cutoff_effective_at_unix_ms::TEXT
            AND record #>> '{state,receipt,cutoff_sequence}' = cutoff_sequence::TEXT
            AND record #> '{state,receipt}' = cutoff_receipt
            AND cutoff_receipt IS NOT NULL)
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS object_write_one_open_authority_per_host
    ON object_write_authorities(
        host_provider, host_partition, host_account_id, host_region,
        immutable_host_id
    ) WHERE state = 'open';
CREATE INDEX IF NOT EXISTS object_write_authorities_node_state
    ON object_write_authorities(node_id, state);
CREATE TABLE IF NOT EXISTS object_write_credentials (
    credential_id TEXT
        CONSTRAINT object_write_credentials_pkey PRIMARY KEY,
    record JSONB NOT NULL
        CONSTRAINT object_write_credentials_record_object_check
        CHECK (jsonb_typeof(record) = 'object'),
    public_key_spki TEXT NOT NULL
        CONSTRAINT object_write_credentials_public_key_spki_check CHECK (
        octet_length(public_key_spki) BETWEEN 1 AND 512
        AND public_key_spki ~ '^[A-Za-z0-9_-]+$'
    ),
    public_key_spki_sha256 TEXT NOT NULL
        CONSTRAINT object_write_credentials_public_key_digest_key UNIQUE
        CONSTRAINT object_write_credentials_public_key_digest_check
        CHECK (public_key_spki_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    writer_authority_id TEXT NOT NULL
        CONSTRAINT object_write_credentials_writer_authority_id_fkey
        REFERENCES object_write_authorities(writer_authority_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    host_provider TEXT NOT NULL,
    host_partition TEXT NOT NULL,
    host_account_id TEXT NOT NULL,
    host_region TEXT NOT NULL,
    immutable_host_id TEXT NOT NULL,
    node_id TEXT NOT NULL
        CONSTRAINT object_write_credentials_node_id_fkey
        REFERENCES node_identities(node_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    node_boot_id TEXT NOT NULL
        CONSTRAINT object_write_credentials_node_boot_id_check
        CHECK (node_boot_id ~ '^[0-9a-f]{32}$'),
    agent_instance_id TEXT NOT NULL
        CONSTRAINT object_write_credentials_agent_instance_id_check
        CHECK (agent_instance_id ~ '^[0-9a-f]{32}$'),
    agent_session_epoch BIGINT NOT NULL
        CONSTRAINT object_write_credentials_agent_epoch_check
        CHECK (agent_session_epoch > 0),
    volume_id TEXT NOT NULL,
    attachment_id TEXT NOT NULL,
    attachment_epoch BIGINT NOT NULL
        CONSTRAINT object_write_credentials_attachment_epoch_check
        CHECK (attachment_epoch > 0),
    private_artifact_id TEXT NOT NULL
        CONSTRAINT object_write_credentials_private_artifact_key UNIQUE,
    private_file_fsync_receipt_id TEXT NOT NULL,
    private_directory_fsync_receipt_id TEXT NOT NULL,
    registered_at_unix_ms BIGINT NOT NULL
        CONSTRAINT object_write_credentials_registered_time_check
        CHECK (registered_at_unix_ms >= 0),
    state TEXT NOT NULL
        CONSTRAINT object_write_credentials_state_check
        CHECK (state IN ('active', 'retired')),
    retirement_kind TEXT
        CONSTRAINT object_write_credentials_retirement_kind_check
        CHECK (retirement_kind IN ('parent_cutoff', 'exact_release')),
    retirement_transition_id TEXT,
    retirement_receipt_id TEXT,
    retired_at_unix_ms BIGINT
        CONSTRAINT object_write_credentials_retired_time_check
        CHECK (retired_at_unix_ms >= registered_at_unix_ms),
    CONSTRAINT object_write_credentials_attachment_lineage_key UNIQUE (
        writer_authority_id, volume_id, attachment_id, attachment_epoch,
        credential_id
    ),
    CONSTRAINT object_write_credentials_record_projection_check CHECK (
        record #>> '{credential,credential_id}' = credential_id
        AND record #>> '{credential,public_key_spki_sha256}' = public_key_spki_sha256
        AND record #>> '{public_key_spki}' = public_key_spki
        AND record #>> '{writer_authority_id}' = writer_authority_id
        AND record #>> '{host_provider_scope,provider}' = host_provider
        AND record #>> '{host_provider_scope,partition}' = host_partition
        AND record #>> '{host_provider_scope,account_id}' = host_account_id
        AND record #>> '{host_provider_scope,region}' = host_region
        AND record #>> '{immutable_host_id}' = immutable_host_id
        AND record #>> '{node_id}' = node_id
        AND record #>> '{node_boot_id}' = node_boot_id
        AND record #>> '{agent_instance_id}' = agent_instance_id
        AND record #>> '{agent_session_epoch}' = agent_session_epoch::TEXT
        AND record #>> '{volume_id}' = volume_id
        AND record #>> '{attachment_id}' = attachment_id
        AND record #>> '{attachment_epoch}' = attachment_epoch::TEXT
        AND record #>> '{private_artifact_id}' = private_artifact_id
        AND record #>> '{private_file_fsync_receipt_id}' = private_file_fsync_receipt_id
        AND record #>> '{private_directory_fsync_receipt_id}' = private_directory_fsync_receipt_id
        AND record #>> '{registered_at_unix_ms}' = registered_at_unix_ms::TEXT
        AND record #>> '{state,kind}' = state
    ),
    CONSTRAINT object_write_credentials_state_shape_check CHECK (
        (state = 'active' AND retirement_kind IS NULL
            AND retirement_transition_id IS NULL
            AND retirement_receipt_id IS NULL AND retired_at_unix_ms IS NULL) OR
        (state = 'retired' AND retirement_kind IS NOT NULL
            AND retirement_transition_id IS NOT NULL
            AND retirement_receipt_id IS NOT NULL AND retired_at_unix_ms IS NOT NULL
            AND record #>> '{state,cause,kind}' = retirement_kind
            AND COALESCE(record #>> '{state,cause,fence_attempt_id}',
                         record #>> '{state,cause,release_transition_id}') =
                retirement_transition_id
            AND record #>> '{state,retirement_receipt_id}' = retirement_receipt_id
            AND record #>> '{state,retired_at_unix_ms}' = retired_at_unix_ms::TEXT)
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS object_write_one_active_credential_per_attachment
    ON object_write_credentials(
        writer_authority_id, volume_id, attachment_id, attachment_epoch
    ) WHERE state = 'active';
CREATE INDEX IF NOT EXISTS object_write_credentials_parent_state
    ON object_write_credentials(writer_authority_id, state, credential_id COLLATE \"C\");
CREATE TABLE IF NOT EXISTS object_write_attempts (
    request_id TEXT
        CONSTRAINT object_write_attempts_pkey PRIMARY KEY
        CONSTRAINT object_write_attempts_request_id_check
        CHECK (request_id ~ '^sha256:[0-9a-f]{64}$'),
    record JSONB NOT NULL
        CONSTRAINT object_write_attempts_record_object_check
        CHECK (jsonb_typeof(record) = 'object'),
    writer_authority_id TEXT NOT NULL
        CONSTRAINT object_write_attempts_writer_authority_id_fkey
        REFERENCES object_write_authorities(writer_authority_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    credential_id TEXT NOT NULL
        CONSTRAINT object_write_attempts_credential_id_fkey
        REFERENCES object_write_credentials(credential_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    volume_id TEXT NOT NULL,
    key_kind TEXT NOT NULL
        CONSTRAINT object_write_attempts_key_kind_check
        CHECK (key_kind IN ('volume_data', 'volume_map', 'volume_commit')),
    object_provider TEXT NOT NULL,
    object_partition TEXT NOT NULL,
    object_account_id TEXT NOT NULL,
    object_region TEXT NOT NULL,
    object_store_scope_id TEXT NOT NULL,
    object_key TEXT NOT NULL,
    content_sha256 TEXT NOT NULL
        CONSTRAINT object_write_attempts_content_digest_check
        CHECK (content_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    content_length BIGINT NOT NULL
        CONSTRAINT object_write_attempts_content_length_check
        CHECK (content_length BETWEEN 0 AND 33554432),
    receiving_started_at_unix_ms BIGINT NOT NULL
        CONSTRAINT object_write_attempts_receiving_time_check
        CHECK (receiving_started_at_unix_ms >= 0),
    state TEXT NOT NULL
        CONSTRAINT object_write_attempts_state_check CHECK (state IN (
        'receiving', 'durable_spooled', 'rejected_before_accept',
        'accepted_spooled', 'provider_issued', 'qualification_response_lost',
        'terminal_visible', 'permanent', 'qualification_unproven_visible',
        'spool_removed'
    )),
    spool_id TEXT
        CONSTRAINT object_write_attempts_spool_id_check
        CHECK (spool_id ~ '^owsp1_[0-9a-f]{64}$'),
    spool_file_fsync_receipt_id TEXT,
    spool_directory_fsync_receipt_id TEXT,
    spool_durable_at_unix_ms BIGINT
        CONSTRAINT object_write_attempts_spool_time_check CHECK (
        spool_durable_at_unix_ms >= receiving_started_at_unix_ms
    ),
    rejection_kind TEXT
        CONSTRAINT object_write_attempts_rejection_kind_check
        CHECK (rejection_kind IN ('writer_closed', 'object_key_conflict')),
    rejection_receipt_id TEXT,
    rejected_at_unix_ms BIGINT
        CONSTRAINT object_write_attempts_rejected_time_check
        CHECK (rejected_at_unix_ms >= spool_durable_at_unix_ms),
    accepted_sequence BIGINT
        CONSTRAINT object_write_attempts_accepted_sequence_check
        CHECK (accepted_sequence > 0),
    accepted_at_unix_ms BIGINT
        CONSTRAINT object_write_attempts_accepted_time_check
        CHECK (accepted_at_unix_ms >= spool_durable_at_unix_ms),
    provider_attempt_id TEXT
        CONSTRAINT object_write_attempts_provider_attempt_id_check
        CHECK (provider_attempt_id ~ '^owpa1_[0-9a-f]{64}$'),
    provider_issued_at_unix_ms BIGINT
        CONSTRAINT object_write_attempts_provider_issued_time_check
        CHECK (provider_issued_at_unix_ms >= accepted_at_unix_ms),
    qualification_request_canonical BYTEA,
    qualification_authorization_canonical BYTEA,
    qualification_successful_put_canonical BYTEA,
    qualification_response_loss_canonical BYTEA,
    qualification_response_lost_attempt_canonical BYTEA,
    qualification_response_loss_sha256 TEXT
        CONSTRAINT object_write_attempts_qualification_response_loss_sha256_check
        CHECK (qualification_response_loss_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    qualification_injection_receipt_id TEXT
        CONSTRAINT object_write_attempts_qualification_injection_receipt_id_check
        CHECK (qualification_injection_receipt_id ~ '^owqinj1_[0-9a-f]{64}$'),
    qualification_injected_at_unix_ms BIGINT
        CONSTRAINT object_write_attempts_qualification_injected_time_check
        CHECK (qualification_injected_at_unix_ms >= provider_issued_at_unix_ms),
    qualification_visibility_head_canonical BYTEA,
    qualification_unproven_intent_canonical BYTEA,
    qualification_unproven_sealed_request_canonical BYTEA,
    qualification_unproven_receipt_canonical BYTEA,
    qualification_unproven_attempt_canonical BYTEA,
    qualification_unproven_resolution_receipt_id TEXT
        CONSTRAINT object_write_attempts_qualification_unproven_receipt_id_check
        CHECK (qualification_unproven_resolution_receipt_id
            ~ '^owqunp1_[0-9a-f]{64}$'),
    terminal_kind TEXT
        CONSTRAINT object_write_attempts_terminal_kind_check
        CHECK (terminal_kind IN (
            'succeeded_visible', 'permanently_failed',
            'qualification_unproven_visible'
        )),
    put_receipt_id TEXT,
    put_completed_at_unix_ms BIGINT
        CONSTRAINT object_write_attempts_put_completed_time_check
        CHECK (put_completed_at_unix_ms >= provider_issued_at_unix_ms),
    visibility_receipt_id TEXT,
    visible_at_unix_ms BIGINT
        CONSTRAINT object_write_attempts_visible_time_check
        CHECK (visible_at_unix_ms >= put_completed_at_unix_ms),
    failure_receipt_id TEXT,
    failed_at_unix_ms BIGINT
        CONSTRAINT object_write_attempts_failed_time_check
        CHECK (failed_at_unix_ms >= provider_issued_at_unix_ms),
    qualification_unproven_reason TEXT
        CONSTRAINT object_write_attempts_qualification_unproven_reason_check
        CHECK (qualification_unproven_reason = 'response_loss_receipt_absent'),
    qualification_head_evidence_canonical BYTEA,
    qualification_unproven_at_unix_ms BIGINT
        CONSTRAINT object_write_attempts_qualification_unproven_time_check
        CHECK (qualification_unproven_at_unix_ms >= provider_issued_at_unix_ms),
    spool_removal_receipt_id TEXT,
    spool_removed_at_unix_ms BIGINT
        CONSTRAINT object_write_attempts_spool_removed_time_check CHECK (
        spool_removed_at_unix_ms >= COALESCE(
            visible_at_unix_ms,
            failed_at_unix_ms,
            qualification_unproven_at_unix_ms
        )
    ),
    CONSTRAINT object_write_attempts_phase_shape_check CHECK (
        (state = 'receiving' AND spool_id IS NULL AND accepted_sequence IS NULL) OR
        (state = 'durable_spooled' AND spool_id IS NOT NULL
            AND spool_file_fsync_receipt_id IS NOT NULL
            AND spool_directory_fsync_receipt_id IS NOT NULL
            AND spool_durable_at_unix_ms IS NOT NULL
            AND rejection_kind IS NULL AND accepted_sequence IS NULL) OR
        (state = 'rejected_before_accept' AND spool_id IS NOT NULL
            AND spool_file_fsync_receipt_id IS NOT NULL
            AND spool_directory_fsync_receipt_id IS NOT NULL
            AND spool_durable_at_unix_ms IS NOT NULL
            AND rejection_kind IS NOT NULL
            AND rejection_receipt_id IS NOT NULL AND rejected_at_unix_ms IS NOT NULL
            AND accepted_sequence IS NULL AND provider_attempt_id IS NULL) OR
        (state IN ('accepted_spooled', 'provider_issued', 'qualification_response_lost',
                   'terminal_visible', 'permanent', 'qualification_unproven_visible',
                   'spool_removed')
            AND spool_id IS NOT NULL
            AND spool_file_fsync_receipt_id IS NOT NULL
            AND spool_directory_fsync_receipt_id IS NOT NULL
            AND spool_durable_at_unix_ms IS NOT NULL
            AND rejection_kind IS NULL AND rejection_receipt_id IS NULL
            AND rejected_at_unix_ms IS NULL AND accepted_sequence IS NOT NULL
            AND accepted_at_unix_ms IS NOT NULL AND provider_attempt_id IS NOT NULL)
    ),
    CONSTRAINT object_write_attempts_provider_issue_shape_check
    CHECK ((state IN ('provider_issued', 'qualification_response_lost',
                      'terminal_visible', 'permanent',
                      'qualification_unproven_visible', 'spool_removed'))
        = (provider_issued_at_unix_ms IS NOT NULL)),
    CONSTRAINT object_write_attempts_qualification_shape_check CHECK (
        ((state = 'qualification_response_lost' OR (
            state IN ('terminal_visible', 'spool_removed')
            AND record #>> '{state,outcome,kind}' = 'succeeded_visible'
            AND record #> '{state,outcome,qualification_ambiguity}' IS NOT NULL
            AND record #> '{state,outcome,qualification_ambiguity}' <> 'null'::JSONB
        )) AND
            qualification_request_canonical IS NOT NULL
            AND qualification_authorization_canonical IS NOT NULL
            AND qualification_successful_put_canonical IS NOT NULL
            AND qualification_response_loss_canonical IS NOT NULL
            AND qualification_response_lost_attempt_canonical IS NOT NULL
            AND qualification_response_loss_sha256 IS NOT NULL
            AND qualification_injection_receipt_id IS NOT NULL
            AND qualification_injected_at_unix_ms IS NOT NULL
        ) OR
        (NOT (state = 'qualification_response_lost' OR (
            state IN ('terminal_visible', 'spool_removed')
            AND record #>> '{state,outcome,kind}' = 'succeeded_visible'
            AND record #> '{state,outcome,qualification_ambiguity}' IS NOT NULL
            AND record #> '{state,outcome,qualification_ambiguity}' <> 'null'::JSONB
        )) AND
            qualification_authorization_canonical IS NULL
            AND qualification_successful_put_canonical IS NULL
            AND qualification_response_loss_canonical IS NULL
            AND qualification_response_lost_attempt_canonical IS NULL
            AND qualification_response_loss_sha256 IS NULL
            AND qualification_injection_receipt_id IS NULL
            AND qualification_injected_at_unix_ms IS NULL
            AND ((terminal_kind = 'qualification_unproven_visible')
                = (qualification_request_canonical IS NOT NULL))
        )
    ),
    CONSTRAINT object_write_attempts_visible_terminal_shape_check
    CHECK ((terminal_kind = 'succeeded_visible'
            AND put_receipt_id IS NOT NULL AND put_completed_at_unix_ms IS NOT NULL
            AND visibility_receipt_id IS NOT NULL AND visible_at_unix_ms IS NOT NULL) OR
           (terminal_kind IS DISTINCT FROM 'succeeded_visible'
            AND put_receipt_id IS NULL AND put_completed_at_unix_ms IS NULL
            AND visibility_receipt_id IS NULL AND visible_at_unix_ms IS NULL)),
    CONSTRAINT object_write_attempts_qualification_visibility_head_shape_check CHECK (
        ((state IN ('terminal_visible', 'spool_removed')
          AND record #>> '{state,outcome,kind}' = 'succeeded_visible'
          AND record #> '{state,outcome,qualification_ambiguity}' IS NOT NULL
          AND record #> '{state,outcome,qualification_ambiguity}' <> 'null'::JSONB)
            = (qualification_visibility_head_canonical IS NOT NULL))
    ),
    CONSTRAINT object_write_attempts_failure_terminal_shape_check
    CHECK ((terminal_kind = 'permanently_failed'
            AND failure_receipt_id IS NOT NULL AND failed_at_unix_ms IS NOT NULL) OR
           (terminal_kind IS DISTINCT FROM 'permanently_failed'
            AND failure_receipt_id IS NULL AND failed_at_unix_ms IS NULL)),
    CONSTRAINT object_write_attempts_qualification_unproven_shape_check
    CHECK ((terminal_kind = 'qualification_unproven_visible'
            AND qualification_request_canonical IS NOT NULL
            AND qualification_unproven_intent_canonical IS NOT NULL
            AND qualification_unproven_sealed_request_canonical IS NOT NULL
            AND qualification_unproven_receipt_canonical IS NOT NULL
            AND qualification_unproven_attempt_canonical IS NOT NULL
            AND qualification_unproven_resolution_receipt_id IS NOT NULL
            AND qualification_unproven_reason IS NOT NULL
            AND qualification_head_evidence_canonical IS NOT NULL
            AND qualification_unproven_at_unix_ms IS NOT NULL) OR
           (terminal_kind IS DISTINCT FROM 'qualification_unproven_visible'
            AND qualification_unproven_intent_canonical IS NULL
            AND qualification_unproven_sealed_request_canonical IS NULL
            AND qualification_unproven_receipt_canonical IS NULL
            AND qualification_unproven_attempt_canonical IS NULL
            AND qualification_unproven_resolution_receipt_id IS NULL
            AND qualification_unproven_reason IS NULL
            AND qualification_head_evidence_canonical IS NULL
            AND qualification_unproven_at_unix_ms IS NULL)),
    CONSTRAINT object_write_attempts_spool_removal_shape_check
    CHECK ((state = 'spool_removed') =
        (spool_removal_receipt_id IS NOT NULL AND spool_removed_at_unix_ms IS NOT NULL)),
    CONSTRAINT object_write_attempts_terminal_state_shape_check CHECK (
        (state = 'qualification_response_lost' AND terminal_kind IS NULL) OR
        (state = 'terminal_visible' AND terminal_kind = 'succeeded_visible') OR
        (state = 'permanent' AND terminal_kind = 'permanently_failed') OR
        (state = 'qualification_unproven_visible'
            AND terminal_kind = 'qualification_unproven_visible') OR
        (state = 'spool_removed' AND terminal_kind IS NOT NULL) OR
        (state NOT IN ('qualification_response_lost', 'terminal_visible', 'permanent',
                       'qualification_unproven_visible', 'spool_removed')
            AND terminal_kind IS NULL)
    ),
    CONSTRAINT object_write_attempts_unused_fields_check CHECK (
        (state = 'receiving'
            AND spool_id IS NULL
            AND spool_file_fsync_receipt_id IS NULL
            AND spool_directory_fsync_receipt_id IS NULL
            AND spool_durable_at_unix_ms IS NULL
            AND rejection_kind IS NULL AND rejection_receipt_id IS NULL
            AND rejected_at_unix_ms IS NULL
            AND accepted_sequence IS NULL AND accepted_at_unix_ms IS NULL
            AND provider_attempt_id IS NULL AND provider_issued_at_unix_ms IS NULL
            AND terminal_kind IS NULL AND put_receipt_id IS NULL
            AND put_completed_at_unix_ms IS NULL
            AND visibility_receipt_id IS NULL AND visible_at_unix_ms IS NULL
            AND failure_receipt_id IS NULL AND failed_at_unix_ms IS NULL
            AND spool_removal_receipt_id IS NULL AND spool_removed_at_unix_ms IS NULL) OR
        (state = 'durable_spooled'
            AND rejection_kind IS NULL AND rejection_receipt_id IS NULL
            AND rejected_at_unix_ms IS NULL
            AND accepted_sequence IS NULL AND accepted_at_unix_ms IS NULL
            AND provider_attempt_id IS NULL AND provider_issued_at_unix_ms IS NULL
            AND terminal_kind IS NULL AND put_receipt_id IS NULL
            AND put_completed_at_unix_ms IS NULL
            AND visibility_receipt_id IS NULL AND visible_at_unix_ms IS NULL
            AND failure_receipt_id IS NULL AND failed_at_unix_ms IS NULL
            AND spool_removal_receipt_id IS NULL AND spool_removed_at_unix_ms IS NULL) OR
        (state = 'rejected_before_accept'
            AND accepted_sequence IS NULL AND accepted_at_unix_ms IS NULL
            AND provider_attempt_id IS NULL AND provider_issued_at_unix_ms IS NULL
            AND terminal_kind IS NULL AND put_receipt_id IS NULL
            AND put_completed_at_unix_ms IS NULL
            AND visibility_receipt_id IS NULL AND visible_at_unix_ms IS NULL
            AND failure_receipt_id IS NULL AND failed_at_unix_ms IS NULL
            AND spool_removal_receipt_id IS NULL AND spool_removed_at_unix_ms IS NULL) OR
        (state = 'accepted_spooled'
            AND provider_issued_at_unix_ms IS NULL AND terminal_kind IS NULL
            AND put_receipt_id IS NULL AND put_completed_at_unix_ms IS NULL
            AND visibility_receipt_id IS NULL AND visible_at_unix_ms IS NULL
            AND failure_receipt_id IS NULL AND failed_at_unix_ms IS NULL
            AND spool_removal_receipt_id IS NULL AND spool_removed_at_unix_ms IS NULL) OR
        (state = 'provider_issued'
            AND terminal_kind IS NULL
            AND put_receipt_id IS NULL AND put_completed_at_unix_ms IS NULL
            AND visibility_receipt_id IS NULL AND visible_at_unix_ms IS NULL
            AND failure_receipt_id IS NULL AND failed_at_unix_ms IS NULL
            AND spool_removal_receipt_id IS NULL AND spool_removed_at_unix_ms IS NULL) OR
        (state = 'qualification_response_lost'
            AND terminal_kind IS NULL
            AND put_receipt_id IS NULL AND put_completed_at_unix_ms IS NULL
            AND visibility_receipt_id IS NULL AND visible_at_unix_ms IS NULL
            AND failure_receipt_id IS NULL AND failed_at_unix_ms IS NULL
            AND qualification_unproven_reason IS NULL
            AND qualification_head_evidence_canonical IS NULL
            AND qualification_unproven_at_unix_ms IS NULL
            AND spool_removal_receipt_id IS NULL AND spool_removed_at_unix_ms IS NULL) OR
        (state IN ('terminal_visible', 'permanent', 'qualification_unproven_visible')
            AND spool_removal_receipt_id IS NULL AND spool_removed_at_unix_ms IS NULL) OR
        state = 'spool_removed'
    ),
    CONSTRAINT object_write_attempts_record_projection_check CHECK (
        COALESCE(record #>> '{ingress,request_id}',
                 record #>> '{descriptor,request_id}') = request_id
        AND COALESCE(record #>> '{ingress,writer_authority_id}',
                     record #>> '{descriptor,writer_authority_id}') = writer_authority_id
        AND COALESCE(record #>> '{ingress,volume_id}',
                     record #>> '{descriptor,volume_id}') = volume_id
        AND COALESCE(record #>> '{ingress,key,kind}',
                     record #>> '{descriptor,key,kind}') = key_kind
        AND COALESCE(record #>> '{ingress,target,object_provider_scope,provider}',
                     record #>> '{descriptor,target,object_provider_scope,provider}') = object_provider
        AND COALESCE(record #>> '{ingress,target,object_provider_scope,partition}',
                     record #>> '{descriptor,target,object_provider_scope,partition}') = object_partition
        AND COALESCE(record #>> '{ingress,target,object_provider_scope,account_id}',
                     record #>> '{descriptor,target,object_provider_scope,account_id}') = object_account_id
        AND COALESCE(record #>> '{ingress,target,object_provider_scope,region}',
                     record #>> '{descriptor,target,object_provider_scope,region}') = object_region
        AND COALESCE(record #>> '{ingress,target,object_store_scope_id}',
                     record #>> '{descriptor,target,object_store_scope_id}') = object_store_scope_id
        AND COALESCE(record #>> '{ingress,target,canonical_logical_key}',
                     record #>> '{descriptor,target,canonical_logical_key}') = object_key
        AND COALESCE(record #>> '{ingress,content_sha256}',
                     record #>> '{descriptor,content_sha256}') = content_sha256
        AND COALESCE(record #>> '{ingress,content_length}',
                     record #>> '{descriptor,content_length}') = content_length::TEXT
        AND (
            (state IN ('receiving', 'durable_spooled', 'rejected_before_accept')
                AND record #>> '{state,kind}' = state) OR
            (state = 'accepted_spooled'
                AND record #>> '{state,kind}' = 'accepted_spooled') OR
            (state = 'provider_issued'
                AND record #>> '{state,kind}' = 'provider_issued') OR
            (state = 'qualification_response_lost'
                AND record #>> '{state,kind}' = 'qualification_response_lost') OR
            (state = 'terminal_visible'
                AND record #>> '{state,kind}' = 'terminal'
                AND record #>> '{state,outcome,kind}' = 'succeeded_visible'
                AND record #>> '{state,spool,kind}' = 'retained') OR
            (state = 'permanent'
                AND record #>> '{state,kind}' = 'terminal'
                AND record #>> '{state,outcome,kind}' = 'permanently_failed'
                AND record #>> '{state,spool,kind}' = 'retained') OR
            (state = 'qualification_unproven_visible'
                AND record #>> '{state,kind}' = 'terminal'
                AND record #>> '{state,outcome,kind}' =
                    'qualification_unproven_visible'
                AND record #>> '{state,spool,kind}' = 'retained') OR
            (state = 'spool_removed'
                AND record #>> '{state,kind}' = 'terminal'
                AND record #>> '{state,spool,kind}' = 'removed')
        )
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS object_write_attempts_writer_sequence
    ON object_write_attempts(writer_authority_id, accepted_sequence)
    WHERE accepted_sequence IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS object_write_attempts_writer_object_accepted
    ON object_write_attempts(writer_authority_id, object_key)
    WHERE accepted_sequence IS NOT NULL;
CREATE INDEX IF NOT EXISTS object_write_attempts_terminal_prefix
    ON object_write_attempts(writer_authority_id, accepted_sequence)
    WHERE accepted_sequence IS NOT NULL
      AND state IN ('terminal_visible', 'permanent', 'spool_removed');
CREATE OR REPLACE FUNCTION object_write_authority_transition_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (OLD.writer_authority_id, OLD.host_provider, OLD.host_partition,
        OLD.host_account_id, OLD.host_region, OLD.immutable_host_id,
        OLD.node_id, OLD.object_provider, OLD.object_partition,
        OLD.object_account_id, OLD.object_region, OLD.workload_principal_id,
        OLD.object_store_scope_id)
       IS DISTINCT FROM
       (NEW.writer_authority_id, NEW.host_provider, NEW.host_partition,
        NEW.host_account_id, NEW.host_region, NEW.immutable_host_id,
        NEW.node_id, NEW.object_provider, NEW.object_partition,
        NEW.object_account_id, NEW.object_region, NEW.workload_principal_id,
        NEW.object_store_scope_id)
       OR NEW.max_accepted_sequence < OLD.max_accepted_sequence
       OR NEW.terminal_prefix_sequence < OLD.terminal_prefix_sequence
       OR NEW.terminal_prefix_sequence > NEW.max_accepted_sequence
       OR (NEW.terminal_prefix_sequence = OLD.terminal_prefix_sequence
           AND NEW.terminal_prefix_sha256 IS DISTINCT FROM OLD.terminal_prefix_sha256)
       OR (NEW.max_accepted_sequence > OLD.max_accepted_sequence AND NOT (
            OLD.state = 'open' AND NEW.state = 'open'
            AND NEW.max_accepted_sequence = OLD.max_accepted_sequence + 1))
       OR NOT (
            NEW.state = OLD.state
            OR (OLD.state = 'open' AND NEW.state = 'cutoff_pending')
            OR (OLD.state = 'cutoff_pending' AND NEW.state = 'cutoff_complete'))
       OR (OLD.fence_attempt_id IS NOT NULL
           AND OLD.fence_attempt_id IS DISTINCT FROM NEW.fence_attempt_id)
       OR (OLD.cutoff_effective_at_unix_ms IS NOT NULL
           AND (OLD.cutoff_effective_at_unix_ms, OLD.cutoff_sequence)
               IS DISTINCT FROM
               (NEW.cutoff_effective_at_unix_ms, NEW.cutoff_sequence))
       OR (OLD.cutoff_receipt IS NOT NULL
           AND OLD.cutoff_receipt IS DISTINCT FROM NEW.cutoff_receipt)
    THEN
        RAISE EXCEPTION 'invalid object-write authority transition';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER object_write_authority_transition_is_forward_only
BEFORE UPDATE ON object_write_authorities FOR EACH ROW
EXECUTE FUNCTION object_write_authority_transition_guard();
CREATE OR REPLACE FUNCTION object_write_credential_transition_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (OLD.credential_id, OLD.public_key_spki, OLD.public_key_spki_sha256,
        OLD.writer_authority_id, OLD.host_provider, OLD.host_partition,
        OLD.host_account_id, OLD.host_region, OLD.immutable_host_id,
        OLD.node_id, OLD.node_boot_id, OLD.agent_instance_id,
        OLD.agent_session_epoch, OLD.volume_id, OLD.attachment_id,
        OLD.attachment_epoch, OLD.private_artifact_id,
        OLD.private_file_fsync_receipt_id,
        OLD.private_directory_fsync_receipt_id, OLD.registered_at_unix_ms)
       IS DISTINCT FROM
       (NEW.credential_id, NEW.public_key_spki, NEW.public_key_spki_sha256,
        NEW.writer_authority_id, NEW.host_provider, NEW.host_partition,
        NEW.host_account_id, NEW.host_region, NEW.immutable_host_id,
        NEW.node_id, NEW.node_boot_id, NEW.agent_instance_id,
        NEW.agent_session_epoch, NEW.volume_id, NEW.attachment_id,
        NEW.attachment_epoch, NEW.private_artifact_id,
        NEW.private_file_fsync_receipt_id,
        NEW.private_directory_fsync_receipt_id, NEW.registered_at_unix_ms)
       OR NOT (OLD.state = 'active' AND NEW.state = 'retired')
    THEN
        RAISE EXCEPTION 'invalid object-write credential transition';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER object_write_credential_transition_is_retirement_only
BEFORE UPDATE ON object_write_credentials FOR EACH ROW
EXECUTE FUNCTION object_write_credential_transition_guard();
CREATE OR REPLACE FUNCTION object_write_attempt_transition_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (OLD.request_id, OLD.writer_authority_id, OLD.credential_id,
        OLD.volume_id, OLD.key_kind, OLD.object_provider,
        OLD.object_partition, OLD.object_account_id, OLD.object_region,
        OLD.object_store_scope_id, OLD.object_key, OLD.content_sha256,
        OLD.content_length, OLD.receiving_started_at_unix_ms)
       IS DISTINCT FROM
       (NEW.request_id, NEW.writer_authority_id, NEW.credential_id,
        NEW.volume_id, NEW.key_kind, NEW.object_provider,
        NEW.object_partition, NEW.object_account_id, NEW.object_region,
        NEW.object_store_scope_id, NEW.object_key, NEW.content_sha256,
        NEW.content_length, NEW.receiving_started_at_unix_ms)
       OR NOT (
            (OLD.state = 'receiving' AND NEW.state = 'durable_spooled')
            OR (OLD.state = 'durable_spooled'
                AND NEW.state IN ('rejected_before_accept', 'accepted_spooled'))
            OR (OLD.state = 'accepted_spooled' AND NEW.state = 'provider_issued')
            OR (OLD.state = 'provider_issued'
                AND NEW.state IN ('qualification_response_lost',
                                  'terminal_visible', 'permanent',
                                  'qualification_unproven_visible'))
            OR (OLD.state = 'qualification_response_lost'
                AND NEW.state = 'terminal_visible')
            OR (OLD.state IN ('terminal_visible', 'permanent',
                              'qualification_unproven_visible')
                AND NEW.state = 'spool_removed'))
       OR (OLD.spool_id IS NOT NULL AND
           (OLD.spool_id, OLD.spool_file_fsync_receipt_id,
            OLD.spool_directory_fsync_receipt_id, OLD.spool_durable_at_unix_ms)
           IS DISTINCT FROM
           (NEW.spool_id, NEW.spool_file_fsync_receipt_id,
            NEW.spool_directory_fsync_receipt_id, NEW.spool_durable_at_unix_ms))
       OR (OLD.accepted_sequence IS NOT NULL AND
           (OLD.accepted_sequence, OLD.accepted_at_unix_ms,
            OLD.provider_attempt_id)
           IS DISTINCT FROM
           (NEW.accepted_sequence, NEW.accepted_at_unix_ms,
            NEW.provider_attempt_id))
       OR (OLD.provider_issued_at_unix_ms IS NOT NULL
           AND OLD.provider_issued_at_unix_ms IS DISTINCT FROM
               NEW.provider_issued_at_unix_ms)
       OR (OLD.qualification_response_loss_canonical IS NOT NULL AND
           (OLD.qualification_request_canonical,
            OLD.qualification_authorization_canonical,
            OLD.qualification_successful_put_canonical,
            OLD.qualification_response_loss_canonical,
            OLD.qualification_response_lost_attempt_canonical,
            OLD.qualification_response_loss_sha256,
            OLD.qualification_injection_receipt_id,
            OLD.qualification_injected_at_unix_ms)
           IS DISTINCT FROM
           (NEW.qualification_request_canonical,
            NEW.qualification_authorization_canonical,
            NEW.qualification_successful_put_canonical,
            NEW.qualification_response_loss_canonical,
            NEW.qualification_response_lost_attempt_canonical,
            NEW.qualification_response_loss_sha256,
            NEW.qualification_injection_receipt_id,
            NEW.qualification_injected_at_unix_ms))
       OR (OLD.qualification_visibility_head_canonical IS NOT NULL
           AND OLD.qualification_visibility_head_canonical IS DISTINCT FROM
               NEW.qualification_visibility_head_canonical)
       OR (OLD.terminal_kind IS NOT NULL AND
           (OLD.terminal_kind, OLD.put_receipt_id,
            OLD.put_completed_at_unix_ms, OLD.visibility_receipt_id,
            OLD.visible_at_unix_ms, OLD.failure_receipt_id,
            OLD.failed_at_unix_ms)
           IS DISTINCT FROM
           (NEW.terminal_kind, NEW.put_receipt_id,
            NEW.put_completed_at_unix_ms, NEW.visibility_receipt_id,
            NEW.visible_at_unix_ms, NEW.failure_receipt_id,
            NEW.failed_at_unix_ms))
       OR (OLD.qualification_unproven_reason IS NOT NULL AND
           (OLD.qualification_request_canonical,
            OLD.qualification_unproven_intent_canonical,
            OLD.qualification_unproven_sealed_request_canonical,
            OLD.qualification_unproven_receipt_canonical,
            OLD.qualification_unproven_attempt_canonical,
            OLD.qualification_unproven_resolution_receipt_id,
            OLD.qualification_unproven_reason,
            OLD.qualification_head_evidence_canonical,
            OLD.qualification_unproven_at_unix_ms)
           IS DISTINCT FROM
           (NEW.qualification_request_canonical,
            NEW.qualification_unproven_intent_canonical,
            NEW.qualification_unproven_sealed_request_canonical,
            NEW.qualification_unproven_receipt_canonical,
            NEW.qualification_unproven_attempt_canonical,
            NEW.qualification_unproven_resolution_receipt_id,
            NEW.qualification_unproven_reason,
            NEW.qualification_head_evidence_canonical,
            NEW.qualification_unproven_at_unix_ms))
    THEN
        RAISE EXCEPTION 'invalid object-write attempt transition';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER object_write_attempt_transition_is_forward_only
BEFORE UPDATE ON object_write_attempts FOR EACH ROW
EXECUTE FUNCTION object_write_attempt_transition_guard();
CREATE OR REPLACE FUNCTION object_write_credential_parent_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM object_write_credentials credential
          JOIN object_write_authorities authority
            ON authority.writer_authority_id = credential.writer_authority_id
         WHERE credential.writer_authority_id = NEW.writer_authority_id
           AND (
                (credential.host_provider, credential.host_partition,
                 credential.host_account_id, credential.host_region,
                 credential.immutable_host_id, credential.node_id)
                IS DISTINCT FROM
                (authority.host_provider, authority.host_partition,
                 authority.host_account_id, authority.host_region,
                 authority.immutable_host_id, authority.node_id)
                OR (credential.state = 'active' AND authority.state <> 'open')
           )
    ) THEN
        RAISE EXCEPTION 'active object-write credential under closed parent authority';
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER object_write_authority_children_closed
AFTER INSERT OR UPDATE ON object_write_authorities
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
EXECUTE FUNCTION object_write_credential_parent_guard();
CREATE CONSTRAINT TRIGGER object_write_credential_parent_open
AFTER INSERT OR UPDATE ON object_write_credentials
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
EXECUTE FUNCTION object_write_credential_parent_guard();
CREATE TABLE IF NOT EXISTS host_fence_provider_queue_v1 (
    fence_attempt_id TEXT
        CONSTRAINT host_fence_provider_queue_v1_pkey PRIMARY KEY,
    request_bytes BYTEA NOT NULL
        CONSTRAINT host_fence_provider_queue_request_bytes_check
        CHECK (octet_length(request_bytes) BETWEEN 2 AND 1048576),
    request_sha256 TEXT NOT NULL
        CONSTRAINT host_fence_provider_queue_request_digest_check
        CHECK (request_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    provider TEXT NOT NULL,
    host_partition TEXT NOT NULL,
    host_account_id TEXT NOT NULL,
    host_region TEXT NOT NULL,
    immutable_host_id TEXT NOT NULL,
    node_id TEXT NOT NULL
        CONSTRAINT host_fence_provider_queue_node_id_fkey
        REFERENCES node_identities(node_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    expected_node_boot_id TEXT NOT NULL
        CONSTRAINT host_fence_provider_queue_boot_id_check
        CHECK (expected_node_boot_id ~ '^[0-9a-f]{32}$'),
    expected_agent_session_epoch BIGINT NOT NULL
        CONSTRAINT host_fence_provider_queue_session_epoch_check
        CHECK (expected_agent_session_epoch > 0),
    writer_authority_id TEXT NOT NULL
        CONSTRAINT host_fence_provider_queue_writer_id_fkey
        REFERENCES object_write_authorities(writer_authority_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    workload_principal_id TEXT NOT NULL,
    object_store_scope_id TEXT NOT NULL,
    network_quarantine_boundary_id TEXT NOT NULL,
    state TEXT NOT NULL
        CONSTRAINT host_fence_provider_queue_state_check
        CHECK (state IN ('pending', 'claimed', 'terminal')),
    worker_id TEXT,
    claim_attempt_token TEXT
        CONSTRAINT host_fence_provider_queue_claim_token_check
        CHECK (claim_attempt_token ~ '^[0-9a-f]{32}$'),
    claim_duration_ms BIGINT
        CONSTRAINT host_fence_provider_queue_claim_duration_check
        CHECK (claim_duration_ms BETWEEN 1 AND 60000),
    claim_generation BIGINT NOT NULL
        CONSTRAINT host_fence_provider_queue_claim_generation_check
        CHECK (claim_generation >= 0),
    claim_lease_expires_at_unix_ms BIGINT
        CONSTRAINT host_fence_provider_queue_claim_lease_check
        CHECK (claim_lease_expires_at_unix_ms >= 0),
    renew_attempt_token TEXT
        CONSTRAINT host_fence_provider_queue_renew_token_check
        CHECK (renew_attempt_token ~ '^[0-9a-f]{32}$'),
    renew_duration_ms BIGINT
        CONSTRAINT host_fence_provider_queue_renew_duration_check
        CHECK (renew_duration_ms BETWEEN 1 AND 60000),
    renew_generation BIGINT NOT NULL
        CONSTRAINT host_fence_provider_queue_renew_generation_check
        CHECK (renew_generation >= 0),
    renewed_from_unix_ms BIGINT
        CONSTRAINT host_fence_provider_queue_renewed_from_check
        CHECK (renewed_from_unix_ms >= 0),
    renewed_to_unix_ms BIGINT
        CONSTRAINT host_fence_provider_queue_renewed_to_check
        CHECK (renewed_to_unix_ms > renewed_from_unix_ms),
    evidence_bytes BYTEA
        CONSTRAINT host_fence_provider_queue_evidence_bytes_check
        CHECK (evidence_bytes IS NULL OR
               octet_length(evidence_bytes) BETWEEN 2 AND 4194304),
    evidence_sha256 TEXT
        CONSTRAINT host_fence_provider_queue_evidence_digest_check
        CHECK (evidence_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    enqueued_at_unix_ms BIGINT NOT NULL
        CONSTRAINT host_fence_provider_queue_enqueued_time_check
        CHECK (enqueued_at_unix_ms >= 0),
    completed_at_unix_ms BIGINT
        CONSTRAINT host_fence_provider_queue_completed_time_check
        CHECK (completed_at_unix_ms >= enqueued_at_unix_ms),
    CONSTRAINT host_fence_provider_queue_request_projection_check CHECK (
        convert_from(request_bytes, 'UTF8')::jsonb #>> '{binding,fence_attempt_id}' =
            fence_attempt_id
        AND convert_from(request_bytes, 'UTF8')::jsonb #>>
            '{binding,provider_scope,provider}' = provider
        AND convert_from(request_bytes, 'UTF8')::jsonb #>>
            '{binding,provider_scope,partition}' = host_partition
        AND convert_from(request_bytes, 'UTF8')::jsonb #>>
            '{binding,provider_scope,account_id}' = host_account_id
        AND convert_from(request_bytes, 'UTF8')::jsonb #>>
            '{binding,provider_scope,region}' = host_region
        AND convert_from(request_bytes, 'UTF8')::jsonb #>>
            '{binding,immutable_host_id}' = immutable_host_id
        AND convert_from(request_bytes, 'UTF8')::jsonb #>> '{binding,node_id}' = node_id
        AND convert_from(request_bytes, 'UTF8')::jsonb #>>
            '{binding,expected_node_boot_id}' = expected_node_boot_id
        AND convert_from(request_bytes, 'UTF8')::jsonb #>>
            '{binding,expected_agent_session_epoch}' =
                expected_agent_session_epoch::TEXT
        AND convert_from(request_bytes, 'UTF8')::jsonb #>>
            '{object_writer,writer_authority_id}' = writer_authority_id
        AND convert_from(request_bytes, 'UTF8')::jsonb #>>
            '{object_writer,workload_principal_id}' = workload_principal_id
        AND convert_from(request_bytes, 'UTF8')::jsonb #>>
            '{object_writer,object_store_scope_id}' = object_store_scope_id
        AND convert_from(request_bytes, 'UTF8')::jsonb #>>
            '{network_quarantine_boundary_id}' = network_quarantine_boundary_id
    ),
    CONSTRAINT host_fence_provider_queue_renew_shape_check CHECK (
        (renew_generation = 0 AND renew_attempt_token IS NULL
            AND renew_duration_ms IS NULL AND renewed_from_unix_ms IS NULL
            AND renewed_to_unix_ms IS NULL) OR
        (renew_generation > 0 AND renew_attempt_token IS NOT NULL
            AND renew_duration_ms IS NOT NULL AND renewed_from_unix_ms IS NOT NULL
            AND renewed_to_unix_ms IS NOT NULL
            AND renewed_to_unix_ms = claim_lease_expires_at_unix_ms)
    ),
    CONSTRAINT host_fence_provider_queue_state_shape_check CHECK (
        (state = 'pending' AND worker_id IS NULL AND claim_attempt_token IS NULL
            AND claim_duration_ms IS NULL
            AND claim_generation = 0 AND claim_lease_expires_at_unix_ms IS NULL
            AND renew_generation = 0 AND evidence_bytes IS NULL
            AND evidence_sha256 IS NULL AND completed_at_unix_ms IS NULL) OR
        (state = 'claimed' AND worker_id IS NOT NULL AND claim_attempt_token IS NOT NULL
            AND claim_duration_ms IS NOT NULL
            AND claim_generation > 0 AND claim_lease_expires_at_unix_ms IS NOT NULL
            AND evidence_bytes IS NULL AND evidence_sha256 IS NULL
            AND completed_at_unix_ms IS NULL) OR
        (state = 'terminal' AND worker_id IS NOT NULL AND claim_attempt_token IS NOT NULL
            AND claim_duration_ms IS NOT NULL
            AND claim_generation > 0 AND claim_lease_expires_at_unix_ms IS NOT NULL
            AND evidence_bytes IS NOT NULL AND evidence_sha256 IS NOT NULL
            AND completed_at_unix_ms IS NOT NULL)
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS host_fence_provider_queue_claim_token_unique
    ON host_fence_provider_queue_v1(claim_attempt_token)
    WHERE claim_attempt_token IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS host_fence_provider_queue_renew_token_unique
    ON host_fence_provider_queue_v1(renew_attempt_token)
    WHERE renew_attempt_token IS NOT NULL;
CREATE INDEX IF NOT EXISTS host_fence_provider_queue_claim_scan
    ON host_fence_provider_queue_v1(
        provider, host_partition, host_account_id, host_region,
        state, claim_lease_expires_at_unix_ms, enqueued_at_unix_ms,
        fence_attempt_id COLLATE \"C\"
    ) WHERE state IN ('pending', 'claimed');
CREATE OR REPLACE FUNCTION control_host_fence_provider_queue_transition_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (OLD.fence_attempt_id, OLD.request_bytes, OLD.request_sha256,
        OLD.provider, OLD.host_partition, OLD.host_account_id, OLD.host_region,
        OLD.immutable_host_id, OLD.node_id, OLD.expected_node_boot_id,
        OLD.expected_agent_session_epoch, OLD.writer_authority_id,
        OLD.workload_principal_id, OLD.object_store_scope_id,
        OLD.network_quarantine_boundary_id, OLD.enqueued_at_unix_ms)
       IS DISTINCT FROM
       (NEW.fence_attempt_id, NEW.request_bytes, NEW.request_sha256,
        NEW.provider, NEW.host_partition, NEW.host_account_id, NEW.host_region,
        NEW.immutable_host_id, NEW.node_id, NEW.expected_node_boot_id,
        NEW.expected_agent_session_epoch, NEW.writer_authority_id,
        NEW.workload_principal_id, NEW.object_store_scope_id,
        NEW.network_quarantine_boundary_id, NEW.enqueued_at_unix_ms)
       OR OLD.state = 'terminal'
       OR NOT (
            (OLD.state = 'pending' AND NEW.state = 'claimed'
                AND NEW.claim_generation = 1)
            OR (OLD.state = 'claimed' AND NEW.state = 'claimed' AND (
                (OLD.claim_attempt_token = NEW.claim_attempt_token
                    AND OLD.worker_id = NEW.worker_id
                    AND OLD.claim_duration_ms = NEW.claim_duration_ms
                    AND OLD.claim_generation = NEW.claim_generation
                    AND OLD.renew_attempt_token IS DISTINCT FROM
                        NEW.renew_attempt_token
                    AND NEW.renew_generation = OLD.renew_generation + 1
                    AND NEW.claim_lease_expires_at_unix_ms >
                        OLD.claim_lease_expires_at_unix_ms)
                OR (OLD.claim_lease_expires_at_unix_ms <=
                        floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT
                    AND OLD.claim_attempt_token <> NEW.claim_attempt_token
                    AND NEW.claim_generation = OLD.claim_generation + 1
                    AND NEW.renew_generation = 0)
            ))
            OR (OLD.state = 'claimed' AND NEW.state = 'terminal'
                AND OLD.worker_id = NEW.worker_id
                AND OLD.claim_attempt_token = NEW.claim_attempt_token
                AND OLD.claim_duration_ms = NEW.claim_duration_ms
                AND OLD.claim_generation = NEW.claim_generation
                AND OLD.claim_lease_expires_at_unix_ms =
                    NEW.claim_lease_expires_at_unix_ms
                AND (OLD.renew_attempt_token, OLD.renew_duration_ms,
                     OLD.renew_generation, OLD.renewed_from_unix_ms,
                     OLD.renewed_to_unix_ms)
                    IS NOT DISTINCT FROM
                    (NEW.renew_attempt_token, NEW.renew_duration_ms,
                     NEW.renew_generation, NEW.renewed_from_unix_ms,
                     NEW.renewed_to_unix_ms))
       )
       OR (OLD.evidence_bytes IS NOT NULL AND
           (OLD.evidence_bytes, OLD.evidence_sha256, OLD.completed_at_unix_ms)
           IS DISTINCT FROM
           (NEW.evidence_bytes, NEW.evidence_sha256, NEW.completed_at_unix_ms))
    THEN
        RAISE EXCEPTION 'invalid Host-fence provider queue transition';
    END IF;
    RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION control_host_fence_provider_queue_cannot_delete()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Host-fence provider queue rows cannot be deleted';
END;
$$;
CREATE TRIGGER host_fence_provider_queue_transition_is_forward_only
BEFORE UPDATE ON host_fence_provider_queue_v1 FOR EACH ROW
EXECUTE FUNCTION control_host_fence_provider_queue_transition_guard();
CREATE TRIGGER host_fence_provider_queue_cannot_delete
BEFORE DELETE ON host_fence_provider_queue_v1 FOR EACH ROW
EXECUTE FUNCTION control_host_fence_provider_queue_cannot_delete();
CREATE TABLE IF NOT EXISTS runtime_node_placement_policies (
    node_id TEXT PRIMARY KEY REFERENCES node_identities(node_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    policy_revision BIGINT NOT NULL CHECK (policy_revision > 0),
    scheduling_state TEXT NOT NULL CHECK (scheduling_state IN ('cordoned', 'schedulable')),
    allocatable_vcpus BIGINT NOT NULL
        CHECK (allocatable_vcpus BETWEEN 1 AND 4294967295),
    allocatable_memory_bytes BIGINT NOT NULL CHECK (allocatable_memory_bytes > 0),
    guest_config_digest TEXT NOT NULL
        CHECK (guest_config_digest ~ '^sha256:[0-9a-f]{64}$'),
    block_frontend TEXT NOT NULL CHECK (block_frontend IN ('kernel_nbd', 'vhost_user_blk')),
    guest_ipv4_network_address TEXT NOT NULL
        CHECK (guest_ipv4_network_address ~ '^[0-9]{1,3}([.][0-9]{1,3}){3}$'),
    node_transport_target TEXT NOT NULL
        CONSTRAINT runtime_node_placement_policies_node_transport_target_check
        CHECK (node_transport_target ~ '^https://[a-z0-9.-]+:[1-9][0-9]{0,4}$')
);
CREATE TABLE IF NOT EXISTS runtime_node_authority_apply_records (
    apply_id TEXT PRIMARY KEY,
    request JSONB NOT NULL CHECK (jsonb_typeof(request) = 'object'),
    request_sha256 TEXT NOT NULL CHECK (request_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    principal JSONB NOT NULL CHECK (jsonb_typeof(principal) = 'object'),
    principal_kind TEXT NOT NULL
        CHECK (principal_kind IN ('deployment_provisioner', 'workos_fleet_administrator')),
    node_id TEXT NOT NULL,
    outcome JSONB NOT NULL CHECK (jsonb_typeof(outcome) = 'object'),
    outcome_kind TEXT NOT NULL CHECK (outcome_kind IN ('applied', 'authority_precondition_failed')),
    committed_at_unix_ms BIGINT NOT NULL CHECK (committed_at_unix_ms >= 0)
);
CREATE TABLE IF NOT EXISTS runtime_provisioner_deployment_identity (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    deployment_id TEXT NOT NULL UNIQUE,
    current_trust_revision BIGINT NOT NULL CHECK (current_trust_revision > 0),
    current_active_set_sha256 TEXT NOT NULL
        CHECK (current_active_set_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    first_committed_at_unix_ms BIGINT NOT NULL CHECK (first_committed_at_unix_ms >= 0)
);
CREATE TABLE IF NOT EXISTS runtime_provisioner_trust_revisions (
    deployment_id TEXT NOT NULL
        REFERENCES runtime_provisioner_deployment_identity(deployment_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    trust_revision BIGINT NOT NULL CHECK (trust_revision > 0),
    active_set_sha256 TEXT NOT NULL
        CHECK (active_set_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    expected_previous_trust_revision BIGINT NULL
        CHECK (expected_previous_trust_revision > 0),
    expected_previous_active_set_sha256 TEXT NULL
        CHECK (expected_previous_active_set_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    committed_at_unix_ms BIGINT NOT NULL CHECK (committed_at_unix_ms >= 0),
    PRIMARY KEY (deployment_id, trust_revision),
    UNIQUE (deployment_id, trust_revision, active_set_sha256),
    CHECK (
        (trust_revision = 1 AND expected_previous_trust_revision IS NULL
            AND expected_previous_active_set_sha256 IS NULL) OR
        (trust_revision > 1
            AND expected_previous_trust_revision = trust_revision - 1
            AND expected_previous_active_set_sha256 IS NOT NULL)
    )
);
ALTER TABLE runtime_provisioner_deployment_identity
    ADD CONSTRAINT runtime_provisioner_current_trust_revision
    FOREIGN KEY (deployment_id, current_trust_revision, current_active_set_sha256)
    REFERENCES runtime_provisioner_trust_revisions(
        deployment_id, trust_revision, active_set_sha256)
    ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE IF NOT EXISTS runtime_provisioner_credential_lineage (
    credential_id TEXT PRIMARY KEY,
    deployment_id TEXT NOT NULL
        REFERENCES runtime_provisioner_deployment_identity(deployment_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    public_key_spki TEXT NOT NULL UNIQUE,
    public_key_spki_sha256 TEXT NOT NULL UNIQUE
        CHECK (public_key_spki_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    state TEXT NOT NULL CHECK (state IN ('active', 'retired')),
    first_committed_at_unix_ms BIGINT NOT NULL CHECK (first_committed_at_unix_ms >= 0),
    retired_at_unix_ms BIGINT NULL CHECK (
        retired_at_unix_ms IS NULL OR
        retired_at_unix_ms >= first_committed_at_unix_ms),
    CHECK ((state = 'active' AND retired_at_unix_ms IS NULL) OR
           (state = 'retired' AND retired_at_unix_ms IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS route_v2_signing_authority (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE
        CONSTRAINT route_v2_signing_authority_singleton_ck CHECK (singleton),
    deployment_id TEXT NOT NULL UNIQUE,
    current_signer_revision BIGINT NOT NULL
        CONSTRAINT route_v2_signing_authority_revision_ck
        CHECK (current_signer_revision > 0),
    current_signer_reference_sha256 TEXT NOT NULL
        CONSTRAINT route_v2_signing_authority_digest_ck
        CHECK (current_signer_reference_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    signer_state TEXT NOT NULL
        CONSTRAINT route_v2_signing_authority_state_ck
        CHECK (signer_state IN ('active', 'disabled')),
    active_kid TEXT NOT NULL
        CONSTRAINT route_v2_signing_authority_active_kid_ck
        CHECK (active_kid = '' OR active_kid ~ '^[0-9a-f]{64}$'),
    public_key_ring_version BIGINT NOT NULL
        CONSTRAINT route_v2_signing_authority_ring_version_ck
        CHECK (public_key_ring_version > 0),
    public_key_ring_digest TEXT NOT NULL
        CONSTRAINT route_v2_signing_authority_ring_digest_ck
        CHECK (public_key_ring_digest ~ '^sha256:[0-9a-f]{64}$'),
    secret_reference_id TEXT NOT NULL,
    first_committed_at_unix_ms BIGINT NOT NULL
        CONSTRAINT route_v2_signing_authority_first_time_ck
        CHECK (first_committed_at_unix_ms >= 0),
    CONSTRAINT route_v2_signing_authority_selection_ck CHECK (
        (signer_state = 'active' AND active_kid <> '' AND secret_reference_id <> '') OR
        (signer_state = 'disabled' AND active_kid = '' AND secret_reference_id = '')
    ),
    CONSTRAINT route_v2_signing_authority_current_key UNIQUE (
        deployment_id, current_signer_revision,
        current_signer_reference_sha256, signer_state, active_kid,
        public_key_ring_version, public_key_ring_digest, secret_reference_id)
);
CREATE TABLE IF NOT EXISTS route_v2_signer_revisions (
    deployment_id TEXT NOT NULL,
    signer_revision BIGINT NOT NULL
        CONSTRAINT route_v2_signer_revision_revision_ck
        CHECK (signer_revision > 0),
    signer_reference_sha256 TEXT NOT NULL
        CONSTRAINT route_v2_signer_revision_digest_ck
        CHECK (signer_reference_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    signer_reference_bytes BYTEA NOT NULL
        CONSTRAINT route_v2_signer_revision_bytes_ck
        CHECK (octet_length(signer_reference_bytes) BETWEEN 1 AND 16384),
    expected_previous_signer_revision BIGINT NULL
        CONSTRAINT route_v2_signer_revision_previous_revision_ck
        CHECK (expected_previous_signer_revision > 0),
    expected_previous_signer_reference_sha256 TEXT NULL
        CONSTRAINT route_v2_signer_revision_previous_digest_ck
        CHECK (expected_previous_signer_reference_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    signer_state TEXT NOT NULL
        CONSTRAINT route_v2_signer_revision_state_ck
        CHECK (signer_state IN ('active', 'disabled')),
    active_kid TEXT NOT NULL
        CONSTRAINT route_v2_signer_revision_active_kid_ck
        CHECK (active_kid = '' OR active_kid ~ '^[0-9a-f]{64}$'),
    public_key_ring_version BIGINT NOT NULL
        CONSTRAINT route_v2_signer_revision_ring_version_ck
        CHECK (public_key_ring_version > 0),
    public_key_ring_digest TEXT NOT NULL
        CONSTRAINT route_v2_signer_revision_ring_digest_ck
        CHECK (public_key_ring_digest ~ '^sha256:[0-9a-f]{64}$'),
    secret_reference_id TEXT NOT NULL,
    committed_at_unix_ms BIGINT NOT NULL
        CONSTRAINT route_v2_signer_revision_committed_time_ck
        CHECK (committed_at_unix_ms >= 0),
    PRIMARY KEY (deployment_id, signer_revision),
    CONSTRAINT route_v2_signer_revisions_exact_key UNIQUE (
        deployment_id, signer_revision, signer_reference_sha256,
        signer_state, active_kid, public_key_ring_version,
        public_key_ring_digest, secret_reference_id),
    CONSTRAINT route_v2_signer_revisions_reference_key UNIQUE (
        deployment_id, signer_revision, signer_reference_sha256),
    CONSTRAINT route_v2_signer_revision_lineage_ck CHECK (
        (signer_revision = 1 AND expected_previous_signer_revision IS NULL
            AND expected_previous_signer_reference_sha256 IS NULL) OR
        (signer_revision > 1
            AND expected_previous_signer_revision = signer_revision - 1
            AND expected_previous_signer_reference_sha256 IS NOT NULL)
    ),
    CONSTRAINT route_v2_signer_revision_selection_ck CHECK (
        (signer_state = 'active' AND active_kid <> '' AND secret_reference_id <> '') OR
        (signer_state = 'disabled' AND active_kid = '' AND secret_reference_id = '')
    ),
    CONSTRAINT route_v2_signer_revisions_authority_fkey
        FOREIGN KEY (deployment_id)
        REFERENCES route_v2_signing_authority(deployment_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT route_v2_signer_revision_previous_fkey
        FOREIGN KEY (
            deployment_id, expected_previous_signer_revision,
            expected_previous_signer_reference_sha256)
        REFERENCES route_v2_signer_revisions(
            deployment_id, signer_revision, signer_reference_sha256)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE route_v2_signing_authority
    ADD CONSTRAINT route_v2_signing_authority_current_revision_fkey
    FOREIGN KEY (
        deployment_id, current_signer_revision,
        current_signer_reference_sha256, signer_state, active_kid,
        public_key_ring_version, public_key_ring_digest, secret_reference_id)
    REFERENCES route_v2_signer_revisions(
        deployment_id, signer_revision, signer_reference_sha256,
        signer_state, active_kid, public_key_ring_version,
        public_key_ring_digest, secret_reference_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE IF NOT EXISTS route_v2_signer_key_lineage (
    kid TEXT PRIMARY KEY
        CONSTRAINT route_v2_signer_key_lineage_kid_ck
        CHECK (kid ~ '^[0-9a-f]{64}$'),
    deployment_id TEXT NOT NULL,
    public_key_spki TEXT NOT NULL UNIQUE,
    secret_reference_id TEXT NOT NULL UNIQUE,
    first_signer_revision BIGINT NOT NULL
        CONSTRAINT route_v2_signer_key_lineage_first_revision_ck
        CHECK (first_signer_revision > 0),
    state TEXT NOT NULL
        CONSTRAINT route_v2_signer_key_lineage_state_ck
        CHECK (state IN ('active', 'retired')),
    first_committed_at_unix_ms BIGINT NOT NULL
        CONSTRAINT route_v2_signer_key_lineage_first_time_ck
        CHECK (first_committed_at_unix_ms >= 0),
    retired_at_unix_ms BIGINT NULL
        CONSTRAINT route_v2_signer_key_lineage_retired_time_ck CHECK (
        retired_at_unix_ms IS NULL OR
        retired_at_unix_ms >= first_committed_at_unix_ms),
    CONSTRAINT route_v2_signer_key_lineage_state_time_ck
        CHECK ((state = 'active' AND retired_at_unix_ms IS NULL) OR
               (state = 'retired' AND retired_at_unix_ms IS NOT NULL)),
    CONSTRAINT route_v2_signer_key_lineage_first_revision_fkey
        FOREIGN KEY (deployment_id, first_signer_revision)
        REFERENCES route_v2_signer_revisions(deployment_id, signer_revision)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT route_v2_signer_key_lineage_authority_fkey
        FOREIGN KEY (deployment_id)
        REFERENCES route_v2_signing_authority(deployment_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE IF NOT EXISTS route_v2_public_key_ring_revisions (
    deployment_id TEXT NOT NULL,
    ring_version BIGINT NOT NULL
        CONSTRAINT route_v2_public_ring_version_ck CHECK (ring_version > 0),
    key_ring_digest TEXT NOT NULL
        CONSTRAINT route_v2_public_ring_digest_ck
        CHECK (key_ring_digest ~ '^sha256:[0-9a-f]{64}$'),
    exact_bytes BYTEA NOT NULL
        CONSTRAINT route_v2_public_ring_bytes_ck
        CHECK (octet_length(exact_bytes) BETWEEN 1 AND 16384),
    expected_previous_ring_version BIGINT NULL
        CONSTRAINT route_v2_public_ring_previous_version_ck
        CHECK (expected_previous_ring_version > 0),
    expected_previous_key_ring_digest TEXT NULL
        CONSTRAINT route_v2_public_ring_previous_digest_ck
        CHECK (expected_previous_key_ring_digest ~ '^sha256:[0-9a-f]{64}$'),
    published_at_unix_ms BIGINT NOT NULL
        CONSTRAINT route_v2_public_ring_published_time_ck
        CHECK (published_at_unix_ms >= 0),
    PRIMARY KEY (deployment_id, ring_version),
    CONSTRAINT route_v2_public_key_ring_revisions_exact_key
        UNIQUE (deployment_id, ring_version, key_ring_digest),
    CONSTRAINT route_v2_public_ring_lineage_ck CHECK (
        (ring_version = 1 AND expected_previous_ring_version IS NULL
            AND expected_previous_key_ring_digest IS NULL) OR
        (ring_version > 1
            AND expected_previous_ring_version = ring_version - 1
            AND expected_previous_key_ring_digest IS NOT NULL)
    ),
    CONSTRAINT route_v2_public_ring_authority_fkey
        FOREIGN KEY (deployment_id)
        REFERENCES route_v2_signing_authority(deployment_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT route_v2_public_ring_previous_fkey
        FOREIGN KEY (
            deployment_id, expected_previous_ring_version,
            expected_previous_key_ring_digest)
        REFERENCES route_v2_public_key_ring_revisions(
            deployment_id, ring_version, key_ring_digest)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE route_v2_signing_authority
    ADD CONSTRAINT route_v2_signing_authority_current_ring_fkey
    FOREIGN KEY (
        deployment_id, public_key_ring_version, public_key_ring_digest)
    REFERENCES route_v2_public_key_ring_revisions(
        deployment_id, ring_version, key_ring_digest)
    ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE route_v2_signer_revisions
    ADD CONSTRAINT route_v2_signer_revision_ring_fkey
    FOREIGN KEY (
        deployment_id, public_key_ring_version, public_key_ring_digest)
    REFERENCES route_v2_public_key_ring_revisions(
        deployment_id, ring_version, key_ring_digest)
    ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE IF NOT EXISTS route_v2_signer_retirements (
    deployment_id TEXT NOT NULL,
    kid TEXT NOT NULL
        CONSTRAINT route_v2_signer_retirement_kid_ck
        CHECK (kid ~ '^[0-9a-f]{64}$'),
    secret_reference_id TEXT NOT NULL,
    retirement_signer_revision BIGINT NOT NULL
        CONSTRAINT route_v2_signer_retirement_revision_ck
        CHECK (retirement_signer_revision > 0),
    last_old_issue_at_unix_ms BIGINT NOT NULL
        CONSTRAINT route_v2_signer_retirement_time_ck
        CHECK (last_old_issue_at_unix_ms >= 0),
    source TEXT NOT NULL
        CONSTRAINT route_v2_signer_retirement_source_ck
        CHECK (source IN ('normal', 'emergency')),
    state TEXT NOT NULL
        CONSTRAINT route_v2_signer_retirement_state_ck
        CHECK (state IN ('pending', 'ring_removed', 'retired')),
    ring_removed_version BIGINT NULL
        CONSTRAINT route_v2_signer_retirement_removed_version_ck
        CHECK (ring_removed_version > 0),
    retired_signer_revision BIGINT NULL
        CONSTRAINT route_v2_signer_retirement_finished_revision_ck
        CHECK (retired_signer_revision > 0),
    retired_at_unix_ms BIGINT NULL
        CONSTRAINT route_v2_signer_retirement_finished_time_ck
        CHECK (retired_at_unix_ms >= last_old_issue_at_unix_ms),
    PRIMARY KEY (deployment_id, kid),
    CONSTRAINT route_v2_signer_retirements_completion_key UNIQUE (
        deployment_id, kid, secret_reference_id, retired_signer_revision),
    CONSTRAINT route_v2_signer_retirement_state_projection_ck CHECK (
        (state = 'pending' AND ring_removed_version IS NULL
            AND retired_signer_revision IS NULL AND retired_at_unix_ms IS NULL) OR
        (state = 'ring_removed' AND ring_removed_version IS NOT NULL
            AND retired_signer_revision IS NULL AND retired_at_unix_ms IS NULL) OR
        (state = 'retired' AND ring_removed_version IS NOT NULL
            AND retired_signer_revision IS NOT NULL AND retired_at_unix_ms IS NOT NULL)
    ),
    CONSTRAINT route_v2_signer_retirement_authority_fkey
        FOREIGN KEY (deployment_id)
        REFERENCES route_v2_signing_authority(deployment_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT route_v2_signer_retirement_key_fkey
        FOREIGN KEY (kid)
        REFERENCES route_v2_signer_key_lineage(kid)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT route_v2_signer_retirement_start_revision_fkey
        FOREIGN KEY (deployment_id, retirement_signer_revision)
        REFERENCES route_v2_signer_revisions(deployment_id, signer_revision)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT route_v2_signer_retirement_removed_ring_fkey
        FOREIGN KEY (deployment_id, ring_removed_version)
        REFERENCES route_v2_public_key_ring_revisions(deployment_id, ring_version)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT route_v2_signer_retirement_finish_revision_fkey
        FOREIGN KEY (deployment_id, retired_signer_revision)
        REFERENCES route_v2_signer_revisions(deployment_id, signer_revision)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);
CREATE UNIQUE INDEX route_v2_signer_one_pending_normal_retirement
    ON route_v2_signer_retirements(deployment_id)
    WHERE source = 'normal' AND state <> 'retired';
CREATE TABLE IF NOT EXISTS route_v2_rotation_operator_authority (
    singleton BOOLEAN
        CONSTRAINT route_v2_rotation_operator_authority_pkey PRIMARY KEY
        DEFAULT TRUE
        CONSTRAINT route_v2_rotation_operator_singleton_ck CHECK (singleton),
    authority_id TEXT NOT NULL
        CONSTRAINT route_v2_rotation_operator_authority_id_key UNIQUE,
    route_deployment_id TEXT NOT NULL,
    release_commit_sha TEXT NOT NULL
        CONSTRAINT route_v2_rotation_operator_release_sha_ck
        CHECK (release_commit_sha ~ '^[0-9a-f]{40}$'),
    trust_sha256 TEXT NOT NULL
        CONSTRAINT route_v2_rotation_operator_trust_sha_ck
        CHECK (trust_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    threshold SMALLINT NOT NULL
        CONSTRAINT route_v2_rotation_operator_threshold_ck
        CHECK (threshold BETWEEN 1 AND 8),
    trust_bytes BYTEA NOT NULL
        CONSTRAINT route_v2_rotation_operator_trust_bytes_ck
        CHECK (octet_length(trust_bytes) BETWEEN 1 AND 16384),
    first_committed_at_unix_ms BIGINT NOT NULL
        CONSTRAINT route_v2_rotation_operator_committed_at_ck
        CHECK (first_committed_at_unix_ms >= 0),
    CONSTRAINT route_v2_rotation_operator_identity_key
        UNIQUE (authority_id, route_deployment_id, release_commit_sha, trust_sha256)
);
CREATE TABLE IF NOT EXISTS route_v2_rotation_operator_credentials (
    credential_id TEXT
        CONSTRAINT route_v2_rotation_operator_credentials_pkey PRIMARY KEY,
    authority_id TEXT NOT NULL,
    credential_ordinal SMALLINT NOT NULL
        CONSTRAINT route_v2_rotation_operator_ordinal_ck
        CHECK (credential_ordinal BETWEEN 0 AND 7),
    public_key_spki TEXT NOT NULL
        CONSTRAINT route_v2_rotation_operator_spki_key UNIQUE,
    public_key_spki_sha256 TEXT NOT NULL
        CONSTRAINT route_v2_rotation_operator_spki_sha_key UNIQUE
        CONSTRAINT route_v2_rotation_operator_spki_sha_ck
        CHECK (public_key_spki_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    first_committed_at_unix_ms BIGINT NOT NULL
        CONSTRAINT route_v2_rotation_operator_credential_committed_at_ck
        CHECK (first_committed_at_unix_ms >= 0),
    CONSTRAINT route_v2_rotation_operator_ordinal_key
        UNIQUE (authority_id, credential_ordinal),
    CONSTRAINT route_v2_rotation_operator_credential_authority_fkey
        FOREIGN KEY (authority_id)
        REFERENCES route_v2_rotation_operator_authority(authority_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS route_v2_signing_command_receipts (
    authority_id TEXT NOT NULL,
    command_id TEXT NOT NULL
        CONSTRAINT route_v2_signing_command_id_ck
        CHECK (command_id ~ '^[0-9a-f]{32}$'),
    release_commit_sha TEXT NOT NULL
        CONSTRAINT route_v2_signing_command_release_sha_ck
        CHECK (release_commit_sha ~ '^[0-9a-f]{40}$'),
    credential_set_sha256 TEXT NOT NULL
        CONSTRAINT route_v2_signing_command_credential_set_sha_ck
        CHECK (credential_set_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    exact_command_sha256 TEXT NOT NULL
        CONSTRAINT route_v2_signing_command_exact_sha_ck
        CHECK (exact_command_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    exact_command_bytes BYTEA NOT NULL
        CONSTRAINT route_v2_signing_command_exact_bytes_ck
        CHECK (octet_length(exact_command_bytes) BETWEEN 1 AND 65536),
    command_kind TEXT NOT NULL
        CONSTRAINT route_v2_signing_command_kind_ck CHECK (command_kind IN (
        'publish_overlap', 'switch_active', 'publish_new_only',
        'retire', 'disable', 'activate')),
    target_deployment_id TEXT NOT NULL,
    expected_signer_revision BIGINT NOT NULL
        CONSTRAINT route_v2_signing_command_expected_revision_ck
        CHECK (expected_signer_revision > 0),
    expected_signer_reference_sha256 TEXT NOT NULL
        CONSTRAINT route_v2_signing_command_expected_sha_ck
        CHECK (expected_signer_reference_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    terminal_outcome TEXT NOT NULL
        CONSTRAINT route_v2_signing_command_terminal_outcome_ck CHECK (
        terminal_outcome IN ('applied', 'authority_precondition_failed')),
    resulting_signer_revision BIGINT NULL
        CONSTRAINT route_v2_signing_command_result_revision_ck
        CHECK (resulting_signer_revision > 0),
    resulting_ring_version BIGINT NULL
        CONSTRAINT route_v2_signing_command_result_ring_ck
        CHECK (resulting_ring_version > 0),
    exact_result_bytes BYTEA NOT NULL
        CONSTRAINT route_v2_signing_command_result_bytes_ck
        CHECK (octet_length(exact_result_bytes) BETWEEN 1 AND 16384),
    committed_at_unix_ms BIGINT NOT NULL
        CONSTRAINT route_v2_signing_command_committed_at_ck
        CHECK (committed_at_unix_ms >= 0),
    CONSTRAINT route_v2_signing_command_receipts_pkey
        PRIMARY KEY (authority_id, command_id),
    CONSTRAINT route_v2_signing_command_result_projection_ck CHECK (
        (terminal_outcome = 'applied'
            AND resulting_signer_revision IS NOT NULL
            AND resulting_ring_version IS NOT NULL) OR
        (terminal_outcome = 'authority_precondition_failed'
            AND resulting_signer_revision IS NULL
            AND resulting_ring_version IS NULL)),
    CONSTRAINT route_v2_signing_command_operator_fkey
        FOREIGN KEY (authority_id)
        REFERENCES route_v2_rotation_operator_authority(authority_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT route_v2_signing_command_target_fkey
        FOREIGN KEY (target_deployment_id)
        REFERENCES route_v2_signing_authority(deployment_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS route_v2_public_ring_deliveries (
    deployment_id TEXT NOT NULL,
    ring_version BIGINT NOT NULL
        CONSTRAINT route_v2_public_ring_delivery_version_ck CHECK (ring_version > 1),
    key_ring_digest TEXT NOT NULL
        CONSTRAINT route_v2_public_ring_delivery_digest_ck
        CHECK (key_ring_digest ~ '^sha256:[0-9a-f]{64}$'),
    expected_previous_ring_version BIGINT NOT NULL
        CONSTRAINT route_v2_public_ring_delivery_previous_version_ck
        CHECK (expected_previous_ring_version > 0),
    expected_previous_key_ring_digest TEXT NOT NULL
        CONSTRAINT route_v2_public_ring_delivery_previous_digest_ck
        CHECK (expected_previous_key_ring_digest ~ '^sha256:[0-9a-f]{64}$'),
    source_authority_id TEXT NOT NULL,
    source_command_id TEXT NOT NULL,
    source_release_commit_sha TEXT NOT NULL
        CONSTRAINT route_v2_public_ring_delivery_release_sha_ck
        CHECK (source_release_commit_sha ~ '^[0-9a-f]{40}$'),
    exact_signed_envelope_sha256 TEXT NOT NULL
        CONSTRAINT route_v2_public_ring_delivery_envelope_sha_key UNIQUE
        CONSTRAINT route_v2_public_ring_delivery_envelope_sha_ck
        CHECK (exact_signed_envelope_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    exact_signed_envelope_bytes BYTEA NOT NULL
        CONSTRAINT route_v2_public_ring_delivery_envelope_bytes_ck
        CHECK (octet_length(exact_signed_envelope_bytes) BETWEEN 1 AND 65536),
    committed_at_unix_ms BIGINT NOT NULL
        CONSTRAINT route_v2_public_ring_delivery_committed_at_ck
        CHECK (committed_at_unix_ms >= 0),
    CONSTRAINT route_v2_public_ring_deliveries_pkey
        PRIMARY KEY (deployment_id, ring_version),
    CONSTRAINT route_v2_public_ring_delivery_predecessor_key
        UNIQUE (deployment_id, expected_previous_ring_version,
                expected_previous_key_ring_digest),
    CONSTRAINT route_v2_public_ring_delivery_adjacency_ck
        CHECK (expected_previous_ring_version = ring_version - 1),
    CONSTRAINT route_v2_public_ring_delivery_ring_fkey
        FOREIGN KEY (deployment_id, ring_version, key_ring_digest)
        REFERENCES route_v2_public_key_ring_revisions(
            deployment_id, ring_version, key_ring_digest)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT route_v2_public_ring_delivery_command_fkey
        FOREIGN KEY (source_authority_id, source_command_id)
        REFERENCES route_v2_signing_command_receipts(authority_id, command_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS route_v2_gateway_identity_authority (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE
        CONSTRAINT route_v2_gateway_authority_singleton_ck CHECK (singleton),
    authority_id TEXT NOT NULL UNIQUE,
    fleet_id TEXT NOT NULL,
    current_policy_revision BIGINT NOT NULL
        CONSTRAINT route_v2_gateway_authority_revision_ck
        CHECK (current_policy_revision > 0),
    current_policy_sha256 TEXT NOT NULL
        CONSTRAINT route_v2_gateway_authority_digest_ck
        CHECK (current_policy_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    first_committed_at_unix_ms BIGINT NOT NULL
        CONSTRAINT route_v2_gateway_authority_first_time_ck
        CHECK (first_committed_at_unix_ms >= 0),
    CONSTRAINT route_v2_gateway_identity_authority_authority_id_fleet_id_key
        UNIQUE (authority_id, fleet_id),
    CONSTRAINT route_v2_gateway_identity_authority_current_key
        UNIQUE (authority_id, fleet_id, current_policy_revision, current_policy_sha256)
);
CREATE TABLE IF NOT EXISTS route_v2_gateway_identity_revisions (
    authority_id TEXT NOT NULL,
    fleet_id TEXT NOT NULL,
    policy_revision BIGINT NOT NULL
        CONSTRAINT route_v2_gateway_revision_revision_ck
        CHECK (policy_revision > 0),
    policy_sha256 TEXT NOT NULL
        CONSTRAINT route_v2_gateway_revision_digest_ck
        CHECK (policy_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    policy_bytes BYTEA NOT NULL
        CONSTRAINT route_v2_gateway_revision_bytes_ck
        CHECK (octet_length(policy_bytes) BETWEEN 1 AND 65536),
    expected_previous_policy_revision BIGINT NULL
        CONSTRAINT route_v2_gateway_revision_previous_revision_ck
        CHECK (expected_previous_policy_revision > 0),
    expected_previous_policy_sha256 TEXT NULL
        CONSTRAINT route_v2_gateway_revision_previous_digest_ck
        CHECK (expected_previous_policy_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    committed_at_unix_ms BIGINT NOT NULL
        CONSTRAINT route_v2_gateway_revision_committed_time_ck
        CHECK (committed_at_unix_ms >= 0),
    PRIMARY KEY (authority_id, policy_revision),
    CONSTRAINT route_v2_gateway_identity_revisions_exact_key
        UNIQUE (authority_id, fleet_id, policy_revision, policy_sha256),
    CONSTRAINT route_v2_gateway_revision_lineage_ck CHECK (
        (policy_revision = 1 AND expected_previous_policy_revision IS NULL
            AND expected_previous_policy_sha256 IS NULL) OR
        (policy_revision > 1
            AND expected_previous_policy_revision = policy_revision - 1
            AND expected_previous_policy_sha256 IS NOT NULL)
    ),
    CONSTRAINT route_v2_gateway_revisions_authority_fkey
        FOREIGN KEY (authority_id, fleet_id)
        REFERENCES route_v2_gateway_identity_authority(authority_id, fleet_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE route_v2_gateway_identity_authority
    ADD CONSTRAINT route_v2_gateway_current_policy_revision
    FOREIGN KEY (
        authority_id, fleet_id, current_policy_revision, current_policy_sha256)
    REFERENCES route_v2_gateway_identity_revisions(
        authority_id, fleet_id, policy_revision, policy_sha256)
    ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE IF NOT EXISTS route_v2_gateway_credential_lineage (
    credential_id TEXT PRIMARY KEY,
    authority_id TEXT NOT NULL
        REFERENCES route_v2_gateway_identity_authority(authority_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    public_key_spki TEXT NOT NULL,
    public_key_spki_sha256 TEXT NOT NULL
        CONSTRAINT route_v2_gateway_credential_digest_ck
        CHECK (public_key_spki_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    state TEXT NOT NULL
        CONSTRAINT route_v2_gateway_credential_state_ck
        CHECK (state IN ('active', 'revoked')),
    first_policy_revision BIGINT NOT NULL
        CONSTRAINT route_v2_gateway_credential_first_revision_ck
        CHECK (first_policy_revision > 0),
    first_committed_at_unix_ms BIGINT NOT NULL
        CONSTRAINT route_v2_gateway_credential_first_time_ck
        CHECK (first_committed_at_unix_ms >= 0),
    revoked_at_unix_ms BIGINT NULL
        CONSTRAINT route_v2_gateway_credential_revoked_time_ck CHECK (
        revoked_at_unix_ms IS NULL OR
        revoked_at_unix_ms >= first_committed_at_unix_ms),
    CONSTRAINT route_v2_gateway_credential_state_time_ck
        CHECK ((state = 'active' AND revoked_at_unix_ms IS NULL) OR
           (state = 'revoked' AND revoked_at_unix_ms IS NOT NULL)),
    CONSTRAINT route_v2_gateway_credential_lineage_spki_key
        UNIQUE (public_key_spki),
    CONSTRAINT route_v2_gateway_credential_lineage_spki_sha256_key
        UNIQUE (public_key_spki_sha256),
    CONSTRAINT route_v2_gateway_credential_lineage_exact_key
        UNIQUE (credential_id, authority_id, public_key_spki_sha256, state),
    CONSTRAINT route_v2_gateway_credential_first_revision_fkey
        FOREIGN KEY (authority_id, first_policy_revision)
        REFERENCES route_v2_gateway_identity_revisions(authority_id, policy_revision)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE IF NOT EXISTS route_v2_gateway_current_credentials (
    credential_id TEXT PRIMARY KEY,
    authority_id TEXT NOT NULL,
    fleet_id TEXT NOT NULL,
    policy_revision BIGINT NOT NULL
        CONSTRAINT route_v2_gateway_current_revision_ck
        CHECK (policy_revision > 0),
    policy_sha256 TEXT NOT NULL
        CONSTRAINT route_v2_gateway_current_policy_digest_ck
        CHECK (policy_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    public_key_spki_sha256 TEXT NOT NULL
        CONSTRAINT route_v2_gateway_current_spki_digest_ck
        CHECK (public_key_spki_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    scope JSONB NOT NULL
        CONSTRAINT route_v2_gateway_current_scope_ck
        CHECK (jsonb_typeof(scope) = 'object'),
    lineage_state TEXT NOT NULL
        CONSTRAINT route_v2_gateway_current_state_ck
        CHECK (lineage_state = 'active'),
    CONSTRAINT route_v2_gateway_current_policy_fkey
        FOREIGN KEY (authority_id, fleet_id, policy_revision, policy_sha256)
        REFERENCES route_v2_gateway_identity_authority(
            authority_id, fleet_id, current_policy_revision, current_policy_sha256)
        ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT route_v2_gateway_current_lineage_fkey
        FOREIGN KEY (
            credential_id, authority_id, public_key_spki_sha256, lineage_state)
        REFERENCES route_v2_gateway_credential_lineage(
            credential_id, authority_id, public_key_spki_sha256, state)
        ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE IF NOT EXISTS agent_registration_attempts (
    node_id TEXT NOT NULL REFERENCES node_identities(node_id),
    registration_attempt_id TEXT NOT NULL,
    attempt_record JSONB NOT NULL CHECK (jsonb_typeof(attempt_record) = 'object'),
    immutable_host_id TEXT NOT NULL,
    node_boot_id TEXT NOT NULL,
    agent_instance_id TEXT NOT NULL,
    guest_config_digest TEXT NOT NULL
        CHECK (guest_config_digest ~ '^sha256:[0-9a-f]{64}$'),
    expected_agent_session_epoch BIGINT CHECK (expected_agent_session_epoch > 0),
    session_record JSONB NOT NULL CHECK (jsonb_typeof(session_record) = 'object'),
    agent_session_epoch BIGINT NOT NULL CHECK (agent_session_epoch > 0),
    lease_deadline_unix_ms BIGINT NOT NULL CHECK (lease_deadline_unix_ms >= 0),
    PRIMARY KEY (node_id, registration_attempt_id),
    UNIQUE (node_id, agent_session_epoch),
    UNIQUE (node_id, registration_attempt_id, agent_session_epoch),
    CONSTRAINT agent_registration_attempts_exact_session_binding_key
        UNIQUE (
            node_id, node_boot_id, agent_instance_id,
            agent_session_epoch
        )
);
CREATE TABLE IF NOT EXISTS current_agent_sessions (
    node_id TEXT PRIMARY KEY REFERENCES node_identities(node_id),
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    immutable_host_id TEXT NOT NULL,
    node_boot_id TEXT NOT NULL,
    agent_instance_id TEXT NOT NULL,
    agent_session_epoch BIGINT NOT NULL CHECK (agent_session_epoch > 0),
    registration_attempt_id TEXT NOT NULL,
    guest_config_digest TEXT NOT NULL
        CHECK (guest_config_digest ~ '^sha256:[0-9a-f]{64}$'),
    lease_deadline_unix_ms BIGINT NOT NULL CHECK (lease_deadline_unix_ms >= 0),
    CONSTRAINT current_agent_sessions_exact_binding_key
        UNIQUE (
            node_id, node_boot_id, agent_instance_id,
            agent_session_epoch
        ),
    FOREIGN KEY (node_id, registration_attempt_id, agent_session_epoch)
        REFERENCES agent_registration_attempts(
            node_id, registration_attempt_id, agent_session_epoch
        )
);
CREATE TABLE IF NOT EXISTS route_node_ring_acks (
    node_id TEXT
        CONSTRAINT route_node_ring_acks_pkey PRIMARY KEY
        REFERENCES node_identities(node_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    canonical_ack_bytes BYTEA NOT NULL
        CONSTRAINT route_node_ring_acks_bytes_check
        CHECK (octet_length(canonical_ack_bytes) BETWEEN 1 AND 1048576),
    canonical_ack_sha256 TEXT NOT NULL
        CONSTRAINT route_node_ring_acks_ack_digest_check
        CHECK (canonical_ack_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    ack_id TEXT NOT NULL,
    ack_sequence BIGINT NOT NULL
        CONSTRAINT route_node_ring_acks_sequence_check
        CHECK (ack_sequence > 0),
    node_boot_id TEXT NOT NULL,
    agent_instance_id TEXT NOT NULL
        CONSTRAINT route_node_ring_acks_agent_instance_check
        CHECK (agent_instance_id ~ '^[0-9a-f]{32}$'),
    admission_session_epoch BIGINT NOT NULL
        CONSTRAINT route_node_ring_acks_session_epoch_check
        CHECK (admission_session_epoch > 0),
    ring_version BIGINT NOT NULL
        CONSTRAINT route_node_ring_acks_ring_version_check
        CHECK (ring_version > 0),
    key_ring_digest TEXT NOT NULL
        CONSTRAINT route_node_ring_acks_ring_digest_check
        CHECK (key_ring_digest ~ '^sha256:[0-9a-f]{64}$'),
    loaded_kids JSONB NOT NULL
        CONSTRAINT route_node_ring_acks_loaded_kids_check
        CHECK (jsonb_typeof(loaded_kids) = 'array'),
    accepted_at_unix_ms BIGINT NOT NULL
        CONSTRAINT route_node_ring_acks_accepted_at_check
        CHECK (accepted_at_unix_ms >= 0),
    CONSTRAINT route_node_ring_acks_session_sequence_key
        UNIQUE (node_id, admission_session_epoch, ack_sequence),
    CONSTRAINT route_node_ring_acks_session_ack_id_key
        UNIQUE (node_id, admission_session_epoch, ack_id),
    CONSTRAINT route_node_ring_acks_exact_session_fkey
        FOREIGN KEY (
            node_id, node_boot_id, agent_instance_id,
            admission_session_epoch
        ) REFERENCES agent_registration_attempts (
            node_id, node_boot_id, agent_instance_id,
            agent_session_epoch
        ) ON UPDATE RESTRICT ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED
);
CREATE OR REPLACE FUNCTION control_route_node_ring_ack_transition_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.node_id IS DISTINCT FROM OLD.node_id
       OR NEW.admission_session_epoch < OLD.admission_session_epoch
       OR (NEW.admission_session_epoch = OLD.admission_session_epoch
           AND NEW.ack_sequence < OLD.ack_sequence)
       OR (NEW.admission_session_epoch = OLD.admission_session_epoch
           AND NEW.ack_sequence = OLD.ack_sequence
           AND NEW IS DISTINCT FROM OLD)
    THEN
        RAISE EXCEPTION 'invalid Route public-ring acknowledgement transition';
    END IF;
    RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION control_route_node_ring_ack_cannot_delete()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Route public-ring acknowledgement cannot be deleted';
END;
$$;
CREATE TRIGGER route_node_ring_ack_transition_is_forward_only
BEFORE UPDATE ON route_node_ring_acks FOR EACH ROW
EXECUTE FUNCTION control_route_node_ring_ack_transition_guard();
CREATE TRIGGER route_node_ring_ack_cannot_delete
BEFORE DELETE ON route_node_ring_acks FOR EACH ROW
EXECUTE FUNCTION control_route_node_ring_ack_cannot_delete();
CREATE TABLE IF NOT EXISTS runtime_inventory_receive_states (
    node_id TEXT PRIMARY KEY REFERENCES node_identities(node_id),
    report JSONB NOT NULL CHECK (jsonb_typeof(report) = 'object'),
    acceptance JSONB NOT NULL CHECK (jsonb_typeof(acceptance) = 'object'),
    node_boot_id TEXT NOT NULL,
    agent_instance_id TEXT NOT NULL,
    agent_session_epoch BIGINT NOT NULL CHECK (agent_session_epoch > 0),
    report_sequence BIGINT NOT NULL CHECK (report_sequence > 0),
    report_id TEXT NOT NULL,
    accepted_at_unix_ms BIGINT NOT NULL CHECK (accepted_at_unix_ms >= 0)
);
-- This is session-bound full-inventory telemetry. It contains no assigned Cat
-- membership and grants no command, admission, settlement, or cleanup power.
CREATE TABLE IF NOT EXISTS runtime_full_inventory_attestations (
    node_id TEXT
        CONSTRAINT runtime_full_inventory_attestations_pkey PRIMARY KEY
        REFERENCES node_identities(node_id),
    attestation JSONB NOT NULL CHECK (jsonb_typeof(attestation) = 'object'),
    full_report JSONB NOT NULL CHECK (jsonb_typeof(full_report) = 'object'),
    node_boot_id TEXT NOT NULL,
    agent_instance_id TEXT NOT NULL,
    agent_session_epoch BIGINT NOT NULL CHECK (agent_session_epoch > 0),
    inventory_epoch BIGINT NOT NULL CHECK (inventory_epoch > 0),
    scan_id TEXT NOT NULL,
    inventory_digest TEXT NOT NULL CHECK (inventory_digest ~ '^sha256:[0-9a-f]{64}$'),
    source_report_id TEXT NOT NULL,
    source_sequence BIGINT NOT NULL CHECK (source_sequence > 0),
    accepted_at_unix_ms BIGINT NOT NULL CHECK (accepted_at_unix_ms >= 0)
);
CREATE TABLE IF NOT EXISTS runtime_current_cat_telemetry (
    node_id TEXT NOT NULL REFERENCES node_identities(node_id),
    cat_id TEXT NOT NULL,
    telemetry_record JSONB NOT NULL CHECK (jsonb_typeof(telemetry_record) = 'object'),
    node_boot_id TEXT NOT NULL,
    agent_instance_id TEXT NOT NULL,
    agent_session_epoch BIGINT NOT NULL CHECK (agent_session_epoch > 0),
    inventory_epoch BIGINT NOT NULL CHECK (inventory_epoch > 0),
    source_report_id TEXT NOT NULL,
    report_sequence BIGINT NOT NULL CHECK (report_sequence > 0),
    accepted_at_unix_ms BIGINT NOT NULL CHECK (accepted_at_unix_ms >= 0),
    source_kind TEXT NOT NULL CHECK (source_kind IN ('full', 'partial')),
    PRIMARY KEY (node_id, cat_id)
);
CREATE OR REPLACE FUNCTION control_runtime_node_credential_lineage_update()
RETURNS trigger AS $$
BEGIN
    IF NEW.credential_id IS DISTINCT FROM OLD.credential_id
       OR NEW.node_id IS DISTINCT FROM OLD.node_id
       OR NEW.public_key_spki_sha256 IS DISTINCT FROM OLD.public_key_spki_sha256
       OR NEW.first_committed_at_unix_ms IS DISTINCT FROM OLD.first_committed_at_unix_ms
       OR OLD.state = 'retired'
       OR OLD.state <> 'active'
       OR NEW.state <> 'retired'
       OR OLD.retired_at_unix_ms IS NOT NULL
       OR NEW.retired_at_unix_ms IS NULL THEN
        RAISE EXCEPTION 'runtime Node credential lineage is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION control_runtime_node_credential_lineage_cannot_delete()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'runtime Node credential lineage cannot be deleted';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER runtime_node_credential_lineage_update
    BEFORE UPDATE ON runtime_node_credential_lineage
    FOR EACH ROW EXECUTE FUNCTION control_runtime_node_credential_lineage_update();
CREATE TRIGGER runtime_node_credential_lineage_cannot_delete
    BEFORE DELETE ON runtime_node_credential_lineage
    FOR EACH ROW EXECUTE FUNCTION control_runtime_node_credential_lineage_cannot_delete();
CREATE OR REPLACE FUNCTION control_runtime_node_policy_update()
RETURNS trigger AS $$
BEGIN
    IF NEW.node_id IS DISTINCT FROM OLD.node_id
       OR NEW.policy_revision <> OLD.policy_revision + 1 THEN
        RAISE EXCEPTION 'runtime Node placement policy revision is not a successor';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION control_runtime_node_policy_cannot_delete()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'runtime Node placement policy cannot be deleted';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER runtime_node_policy_update
    BEFORE UPDATE ON runtime_node_placement_policies
    FOR EACH ROW EXECUTE FUNCTION control_runtime_node_policy_update();
CREATE TRIGGER runtime_node_policy_cannot_delete
    BEFORE DELETE ON runtime_node_placement_policies
    FOR EACH ROW EXECUTE FUNCTION control_runtime_node_policy_cannot_delete();
CREATE OR REPLACE FUNCTION control_runtime_node_apply_is_immutable()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'runtime Node authority apply result is immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER runtime_node_apply_is_immutable
    BEFORE UPDATE OR DELETE ON runtime_node_authority_apply_records
    FOR EACH ROW EXECUTE FUNCTION control_runtime_node_apply_is_immutable();
CREATE OR REPLACE FUNCTION control_runtime_provisioner_revision_is_immutable()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'runtime provisioner trust revision is immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER runtime_provisioner_revision_is_immutable
    BEFORE UPDATE OR DELETE ON runtime_provisioner_trust_revisions
    FOR EACH ROW EXECUTE FUNCTION control_runtime_provisioner_revision_is_immutable();
CREATE OR REPLACE FUNCTION control_runtime_provisioner_credential_update()
RETURNS trigger AS $$
BEGIN
    IF NEW.credential_id IS DISTINCT FROM OLD.credential_id
       OR NEW.deployment_id IS DISTINCT FROM OLD.deployment_id
       OR NEW.public_key_spki IS DISTINCT FROM OLD.public_key_spki
       OR NEW.public_key_spki_sha256 IS DISTINCT FROM OLD.public_key_spki_sha256
       OR NEW.first_committed_at_unix_ms IS DISTINCT FROM OLD.first_committed_at_unix_ms
       OR OLD.state = 'retired'
       OR OLD.state <> 'active'
       OR NEW.state <> 'retired'
       OR OLD.retired_at_unix_ms IS NOT NULL
       OR NEW.retired_at_unix_ms IS NULL THEN
        RAISE EXCEPTION 'runtime provisioner credential lineage is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION control_runtime_provisioner_credential_cannot_delete()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'runtime provisioner credential lineage cannot be deleted';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER runtime_provisioner_credential_update
    BEFORE UPDATE ON runtime_provisioner_credential_lineage
    FOR EACH ROW EXECUTE FUNCTION control_runtime_provisioner_credential_update();
CREATE TRIGGER runtime_provisioner_credential_cannot_delete
    BEFORE DELETE ON runtime_provisioner_credential_lineage
    FOR EACH ROW EXECUTE FUNCTION control_runtime_provisioner_credential_cannot_delete();
CREATE OR REPLACE FUNCTION control_runtime_provisioner_pointer_update()
RETURNS trigger AS $$
BEGIN
    IF NEW.singleton IS DISTINCT FROM OLD.singleton
       OR NEW.deployment_id IS DISTINCT FROM OLD.deployment_id
       OR NEW.first_committed_at_unix_ms IS DISTINCT FROM OLD.first_committed_at_unix_ms
       OR NEW.current_trust_revision <> OLD.current_trust_revision + 1
       OR NEW.current_active_set_sha256 = OLD.current_active_set_sha256 THEN
        RAISE EXCEPTION 'runtime provisioner trust pointer is not a successor';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION control_runtime_provisioner_pointer_cannot_delete()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'runtime provisioner deployment identity cannot be deleted';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER runtime_provisioner_pointer_update
    BEFORE UPDATE ON runtime_provisioner_deployment_identity
    FOR EACH ROW EXECUTE FUNCTION control_runtime_provisioner_pointer_update();
CREATE TRIGGER runtime_provisioner_pointer_cannot_delete
    BEFORE DELETE ON runtime_provisioner_deployment_identity
    FOR EACH ROW EXECUTE FUNCTION control_runtime_provisioner_pointer_cannot_delete();
CREATE OR REPLACE FUNCTION control_route_v2_signer_revision_is_immutable()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'Route v2 signer revision is immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER route_v2_signer_revision_is_immutable
    BEFORE UPDATE OR DELETE ON route_v2_signer_revisions
    FOR EACH ROW EXECUTE FUNCTION control_route_v2_signer_revision_is_immutable();
CREATE OR REPLACE FUNCTION control_route_v2_signer_key_lineage_update()
RETURNS trigger AS $$
BEGIN
    IF NEW.kid IS DISTINCT FROM OLD.kid
       OR NEW.deployment_id IS DISTINCT FROM OLD.deployment_id
       OR NEW.public_key_spki IS DISTINCT FROM OLD.public_key_spki
       OR NEW.secret_reference_id IS DISTINCT FROM OLD.secret_reference_id
       OR NEW.first_signer_revision IS DISTINCT FROM OLD.first_signer_revision
       OR NEW.first_committed_at_unix_ms IS DISTINCT FROM OLD.first_committed_at_unix_ms
       OR OLD.state = 'retired'
       OR OLD.state <> 'active'
       OR NEW.state <> 'retired'
       OR OLD.retired_at_unix_ms IS NOT NULL
       OR NEW.retired_at_unix_ms IS NULL THEN
        RAISE EXCEPTION 'Route v2 signer key lineage is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION control_route_v2_signer_key_lineage_cannot_delete()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'Route v2 signer key lineage cannot be deleted';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER route_v2_signer_key_lineage_update
    BEFORE UPDATE ON route_v2_signer_key_lineage
    FOR EACH ROW EXECUTE FUNCTION control_route_v2_signer_key_lineage_update();
CREATE TRIGGER route_v2_signer_key_lineage_cannot_delete
    BEFORE DELETE ON route_v2_signer_key_lineage
    FOR EACH ROW EXECUTE FUNCTION control_route_v2_signer_key_lineage_cannot_delete();
CREATE OR REPLACE FUNCTION control_route_v2_signing_authority_update()
RETURNS trigger AS $$
BEGIN
    IF NEW.singleton IS DISTINCT FROM OLD.singleton
       OR NEW.deployment_id IS DISTINCT FROM OLD.deployment_id
       OR NEW.first_committed_at_unix_ms IS DISTINCT FROM OLD.first_committed_at_unix_ms
       OR NEW.current_signer_revision <> OLD.current_signer_revision + 1
       OR NEW.current_signer_reference_sha256 = OLD.current_signer_reference_sha256 THEN
        RAISE EXCEPTION 'Route v2 signing authority pointer is not a successor';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION control_route_v2_signing_authority_cannot_delete()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'Route v2 signing authority cannot be deleted';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER route_v2_signing_authority_update
    BEFORE UPDATE ON route_v2_signing_authority
    FOR EACH ROW EXECUTE FUNCTION control_route_v2_signing_authority_update();
CREATE TRIGGER route_v2_signing_authority_cannot_delete
    BEFORE DELETE ON route_v2_signing_authority
    FOR EACH ROW EXECUTE FUNCTION control_route_v2_signing_authority_cannot_delete();
CREATE OR REPLACE FUNCTION control_route_v2_public_ring_revision_is_immutable()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'Route v2 public ring revision is immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER route_v2_public_ring_revision_is_immutable
    BEFORE UPDATE OR DELETE ON route_v2_public_key_ring_revisions
    FOR EACH ROW EXECUTE FUNCTION control_route_v2_public_ring_revision_is_immutable();
CREATE OR REPLACE FUNCTION control_route_v2_rotation_record_is_immutable()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'Route v2 rotation operator and delivery records are immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER route_v2_rotation_operator_authority_is_immutable
    BEFORE UPDATE OR DELETE ON route_v2_rotation_operator_authority
    FOR EACH ROW EXECUTE FUNCTION control_route_v2_rotation_record_is_immutable();
CREATE TRIGGER route_v2_rotation_operator_credential_is_immutable
    BEFORE UPDATE OR DELETE ON route_v2_rotation_operator_credentials
    FOR EACH ROW EXECUTE FUNCTION control_route_v2_rotation_record_is_immutable();
CREATE TRIGGER route_v2_signing_command_receipt_is_immutable
    BEFORE UPDATE OR DELETE ON route_v2_signing_command_receipts
    FOR EACH ROW EXECUTE FUNCTION control_route_v2_rotation_record_is_immutable();
CREATE TRIGGER route_v2_public_ring_delivery_is_immutable
    BEFORE UPDATE OR DELETE ON route_v2_public_ring_deliveries
    FOR EACH ROW EXECUTE FUNCTION control_route_v2_rotation_record_is_immutable();
CREATE OR REPLACE FUNCTION control_route_v2_signer_retirement_update()
RETURNS trigger AS $$
BEGIN
    IF NEW.deployment_id IS DISTINCT FROM OLD.deployment_id
       OR NEW.kid IS DISTINCT FROM OLD.kid
       OR NEW.secret_reference_id IS DISTINCT FROM OLD.secret_reference_id
       OR NEW.retirement_signer_revision IS DISTINCT FROM OLD.retirement_signer_revision
       OR NEW.last_old_issue_at_unix_ms IS DISTINCT FROM OLD.last_old_issue_at_unix_ms
       OR NEW.source IS DISTINCT FROM OLD.source
       OR (OLD.state = 'pending' AND NOT (
            NEW.state = 'ring_removed'
            AND OLD.ring_removed_version IS NULL
            AND NEW.ring_removed_version IS NOT NULL
            AND NEW.retired_signer_revision IS NULL
            AND NEW.retired_at_unix_ms IS NULL))
       OR (OLD.state = 'ring_removed' AND NOT (
            NEW.state = 'retired'
            AND NEW.ring_removed_version IS NOT DISTINCT FROM OLD.ring_removed_version
            AND OLD.retired_signer_revision IS NULL
            AND NEW.retired_signer_revision IS NOT NULL
            AND OLD.retired_at_unix_ms IS NULL
            AND NEW.retired_at_unix_ms IS NOT NULL))
       OR OLD.state = 'retired' THEN
        RAISE EXCEPTION 'Route v2 signer retirement is not an exact forward transition';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION control_route_v2_signer_retirement_cannot_delete()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'Route v2 signer retirement cannot be deleted';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER route_v2_signer_retirement_update
    BEFORE UPDATE ON route_v2_signer_retirements
    FOR EACH ROW EXECUTE FUNCTION control_route_v2_signer_retirement_update();
CREATE TRIGGER route_v2_signer_retirement_cannot_delete
    BEFORE DELETE ON route_v2_signer_retirements
    FOR EACH ROW EXECUTE FUNCTION control_route_v2_signer_retirement_cannot_delete();
CREATE OR REPLACE FUNCTION control_route_v2_gateway_revision_is_immutable()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'Route v2 Gateway identity revision is immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER route_v2_gateway_revision_is_immutable
    BEFORE UPDATE OR DELETE ON route_v2_gateway_identity_revisions
    FOR EACH ROW EXECUTE FUNCTION control_route_v2_gateway_revision_is_immutable();
CREATE OR REPLACE FUNCTION control_route_v2_gateway_credential_update()
RETURNS trigger AS $$
BEGIN
    IF NEW.credential_id IS DISTINCT FROM OLD.credential_id
       OR NEW.authority_id IS DISTINCT FROM OLD.authority_id
       OR NEW.public_key_spki IS DISTINCT FROM OLD.public_key_spki
       OR NEW.public_key_spki_sha256 IS DISTINCT FROM OLD.public_key_spki_sha256
       OR NEW.first_policy_revision IS DISTINCT FROM OLD.first_policy_revision
       OR NEW.first_committed_at_unix_ms IS DISTINCT FROM OLD.first_committed_at_unix_ms
       OR OLD.state = 'revoked'
       OR OLD.state <> 'active'
       OR NEW.state <> 'revoked'
       OR OLD.revoked_at_unix_ms IS NOT NULL
       OR NEW.revoked_at_unix_ms IS NULL THEN
        RAISE EXCEPTION 'Route v2 Gateway credential lineage is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION control_route_v2_gateway_credential_cannot_delete()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'Route v2 Gateway credential lineage cannot be deleted';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER route_v2_gateway_credential_update
    BEFORE UPDATE ON route_v2_gateway_credential_lineage
    FOR EACH ROW EXECUTE FUNCTION control_route_v2_gateway_credential_update();
CREATE TRIGGER route_v2_gateway_credential_cannot_delete
    BEFORE DELETE ON route_v2_gateway_credential_lineage
    FOR EACH ROW EXECUTE FUNCTION control_route_v2_gateway_credential_cannot_delete();
CREATE OR REPLACE FUNCTION control_route_v2_gateway_pointer_update()
RETURNS trigger AS $$
BEGIN
    IF NEW.singleton IS DISTINCT FROM OLD.singleton
       OR NEW.authority_id IS DISTINCT FROM OLD.authority_id
       OR NEW.fleet_id IS DISTINCT FROM OLD.fleet_id
       OR NEW.first_committed_at_unix_ms IS DISTINCT FROM OLD.first_committed_at_unix_ms
       OR NEW.current_policy_revision <> OLD.current_policy_revision + 1
       OR NEW.current_policy_sha256 = OLD.current_policy_sha256 THEN
        RAISE EXCEPTION 'Route v2 Gateway identity pointer is not a successor';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION control_route_v2_gateway_pointer_cannot_delete()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'Route v2 Gateway identity authority cannot be deleted';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER route_v2_gateway_pointer_update
    BEFORE UPDATE ON route_v2_gateway_identity_authority
    FOR EACH ROW EXECUTE FUNCTION control_route_v2_gateway_pointer_update();
CREATE TRIGGER route_v2_gateway_pointer_cannot_delete
    BEFORE DELETE ON route_v2_gateway_identity_authority
    FOR EACH ROW EXECUTE FUNCTION control_route_v2_gateway_pointer_cannot_delete();
CREATE OR REPLACE FUNCTION control_node_identity_lineage_is_immutable()
RETURNS trigger AS $$
BEGIN
    IF NEW.node_id IS DISTINCT FROM OLD.node_id
       OR NEW.host_provider IS DISTINCT FROM OLD.host_provider
       OR NEW.host_partition IS DISTINCT FROM OLD.host_partition
       OR NEW.host_account_id IS DISTINCT FROM OLD.host_account_id
       OR NEW.host_region IS DISTINCT FROM OLD.host_region
       OR NEW.immutable_host_id IS DISTINCT FROM OLD.immutable_host_id
       OR NEW.state_path_id IS DISTINCT FROM OLD.state_path_id THEN
        RAISE EXCEPTION 'NodeIdentity lineage is immutable';
    END IF;
    IF OLD.state = 'retired' AND NEW.state <> 'retired' THEN
        RAISE EXCEPTION 'retired NodeIdentity cannot be reprovisioned';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION control_node_identity_cannot_be_deleted()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'NodeIdentity lineage cannot be deleted';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER node_identity_lineage_is_immutable
    BEFORE UPDATE ON node_identities
    FOR EACH ROW EXECUTE FUNCTION control_node_identity_lineage_is_immutable();
CREATE TRIGGER node_identity_cannot_be_deleted
    BEFORE DELETE ON node_identities
    FOR EACH ROW EXECUTE FUNCTION control_node_identity_cannot_be_deleted();
CREATE OR REPLACE FUNCTION control_agent_registration_attempt_is_immutable()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'AgentRegistrationAttempt and its first result are immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER agent_registration_attempt_is_immutable
    BEFORE UPDATE OR DELETE ON agent_registration_attempts
    FOR EACH ROW EXECUTE FUNCTION control_agent_registration_attempt_is_immutable();
CREATE OR REPLACE FUNCTION control_production_mutation_admission_command_is_immutable()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'production mutation admission command receipts are immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER production_mutation_admission_command_is_immutable
    BEFORE UPDATE OR DELETE ON production_mutation_admission_commands
    FOR EACH ROW EXECUTE FUNCTION
        control_production_mutation_admission_command_is_immutable();
CREATE OR REPLACE FUNCTION control_production_mutation_admission_successor()
RETURNS trigger AS $$
BEGIN
    IF NEW.singleton IS DISTINCT FROM OLD.singleton
       OR NEW.revision <> OLD.revision + 1
       OR NEW.mode = OLD.mode
       OR NEW.last_command_id IS NULL
       OR NEW.last_command_id IS NOT DISTINCT FROM OLD.last_command_id
       OR NEW.updated_at_unix_ms < OLD.updated_at_unix_ms
       OR NOT (
            (OLD.binding IS NULL AND OLD.mode = 'closed'
                AND OLD.revision = 1
                AND NEW.mode IN ('qualification', 'open')
                AND NEW.binding IS NOT NULL) OR
            (OLD.mode = 'closed' AND OLD.binding_kind = 'qualification'
                AND NEW.mode IN ('qualification', 'open')
                AND NEW.binding IS NOT NULL) OR
            (OLD.mode = 'closed' AND OLD.binding_kind = 'open'
                AND NEW.mode = 'open' AND NEW.binding = OLD.binding
                AND NEW.binding_sha256 = OLD.binding_sha256
                AND NEW.binding_kind = OLD.binding_kind) OR
            (OLD.mode IN ('qualification', 'open') AND NEW.mode = 'closed'
                AND NEW.binding = OLD.binding
                AND NEW.binding_sha256 = OLD.binding_sha256
                AND NEW.binding_kind = OLD.binding_kind)
       ) THEN
        RAISE EXCEPTION 'production mutation admission pointer is not an exact successor';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION control_production_mutation_admission_cannot_delete()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'production mutation admission singleton cannot be deleted';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER production_mutation_admission_successor
    BEFORE UPDATE ON production_mutation_admission
    FOR EACH ROW EXECUTE FUNCTION control_production_mutation_admission_successor();
CREATE TRIGGER production_mutation_admission_cannot_delete
    BEFORE DELETE ON production_mutation_admission
    FOR EACH ROW EXECUTE FUNCTION control_production_mutation_admission_cannot_delete();
";

#[cfg(test)]
mod object_write_gateway_catalog_tests {
    use std::collections::BTreeSet;

    use super::{
        object_write_gateway_catalog_sha256, object_write_gateway_contract_sha256,
        object_write_gateway_function_body, ObjectWriteGatewayFunction,
        HOST_FENCE_PROVIDER_FUNCTIONS, OBJECT_WRITE_GATEWAY_FUNCTIONS,
        OBJECT_WRITE_GATEWAY_FUNCTION_CATALOG, SCHEMA,
    };

    const ROLE_INSTALLER: &str =
        include_str!("../../../deploy/postgres/object-write-gateway-role-v1.sql");
    const CLIENT_SOURCE: &str = include_str!("object_write_gateway_client.rs");
    const DAEMON_SOURCE: &str = include_str!("../../../cmd/object-write-gatewayd/src/main.rs");
    const SERVICE_SOURCE: &str = include_str!("../object_write_gateway/mod.rs");

    #[test]
    fn the_production_surface_is_exact_and_attests_the_qualification_lock() {
        let executable: BTreeSet<_> = OBJECT_WRITE_GATEWAY_FUNCTION_CATALOG
            .iter()
            .filter(|function| function.gateway_execute)
            .map(|function| function.name)
            .collect();
        let expected = BTreeSet::from([
            "control_object_write_gateway_accept_v1",
            "control_object_write_gateway_begin_ingress_v1",
            "control_object_write_gateway_provider_issued_v1",
            "control_object_write_gateway_qualification_response_lost_v1",
            "control_object_write_gateway_recover_accepted_v1",
            "control_object_write_gateway_recover_ingress_v1",
            "control_object_write_gateway_register_v1",
            "control_object_write_gateway_spool_durable_v1",
            "control_object_write_gateway_spool_removed_v1",
            "control_object_write_gateway_qualification_lock_v1",
            "control_object_write_gateway_startup_v1",
            "control_object_write_gateway_terminal_v1",
        ]);
        assert_eq!(executable, expected);
        assert!(OBJECT_WRITE_GATEWAY_FUNCTIONS
            .contains("CREATE OR REPLACE FUNCTION __CATS_SCHEMA_IDENT__.control_object_write_gateway_qualification_lock_v1"));
        assert!(OBJECT_WRITE_GATEWAY_FUNCTIONS.contains("12::BIGINT"));
        assert!(OBJECT_WRITE_GATEWAY_FUNCTIONS.contains("qualification_lock_available BOOLEAN"));
        assert!(OBJECT_WRITE_GATEWAY_FUNCTIONS.contains("pg_catalog.convert_to(catalog_input"));
        // The capability is attested from pg_catalog, never asserted as a literal.
        assert!(!OBJECT_WRITE_GATEWAY_FUNCTIONS.contains("        FALSE;"));
        assert!(OBJECT_WRITE_GATEWAY_FUNCTIONS.contains(
            "has_function_privilege(\n                    session_user, function.oid, 'EXECUTE')"
        ));
        // The E13 lock must hold both ADR-0055 locks in the caller's transaction.
        assert!(OBJECT_WRITE_GATEWAY_FUNCTIONS.contains("pg_advisory_xact_lock"));
        assert!(OBJECT_WRITE_GATEWAY_FUNCTIONS.contains("FOR SHARE"));
        assert!(object_write_gateway_contract_sha256()
            .unwrap()
            .starts_with("sha256:"));
        assert!(object_write_gateway_catalog_sha256()
            .unwrap()
            .starts_with("sha256:"));
    }

    #[test]
    fn every_installed_routine_has_closed_identity_and_source_attestation() {
        for function in OBJECT_WRITE_GATEWAY_FUNCTION_CATALOG {
            let ObjectWriteGatewayFunction {
                name,
                identity_arguments,
                result,
                security_definer,
                gateway_execute,
                ..
            } = function;
            let body = object_write_gateway_function_body(name).unwrap();
            assert!(!identity_arguments.contains("VARIADIC"));
            assert!(!result.is_empty());
            if *security_definer {
                assert!(body
                    .contains("session_user::TEXT IS DISTINCT FROM 'cats_object_write_gateway'"));
            }
            let listed_by_startup = OBJECT_WRITE_GATEWAY_FUNCTIONS
                .split("RETURN QUERY SELECT")
                .next()
                .unwrap()
                .contains(&format!("'{name}'"));
            assert!(listed_by_startup, "startup omitted {name}");
            if *gateway_execute {
                assert!(ROLE_INSTALLER.contains(&format!(".{name}(")));
            }
        }
        assert_eq!(
            ROLE_INSTALLER.matches("GRANT EXECUTE ON FUNCTION").count(),
            12
        );
        assert!(ROLE_INSTALLER.contains("control_object_write_gateway_qualification_lock_v1"));
    }

    #[test]
    fn existing_gateway_role_is_normalized_without_superuser_only_alter_options() {
        let existing_role_alter = ROLE_INSTALLER
            .split_once("ALTER ROLE cats_object_write_gateway")
            .expect("role installer normalizes an existing role")
            .1
            .split_once(';')
            .expect("existing-role ALTER terminates")
            .0;
        for privileged_option in ["NOSUPERUSER", "NOREPLICATION", "NOBYPASSRLS"] {
            assert!(
                !existing_role_alter.contains(privileged_option),
                "RDS rejects privileged ALTER option {privileged_option}"
            );
        }
        for catalog_flag in ["rolsuper", "rolreplication", "rolbypassrls"] {
            assert!(
                ROLE_INSTALLER.contains(catalog_flag),
                "existing role does not fail closed on {catalog_flag}"
            );
        }
    }

    #[test]
    fn every_physical_dial_checks_identity_prosrc_and_ambient_privileges() {
        for required in [
            "current_user::TEXT, session_user::TEXT, current_schema()::TEXT",
            "verify_direct_routine_catalog(",
            "pg_get_function_identity_arguments(function.oid)",
            "pg_get_function_result(function.oid)",
            "function.prosecdef::TEXT",
            "function.prosrc",
            "function.proconfig",
            "function.proowner=namespace.nspowner",
            "has_function_privilege(",
            "has_database_privilege(session_user, current_database(), 'TEMPORARY')",
            "has_any_column_privilege",
            "has_sequence_privilege",
        ] {
            assert!(
                CLIENT_SOURCE.contains(required),
                "missing dial probe: {required}"
            );
        }
        assert!(CLIENT_SOURCE.contains("connect_verified_client(\n                &self.dsn"));
    }

    #[test]
    fn production_gateway_has_no_store_or_raw_object_table_fallback() {
        assert!(!DAEMON_SOURCE.contains("Store::"));
        assert!(!DAEMON_SOURCE.contains("use cats_control_plane::store::{DsnSource, Store}"));
        assert!(!SERVICE_SOURCE.contains("Arc<Store>"));
        for table in [
            "object_write_authorities",
            "object_write_credentials",
            "object_write_attempts",
            "control_schema_version",
            "schema_migrations",
        ] {
            assert!(!CLIENT_SOURCE.contains(&format!("FROM {table}")));
            assert!(!CLIENT_SOURCE.contains(&format!("UPDATE {table}")));
            assert!(!CLIENT_SOURCE.contains(&format!("INSERT INTO {table}")));
            assert!(!CLIENT_SOURCE.contains(&format!("DELETE FROM {table}")));
        }
        assert!(ROLE_INSTALLER.contains("REVOKE ALL ON ALL TABLES"));
        assert!(ROLE_INSTALLER.contains("REVOKE ALL ON ALL SEQUENCES"));
        assert!(ROLE_INSTALLER.contains("REVOKE ALL ON ALL FUNCTIONS"));
        assert!(ROLE_INSTALLER
            .contains("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA :\"control_schema\" FROM PUBLIC"));
        assert!(!ROLE_INSTALLER.contains("GRANT SELECT"));
        assert!(!ROLE_INSTALLER.contains("GRANT INSERT"));
        assert!(!ROLE_INSTALLER.contains("GRANT UPDATE"));
        assert!(!ROLE_INSTALLER.contains("GRANT DELETE"));
    }

    #[test]
    fn qualification_request_identity_binds_credential_before_fault() {
        let body =
            object_write_gateway_function_body("control_object_write_gateway_begin_ingress_v1")
                .unwrap();
        let hash = &body[body.find("hash_input :=").unwrap()..body.find("request_id :=").unwrap()];
        assert!(
            hash.find("'cats.object-write-request.v1'").unwrap()
                < hash.find("pg_catalog.int8send(content_length)").unwrap()
        );
        let qualification_hash = &hash[hash.find("hash_input := hash_input ||").unwrap()..];
        let ordered = [
            "'qualification-credential'",
            "requested_attachment #>> '{credential_id}'",
            "requested_attachment #>> '{public_key_spki_sha256}'",
            "'qualification-fault:successful-put-response-loss'",
            "'{qualification_fault,qualification_id}'",
            "'{qualification_fault,fault_id}'",
            "'{qualification_fault,qualification_catalog_sha256}'",
        ];
        let mut prior = 0;
        for marker in ordered {
            let position = qualification_hash
                .find(marker)
                .unwrap_or_else(|| panic!("missing {marker}"));
            assert!(position >= prior, "request identity reordered {marker}");
            prior = position;
        }
        assert_eq!(
            qualification_hash
                .matches("'qualification-credential'")
                .count(),
            1
        );
    }

    #[test]
    fn qualification_resolution_is_serialized_before_discovery() {
        let response = object_write_gateway_function_body(
            "control_object_write_gateway_qualification_response_lost_v1",
        )
        .unwrap();
        assert!(
            response.find("pg_catalog.pg_advisory_xact_lock(").unwrap()
                < response
                    .find("FROM __CATS_SCHEMA_IDENT__.object_write_attempts")
                    .unwrap()
        );

        let lock_request = &CLIENT_SOURCE[CLIENT_SOURCE
            .find("impl QualificationFaultAuthority for ObjectWriteGatewayClient")
            .unwrap()..];
        assert!(
            lock_request.find("lock_qualification_request(").unwrap()
                < lock_request
                    .find("query_qualification_response_loss(")
                    .unwrap()
        );
        assert!(lock_request.contains("BEGIN ISOLATION LEVEL READ COMMITTED"));
    }

    #[test]
    fn qualified_terminals_are_sealed_and_prefix_the_full_receipt() {
        for required in [
            "qualified object-write terminal requires a sealed authority capability",
            "qualification_unproven_visible_intent",
            "qualification_unproven_receipt_canonical",
        ] {
            assert!(
                CLIENT_SOURCE.contains(required)
                    || OBJECT_WRITE_GATEWAY_FUNCTIONS.contains(required)
                    || SCHEMA.contains(required),
                "missing qualification seal: {required}"
            );
        }
        assert!(OBJECT_WRITE_GATEWAY_FUNCTIONS.contains(
            "control_object_write_gateway_frame_v1(\n                    prefix_row.qualification_unproven_receipt_canonical)"
        ));
        let host_prefix = &HOST_FENCE_PROVIDER_FUNCTIONS[HOST_FENCE_PROVIDER_FUNCTIONS
            .find("ELSIF attempt_row.terminal_kind = 'qualification_unproven_visible'")
            .unwrap()..];
        assert!(host_prefix.contains("control_host_fence_provider_frame_v1("));
        assert!(host_prefix.contains("attempt_row.qualification_unproven_receipt_canonical"));
        for column in [
            "qualification_unproven_intent_canonical",
            "qualification_unproven_sealed_request_canonical",
            "qualification_unproven_receipt_canonical",
            "qualification_unproven_attempt_canonical",
            "qualification_unproven_resolution_receipt_id",
        ] {
            assert!(SCHEMA.contains(&format!("OLD.{column}")));
            assert!(SCHEMA.contains(&format!("NEW.{column}")));
        }
    }
}

#[cfg(test)]
mod atomic_lifecycle_schema_tests {
    use super::{
        CONTROL_TABLES, FORBIDDEN_LEGACY_CONTROL_COLUMNS, FORBIDDEN_LEGACY_CONTROL_TABLES,
        REQUIRED_CHECK_CONSTRAINTS, REQUIRED_FOREIGN_KEYS, REQUIRED_UNIQUE_INDEXES, SCHEMA,
        SCHEMA_VERSION,
    };

    #[test]
    fn v19_manifest_has_no_forbidden_legacy_authority() {
        assert_eq!(SCHEMA_VERSION, 19);
        for table in FORBIDDEN_LEGACY_CONTROL_TABLES {
            assert!(!CONTROL_TABLES.contains(table));
            assert!(
                !SCHEMA.contains(&format!("CREATE TABLE IF NOT EXISTS {table} ")),
                "legacy authority table {table} returned to the clean schema"
            );
        }
        for (table, column) in FORBIDDEN_LEGACY_CONTROL_COLUMNS {
            let marker = format!("CREATE TABLE IF NOT EXISTS {table} (");
            let table_ddl = SCHEMA
                .split_once(&marker)
                .unwrap_or_else(|| panic!("authoritative table {table} is absent from SCHEMA"))
                .1
                .split_once("\n);")
                .unwrap_or_else(|| panic!("authoritative table {table} has no DDL terminator"))
                .0;
            assert!(
                !table_ddl
                    .lines()
                    .any(|line| line.trim_start().starts_with(&format!("{column} "))),
                "legacy authority projection {table}.{column} returned to the clean schema"
            );
        }
    }

    #[test]
    fn runtime_ready_and_volume_transition_sum_types_are_catalog_bound() {
        assert!(REQUIRED_CHECK_CONSTRAINTS
            .iter()
            .any(|(table, constraint, definition)| {
                *table == "cat_records"
                    && *constraint == "cat_records_runtime_ready_shape_check"
                    && definition.contains("stable_state = 'suspended'")
                    && definition.contains("effective_runtime_ready_operation_id IS NULL")
                    && definition.contains("runtime_incarnation IS NOT NULL")
            }));
        assert!(REQUIRED_CHECK_CONSTRAINTS
            .iter()
            .any(|(table, constraint, definition)| {
                *table == "volume_records"
                    && *constraint == "volume_records_transition_shape_check"
                    && definition.contains("transition_source_kind = 'independent'")
                    && definition.contains("transition_source_kind = 'lifecycle'")
                    && definition.contains("transition_operation_id IS NOT NULL")
                    && definition.contains("transition_request_fingerprint IS NOT NULL")
            }));
        assert!(REQUIRED_FOREIGN_KEYS
            .iter()
            .any(|(table, constraint, definition)| {
                *table == "volume_records"
                    && *constraint == "volume_records_lifecycle_transition_operation_fkey"
                    && definition.contains(
                        "REFERENCES runtime_operations(operation_id, canonical_request_sha256)",
                    )
            }));
        assert!(REQUIRED_UNIQUE_INDEXES
            .iter()
            .any(|(table, constraint, columns, predicate)| {
                *table == "runtime_operations"
                    && *constraint == "runtime_operations_request_scope_key"
                    && *columns == "operation_id,canonical_request_sha256"
                    && predicate.is_none()
            }));
    }

    #[test]
    fn terminal_result_catalog_rejects_removed_failure_variants() {
        for removed in ["cold_failed", "delete_failed"] {
            assert!(
                !SCHEMA.contains(removed),
                "removed terminal result {removed} returned to the fresh schema"
            );
            assert!(
                REQUIRED_CHECK_CONSTRAINTS
                    .iter()
                    .all(|(_, _, definition)| !definition.contains(removed)),
                "removed terminal result {removed} returned to catalog validation"
            );
        }
        let terminal_set = REQUIRED_CHECK_CONSTRAINTS
            .iter()
            .find(|(table, constraint, _)| {
                *table == "runtime_operations"
                    && *constraint == "runtime_operations_terminal_result_kind_check"
            })
            .map(|(_, _, definition)| *definition)
            .expect("runtime terminal closed set is catalog-bound");
        for retained in ["'cold'::text", "'killed'::text", "'deleted'::text"] {
            assert!(terminal_set.contains(retained));
        }
    }
}

#[cfg(test)]
mod semantic_protocol_schema_tests {
    use super::{CONTROL_TABLES, SCHEMA, SCHEMA_VERSION};

    #[test]
    fn v19_contains_only_current_slug_uniqueness_and_rwo_binding_constraints() {
        assert_eq!(SCHEMA_VERSION, 19);
        for table in [
            "cats",
            "nodes",
            "node_heartbeats",
            "persistent_disks",
            "disk_bindings",
        ] {
            assert!(CONTROL_TABLES.contains(&table));
            assert!(SCHEMA.contains(&format!("CREATE TABLE IF NOT EXISTS {table} (")));
        }
        assert!(SCHEMA.contains(
            "CREATE UNIQUE INDEX IF NOT EXISTS cats_current_slug_unique\nON cats(workspace_id, cat_slug) WHERE destroyed_at IS NULL"
        ));
        assert!(SCHEMA.contains(
            "CREATE UNIQUE INDEX IF NOT EXISTS disks_current_slug_unique\nON persistent_disks(workspace_id, disk_slug) WHERE deleted_at IS NULL"
        ));
        assert!(SCHEMA.contains("CONSTRAINT disk_bindings_disk_unique UNIQUE (disk_id)"));
        assert!(SCHEMA.contains("control_endpoint TEXT NOT NULL"));
        assert!(SCHEMA.contains("last_heartbeat_at BIGINT NOT NULL"));
    }
}
