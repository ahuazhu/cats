//! Shared PostgreSQL-time primitive for surviving machine authorities.

use cats_api::runtime_reconciliation::UnixMillis;
use postgres::Transaction;

use super::pg_codec::PgBigInt;
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};

pub(in crate::store) fn database_now(
    transaction: &mut Transaction<'_>,
) -> AuthorityTxResult<UnixMillis> {
    let value = transaction
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT",
            &[],
        )?
        .try_get::<_, i64>(0)?;
    UnixMillis::from_pg(value).map_err(|_| {
        AuthorityTransactionError::Application(cats_api::error::ApiError::failed_precondition(
            "database clock is outside the wire range",
        ))
    })
}
