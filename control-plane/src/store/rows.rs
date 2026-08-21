use super::*;

// ---------------------------------------------------------------------------
// Row mappers and enum codecs
// ---------------------------------------------------------------------------
//
// Column type mapping from the schema: BIGINT reads as i64 and is cast to the
// narrower unsigned field where the API type demands it; BOOLEAN reads as
// bool directly.

pub(super) type RowResult<T> = std::result::Result<T, postgres::Error>;

pub(super) fn row_to_account(row: &postgres::Row) -> RowResult<AccountRecord> {
    let kind = match row.try_get::<_, &str>(3)? {
        "personal" => AccountKind::Personal,
        _ => AccountKind::Organization,
    };
    Ok(AccountRecord {
        id: row.try_get(0)?,
        slug: row.try_get(1)?,
        display_name: row.try_get(2)?,
        kind,
        workos_organization_id: row.try_get(4)?,
        billing_account_id: row.try_get(5)?,
        personal_owner_user_id: row.try_get(6)?,
        status: row.try_get(7)?,
    })
}

pub(super) fn row_to_workspace(row: &postgres::Row) -> RowResult<WorkspaceRecord> {
    Ok(WorkspaceRecord {
        id: row.try_get(0)?,
        account_id: row.try_get(1)?,
        slug: row.try_get(2)?,
        display_name: row.try_get(3)?,
        is_default: row.try_get(4)?,
    })
}
