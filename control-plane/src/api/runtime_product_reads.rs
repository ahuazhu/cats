//! Workspace-qualified public reads composed from current runtime authority.

use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::Response;
use cats_api::error::ApiError;
use cats_api::runtime_product_reads::{
    decode_product_read_cursor, ProductReadResource, PRODUCT_READ_DEFAULT_LIMIT,
    PRODUCT_READ_MAX_LIMIT,
};
use cats_api::runtime_reconciliation::Id;
use serde::Serialize;

use super::{check_workspace_auth, ApiResult};
use crate::server::AppState;
use crate::store::runtime_authority::product_reads::{ProductPageRead, ProductRead};

pub(super) async fn list_runtime_cats(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let workspace_id = authorize_workspace(&state, &uri, &headers).await?;
    let (limit, after) = parse_page_query(&uri, ProductReadResource::Cats)?;
    let readiness = state.readiness.clone();
    let read = state
        .store
        .execute(move |store| {
            let read = store.list_runtime_cats(&workspace_id, after.as_ref(), limit);
            if matches!(read, Ok(ProductPageRead::Corrupt)) {
                readiness.poison();
            }
            read
        })
        .await?;
    match read {
        ProductPageRead::Found(page) => json_response(&page),
        ProductPageRead::Corrupt => corrupt_response("Cat collection"),
    }
}

pub(super) async fn get_runtime_cat(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let workspace_id = authorize_workspace(&state, &uri, &headers).await?;
    let Some(raw_id) = exact_item_segment(&uri, &workspace_id, "cats") else {
        return Err(ApiError::not_found("cat").into());
    };
    let Some(cat_id) = Id::new(raw_id.to_owned()).filter(|id| id.as_str().starts_with("cat_"))
    else {
        return Err(ApiError::not_found("cat").into());
    };
    let readiness = state.readiness.clone();
    let read = state
        .store
        .execute(move |store| {
            let read = store.get_runtime_cat(&workspace_id, &cat_id);
            if matches!(read, Ok(ProductRead::Corrupt)) {
                readiness.poison();
            }
            read
        })
        .await?;
    match read {
        ProductRead::Found(cat) => json_response(cat.as_ref()),
        ProductRead::NotFound => Err(ApiError::not_found("cat").into()),
        ProductRead::Corrupt => corrupt_response("Cat"),
    }
}

pub(super) async fn list_runtime_disks(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let workspace_id = authorize_workspace(&state, &uri, &headers).await?;
    let (limit, after) = parse_page_query(&uri, ProductReadResource::Disks)?;
    let readiness = state.readiness.clone();
    let read = state
        .store
        .execute(move |store| {
            let read = store.list_runtime_disks(&workspace_id, after.as_ref(), limit);
            if matches!(read, Ok(ProductPageRead::Corrupt)) {
                readiness.poison();
            }
            read
        })
        .await?;
    match read {
        ProductPageRead::Found(page) => json_response(&page),
        ProductPageRead::Corrupt => corrupt_response("Disk collection"),
    }
}

pub(super) async fn get_runtime_disk(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let workspace_id = authorize_workspace(&state, &uri, &headers).await?;
    let Some(raw_id) = exact_item_segment(&uri, &workspace_id, "disks") else {
        return Err(ApiError::not_found("disk").into());
    };
    let Some(disk_id) = Id::new(raw_id.to_owned()).filter(|id| id.as_str().starts_with("disk_"))
    else {
        return Err(ApiError::not_found("disk").into());
    };
    let readiness = state.readiness.clone();
    let read = state
        .store
        .execute(move |store| {
            let read = store.get_runtime_disk(&workspace_id, &disk_id);
            if matches!(read, Ok(ProductRead::Corrupt)) {
                readiness.poison();
            }
            read
        })
        .await?;
    match read {
        ProductRead::Found(disk) => json_response(disk.as_ref()),
        ProductRead::NotFound => Err(ApiError::not_found("disk").into()),
        ProductRead::Corrupt => corrupt_response("Disk"),
    }
}

async fn authorize_workspace(state: &AppState, uri: &Uri, headers: &HeaderMap) -> ApiResult<Id> {
    let workspace = uri.path().split('/').nth(3).unwrap_or("");
    let scope = check_workspace_auth(state, headers, workspace).await?;
    let workspace_id = Id::new(scope.workspace.id)
        .ok_or_else(|| ApiError::internal("stored workspace ID is invalid"))?;
    if workspace != workspace_id.as_str() {
        return Err(ApiError::not_found("workspace").into());
    }
    Ok(workspace_id)
}

fn exact_item_segment<'a>(uri: &'a Uri, workspace_id: &Id, collection: &str) -> Option<&'a str> {
    let mut segments = uri.path().split('/');
    match (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) {
        (
            Some(""),
            Some("v1"),
            Some("workspaces"),
            Some(workspace),
            Some(actual_collection),
            Some(id),
            None,
        ) if workspace == workspace_id.as_str()
            && actual_collection == collection
            && !id.is_empty()
            && uri.query().is_none() =>
        {
            Some(id)
        }
        _ => None,
    }
}

fn parse_page_query(uri: &Uri, resource: ProductReadResource) -> ApiResult<(usize, Option<Id>)> {
    let mut limit = None;
    let mut cursor = None;
    let Some(query) = uri.query() else {
        return Ok((PRODUCT_READ_DEFAULT_LIMIT, None));
    };
    if query.is_empty() {
        return Ok((PRODUCT_READ_DEFAULT_LIMIT, None));
    }
    for field in query.split('&') {
        let Some((key, value)) = field.split_once('=') else {
            return Err(ApiError::invalid("invalid page query").into());
        };
        match key {
            "limit" if limit.is_none() => {
                if value.is_empty()
                    || value.starts_with('0')
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(ApiError::invalid(
                        "limit must be a canonical integer from 1 to 100",
                    )
                    .into());
                }
                let parsed = value.parse::<usize>().map_err(|_| {
                    ApiError::invalid("limit must be a canonical integer from 1 to 100")
                })?;
                if parsed > PRODUCT_READ_MAX_LIMIT {
                    return Err(ApiError::invalid(
                        "limit must be a canonical integer from 1 to 100",
                    )
                    .into());
                }
                limit = Some(parsed);
            }
            "cursor" if cursor.is_none() => {
                let decoded = decode_product_read_cursor(resource, value)
                    .map_err(|_| ApiError::invalid("cursor is invalid"))?;
                cursor = Some(decoded);
            }
            _ => return Err(ApiError::invalid("invalid page query").into()),
        }
    }
    Ok((limit.unwrap_or(PRODUCT_READ_DEFAULT_LIMIT), cursor))
}

fn json_response(value: &impl Serialize) -> ApiResult<Response> {
    let body = serde_json::to_vec(value)
        .map_err(|_| ApiError::internal("could not encode product read response"))?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body))
        .map_err(|_| ApiError::internal("could not construct product read response").into())
}

fn corrupt_response(resource: &str) -> ApiResult<Response> {
    tracing::error!(
        resource,
        "runtime product query found stored authority corruption"
    );
    Err(ApiError::internal("stored runtime product authority is corrupt").into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_api::runtime_product_reads::{encode_product_read_cursor, ProductReadResource};

    #[test]
    fn page_query_is_closed_canonical_and_bounded() {
        let cursor =
            encode_product_read_cursor(ProductReadResource::Cats, &Id::new("cat_01").unwrap());
        for (query, expected_limit, has_cursor) in [
            ("/cats", 50, false),
            ("/cats?", 50, false),
            ("/cats?limit=1", 1, false),
            ("/cats?limit=100", 100, false),
            (&format!("/cats?cursor={cursor}"), 50, true),
            (&format!("/cats?limit=2&cursor={cursor}"), 2, true),
        ] {
            let uri = query.parse().unwrap();
            let (limit, after) = parse_page_query(&uri, ProductReadResource::Cats).unwrap();
            assert_eq!(limit, expected_limit, "{query}");
            assert_eq!(after.is_some(), has_cursor, "{query}");
        }

        for query in [
            "/cats?limit",
            "/cats?limit=",
            "/cats?limit=0",
            "/cats?limit=01",
            "/cats?limit=+1",
            "/cats?limit=101",
            "/cats?limit=1&limit=2",
            "/cats?cursor=",
            "/cats?cursor=not-base64!",
            "/cats?unknown=1",
            "/cats?limit=1&",
        ] {
            let uri = query.parse().unwrap();
            assert!(
                parse_page_query(&uri, ProductReadResource::Cats).is_err(),
                "{query}"
            );
        }
        let disk_cursor =
            encode_product_read_cursor(ProductReadResource::Disks, &Id::new("disk_01").unwrap());
        let uri = format!("/cats?cursor={disk_cursor}").parse().unwrap();
        assert!(parse_page_query(&uri, ProductReadResource::Cats).is_err());
    }
}
