//! Shared error codes and the HTTP error body used by every Cats HTTP surface.

use serde::{Deserialize, Serialize};

/// Stable machine-readable error codes.
///
/// These map onto HTTP status codes but are the primary contract: clients
/// must switch on `code`, not on the status line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidArgument,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    AlreadyExists,
    /// Resource state does not allow the request (e.g. deleting a bound disk).
    FailedPrecondition,
    /// The prepaid balance is exhausted; clients should direct the user to
    /// the billing top-up flow before retrying paid work.
    PaymentRequired,
    /// Concurrent modification (generation/If-Match mismatch) or RWO conflict.
    Conflict,
    /// A stale fencing epoch or route epoch was presented.
    StaleEpoch,
    DeadlineExceeded,
    Unavailable,
    Internal,
}

impl ErrorCode {
    pub fn http_status(self) -> u16 {
        match self {
            ErrorCode::InvalidArgument => 400,
            ErrorCode::Unauthenticated => 401,
            ErrorCode::PermissionDenied => 403,
            ErrorCode::NotFound => 404,
            ErrorCode::AlreadyExists => 409,
            ErrorCode::FailedPrecondition => 412,
            ErrorCode::PaymentRequired => 402,
            ErrorCode::Conflict => 409,
            ErrorCode::StaleEpoch => 409,
            ErrorCode::DeadlineExceeded => 504,
            ErrorCode::Unavailable => 503,
            ErrorCode::Internal => 500,
        }
    }
}

/// Error body returned by control plane, node agent and gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl ErrorBody {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            request_id: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    pub fn not_found(what: impl std::fmt::Display) -> Self {
        Self::new(ErrorCode::NotFound, format!("{what} not found"))
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgument, message)
    }
    pub fn unauthenticated(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unauthenticated, message)
    }
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Conflict, message)
    }
    pub fn failed_precondition(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::FailedPrecondition, message)
    }
    pub fn payment_required(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::PaymentRequired, message)
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unavailable, message)
    }
}
