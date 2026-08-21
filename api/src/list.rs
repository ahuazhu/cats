//! Small collection envelope shared by non-cursor HTTP APIs.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListResponse<T> {
    pub items: Vec<T>,
}
