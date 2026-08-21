//! Elected automatic projection from Endpoint metadata and atomic lifecycle
//! authority into independent per-Endpoint Route commands.
//!
//! PostgreSQL row locks and exact predecessor constraints remain the real
//! concurrency authority. Singleton election only avoids duplicate scanning;
//! a briefly overlapping replica is harmless and cannot create a second lane.

use std::sync::Arc;
use std::time::Duration;

use cats_api::runtime_reconciliation::Id;

use super::route_operations::ROUTE_CONTROLLER_PAGE_MAX_ENDPOINTS;
use crate::store::Store;

const ROUTE_CONTROLLER_INTERVAL: Duration = Duration::from_millis(250);

pub(crate) struct RouteController {
    store: Arc<Store>,
}

impl RouteController {
    pub(crate) fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    /// Run until the elected-role supervisor cancels this owned task. Every
    /// tick advances one bounded ordered page; reaching the end wraps to the
    /// first Endpoint on the following tick so quiescent early rows cannot
    /// starve later metadata changes.
    pub(crate) async fn run(self) {
        let mut after_endpoint_id: Option<Id> = None;
        let mut interval = tokio::time::interval(ROUTE_CONTROLLER_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let after = after_endpoint_id.clone();
            let result = self
                .store
                .execute(move |store| {
                    store.reconcile_route_controller_page(
                        after.as_ref(),
                        ROUTE_CONTROLLER_PAGE_MAX_ENDPOINTS,
                    )
                })
                .await;
            match result {
                Ok(page) => {
                    if page.mutations != 0 {
                        tracing::info!(
                            examined = page.examined,
                            mutations = page.mutations,
                            "atomic Route controller page committed"
                        );
                    }
                    after_endpoint_id = page.next_after_endpoint_id;
                }
                Err(error) => {
                    tracing::warn!(%error, "atomic Route controller page failed");
                }
            }
        }
    }
}
