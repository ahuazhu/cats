use super::*;

/// Independently elected background roles. Splitting the locks lets a healthy
/// replica share the work instead of making one process the hot standby for
/// every singleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingletonRole {
    Reconciler,
    BillingEnforcer,
    UsageProjector,
}

impl SingletonRole {
    fn lock_key(self) -> i32 {
        match self {
            Self::Reconciler => 420_201,
            Self::BillingEnforcer => 420_202,
            Self::UsageProjector => 420_203,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Reconciler => "reconciler",
            Self::BillingEnforcer => "billing-enforcer",
            Self::UsageProjector => "usage-projector",
        }
    }
}

/// One dedicated PostgreSQL session used for singleton election.
///
/// Session advisory locks are released by PostgreSQL when the connection is
/// lost, which makes database failover and process death the fencing event.
/// A standby keeps its session and retries on it instead of opening a new
/// connection on every election poll.
pub(crate) struct SingletonSession {
    client: Option<Client>,
    _connection_budget: ConnectionBudgetPermit,
    role: SingletonRole,
    acquired: bool,
}

impl SingletonSession {
    pub(crate) fn try_acquire(&mut self) -> Result<bool> {
        if self.acquired {
            return Ok(true);
        }
        let role_key = self.role.lock_key();
        let acquired = off_runtime(|| {
            self.client
                .as_mut()
                .expect("singleton session is live until drop")
                .query_one(
                    "SELECT pg_try_advisory_lock(hashtext(current_schema()), $1)",
                    &[&role_key],
                )
                .map_err(internal)?
                .try_get(0)
                .map_err(internal)
        })?;
        self.acquired = acquired;
        Ok(acquired)
    }

    pub(crate) fn check(&mut self) -> Result<()> {
        off_runtime(|| {
            self.client
                .as_mut()
                .expect("singleton session is live until drop")
                .simple_query("SELECT 1")
                .map_err(internal)
                .map(|_| ())
        })
    }
}

impl Drop for SingletonSession {
    fn drop(&mut self) {
        if let Some(client) = self.client.take() {
            off_runtime(move || drop(client));
        }
    }
}

/// Ownership fence for one detached OCI deployment attempt.
///
/// The lock is acquired before the deployment record commits and is held by
/// the detached task. Another replica can therefore distinguish a live task
/// from a row whose owner process or database session disappeared, without a
/// process-local registry or a persisted wall-clock lease.
pub struct OciDeploymentLease {
    client: Option<Client>,
    _connection_budget: ConnectionBudgetPermit,
}

impl Drop for OciDeploymentLease {
    fn drop(&mut self) {
        if let Some(client) = self.client.take() {
            off_runtime(move || drop(client));
        }
    }
}

impl Store {
    pub(crate) fn singleton_session(&self, role: SingletonRole) -> Result<SingletonSession> {
        let connection_budget = acquire_singleton_connection_budget()?;
        let mut client =
            off_runtime(|| schema::connect_client(&self.dsn, self.ca_file.as_deref()))?;
        off_runtime(|| {
            client
                .batch_execute("SET statement_timeout = '5s'; SET lock_timeout = '2s'")
                .map_err(internal)
        })?;
        Ok(SingletonSession {
            client: Some(client),
            _connection_budget: connection_budget,
            role,
            acquired: false,
        })
    }

    pub(super) fn try_oci_deployment_lease(
        &self,
        operation_id: &str,
    ) -> Result<Option<OciDeploymentLease>> {
        let connection_budget = acquire_oci_connection_budget()?;
        let mut client =
            off_runtime(|| schema::connect_client(&self.dsn, self.ca_file.as_deref()))?;
        off_runtime(|| configure_session(&mut client))?;
        let acquired = off_runtime(|| {
            client
                .query_one(
                    "SELECT pg_try_advisory_lock(
                        hashtextextended(current_schema() || ':oci-owner:' || $1, 0::BIGINT)
                     )",
                    &[&operation_id],
                )
                .map_err(internal)?
                .try_get(0)
                .map_err(internal)
        })?;
        if acquired {
            Ok(Some(OciDeploymentLease {
                client: Some(client),
                _connection_budget: connection_budget,
            }))
        } else {
            off_runtime(move || drop(client));
            Ok(None)
        }
    }
}
