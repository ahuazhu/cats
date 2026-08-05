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
}

/// Serializes every convergence attempt for one externally fenced node across
/// all control-plane replicas. The dedicated PostgreSQL session deliberately
/// stays outside `Store`'s shared client mutex and any SQL transaction while
/// object/metadata-store calls are awaited by the controller.
pub(crate) struct NodeFenceLease {
    client: Option<Client>,
}

impl NodeFenceLease {
    /// Prove the advisory-lock session still exists after an awaited external
    /// call. A disconnected old task must stop before committing Cat state;
    /// conditional lease CAS still protects any replacement writer meanwhile.
    pub(crate) fn check(&mut self) -> Result<()> {
        off_runtime(|| {
            self.client
                .as_mut()
                .expect("node fence session is live until drop")
                .simple_query("SELECT 1")
                .map_err(internal)
                .map(|_| ())
        })
    }

    #[cfg(test)]
    pub(crate) fn backend_pid(&mut self) -> Result<i32> {
        off_runtime(|| {
            self.client
                .as_mut()
                .expect("node fence session is live until drop")
                .query_one("SELECT pg_backend_pid()", &[])
                .map_err(internal)?
                .try_get(0)
                .map_err(internal)
        })
    }
}

impl Drop for NodeFenceLease {
    fn drop(&mut self) {
        if let Some(client) = self.client.take() {
            off_runtime(move || drop(client));
        }
    }
}

impl Drop for OciDeploymentLease {
    fn drop(&mut self) {
        if let Some(client) = self.client.take() {
            off_runtime(move || drop(client));
        }
    }
}

impl Store {
    pub(crate) fn node_fence_lease(&self, node_id: &str) -> Result<Option<NodeFenceLease>> {
        self.try_scoped_safety_lease("node-fence", node_id)
    }

    pub(crate) fn destroy_cleanup_lease(&self, cat_id: &str) -> Result<Option<NodeFenceLease>> {
        self.try_scoped_safety_lease("destroy-cleanup", cat_id)
    }

    fn try_scoped_safety_lease(&self, scope: &str, id: &str) -> Result<Option<NodeFenceLease>> {
        let mut client =
            off_runtime(|| schema::connect_client(&self.dsn, self.ca_file.as_deref()))?;
        let acquired: bool = off_runtime(|| {
            client
                .query_one(
                    "SELECT pg_try_advisory_lock(
                        hashtextextended(current_schema() || ':' || $1 || ':' || $2, 0::BIGINT)
                     )",
                    &[&scope, &id],
                )
                .map_err(internal)
                .and_then(|row| row.try_get(0).map_err(internal))
        })?;
        if acquired {
            Ok(Some(NodeFenceLease {
                client: Some(client),
            }))
        } else {
            off_runtime(move || drop(client));
            Ok(None)
        }
    }

    pub(crate) fn singleton_session(&self, role: SingletonRole) -> Result<SingletonSession> {
        let mut client =
            off_runtime(|| schema::connect_client(&self.dsn, self.ca_file.as_deref()))?;
        off_runtime(|| {
            client
                .batch_execute("SET statement_timeout = '5s'; SET lock_timeout = '2s'")
                .map_err(internal)
        })?;
        Ok(SingletonSession {
            client: Some(client),
            role,
            acquired: false,
        })
    }

    pub(super) fn try_oci_deployment_lease(
        &self,
        operation_id: &str,
    ) -> Result<Option<OciDeploymentLease>> {
        let mut client =
            off_runtime(|| schema::connect_client(&self.dsn, self.ca_file.as_deref()))?;
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
            }))
        } else {
            off_runtime(move || drop(client));
            Ok(None)
        }
    }
}
