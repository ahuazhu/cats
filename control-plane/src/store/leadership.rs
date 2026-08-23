use super::*;

/// Independently elected background roles. Splitting the locks lets a healthy
/// replica share the work instead of making one process the hot standby for
/// every singleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingletonRole {
    UsageProjector,
    SemanticActionRecovery,
}

impl SingletonRole {
    fn lock_key(self) -> i32 {
        match self {
            Self::UsageProjector => 420_203,
            Self::SemanticActionRecovery => 420_204,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::UsageProjector => "usage-projector",
            Self::SemanticActionRecovery => "semantic-action-recovery",
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
    connection_budget: Option<ConnectionBudgetPermit>,
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

    /// Destroy the PostgreSQL client on the dedicated leadership executor.
    /// Unlike `Drop`, this is joinable: graceful singleton shutdown must not
    /// return while advisory-lock release is still queued as cleanup work.
    pub(crate) fn close_now(mut self) {
        drop(self.client.take());
        drop(self.connection_budget.take());
    }
}

impl Drop for SingletonSession {
    fn drop(&mut self) {
        match (self.client.take(), self.connection_budget.take()) {
            (Some(client), Some(connection_budget)) => {
                drop_on_leadership_executor((client, connection_budget));
            }
            (client, connection_budget) => {
                drop(client);
                drop(connection_budget);
            }
        }
    }
}

impl Store {
    pub(crate) fn singleton_session(&self, role: SingletonRole) -> Result<SingletonSession> {
        let connection_budget = acquire_singleton_connection_budget()?;
        let mut client =
            off_runtime(|| schema::connect_client(&self.dsn, self.ca_file.as_deref()))?;
        off_runtime(|| configure_session(&mut client))?;
        Ok(SingletonSession {
            client: Some(client),
            connection_budget: Some(connection_budget),
            role,
            acquired: false,
        })
    }
}
