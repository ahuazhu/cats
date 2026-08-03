//! Deployment records for OCI applications.
//!
//! A deploy is long (registry transfer plus layer extraction) and its caller
//! may disappear mid-flight, so the record -- not the HTTP request -- is the
//! unit of work. `(cat_id, app, image_digest)` is the deployment's identity:
//! [`Store::claim_oci_deployment`] resolves a request against that identity in
//! one transaction, so a retry joins or replays the first attempt instead of
//! starting a second pull, flatten and service restart.

use super::*;

/// The operation `kind` for an OCI deploy, matching the `cat.<verb>` shape the
/// lifecycle actions already use.
pub const OCI_DEPLOY_OPERATION_KIND: &str = "cat.oci-deploy";

/// What a caller should do with a deployment request, decided by the record.
#[derive(Debug, Clone)]
pub enum OciDeploymentClaim {
    /// This caller owns the deploy and must drive it to a terminal phase.
    Claimed {
        record_id: String,
        operation: Operation,
    },
    /// An attempt for this exact identity is already running. The caller must
    /// not start a second one; it waits on or reports the existing operation.
    AlreadyRunning {
        record_id: String,
        operation: Operation,
    },
    /// This identity already succeeded. Replaying it must not touch the Guest:
    /// re-running activation would restart a service that is already correct.
    Replay {
        operation: Operation,
        deployment: OciDeployment,
    },
}

impl Store {
    /// Resolve a deploy request against the deployment identity.
    ///
    /// A previous attempt left in `failed` is retried on the same row, so a
    /// recovered failure does not need a different digest to make progress.
    pub fn claim_oci_deployment(
        &self,
        cat: &Cat,
        app: &str,
        image_digest: &str,
    ) -> Result<OciDeploymentClaim> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let existing: Option<(String, String, String)> = tx
            .query_row(
                "SELECT id, phase, operation_id FROM oci_deployments
                  WHERE cat_id=?1 AND app=?2 AND image_digest=?3",
                params![cat.id, app, image_digest],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(internal)?;
        let now = now_unix();
        let claim = match existing {
            Some((record_id, phase, operation_id)) if phase == "succeeded" => {
                let operation = tx
                    .query_row(
                        "SELECT * FROM operations WHERE id=?1",
                        params![operation_id],
                        row_to_operation,
                    )
                    .map_err(internal)?;
                let deployment = tx
                    .query_row(
                        "SELECT * FROM oci_deployments WHERE id=?1",
                        params![record_id],
                        row_to_oci_deployment,
                    )
                    .map_err(internal)?
                    .ok_or_else(|| {
                        ApiError::internal("succeeded OCI deployment is missing its result")
                    })?;
                OciDeploymentClaim::Replay {
                    operation,
                    deployment,
                }
            }
            Some((record_id, phase, operation_id)) if phase == "running" => {
                let operation = tx
                    .query_row(
                        "SELECT * FROM operations WHERE id=?1",
                        params![operation_id],
                        row_to_operation,
                    )
                    .map_err(internal)?;
                OciDeploymentClaim::AlreadyRunning {
                    record_id,
                    operation,
                }
            }
            // 'failed': retry in place. The operation is replaced so a caller
            // polling the new one cannot read the previous failure.
            Some((record_id, _, _)) => {
                let operation = Self::insert_operation(
                    &tx,
                    &cat.workspace_id,
                    OCI_DEPLOY_OPERATION_KIND,
                    &cat.id,
                    cat.generation,
                )?;
                tx.execute(
                    "UPDATE oci_deployments SET
                        phase='running', operation_id=?2, error_json=NULL,
                        manifest_digest=NULL, service=NULL, active=0, updated_at=?3
                      WHERE id=?1",
                    params![record_id, operation.id, now],
                )
                .map_err(internal)?;
                OciDeploymentClaim::Claimed {
                    record_id,
                    operation,
                }
            }
            None => {
                let operation = Self::insert_operation(
                    &tx,
                    &cat.workspace_id,
                    OCI_DEPLOY_OPERATION_KIND,
                    &cat.id,
                    cat.generation,
                )?;
                let record_id = new_id(ids::OCI_DEPLOYMENT_PREFIX);
                tx.execute(
                    "INSERT INTO oci_deployments
                        (id, cat_id, app, image_digest, operation_id,
                         phase, created_at, updated_at)
                     VALUES (?1,?2,?3,?4,?5,'running',?6,?6)",
                    params![record_id, cat.id, app, image_digest, operation.id, now],
                )
                .map_err(internal)?;
                OciDeploymentClaim::Claimed {
                    record_id,
                    operation,
                }
            }
        };
        tx.commit().map_err(internal)?;
        Ok(claim)
    }

    /// Record a finished deploy and move its operation to `Succeeded`.
    pub fn succeed_oci_deployment(
        &self,
        record_id: &str,
        deployment: &OciDeployment,
    ) -> Result<()> {
        let operation_id = self.with(|c| {
            c.execute(
                "UPDATE oci_deployments SET
                    phase='succeeded', manifest_digest=?2, service=?3, active=?4,
                    error_json=NULL, updated_at=?5
                  WHERE id=?1",
                params![
                    record_id,
                    deployment.manifest_digest,
                    deployment.service,
                    i64::from(deployment.active),
                    now_unix()
                ],
            )?;
            c.query_row(
                "SELECT operation_id FROM oci_deployments WHERE id=?1",
                params![record_id],
                |row| row.get::<_, String>(0),
            )
        })?;
        self.finish_operation(&operation_id, None)
    }

    /// Record a failed deploy and move its operation to `Failed`.
    ///
    /// The error is persisted on the record as well as the operation so a
    /// retry of the same digest can see it is recovering a failure, and so an
    /// operator reading the record alone learns why it failed.
    pub fn fail_oci_deployment(&self, record_id: &str, error: &ErrorBody) -> Result<()> {
        let error_json = serde_json::to_string(error).map_err(internal)?;
        let operation_id = self.with(|c| {
            c.execute(
                "UPDATE oci_deployments SET phase='failed', error_json=?2, updated_at=?3
                  WHERE id=?1",
                params![record_id, error_json, now_unix()],
            )?;
            c.query_row(
                "SELECT operation_id FROM oci_deployments WHERE id=?1",
                params![record_id],
                |row| row.get::<_, String>(0),
            )
        })?;
        self.finish_operation(&operation_id, Some(error))
    }

    /// The deployment result behind an operation, once it has succeeded.
    pub fn oci_deployment_for_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<OciDeployment>> {
        self.with(|c| {
            c.query_row(
                "SELECT * FROM oci_deployments WHERE operation_id=?1",
                params![operation_id],
                row_to_oci_deployment,
            )
            .optional()
            .map(Option::flatten)
        })
    }

    /// Every application currently deployed in a Cat.
    pub fn list_oci_deployments(&self, cat_id: &str) -> Result<Vec<OciDeployment>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT * FROM oci_deployments
                  WHERE cat_id=?1 AND phase='succeeded'
                  ORDER BY app",
            )?;
            let rows = stmt.query_map(params![cat_id], row_to_oci_deployment)?;
            rows.filter_map(|row| row.transpose()).collect()
        })
    }

    /// Fail every deployment still marked `running`, with its operation.
    ///
    /// Called once at startup. An in-flight deploy is driven by an in-memory
    /// task holding pull credentials that are deliberately never persisted, so
    /// a restart cannot resume it. Leaving the row `running` would block that
    /// identity for good and leave the operation forever unresolved; reporting
    /// the truth lets the caller retry. Returns how many rows were converged.
    pub fn fail_interrupted_oci_deployments(&self) -> Result<usize> {
        let stranded: Vec<(String, String)> = self.with(|c| {
            let mut stmt =
                c.prepare("SELECT id, app FROM oci_deployments WHERE phase='running'")?;
            let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            rows.collect()
        })?;
        for (record_id, app) in &stranded {
            let error = ErrorBody::new(
                ErrorCode::Unavailable,
                format!(
                    "deploying {app} was interrupted by a control-plane restart and \
                     cannot be resumed because registry credentials are never \
                     persisted; retry the deploy"
                ),
            );
            self.fail_oci_deployment(record_id, &error)?;
        }
        Ok(stranded.len())
    }
}
