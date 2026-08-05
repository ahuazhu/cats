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
pub enum OciDeploymentClaim {
    /// This caller owns the deploy and must drive it to a terminal phase.
    Claimed {
        record_id: String,
        operation: Operation,
        lease: Box<OciDeploymentLease>,
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
        self.enter(|client| {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            tx.query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended(
                    current_schema() || ':oci-identity:' || $1 || ':' || $2 || ':' || $3,
                    0::BIGINT
                 ))",
                &[&cat.id, &app, &image_digest],
            )
            .map_err(internal)?;
            let existing: Option<(String, String, String)> = tx
                .query_opt(
                    "SELECT id, phase, operation_id FROM oci_deployments
                  WHERE cat_id=$1 AND app=$2 AND image_digest=$3
                  FOR UPDATE",
                    &[&cat.id, &app, &image_digest],
                )
                .map_err(internal)?
                .map(|row| {
                    Ok::<_, postgres::Error>((row.try_get(0)?, row.try_get(1)?, row.try_get(2)?))
                })
                .transpose()
                .map_err(internal)?;
            let now = now_unix();
            // A stale-owner probe holds the old operation's advisory lock until
            // this transaction commits. A concurrent retry therefore joins
            // this attempt instead of racing another replacement operation.
            let mut stale_owner = None;
            let claim = match existing {
                Some((record_id, phase, operation_id)) if phase == "succeeded" => {
                    let row = tx
                        .query_one("SELECT * FROM operations WHERE id=$1", &[&operation_id])
                        .map_err(internal)?;
                    let operation = row_to_operation(&row).map_err(internal)?;
                    let row = tx
                        .query_one("SELECT * FROM oci_deployments WHERE id=$1", &[&record_id])
                        .map_err(internal)?;
                    let deployment =
                        row_to_oci_deployment(&row)
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
                    match self.try_oci_deployment_lease(&operation_id)? {
                        None => {
                            let row = tx
                                .query_one(
                                    "SELECT * FROM operations WHERE id=$1",
                                    &[&operation_id],
                                )
                                .map_err(internal)?;
                            let operation = row_to_operation(&row).map_err(internal)?;
                            OciDeploymentClaim::AlreadyRunning {
                                record_id,
                                operation,
                            }
                        }
                        Some(lease) => {
                            stale_owner = Some(lease);
                            let interrupted = ErrorBody::new(
                                ErrorCode::Unavailable,
                                "OCI deployment owner disappeared before recording an outcome; retrying the deploy",
                            );
                            Self::finish_operation_in(
                                &mut tx,
                                &operation_id,
                                Some(&interrupted),
                            )?;
                            Self::replace_oci_attempt(&mut tx, self, cat, &record_id, now)?
                        }
                    }
                }
                // 'failed' or 'superseded': deploy again on the same row. Failed
                // means it never took effect; superseded means it no longer is in
                // effect, which is what makes a rollback to an older digest real
                // work rather than a replay. The operation is replaced so a caller
                // polling the new one cannot read the previous outcome.
                Some((record_id, _, _)) => {
                    Self::replace_oci_attempt(&mut tx, self, cat, &record_id, now)?
                }
                None => {
                    let operation = Self::insert_operation(
                        &mut tx,
                        &cat.workspace_id,
                        OCI_DEPLOY_OPERATION_KIND,
                        &cat.id,
                        cat.generation,
                    )?;
                    let record_id = new_id(ids::OCI_DEPLOYMENT_PREFIX);
                    let lease = self
                        .try_oci_deployment_lease(&operation.id)?
                        .ok_or_else(|| ApiError::internal("new OCI operation lock is occupied"))?;
                    tx.execute(
                        "INSERT INTO oci_deployments
                        (id, cat_id, app, image_digest, operation_id,
                         phase, created_at, updated_at)
                     VALUES ($1,$2,$3,$4,$5,'running',$6,$6)",
                        &[
                            &record_id,
                            &cat.id,
                            &app,
                            &image_digest,
                            &operation.id,
                            &now,
                        ],
                    )
                    .map_err(internal)?;
                    OciDeploymentClaim::Claimed {
                        record_id,
                        operation,
                        lease: Box::new(lease),
                    }
                }
            };
            tx.commit().map_err(internal)?;
            drop(stale_owner);
            Ok(claim)
        })
    }

    fn replace_oci_attempt(
        tx: &mut postgres::Transaction<'_>,
        store: &Store,
        cat: &Cat,
        record_id: &str,
        now: i64,
    ) -> Result<OciDeploymentClaim> {
        let operation = Self::insert_operation(
            tx,
            &cat.workspace_id,
            OCI_DEPLOY_OPERATION_KIND,
            &cat.id,
            cat.generation,
        )?;
        let lease = store
            .try_oci_deployment_lease(&operation.id)?
            .ok_or_else(|| ApiError::internal("new OCI operation lock is occupied"))?;
        tx.execute(
            "UPDATE oci_deployments SET
                phase='running', operation_id=$2, error_json=NULL,
                manifest_digest=NULL, service=NULL, active=FALSE, updated_at=$3
              WHERE id=$1",
            &[&record_id, &operation.id, &now],
        )
        .map_err(internal)?;
        Ok(OciDeploymentClaim::Claimed {
            record_id: record_id.to_string(),
            operation,
            lease: Box::new(lease),
        })
    }

    /// Record a finished deploy and move its operation to `Succeeded`.
    ///
    /// Supersedes whatever was activated for this app before, in the same
    /// transaction: the app's previous digest is no longer what the Guest runs,
    /// and `oci_deployments_one_current_per_app` would reject the write if both
    /// rows claimed to be current. Doing it atomically with the operation also
    /// means a crash cannot leave a terminal record behind a running operation.
    pub fn succeed_oci_deployment(
        &self,
        record_id: &str,
        operation_id: &str,
        deployment: &OciDeployment,
    ) -> Result<bool> {
        self.enter(|client| {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            let Some((cat_id, app)) =
                Self::owned_oci_deployment_keys(&mut tx, record_id, operation_id)?
            else {
                return Ok(false);
            };
            let now = now_unix();
            tx.execute(
                "UPDATE oci_deployments SET phase='superseded', active=FALSE, updated_at=$4
              WHERE cat_id=$1 AND app=$2 AND phase='succeeded' AND id<>$3",
                &[&cat_id, &app, &record_id, &now],
            )
            .map_err(internal)?;
            tx.execute(
                "UPDATE oci_deployments SET
                phase='succeeded', manifest_digest=$2, service=$3, active=$4,
                error_json=NULL, updated_at=$5
              WHERE id=$1",
                &[
                    &record_id,
                    &deployment.manifest_digest,
                    &deployment.service,
                    &deployment.active,
                    &now,
                ],
            )
            .map_err(internal)?;
            Self::finish_operation_in(&mut tx, operation_id, None)?;
            tx.commit().map_err(internal)?;
            Ok(true)
        })
    }

    /// Record a failed deploy and move its operation to `Failed`.
    ///
    /// The error is persisted on the record as well as the operation so a
    /// retry of the same digest can see it is recovering a failure, and so an
    /// operator reading the record alone learns why it failed. A failure leaves
    /// whatever was already activated for the app alone -- it is still what the
    /// Guest runs.
    pub fn fail_oci_deployment(
        &self,
        record_id: &str,
        operation_id: &str,
        error: &ErrorBody,
    ) -> Result<bool> {
        self.enter(|client| {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            if Self::owned_oci_deployment_keys(&mut tx, record_id, operation_id)?.is_none() {
                return Ok(false);
            }
            let error_json = serde_json::to_string(error).map_err(internal)?;
            tx.execute(
                "UPDATE oci_deployments SET phase='failed', error_json=$2, updated_at=$3
              WHERE id=$1",
                &[&record_id, &error_json, &now_unix()],
            )
            .map_err(internal)?;
            Self::finish_operation_in(&mut tx, operation_id, Some(error))?;
            tx.commit().map_err(internal)?;
            Ok(true)
        })
    }

    fn owned_oci_deployment_keys(
        tx: &mut postgres::Transaction<'_>,
        record_id: &str,
        operation_id: &str,
    ) -> Result<Option<(String, String)>> {
        let row = tx
            .query_opt(
                "SELECT cat_id, app FROM oci_deployments
                  WHERE id=$1 AND operation_id=$2 AND phase='running'
                  FOR UPDATE",
                &[&record_id, &operation_id],
            )
            .map_err(internal)?;
        row.map(|row| {
            Ok((
                row.try_get(0).map_err(internal)?,
                row.try_get(1).map_err(internal)?,
            ))
        })
        .transpose()
    }

    /// The deployment result behind an operation, once it has succeeded.
    pub fn oci_deployment_for_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<OciDeployment>> {
        self.with(|client| {
            client
                .query_opt(
                    "SELECT * FROM oci_deployments WHERE operation_id=$1",
                    &[&operation_id],
                )?
                .map(|row| row_to_oci_deployment(&row))
                .transpose()
                .map(Option::flatten)
        })
    }

    /// Every application currently deployed in a Cat, one row per app.
    ///
    /// `oci_deployments_one_current_per_app` is what makes that true, so this
    /// needs no ordering trick or de-duplication to avoid answering with a
    /// digest the Guest has already replaced.
    pub fn list_oci_deployments(&self, cat_id: &str) -> Result<Vec<OciDeployment>> {
        self.with(|client| {
            client
                .query(
                    "SELECT * FROM oci_deployments
                      WHERE cat_id=$1 AND phase='succeeded'
                      ORDER BY app",
                    &[&cat_id],
                )?
                .iter()
                .map(row_to_oci_deployment)
                .filter_map(|row| row.transpose())
                .collect::<std::result::Result<Vec<_>, postgres::Error>>()
        })
    }

    /// Fail every deployment still marked `running`, with its operation.
    ///
    /// Called periodically by the elected reconciler. An in-flight deploy is
    /// driven by an in-memory task holding pull credentials that are
    /// deliberately never persisted, so a dead owner cannot resume it. Rows
    /// whose owner session lock is still held are skipped; stranded rows are
    /// failed so the caller can retry. Returns how many rows were converged.
    pub fn fail_interrupted_oci_deployments(&self) -> Result<usize> {
        let stranded: Vec<(String, String, String)> = self.with(|client| {
            client
                .query(
                    "SELECT id, app, operation_id FROM oci_deployments WHERE phase='running'",
                    &[],
                )?
                .iter()
                .map(|row| Ok((row.try_get(0)?, row.try_get(1)?, row.try_get(2)?)))
                .collect::<std::result::Result<Vec<_>, postgres::Error>>()
        })?;
        let mut failed = 0;
        for (record_id, app, operation_id) in &stranded {
            let Some(_owner_fence) = self.try_oci_deployment_lease(operation_id)? else {
                continue;
            };
            let error = ErrorBody::new(
                ErrorCode::Unavailable,
                format!(
                    "deploying {app} was interrupted by a control-plane restart and \
                     cannot be resumed because registry credentials are never \
                     persisted; retry the deploy"
                ),
            );
            failed += usize::from(self.fail_oci_deployment(record_id, operation_id, &error)?);
        }
        Ok(failed)
    }
}
