//! OCI deployment records and cross-replica attempt ownership.
//!
//! OCI deployment is independent from Cat lifecycle authority. A deployment
//! attempt never carries a Desired revision, lifecycle generation, or Cat
//! Operation ID. The Cat must already have an exact terminal Running head;
//! Control then uses the admin-owned Node transport target for the call.

use cats_api::error::{ApiError, ErrorBody, ErrorCode};
use cats_api::oci::{OciDeployment, OciDeploymentAttempt, OciDeploymentAttemptState};
use cats_api::runtime_reconciliation::{ContractVersion, Id, NodeTransportTarget};
use postgres::Row;

use super::*;

pub struct OciRuntimeTarget {
    pub cat_id: Id,
    pub node_transport_target: NodeTransportTarget,
}

pub enum OciDeploymentClaim {
    Claimed {
        record_id: Id,
        attempt_id: Id,
        lease: Box<OciDeploymentLease>,
    },
    AlreadyRunning {
        record_id: Id,
        attempt_id: Id,
    },
    Replay {
        deployment: OciDeployment,
    },
}

impl Store {
    /// Resolve a current Running Cat and the admin-owned transport target of
    /// its exact RuntimeReady lifecycle head. Telemetry and Agent self-report
    /// cannot supply or override this target.
    pub fn resolve_oci_runtime_target(
        &self,
        workspace_id: &Id,
        name_or_id: &Id,
    ) -> Result<OciRuntimeTarget> {
        self.enter(|client| {
            let client = client?;
            let mut transaction = client.transaction().map_err(internal)?;
            transaction
                .batch_execute("SET TRANSACTION READ ONLY")
                .map_err(internal)?;
            let cats = transaction
                .query(
                    "SELECT cat_id, stable_state, lifecycle_head_operation_id,
                        effective_runtime_ready_operation_id
                   FROM cat_records
                  WHERE workspace_id=$1 AND deleted_at IS NULL
                    AND (cat_id=$2 OR name=$2)
                  LIMIT 2",
                    &[&workspace_id.as_str(), &name_or_id.as_str()],
                )
                .map_err(internal)?;
            let row = match cats.as_slice() {
                [] => return Err(ApiError::not_found("cat")),
                [row] => row,
                _ => return Err(internal("ambiguous Cat name or ID in v18 catalog")),
            };
            let cat_id = Id::new(row.try_get::<_, String>("cat_id").map_err(internal)?)
                .ok_or_else(|| internal("stored Cat ID is invalid"))?;
            if row
                .try_get::<_, Option<String>>("stable_state")
                .map_err(internal)?
                .as_deref()
                != Some("running")
            {
                return Err(ApiError::failed_precondition(
                    "OCI deployment requires the Cat to be Running",
                ));
            }
            let head: Option<String> = row
                .try_get("lifecycle_head_operation_id")
                .map_err(internal)?;
            let ready: Option<String> = row
                .try_get("effective_runtime_ready_operation_id")
                .map_err(internal)?;
            if head.is_none() || head != ready {
                return Err(internal(
                    "Running Cat has no exact RuntimeReady lifecycle head",
                ));
            }
            let target = transaction
                .query_opt(
                    "SELECT policy.node_transport_target
                   FROM runtime_operations operation
                   JOIN runtime_node_placement_policies policy
                     ON policy.node_id=operation.node_id
                   JOIN node_identities identity
                     ON identity.node_id=operation.node_id
                   JOIN current_agent_sessions session
                     ON session.node_id=operation.node_id
                  WHERE operation.operation_id=$1
                    AND operation.workspace_id=$2
                    AND operation.cat_id=$3
                    AND operation.state='terminal'
                    AND operation.terminal_result_kind='runtime_ready'
                    AND identity.state='provisioned'
                    AND session.lease_deadline_unix_ms >=
                        floor(extract(epoch from clock_timestamp()) * 1000)::BIGINT",
                    &[&head, &workspace_id.as_str(), &cat_id.as_str()],
                )
                .map_err(internal)?;
            transaction.commit().map_err(internal)?;
            let target = target.ok_or_else(|| {
                ApiError::unavailable(
                    "Running Cat's Node has no current authenticated transport session",
                )
            })?;
            let node_transport_target = NodeTransportTarget::new(
                target
                    .try_get::<_, String>("node_transport_target")
                    .map_err(internal)?,
            )
            .ok_or_else(|| internal("stored Node transport target is invalid"))?;
            Ok(OciRuntimeTarget {
                cat_id,
                node_transport_target,
            })
        })
    }

    pub fn claim_oci_deployment(
        &self,
        cat_id: &Id,
        app: &str,
        image_digest: &str,
    ) -> Result<OciDeploymentClaim> {
        self.enter(|client| {
            let client = client?;
            let mut transaction = client.transaction().map_err(internal)?;
            transaction
                .query_one(
                    "SELECT pg_advisory_xact_lock(hashtextextended(
                        current_schema() || ':oci-identity:' || $1 || ':' || $2 || ':' || $3,
                        0::BIGINT
                     ))",
                    &[&cat_id.as_str(), &app, &image_digest],
                )
                .map_err(internal)?;
            let existing: Option<(Id, String, Id)> = transaction
                .query_opt(
                    "SELECT id, phase, attempt_id FROM oci_deployments
                      WHERE cat_id=$1 AND app=$2 AND image_digest=$3
                      FOR UPDATE",
                    &[&cat_id.as_str(), &app, &image_digest],
                )
                .map_err(internal)?
                .map(|row| -> Result<(Id, String, Id)> {
                    Ok((
                        stored_id(&row, "id")?,
                        row.try_get("phase").map_err(internal)?,
                        stored_id(&row, "attempt_id")?,
                    ))
                })
                .transpose()?;
            let now = now_unix();
            let mut stale_owner = None;
            let claim = match existing {
                Some((record_id, phase, _)) if phase == "succeeded" => {
                    let row = transaction
                        .query_one(
                            "SELECT * FROM oci_deployments WHERE id=$1",
                            &[&record_id.as_str()],
                        )
                        .map_err(internal)?;
                    OciDeploymentClaim::Replay {
                        deployment: decode_succeeded_deployment(&row)?,
                    }
                }
                Some((record_id, phase, attempt_id)) if phase == "running" => {
                    match self.try_oci_deployment_lease(attempt_id.as_str())? {
                        None => OciDeploymentClaim::AlreadyRunning {
                            record_id,
                            attempt_id,
                        },
                        Some(lease) => {
                            stale_owner = Some(lease);
                            replace_attempt(&mut transaction, self, &record_id, now)?
                        }
                    }
                }
                Some((record_id, _, _)) => {
                    replace_attempt(&mut transaction, self, &record_id, now)?
                }
                None => {
                    let record_id = generated_id(ids::OCI_DEPLOYMENT_PREFIX);
                    let attempt_id = generated_id("oci_attempt_");
                    let lease = self
                        .try_oci_deployment_lease(attempt_id.as_str())?
                        .ok_or_else(|| internal("new OCI attempt ownership lock is occupied"))?;
                    transaction
                        .execute(
                            "INSERT INTO oci_deployments
                                (id, cat_id, app, image_digest, attempt_id,
                                 phase, created_at, updated_at)
                             VALUES ($1,$2,$3,$4,$5,'running',$6,$6)",
                            &[
                                &record_id.as_str(),
                                &cat_id.as_str(),
                                &app,
                                &image_digest,
                                &attempt_id.as_str(),
                                &now,
                            ],
                        )
                        .map_err(internal)?;
                    OciDeploymentClaim::Claimed {
                        record_id,
                        attempt_id,
                        lease: Box::new(lease),
                    }
                }
            };
            transaction.commit().map_err(internal)?;
            drop(stale_owner);
            Ok(claim)
        })
    }

    pub fn succeed_oci_deployment(
        &self,
        record_id: &Id,
        attempt_id: &Id,
        deployment: &OciDeployment,
    ) -> Result<bool> {
        self.enter(|client| {
            let client = client?;
            let mut transaction = client.transaction().map_err(internal)?;
            let Some((cat_id, app)) = owned_attempt(&mut transaction, record_id, attempt_id)?
            else {
                return Ok(false);
            };
            let now = now_unix();
            transaction
                .execute(
                    "UPDATE oci_deployments
                        SET phase='superseded', active=FALSE, updated_at=$4
                      WHERE cat_id=$1 AND app=$2 AND phase='succeeded' AND id<>$3",
                    &[&cat_id, &app, &record_id.as_str(), &now],
                )
                .map_err(internal)?;
            transaction
                .execute(
                    "UPDATE oci_deployments SET
                        phase='succeeded', manifest_digest=$3, service=$4,
                        active=$5, error_json=NULL, updated_at=$6
                      WHERE id=$1 AND attempt_id=$2 AND phase='running'",
                    &[
                        &record_id.as_str(),
                        &attempt_id.as_str(),
                        &deployment.manifest_digest,
                        &deployment.service,
                        &deployment.active,
                        &now,
                    ],
                )
                .map_err(internal)?;
            transaction.commit().map_err(internal)?;
            Ok(true)
        })
    }

    pub fn fail_oci_deployment(
        &self,
        record_id: &Id,
        attempt_id: &Id,
        error: &ErrorBody,
    ) -> Result<bool> {
        let encoded = serde_json::to_string(error).map_err(internal)?;
        self.enter(|client| {
            let client = client?;
            let changed = client
                .execute(
                    "UPDATE oci_deployments SET
                    phase='failed', error_json=$3, updated_at=$4
                  WHERE id=$1 AND attempt_id=$2 AND phase='running'",
                    &[
                        &record_id.as_str(),
                        &attempt_id.as_str(),
                        &encoded,
                        &now_unix(),
                    ],
                )
                .map_err(internal)?;
            Ok(changed == 1)
        })
    }

    pub fn oci_deployment_attempt(
        &self,
        workspace_id: &Id,
        cat_id: &Id,
        attempt_id: &Id,
    ) -> Result<OciDeploymentAttempt> {
        self.enter(|client| {
            let client = client?;
            let row = client
                .query_opt(
                    "SELECT deployment.* FROM oci_deployments deployment
                   JOIN cat_records cat ON cat.cat_id=deployment.cat_id
                  WHERE cat.workspace_id=$1 AND deployment.cat_id=$2
                    AND deployment.attempt_id=$3",
                    &[
                        &workspace_id.as_str(),
                        &cat_id.as_str(),
                        &attempt_id.as_str(),
                    ],
                )
                .map_err(internal)?;
            let row = row.ok_or_else(|| ApiError::not_found("OCI deployment attempt"))?;
            decode_attempt(&row)
        })
    }

    pub fn list_oci_deployments(&self, cat_id: &Id) -> Result<Vec<OciDeployment>> {
        self.enter(|client| {
            let client = client?;
            client
                .query(
                    "SELECT * FROM oci_deployments
                      WHERE cat_id=$1 AND phase='succeeded'
                      ORDER BY app",
                    &[&cat_id.as_str()],
                )
                .map_err(internal)?
                .iter()
                .map(decode_succeeded_deployment)
                .collect()
        })
    }
}

fn replace_attempt(
    transaction: &mut postgres::Transaction<'_>,
    store: &Store,
    record_id: &Id,
    now: i64,
) -> Result<OciDeploymentClaim> {
    let attempt_id = generated_id("oci_attempt_");
    let lease = store
        .try_oci_deployment_lease(attempt_id.as_str())?
        .ok_or_else(|| internal("new OCI attempt ownership lock is occupied"))?;
    transaction
        .execute(
            "UPDATE oci_deployments SET
                phase='running', attempt_id=$2, error_json=NULL,
                manifest_digest=NULL, service=NULL, active=FALSE, updated_at=$3
              WHERE id=$1",
            &[&record_id.as_str(), &attempt_id.as_str(), &now],
        )
        .map_err(internal)?;
    Ok(OciDeploymentClaim::Claimed {
        record_id: record_id.clone(),
        attempt_id,
        lease: Box::new(lease),
    })
}

fn owned_attempt(
    transaction: &mut postgres::Transaction<'_>,
    record_id: &Id,
    attempt_id: &Id,
) -> Result<Option<(String, String)>> {
    transaction
        .query_opt(
            "SELECT cat_id, app FROM oci_deployments
              WHERE id=$1 AND attempt_id=$2 AND phase='running'
              FOR UPDATE",
            &[&record_id.as_str(), &attempt_id.as_str()],
        )
        .map(|row| row.map(|row| (row.get("cat_id"), row.get("app"))))
        .map_err(internal)
}

fn decode_attempt(row: &Row) -> Result<OciDeploymentAttempt> {
    let attempt_id = stored_id(row, "attempt_id")?;
    let phase: String = row.try_get("phase").map_err(internal)?;
    let (state, deployment, error) = match phase.as_str() {
        "running" => (OciDeploymentAttemptState::Running, None, None),
        "succeeded" => (
            OciDeploymentAttemptState::Succeeded,
            Some(decode_succeeded_deployment(row)?),
            None,
        ),
        "failed" => {
            let encoded: Option<String> = row.try_get("error_json").map_err(internal)?;
            let error = encoded
                .map(|encoded| serde_json::from_str(&encoded).map_err(internal))
                .transpose()?
                .unwrap_or_else(|| ErrorBody::new(ErrorCode::Unavailable, "OCI deployment failed"));
            (OciDeploymentAttemptState::Failed, None, Some(error))
        }
        _ => return Err(internal("OCI attempt has an invalid non-current phase")),
    };
    Ok(OciDeploymentAttempt {
        version: ContractVersion::V1,
        attempt_id,
        state,
        deployment,
        error,
    })
}

fn decode_succeeded_deployment(row: &Row) -> Result<OciDeployment> {
    let manifest_digest: Option<String> = row.try_get("manifest_digest").map_err(internal)?;
    let service: Option<String> = row.try_get("service").map_err(internal)?;
    Ok(OciDeployment {
        app: row.try_get("app").map_err(internal)?,
        image_digest: row.try_get("image_digest").map_err(internal)?,
        manifest_digest: manifest_digest
            .ok_or_else(|| internal("succeeded OCI deployment has no manifest digest"))?,
        service: service.ok_or_else(|| internal("succeeded OCI deployment has no service"))?,
        active: row.try_get("active").map_err(internal)?,
    })
}

fn stored_id(row: &Row, column: &str) -> Result<Id> {
    Id::new(row.try_get::<_, String>(column).map_err(internal)?)
        .ok_or_else(|| internal(format!("stored {column} is not a valid ID")))
}

fn generated_id(prefix: &str) -> Id {
    Id::new(new_id(prefix)).expect("generated OCI IDs are valid")
}
