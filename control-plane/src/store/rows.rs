use super::*;

// ---------------------------------------------------------------------------
// Row mappers and enum codecs
// ---------------------------------------------------------------------------
//
// Column type mapping from the schema: BIGINT reads as i64 and is cast to the
// narrower unsigned field where the API type demands it; BOOLEAN reads as
// bool directly.

pub(super) type RowResult<T> = std::result::Result<T, postgres::Error>;

pub(super) fn desired_str(d: DesiredState) -> &'static str {
    match d {
        DesiredState::Running => "running",
        DesiredState::Suspended => "suspended",
        DesiredState::Warm => "warm",
        DesiredState::Cold => "cold",
        DesiredState::Deleted => "deleted",
    }
}

pub fn parse_desired(s: &str) -> DesiredState {
    match s {
        "running" => DesiredState::Running,
        "suspended" => DesiredState::Suspended,
        "warm" => DesiredState::Warm,
        "deleted" => DesiredState::Deleted,
        _ => DesiredState::Cold,
    }
}

pub(super) fn observed_str(o: ObservedState) -> &'static str {
    match o {
        ObservedState::Creating => "creating",
        ObservedState::Starting => "starting",
        ObservedState::Running => "running",
        ObservedState::Suspending => "suspending",
        ObservedState::Suspended => "suspended",
        ObservedState::Warming => "warming",
        ObservedState::Warm => "warm",
        ObservedState::Stopping => "stopping",
        ObservedState::Cold => "cold",
        ObservedState::Failed => "failed",
        ObservedState::Deleted => "deleted",
        ObservedState::Unknown => "unknown",
    }
}

pub fn parse_observed(s: &str) -> ObservedState {
    match s {
        "creating" => ObservedState::Creating,
        "starting" => ObservedState::Starting,
        "running" => ObservedState::Running,
        "suspending" => ObservedState::Suspending,
        "suspended" => ObservedState::Suspended,
        "warming" => ObservedState::Warming,
        "warm" => ObservedState::Warm,
        "stopping" => ObservedState::Stopping,
        "failed" => ObservedState::Failed,
        "deleted" => ObservedState::Deleted,
        "unknown" => ObservedState::Unknown,
        _ => ObservedState::Cold,
    }
}

pub(super) fn disk_state_str(s: DiskState) -> &'static str {
    match s {
        DiskState::Creating => "creating",
        DiskState::Available => "available",
        DiskState::Bound => "bound",
        DiskState::Deleting => "deleting",
        DiskState::Deleted => "deleted",
    }
}

pub(super) fn node_state_str(s: NodeState) -> &'static str {
    match s {
        NodeState::Ready => "ready",
        NodeState::Cordoned => "cordoned",
        NodeState::Draining => "draining",
        NodeState::Lost => "lost",
        NodeState::Fenced => "fenced",
    }
}

pub(super) fn wake_str(w: WakePolicy) -> &'static str {
    match w {
        WakePolicy::WakeOnRequest => "wake_on_request",
        WakePolicy::NoWake => "no_wake",
    }
}

pub fn parse_wake(s: &str) -> WakePolicy {
    if s == "no_wake" {
        WakePolicy::NoWake
    } else {
        WakePolicy::WakeOnRequest
    }
}

pub(super) fn row_to_cat(r: &postgres::Row) -> RowResult<Cat> {
    Ok(Cat {
        id: r.try_get("id")?,
        workspace_id: r.try_get("workspace_id")?,
        name: r.try_get("name")?,
        image: r.try_get("image")?,
        spec: CatSpec {
            cpus: r.try_get::<_, i64>("cpus")? as u32,
            memory_mib: r.try_get::<_, i64>("memory_mib")? as u64,
        },
        root_disk_id: r.try_get("root_disk_id")?,
        desired_state: parse_desired(r.try_get::<_, &str>("desired_state")?),
        observed_state: parse_observed(r.try_get::<_, &str>("observed_state")?),
        generation: r.try_get("generation")?,
        auto_suspend: r.try_get("auto_suspend")?,
        node_id: r.try_get("node_id")?,
        created_at_unix: r.try_get("created_at")?,
        observed_state_since_unix_ms: r.try_get("observed_state_since_ms")?,
        expires_at_unix: r.try_get("expires_at_unix")?,
    })
}

pub(super) fn row_to_work_lease(r: &postgres::Row) -> RowResult<WorkLease> {
    Ok(WorkLease {
        id: r.try_get(0)?,
        cat_id: r.try_get(1)?,
        kind: parse_work_kind(r.try_get::<_, &str>(2)?),
        owner_id: r.try_get(3)?,
        label: r.try_get(4)?,
        expires_at_unix_ms: r.try_get(5)?,
    })
}

pub(super) fn work_kind_str(kind: WorkKind) -> &'static str {
    match kind {
        WorkKind::Gateway => "gateway",
        WorkKind::Exec => "exec",
        WorkKind::Guest => "guest",
        WorkKind::Pin => "pin",
        WorkKind::Control => "control",
    }
}

pub(super) fn parse_work_kind(kind: &str) -> WorkKind {
    match kind {
        "gateway" => WorkKind::Gateway,
        "exec" => WorkKind::Exec,
        "guest" => WorkKind::Guest,
        "pin" => WorkKind::Pin,
        _ => WorkKind::Control,
    }
}

pub(super) fn row_to_disk(r: &postgres::Row) -> RowResult<Disk> {
    let kind: String = r.try_get("kind")?;
    let state: String = r.try_get("state")?;
    Ok(Disk {
        id: r.try_get("id")?,
        workspace_id: r.try_get("workspace_id")?,
        name: r.try_get("name")?,
        kind: if kind == "root" {
            DiskKind::Root
        } else {
            DiskKind::Persistent
        },
        size_bytes: r.try_get::<_, i64>("size_bytes")? as u64,
        state: match state.as_str() {
            "creating" => DiskState::Creating,
            "bound" => DiskState::Bound,
            "deleting" => DiskState::Deleting,
            "deleted" => DiskState::Deleted,
            _ => DiskState::Available,
        },
        durability: DiskDurability::parse(r.try_get::<_, &str>("durability")?)
            .unwrap_or(DiskDurability::Strict),
        volume_id: r.try_get("volume_id")?,
        bound_cat_id: None,
        created_at_unix: r.try_get("created_at")?,
    })
}

pub(super) fn row_to_node(r: &postgres::Row) -> RowResult<Node> {
    let state: String = r.try_get("state")?;
    let telemetry_json: Option<String> = r.try_get("telemetry_json")?;
    Ok(Node {
        id: r.try_get("id")?,
        agent_url: r.try_get("agent_url")?,
        gateway_url: r.try_get("gateway_url")?,
        state: match state.as_str() {
            "cordoned" => NodeState::Cordoned,
            "draining" => NodeState::Draining,
            "lost" => NodeState::Lost,
            "fenced" => NodeState::Fenced,
            _ => NodeState::Ready,
        },
        capacity: NodeCapacity {
            cpus: r.try_get::<_, i64>("cpus")? as u32,
            memory_mib: r.try_get::<_, i64>("memory_mib")? as u64,
        },
        last_heartbeat_unix: r.try_get::<_, i64>("last_heartbeat_ms")? / 1000,
        telemetry: telemetry_json.and_then(|json| serde_json::from_str(&json).ok()),
    })
}

pub(super) fn summarize_node(node: Node, cats: &[Cat], orphan_cats: u64) -> NodeSummary {
    let assigned_cpus = cats.iter().map(|cat| cat.spec.cpus).sum();
    let assigned_memory_mib = cats.iter().map(|cat| cat.spec.memory_mib).sum();
    NodeSummary {
        heartbeat_age_seconds: now_unix()
            .saturating_sub(node.last_heartbeat_unix)
            .try_into()
            .unwrap_or(0),
        node,
        assigned_cats: cats.len() as u64,
        assigned_cpus,
        assigned_memory_mib,
        orphan_cats,
    }
}

pub(super) fn row_to_operation(r: &postgres::Row) -> RowResult<Operation> {
    let phase: String = r.try_get("phase")?;
    let err_json: Option<String> = r.try_get("error_json")?;
    Ok(Operation {
        id: r.try_get("id")?,
        workspace_id: r.try_get("workspace_id")?,
        kind: r.try_get("kind")?,
        resource_id: r.try_get("resource_id")?,
        resource_generation: r.try_get("resource_generation")?,
        phase: match phase.as_str() {
            "running" => OperationPhase::Running,
            "succeeded" => OperationPhase::Succeeded,
            "failed" => OperationPhase::Failed,
            _ => OperationPhase::Pending,
        },
        error: err_json.and_then(|j| serde_json::from_str(&j).ok()),
        created_at_unix: r.try_get("created_at")?,
        updated_at_unix: r.try_get("updated_at")?,
    })
}

/// `None` while the deployment has not succeeded: a running or failed record
/// has no manifest digest or service name yet, and inventing one would let a
/// caller read an unfinished deploy as a result.
pub(super) fn row_to_oci_deployment(r: &postgres::Row) -> RowResult<Option<OciDeployment>> {
    let manifest_digest: Option<String> = r.try_get("manifest_digest")?;
    let service: Option<String> = r.try_get("service")?;
    let (Some(manifest_digest), Some(service)) = (manifest_digest, service) else {
        return Ok(None);
    };
    Ok(Some(OciDeployment {
        app: r.try_get("app")?,
        image_digest: r.try_get("image_digest")?,
        manifest_digest,
        service,
        active: r.try_get("active")?,
    }))
}

pub(super) fn row_to_endpoint(r: &postgres::Row) -> RowResult<Endpoint> {
    Ok(Endpoint {
        id: r.try_get("id")?,
        cat_id: r.try_get("cat_id")?,
        name: r.try_get("name")?,
        hostname: r.try_get("hostname")?,
        target_port: r.try_get::<_, i64>("target_port")? as u16,
        protocol: r.try_get("protocol")?,
        wake_policy: parse_wake(r.try_get::<_, &str>("wake_policy")?),
    })
}

pub(super) fn row_to_account(row: &postgres::Row) -> RowResult<AccountRecord> {
    let kind = match row.try_get::<_, &str>(3)? {
        "personal" => AccountKind::Personal,
        _ => AccountKind::Organization,
    };
    Ok(AccountRecord {
        id: row.try_get(0)?,
        slug: row.try_get(1)?,
        display_name: row.try_get(2)?,
        kind,
        workos_organization_id: row.try_get(4)?,
        billing_account_id: row.try_get(5)?,
        personal_owner_user_id: row.try_get(6)?,
        status: row.try_get(7)?,
    })
}

pub(super) fn row_to_workspace(row: &postgres::Row) -> RowResult<WorkspaceRecord> {
    Ok(WorkspaceRecord {
        id: row.try_get(0)?,
        account_id: row.try_get(1)?,
        slug: row.try_get(2)?,
        display_name: row.try_get(3)?,
        is_default: row.try_get(4)?,
    })
}
