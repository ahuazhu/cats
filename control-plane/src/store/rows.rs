use super::*;

// ---------------------------------------------------------------------------
// Row mappers and enum codecs
// ---------------------------------------------------------------------------

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

pub(super) fn row_to_cat(r: &rusqlite::Row<'_>) -> rusqlite::Result<Cat> {
    Ok(Cat {
        id: r.get("id")?,
        workspace_id: r.get("workspace_id")?,
        name: r.get("name")?,
        image: r.get("image")?,
        spec: CatSpec {
            cpus: r.get("cpus")?,
            memory_mib: r.get::<_, i64>("memory_mib")? as u64,
        },
        root_disk_id: r.get("root_disk_id")?,
        desired_state: parse_desired(&r.get::<_, String>("desired_state")?),
        observed_state: parse_observed(&r.get::<_, String>("observed_state")?),
        generation: r.get("generation")?,
        auto_suspend: r.get::<_, i64>("auto_suspend")? != 0,
        node_id: r.get("node_id")?,
        created_at_unix: r.get("created_at")?,
        observed_state_since_unix_ms: r.get("observed_state_since_ms")?,
        expires_at_unix: r.get("expires_at_unix")?,
    })
}

pub(super) fn row_to_work_lease(r: &rusqlite::Row<'_>) -> rusqlite::Result<WorkLease> {
    Ok(WorkLease {
        id: r.get(0)?,
        cat_id: r.get(1)?,
        kind: parse_work_kind(&r.get::<_, String>(2)?),
        owner_id: r.get(3)?,
        label: r.get(4)?,
        expires_at_unix_ms: r.get(5)?,
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

pub(super) fn row_to_disk(r: &rusqlite::Row<'_>) -> rusqlite::Result<Disk> {
    let kind: String = r.get("kind")?;
    let state: String = r.get("state")?;
    Ok(Disk {
        id: r.get("id")?,
        workspace_id: r.get("workspace_id")?,
        name: r.get("name")?,
        kind: if kind == "root" {
            DiskKind::Root
        } else {
            DiskKind::Persistent
        },
        size_bytes: r.get::<_, i64>("size_bytes")? as u64,
        state: match state.as_str() {
            "creating" => DiskState::Creating,
            "bound" => DiskState::Bound,
            "deleting" => DiskState::Deleting,
            "deleted" => DiskState::Deleted,
            _ => DiskState::Available,
        },
        durability: DiskDurability::parse(&r.get::<_, String>("durability")?)
            .unwrap_or(DiskDurability::Strict),
        volume_id: r.get("volume_id")?,
        bound_cat_id: None,
        created_at_unix: r.get("created_at")?,
    })
}

pub(super) fn row_to_node(r: &rusqlite::Row<'_>) -> rusqlite::Result<Node> {
    let state: String = r.get("state")?;
    let telemetry_json: Option<String> = r.get("telemetry_json")?;
    Ok(Node {
        id: r.get("id")?,
        agent_url: r.get("agent_url")?,
        gateway_url: r.get("gateway_url")?,
        state: match state.as_str() {
            "cordoned" => NodeState::Cordoned,
            "draining" => NodeState::Draining,
            "lost" => NodeState::Lost,
            "fenced" => NodeState::Fenced,
            _ => NodeState::Ready,
        },
        capacity: NodeCapacity {
            cpus: r.get("cpus")?,
            memory_mib: r.get::<_, i64>("memory_mib")? as u64,
        },
        last_heartbeat_unix: r.get::<_, i64>("last_heartbeat_ms")? / 1000,
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

pub(super) fn row_to_operation(r: &rusqlite::Row<'_>) -> rusqlite::Result<Operation> {
    let phase: String = r.get("phase")?;
    let err_json: Option<String> = r.get("error_json")?;
    Ok(Operation {
        id: r.get("id")?,
        workspace_id: r.get("workspace_id")?,
        kind: r.get("kind")?,
        resource_id: r.get("resource_id")?,
        resource_generation: r.get("resource_generation")?,
        phase: match phase.as_str() {
            "running" => OperationPhase::Running,
            "succeeded" => OperationPhase::Succeeded,
            "failed" => OperationPhase::Failed,
            _ => OperationPhase::Pending,
        },
        error: err_json.and_then(|j| serde_json::from_str(&j).ok()),
        created_at_unix: r.get("created_at")?,
        updated_at_unix: r.get("updated_at")?,
    })
}

/// `None` while the deployment has not succeeded: a running or failed record
/// has no manifest digest or service name yet, and inventing one would let a
/// caller read an unfinished deploy as a result.
pub(super) fn row_to_oci_deployment(
    r: &rusqlite::Row<'_>,
) -> rusqlite::Result<Option<OciDeployment>> {
    let manifest_digest: Option<String> = r.get("manifest_digest")?;
    let service: Option<String> = r.get("service")?;
    let (Some(manifest_digest), Some(service)) = (manifest_digest, service) else {
        return Ok(None);
    };
    Ok(Some(OciDeployment {
        app: r.get("app")?,
        image_digest: r.get("image_digest")?,
        manifest_digest,
        service,
        active: r.get::<_, i64>("active")? != 0,
    }))
}

pub(super) fn row_to_endpoint(r: &rusqlite::Row<'_>) -> rusqlite::Result<Endpoint> {
    Ok(Endpoint {
        id: r.get("id")?,
        cat_id: r.get("cat_id")?,
        name: r.get("name")?,
        hostname: r.get("hostname")?,
        target_port: r.get("target_port")?,
        protocol: r.get("protocol")?,
        wake_policy: parse_wake(&r.get::<_, String>("wake_policy")?),
    })
}

pub(super) fn row_to_account(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccountRecord> {
    let kind = match row.get::<_, String>(3)?.as_str() {
        "personal" => AccountKind::Personal,
        _ => AccountKind::Organization,
    };
    Ok(AccountRecord {
        id: row.get(0)?,
        slug: row.get(1)?,
        display_name: row.get(2)?,
        kind,
        workos_organization_id: row.get(4)?,
        billing_account_id: row.get(5)?,
        personal_owner_user_id: row.get(6)?,
        status: row.get(7)?,
    })
}

pub(super) fn row_to_workspace(row: &rusqlite::Row<'_>) -> rusqlite::Result<WorkspaceRecord> {
    Ok(WorkspaceRecord {
        id: row.get(0)?,
        account_id: row.get(1)?,
        slug: row.get(2)?,
        display_name: row.get(3)?,
        is_default: row.get(4)?,
    })
}
