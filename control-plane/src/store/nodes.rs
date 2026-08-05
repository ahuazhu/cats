use super::*;

impl Store {
    // ------------------------------------------------------------------
    // Nodes
    // ------------------------------------------------------------------

    pub fn register_node(
        &self,
        node_id: &str,
        agent_url: &str,
        gateway_url: &str,
        cpus: u32,
        memory_mib: u64,
    ) -> Result<()> {
        let now = now_ms();
        let cpus = cpus as i64;
        let memory_mib = memory_mib as i64;
        self.with(|client| {
            client
                .execute(
                    "INSERT INTO nodes (id, agent_url, gateway_url, state, cpus, memory_mib,
                                        last_heartbeat_ms, scheduling_disabled)
                     VALUES ($1,$2,$3,'ready',$4,$5,$6,FALSE)
                     ON CONFLICT(id) DO UPDATE SET
                       agent_url=$2, gateway_url=$3,
                       state=CASE
                           WHEN nodes.state='draining' THEN 'draining'
                           WHEN nodes.state='fenced' THEN 'fenced'
                           WHEN nodes.state='lost' THEN 'lost'
                           WHEN nodes.scheduling_disabled THEN 'cordoned'
                           ELSE 'ready'
                       END,
                       cpus=$4, memory_mib=$5, last_heartbeat_ms=$6,
                       reported_cats_json=NULL",
                    &[&node_id, &agent_url, &gateway_url, &cpus, &memory_mib, &now],
                )
                .map(|_| ())
        })
    }

    /// Record a heartbeat: telemetry plus the agent's own runtime inventory,
    /// stored verbatim so the control plane can later be compared against
    /// what the node actually runs (issue #98). Returns whether the reported
    /// inventory differs from the previous heartbeat, so callers can log
    /// changes without repeating themselves every beat.
    pub fn heartbeat_node(
        &self,
        node_id: &str,
        telemetry: Option<&NodeTelemetry>,
        reported: &[HeartbeatCat],
    ) -> Result<bool> {
        let telemetry_json = telemetry
            .map(|value| serde_json::to_string(value).expect("node telemetry must serialize"));
        // The agent's map iteration order is not stable between heartbeats;
        // sort so an unchanged inventory compares equal as a string.
        let mut reported: Vec<&HeartbeatCat> = reported.iter().collect();
        reported.sort_by(|a, b| a.cat_id.cmp(&b.cat_id));
        let reported_json = serde_json::to_string(&reported).expect("reported cats must serialize");
        self.with(|client| {
            let previous: Option<Option<String>> = client
                .query_opt(
                    "SELECT reported_cats_json FROM nodes WHERE id=$1",
                    &[&node_id],
                )?
                .map(|row| row.try_get(0))
                .transpose()?;
            let Some(previous) = previous else {
                return Ok(Err(ApiError::not_found(format!("node {node_id}"))));
            };
            client.execute(
                "UPDATE nodes SET last_heartbeat_ms=$2, telemetry_json=$3,
                        reported_cats_json=$4
                 WHERE id=$1",
                &[&node_id, &now_ms(), &telemetry_json, &reported_json],
            )?;
            Ok(Ok(previous.as_deref() != Some(reported_json.as_str())))
        })?
    }

    /// The runtime inventory the agent carried in its most recent heartbeat.
    /// Empty both for "reported nothing" and "never reported".
    pub fn reported_cats(&self, node_id: &str) -> Result<Vec<HeartbeatCat>> {
        let json: Option<String> = self
            .with(|client| {
                client
                    .query_opt(
                        "SELECT reported_cats_json FROM nodes WHERE id=$1",
                        &[&node_id],
                    )?
                    .map(|row| row.try_get(0))
                    .transpose()
            })?
            .ok_or_else(|| ApiError::not_found(format!("node {node_id}")))?;
        Ok(json
            .as_deref()
            .map(|json| serde_json::from_str(json).unwrap_or_default())
            .unwrap_or_default())
    }

    /// Reported Cats with no matching assignment on this node: the agent runs
    /// them, but no control-plane record places them here. These are exactly
    /// the runtimes every operator surface would otherwise miss (issue #98).
    pub fn orphan_reported_cats(&self, node_id: &str) -> Result<Vec<HeartbeatCat>> {
        let reported = self.reported_cats(node_id)?;
        if reported.is_empty() {
            return Ok(reported);
        }
        let assigned: std::collections::HashSet<String> = self
            .cats_on_node(node_id)?
            .into_iter()
            .map(|cat| cat.id)
            .collect();
        Ok(reported
            .into_iter()
            .filter(|hb| !assigned.contains(&hb.cat_id))
            .collect())
    }

    /// Make a reachable Lost node schedulable again after its heartbeat has
    /// proved every preserved Cat claim with a same-generation runtime entry.
    /// The state predicate makes this safe against a concurrent admin fence.
    pub fn recover_lost_node(&self, node_id: &str) -> Result<bool> {
        self.with(|client| {
            client
                .execute(
                    "UPDATE nodes
                        SET state=CASE
                                WHEN scheduling_disabled THEN 'cordoned'
                                ELSE 'ready'
                            END
                      WHERE id=$1 AND state='lost'",
                    &[&node_id],
                )
                .map(|changed| changed == 1)
        })
    }

    pub fn list_nodes(&self) -> Result<Vec<Node>> {
        self.with(|client| {
            client
                .query("SELECT * FROM nodes ORDER BY id", &[])?
                .iter()
                .map(row_to_node)
                .collect::<std::result::Result<Vec<_>, postgres::Error>>()
        })
    }

    pub fn get_node(&self, node_id: &str) -> Result<Node> {
        self.with(|client| {
            client
                .query_opt("SELECT * FROM nodes WHERE id=$1", &[&node_id])?
                .map(|row| row_to_node(&row))
                .transpose()
        })?
        .ok_or_else(|| ApiError::not_found(format!("node {node_id}")))
    }

    pub fn set_node_state(&self, node_id: &str, state: NodeState) -> Result<()> {
        let state = node_state_str(state);
        let n = self.with(|client| {
            client.execute(
                "UPDATE nodes
                    SET state=CASE
                            WHEN state='fenced' AND $2<>'fenced' THEN state
                            WHEN $2='cordoned' AND state='lost' THEN state
                            ELSE $2
                        END,
                        scheduling_disabled=CASE
                            WHEN state='fenced' THEN TRUE
                            WHEN $2='ready' THEN FALSE
                            WHEN $2 IN ('cordoned','draining','fenced') THEN TRUE
                            ELSE scheduling_disabled
                        END
                  WHERE id=$1",
                &[&node_id, &state],
            )
        })?;
        if n == 0 {
            return Err(ApiError::not_found(format!("node {node_id}")));
        }
        Ok(())
    }

    pub fn cats_on_node(&self, node_id: &str) -> Result<Vec<Cat>> {
        self.with(|client| {
            client
                .query(
                    "SELECT * FROM cats WHERE node_id=$1 ORDER BY workspace_id, name",
                    &[&node_id],
                )?
                .iter()
                .map(row_to_cat)
                .collect::<std::result::Result<Vec<_>, postgres::Error>>()
        })
    }

    pub fn node_summary(&self, node_id: &str) -> Result<NodeSummary> {
        let node = self.get_node(node_id)?;
        let cats = self.cats_on_node(node_id)?;
        let orphans = self.orphan_reported_cats(node_id)?.len() as u64;
        Ok(summarize_node(node, &cats, orphans))
    }

    pub fn list_node_summaries(&self) -> Result<Vec<NodeSummary>> {
        self.list_nodes()?
            .into_iter()
            .map(|node| {
                let cats = self.cats_on_node(&node.id)?;
                let orphans = self.orphan_reported_cats(&node.id)?.len() as u64;
                Ok(summarize_node(node, &cats, orphans))
            })
            .collect()
    }

    pub fn node_cat_summaries(&self, node_id: &str) -> Result<Vec<NodeCatSummary>> {
        let node = self.get_node(node_id)?;
        let mut actual_by_cat: HashMap<String, CatResourceTelemetry> = node
            .telemetry
            .map(|telemetry| {
                telemetry
                    .cat_resources
                    .into_iter()
                    .map(|actual| (actual.cat_id.clone(), actual))
                    .collect()
            })
            .unwrap_or_default();
        self.cats_on_node(node_id)?
            .into_iter()
            .map(|cat| {
                let requested_disk_bytes = self
                    .list_disks_for_cat(&cat.id)?
                    .into_iter()
                    .fold(0_u64, |total, disk| total.saturating_add(disk.size_bytes));
                let actual = actual_by_cat.remove(&cat.id);
                Ok(NodeCatSummary {
                    cat,
                    requested_disk_bytes,
                    actual,
                })
            })
            .collect()
    }

    pub fn delete_node(&self, node_id: &str) -> Result<()> {
        self.enter(|client| {
            let client = client?;
            let mut tx = client.transaction().map_err(internal)?;
            let assigned: i64 = tx
                .query_one("SELECT COUNT(*) FROM cats WHERE node_id=$1", &[&node_id])
                .map_err(internal)?
                .try_get(0)
                .map_err(internal)?;
            if assigned != 0 {
                return Err(ApiError::failed_precondition(
                    "node still owns Cats; drain it before deletion",
                ));
            }
            let state: Option<String> = tx
                .query_opt("SELECT state FROM nodes WHERE id=$1", &[&node_id])
                .map_err(internal)?
                .map(|row| row.try_get(0))
                .transpose()
                .map_err(internal)?;
            let state = state.ok_or_else(|| ApiError::not_found(format!("node {node_id}")))?;
            if state == "ready" || state == "draining" {
                return Err(ApiError::failed_precondition(
                    "only cordoned, lost, or fenced nodes can be deleted",
                ));
            }
            tx.execute("DELETE FROM nodes WHERE id=$1", &[&node_id])
                .map_err(internal)?;
            tx.commit().map_err(internal)
        })
    }
}
