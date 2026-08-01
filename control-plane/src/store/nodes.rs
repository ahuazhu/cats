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
        self.with(|c| {
            c.execute(
                "INSERT INTO nodes (id, agent_url, gateway_url, state, cpus, memory_mib,
                                    last_heartbeat_ms, scheduling_disabled)
                 VALUES (?1,?2,?3,'ready',?4,?5,?6,0)
                 ON CONFLICT(id) DO UPDATE SET
                   agent_url=?2, gateway_url=?3,
                   state=CASE
                       WHEN nodes.state='draining' THEN 'draining'
                       WHEN nodes.state='fenced' THEN 'fenced'
                       WHEN nodes.scheduling_disabled=1 THEN 'cordoned'
                       ELSE 'ready'
                   END,
                   cpus=?4, memory_mib=?5, last_heartbeat_ms=?6",
                params![
                    node_id,
                    agent_url,
                    gateway_url,
                    cpus,
                    memory_mib as i64,
                    now
                ],
            )
            .map(|_| ())
        })
    }

    pub fn heartbeat_node(&self, node_id: &str, telemetry: Option<&NodeTelemetry>) -> Result<()> {
        let telemetry_json = telemetry
            .map(|value| serde_json::to_string(value).expect("node telemetry must serialize"));
        let n = self.with(|c| {
            c.execute(
                "UPDATE nodes SET last_heartbeat_ms=?2, telemetry_json=?3,
                                  state=CASE
                                      WHEN state='lost' AND scheduling_disabled=1 THEN 'cordoned'
                                      WHEN state='lost' THEN 'ready'
                                      ELSE state
                                  END
                 WHERE id=?1",
                params![node_id, now_ms(), telemetry_json],
            )
        })?;
        if n == 0 {
            return Err(ApiError::not_found(format!("node {node_id}")));
        }
        Ok(())
    }

    pub fn list_nodes(&self) -> Result<Vec<Node>> {
        self.with(|c| {
            let mut stmt = c.prepare("SELECT * FROM nodes ORDER BY id")?;
            let rows = stmt.query_map([], row_to_node)?;
            rows.collect()
        })
    }

    pub fn get_node(&self, node_id: &str) -> Result<Node> {
        self.with(|c| {
            c.query_row(
                "SELECT * FROM nodes WHERE id=?1",
                params![node_id],
                row_to_node,
            )
            .optional()
        })?
        .ok_or_else(|| ApiError::not_found(format!("node {node_id}")))
    }

    pub fn set_node_state(&self, node_id: &str, state: NodeState) -> Result<()> {
        let state = node_state_str(state);
        let n = self.with(|c| {
            c.execute(
                "UPDATE nodes
                    SET state=CASE
                            WHEN state='fenced' AND ?2<>'fenced' THEN state
                            WHEN ?2='cordoned' AND state='lost' THEN state
                            ELSE ?2
                        END,
                        scheduling_disabled=CASE
                            WHEN state='fenced' THEN 1
                            WHEN ?2='ready' THEN 0
                            WHEN ?2 IN ('cordoned','draining','fenced') THEN 1
                            ELSE scheduling_disabled
                        END
                  WHERE id=?1",
                params![node_id, state],
            )
        })?;
        if n == 0 {
            return Err(ApiError::not_found(format!("node {node_id}")));
        }
        Ok(())
    }

    pub fn cats_on_node(&self, node_id: &str) -> Result<Vec<Cat>> {
        self.with(|c| {
            let mut stmt =
                c.prepare("SELECT * FROM cats WHERE node_id=?1 ORDER BY workspace_id, name")?;
            let rows = stmt.query_map(params![node_id], row_to_cat)?;
            rows.collect()
        })
    }

    pub fn node_summary(&self, node_id: &str) -> Result<NodeSummary> {
        let node = self.get_node(node_id)?;
        let cats = self.cats_on_node(node_id)?;
        Ok(summarize_node(node, &cats))
    }

    pub fn list_node_summaries(&self) -> Result<Vec<NodeSummary>> {
        self.list_nodes()?
            .into_iter()
            .map(|node| {
                let cats = self.cats_on_node(&node.id)?;
                Ok(summarize_node(node, &cats))
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
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let assigned: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM cats WHERE node_id=?1",
                params![node_id],
                |row| row.get(0),
            )
            .map_err(internal)?;
        if assigned != 0 {
            return Err(ApiError::failed_precondition(
                "node still owns Cats; drain it before deletion",
            ));
        }
        let state: Option<String> = tx
            .query_row(
                "SELECT state FROM nodes WHERE id=?1",
                params![node_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(internal)?;
        let state = state.ok_or_else(|| ApiError::not_found(format!("node {node_id}")))?;
        if state == "ready" || state == "draining" {
            return Err(ApiError::failed_precondition(
                "only cordoned, lost, or fenced nodes can be deleted",
            ));
        }
        tx.execute("DELETE FROM nodes WHERE id=?1", params![node_id])
            .map_err(internal)?;
        tx.commit().map_err(internal)
    }
}
