use postgres::Transaction;

pub(super) trait SemanticPlacementStrategy {
    fn select_running_node(
        &self,
        transaction: &mut Transaction<'_>,
        excluded_node_id: Option<&str>,
    ) -> Result<Option<String>, postgres::Error>;
}

#[derive(Debug, Clone, Copy)]
pub(super) struct LeastAllocatedPlacement;

impl SemanticPlacementStrategy for LeastAllocatedPlacement {
    /// Serializes fleet placement across Control replicas, then selects the
    /// running Node with the least committed semantic load. An in-progress
    /// action reserves its target immediately through
    /// `current_action_node_id`; otherwise the stable `node_id` is the
    /// reservation. Heartbeat telemetry is diagnostic and deliberately does
    /// not participate in this authority decision.
    fn select_running_node(
        &self,
        transaction: &mut Transaction<'_>,
        excluded_node_id: Option<&str>,
    ) -> Result<Option<String>, postgres::Error> {
        transaction.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended(
                current_schema() || ':semantic-placement', 0::BIGINT))",
            &[],
        )?;
        transaction
            .query_opt(
                "WITH placement_load AS (
                    SELECT COALESCE(current_action_node_id, node_id) AS effective_node_id,
                           SUM(cpu_count) AS assigned_vcpus,
                           SUM(memory_bytes) AS assigned_memory_bytes,
                           COUNT(*) AS assigned_cats
                      FROM cats
                     WHERE destroyed_at IS NULL
                       AND COALESCE(current_action_node_id, node_id) IS NOT NULL
                     GROUP BY COALESCE(current_action_node_id, node_id)
                 )
                 SELECT node.node_id
                   FROM nodes node
                   LEFT JOIN placement_load load
                     ON load.effective_node_id=node.node_id
                  WHERE node.status='running'
                    AND ($1::TEXT IS NULL OR node.node_id<>$1)
                  ORDER BY COALESCE(load.assigned_vcpus, 0),
                           COALESCE(load.assigned_memory_bytes, 0),
                           COALESCE(load.assigned_cats, 0),
                           node.node_id COLLATE \"C\"
                  LIMIT 1
                  FOR SHARE OF node",
                &[&excluded_node_id],
            )
            .map(|row| row.map(|row| row.get(0)))
    }
}
