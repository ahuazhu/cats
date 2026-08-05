use super::*;

impl Store {
    // ------------------------------------------------------------------
    // Endpoints / routes
    // ------------------------------------------------------------------

    pub fn create_endpoint(
        &self,
        cat: &Cat,
        name: &str,
        target_port: u16,
        protocol: &str,
        wake: WakePolicy,
    ) -> Result<Endpoint> {
        let port = target_port as i64;
        if let Some(mut endpoint) = self
            .endpoints_for_cat(&cat.id)?
            .into_iter()
            .find(|endpoint| endpoint.name == name)
        {
            if name != DEFAULT_ENDPOINT_NAME {
                return Err(ApiError::new(
                    ErrorCode::AlreadyExists,
                    "endpoint name in use",
                ));
            }
            self.with(|client| {
                client.execute(
                    "UPDATE endpoints
                        SET target_port=$2, protocol=$3, wake_policy=$4
                      WHERE id=$1",
                    &[&endpoint.id, &port, &protocol, &wake_str(wake)],
                )?;
                client.execute(
                    "UPDATE routes
                        SET target_port=$2, epoch=epoch+1
                      WHERE hostname=$1",
                    &[&endpoint.hostname, &port],
                )?;
                Ok(())
            })?;
            endpoint.target_port = target_port;
            endpoint.protocol = protocol.to_string();
            endpoint.wake_policy = wake;
            return Ok(endpoint);
        }
        let id = new_id(ids::ENDPOINT_PREFIX);
        let hostname = public_endpoint_hostname(cat, name);
        self.with(|client| {
            client.execute(
                "INSERT INTO endpoints (id, cat_id, name, hostname, target_port, protocol, wake_policy)
                 VALUES ($1,$2,$3,$4,$5,$6,$7)",
                &[
                    &id,
                    &cat.id,
                    &name,
                    &hostname,
                    &port,
                    &protocol,
                    &wake_str(wake),
                ],
            )?;
            client
                .execute(
                    "INSERT INTO routes (hostname, cat_id, node_id, gateway_url, target_port, epoch, state)
                     VALUES ($1,$2,NULL,NULL,$3,0,'unbound')",
                    &[&hostname, &cat.id, &port],
                )
                .map(|_| ())
        })
        .map_err(|e| {
            if e.code == ErrorCode::Conflict {
                ApiError::new(ErrorCode::AlreadyExists, "endpoint name in use")
            } else {
                e
            }
        })?;
        Ok(Endpoint {
            id,
            cat_id: cat.id.clone(),
            name: name.to_string(),
            hostname,
            target_port,
            protocol: protocol.to_string(),
            wake_policy: wake,
        })
    }

    pub fn endpoints_for_cat(&self, cat_id: &str) -> Result<Vec<Endpoint>> {
        self.with(|client| {
            client
                .query(
                    "SELECT * FROM endpoints WHERE cat_id=$1 ORDER BY id",
                    &[&cat_id],
                )?
                .iter()
                .map(row_to_endpoint)
                .collect::<std::result::Result<Vec<_>, postgres::Error>>()
        })
    }

    /// Publish routes for a cat now running on `node`; bumps each epoch.
    pub fn publish_routes(&self, cat_id: &str, node_id: &str, gateway_url: &str) -> Result<()> {
        self.with(|client| {
            client
                .execute(
                    "UPDATE routes SET node_id=$2, gateway_url=$3, epoch=epoch+1, state='active'
                     WHERE cat_id=$1",
                    &[&cat_id, &node_id, &gateway_url],
                )
                .map(|_| ())
        })
    }

    pub fn unbind_routes(&self, cat_id: &str) -> Result<()> {
        self.with(|client| {
            client
                .execute(
                    "UPDATE routes SET node_id=NULL, gateway_url=NULL, epoch=epoch+1, state='unbound'
                     WHERE cat_id=$1",
                    &[&cat_id],
                )
                .map(|_| ())
        })
    }

    pub fn resolve_route(&self, hostname: &str) -> Result<(RouteBinding, String)> {
        let row = self
            .with(|client| {
                client
                    .query_opt(
                        "SELECT r.hostname, r.cat_id, r.node_id, r.gateway_url, r.target_port, r.epoch,
                                r.state, e.wake_policy, c.workspace_id
                           FROM routes r
                           JOIN endpoints e ON e.hostname = r.hostname
                           JOIN cats c ON c.id = r.cat_id
                          WHERE r.hostname = $1",
                        &[&hostname],
                    )?
                    .map(|r| {
                        Ok((
                            RouteBinding {
                                hostname: r.try_get(0)?,
                                cat_id: r.try_get(1)?,
                                node_id: r.try_get::<_, Option<String>>(2)?.unwrap_or_default(),
                                gateway_url: r.try_get::<_, Option<String>>(3)?.unwrap_or_default(),
                                target_port: r.try_get::<_, i64>(4)? as u16,
                                epoch: r.try_get(5)?,
                                wake_policy: parse_wake(r.try_get::<_, &str>(7)?),
                                workspace_id: r.try_get(8)?,
                            },
                            r.try_get::<_, String>(6)?,
                        ))
                    })
                    .transpose()
            })?
            .ok_or_else(|| ApiError::not_found(format!("route {hostname}")))?;
        Ok(row)
    }
}
