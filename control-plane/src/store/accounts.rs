use super::*;

impl Store {
    // ------------------------------------------------------------------
    // Accounts and workspaces
    // ------------------------------------------------------------------

    /// Idempotently seed the Accounts a deployment is configured to own up
    /// front. Personal Accounts come from AuthKit onboarding instead; this is
    /// the path for self-hosted and development deployments whose Accounts map
    /// to a WorkOS Organization by static configuration.
    pub fn ensure_configured_accounts(
        &self,
        account_organizations: &BTreeMap<String, String>,
    ) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        for (account_slug, organization_id) in account_organizations {
            if account_slug.is_empty() || organization_id.is_empty() {
                continue;
            }
            ensure_configured_account(&tx, account_slug, organization_id)?;
        }
        tx.commit().map_err(internal)
    }

    /// Idempotently create the local half of a Personal Account provision.
    /// It remains hidden until the signup grant is durably applied.
    pub fn ensure_personal_account(
        &self,
        workos_user_id: &str,
        workos_organization_id: &str,
        display_name: &str,
    ) -> Result<(AccountRecord, WorkspaceRecord)> {
        if workos_user_id.is_empty() || workos_organization_id.is_empty() {
            return Err(ApiError::invalid(
                "WorkOS user and organization IDs must not be empty",
            ));
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        if let Some(account) =
            find_account_by_personal_owner(&tx, workos_user_id).map_err(internal)?
        {
            if account.workos_organization_id != workos_organization_id {
                return Err(ApiError::conflict(
                    "personal account WorkOS organization changed",
                ));
            }
            let workspace = default_workspace_for_account(&tx, &account.id)?;
            tx.commit().map_err(internal)?;
            return Ok((account, workspace));
        }

        if find_account_by_organization(&tx, workos_organization_id)
            .map_err(internal)?
            .is_some()
        {
            return Err(ApiError::conflict(
                "WorkOS organization already belongs to another Cats account",
            ));
        }
        let account_id = new_id(ids::ACCOUNT_PREFIX);
        let workspace_id = new_id(ids::WORKSPACE_PREFIX);
        let requested_slug = dns_slug(
            display_name
                .split('@')
                .next()
                .filter(|value| !value.is_empty())
                .unwrap_or("personal"),
            48,
        );
        let account_slug = unique_account_slug(&tx, &requested_slug)?;
        let billing_account_id = format!("billing_account/account/{account_id}");
        let created_at = now_unix();
        tx.execute(
            "INSERT INTO accounts (
                id, slug, display_name, kind, workos_organization_id,
                billing_account_id, personal_owner_user_id, status, created_at
             ) VALUES (?1,?2,?3,'personal',?4,?5,?6,'provisioning',?7)",
            params![
                account_id,
                account_slug,
                display_name,
                workos_organization_id,
                billing_account_id,
                workos_user_id,
                created_at
            ],
        )
        .map_err(internal)?;
        tx.execute(
            "INSERT INTO workspaces (
                id, account_id, slug, display_name, is_default, created_at
             ) VALUES (?1,?2,'default','Default',1,?3)",
            params![workspace_id, account_id, created_at],
        )
        .map_err(internal)?;
        tx.execute(
            "INSERT OR REPLACE INTO account_membership_shadow (
                workos_membership_id, account_id, workos_user_id, role_slug,
                status, updated_at
             ) VALUES (?1,?2,?3,'owner','active',?4)",
            params![
                format!("personal-owner:{workos_user_id}"),
                account_id,
                workos_user_id,
                created_at
            ],
        )
        .map_err(internal)?;
        let account = find_account_by_personal_owner(&tx, workos_user_id)
            .map_err(internal)?
            .ok_or_else(|| ApiError::internal("personal account insert was not visible"))?;
        let workspace = default_workspace_for_account(&tx, &account.id)?;
        tx.commit().map_err(internal)?;
        Ok((account, workspace))
    }

    pub fn signup_grant_state(
        &self,
        workos_user_id: &str,
        campaign: &str,
        billing_account_id: &str,
    ) -> Result<SignupGrantState> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO signup_grant_eligibility (
                workos_user_id, campaign, billing_account_id, state, created_at
             ) VALUES (?1,?2,?3,'pending',?4)",
            params![workos_user_id, campaign, billing_account_id, now_unix()],
        )
        .map_err(internal)?;
        let (beneficiary, state): (String, String) = conn
            .query_row(
                "SELECT billing_account_id, state
                   FROM signup_grant_eligibility
                  WHERE workos_user_id=?1 AND campaign=?2",
                params![workos_user_id, campaign],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(internal)?;
        if beneficiary != billing_account_id {
            return Err(ApiError::conflict(
                "signup grant beneficiary cannot be changed",
            ));
        }
        Ok(if state == "applied" {
            SignupGrantState::Applied
        } else {
            SignupGrantState::Pending
        })
    }

    pub fn mark_signup_grant_applied(
        &self,
        workos_user_id: &str,
        campaign: &str,
        billing_account_id: &str,
    ) -> Result<()> {
        self.with(|conn| {
            let changed = conn.execute(
                "UPDATE signup_grant_eligibility
                    SET state='applied', applied_at=?4
                  WHERE workos_user_id=?1 AND campaign=?2
                    AND billing_account_id=?3 AND state IN ('pending','applied')",
                params![workos_user_id, campaign, billing_account_id, now_unix()],
            )?;
            if changed == 0 {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            Ok(())
        })
    }

    pub fn activate_account(&self, account_id: &str) -> Result<()> {
        self.with(|conn| {
            let changed = conn.execute(
                "UPDATE accounts SET status='active' WHERE id=?1",
                params![account_id],
            )?;
            if changed == 0 {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            Ok(())
        })
    }

    pub fn account_for_organization(&self, organization_id: &str) -> Result<Option<AccountRecord>> {
        self.with(|conn| find_account_by_organization(conn, organization_id))
    }

    pub fn account_by_id(&self, account_id: &str) -> Result<AccountRecord> {
        let conn = self.conn.lock().unwrap();
        match conn.query_row(
            "SELECT id, slug, display_name, kind, workos_organization_id,
                        billing_account_id, personal_owner_user_id, status
                   FROM accounts WHERE id=?1",
            params![account_id],
            row_to_account,
        ) {
            Ok(account) => Ok(account),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                Err(ApiError::new(ErrorCode::NotFound, "account not found"))
            }
            Err(error) => Err(internal(error)),
        }
    }

    pub fn workspaces_for_account(&self, account_id: &str) -> Result<Vec<WorkspaceRecord>> {
        self.with(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, account_id, slug, display_name, is_default
                   FROM workspaces WHERE account_id=?1
                  ORDER BY is_default DESC, slug",
            )?;
            let rows = stmt
                .query_map(params![account_id], row_to_workspace)?
                .collect();
            rows
        })
    }

    pub fn create_workspace(
        &self,
        account_id: &str,
        slug: &str,
        display_name: &str,
    ) -> Result<WorkspaceRecord> {
        validate_workspace_slug(slug)?;
        if display_name.trim().is_empty() || display_name.len() > 100 {
            return Err(ApiError::invalid(
                "workspace display_name must be 1 to 100 characters",
            ));
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let account = tx
            .query_row(
                "SELECT id, slug, display_name, kind, workos_organization_id,
                        billing_account_id, personal_owner_user_id, status
                   FROM accounts WHERE id=?1",
                params![account_id],
                row_to_account,
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => {
                    ApiError::new(ErrorCode::NotFound, "account not found")
                }
                other => internal(other),
            })?;
        if account.status != "active" {
            return Err(ApiError::failed_precondition("account is not active"));
        }
        let workspace_id = new_id(ids::WORKSPACE_PREFIX);
        tx.execute(
            "INSERT INTO workspaces (
                id, account_id, slug, display_name, is_default, created_at
             ) VALUES (?1,?2,?3,?4,0,?5)",
            params![
                workspace_id,
                account.id,
                slug,
                display_name.trim(),
                now_unix()
            ],
        )
        .map_err(|error| {
            if is_constraint(&error) {
                ApiError::conflict("workspace slug already exists in this account")
            } else {
                internal(error)
            }
        })?;
        let workspace = tx
            .query_row(
                "SELECT id, account_id, slug, display_name, is_default
                   FROM workspaces WHERE id=?1",
                params![workspace_id],
                row_to_workspace,
            )
            .map_err(internal)?;
        tx.commit().map_err(internal)?;
        Ok(workspace)
    }

    pub fn update_workspace(
        &self,
        workspace_id: &str,
        slug: Option<&str>,
        display_name: Option<&str>,
    ) -> Result<WorkspaceRecord> {
        if slug.is_none() && display_name.is_none() {
            return Err(ApiError::invalid(
                "at least one workspace field must be supplied",
            ));
        }
        if let Some(slug) = slug {
            validate_workspace_slug(slug)?;
        }
        if display_name.is_some_and(|value| value.trim().is_empty() || value.len() > 100) {
            return Err(ApiError::invalid(
                "workspace display_name must be 1 to 100 characters",
            ));
        }
        let conn = self.conn.lock().unwrap();
        let changed = conn
            .execute(
                "UPDATE workspaces
                    SET slug=COALESCE(?2, slug),
                        display_name=COALESCE(?3, display_name)
                  WHERE id=?1",
                params![workspace_id, slug, display_name.map(str::trim)],
            )
            .map_err(|error| {
                if is_constraint(&error) {
                    ApiError::conflict("workspace slug already exists in this account")
                } else {
                    internal(error)
                }
            })?;
        if changed == 0 {
            return Err(ApiError::new(ErrorCode::NotFound, "workspace not found"));
        }
        conn.query_row(
            "SELECT id, account_id, slug, display_name, is_default
               FROM workspaces WHERE id=?1",
            params![workspace_id],
            row_to_workspace,
        )
        .map_err(internal)
    }

    pub fn workspace_scope(&self, workspace_id: &str) -> Result<WorkspaceScope> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT
                a.id, a.slug, a.display_name, a.kind,
                a.workos_organization_id, a.billing_account_id,
                a.personal_owner_user_id, a.status,
                w.id, w.account_id, w.slug, w.display_name, w.is_default
               FROM workspaces w
               JOIN accounts a ON a.id=w.account_id
              WHERE w.id=?1",
            params![workspace_id],
            |row| {
                Ok(WorkspaceScope {
                    account: row_to_account(row)?,
                    workspace: WorkspaceRecord {
                        id: row.get(8)?,
                        account_id: row.get(9)?,
                        slug: row.get(10)?,
                        display_name: row.get(11)?,
                        is_default: row.get::<_, i64>(12)? != 0,
                    },
                })
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => {
                ApiError::new(ErrorCode::NotFound, format!("workspace {workspace_id}"))
            }
            other => internal(other),
        })
    }

    pub fn workspace_by_id(&self, workspace_id: &str) -> Result<WorkspaceRecord> {
        let conn = self.conn.lock().unwrap();
        match conn.query_row(
            "SELECT id, account_id, slug, display_name, is_default
                   FROM workspaces WHERE id=?1",
            params![workspace_id],
            row_to_workspace,
        ) {
            Ok(workspace) => Ok(workspace),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                Err(ApiError::new(ErrorCode::NotFound, "workspace not found"))
            }
            Err(error) => Err(internal(error)),
        }
    }

    pub fn create_workspace_token(
        &self,
        workspace_id: &str,
        label: &str,
        token_hash: &str,
    ) -> Result<WorkspaceToken> {
        let label = label.trim();
        if label.is_empty() || label.len() > 100 {
            return Err(ApiError::invalid("token label must be 1 to 100 characters"));
        }
        self.workspace_by_id(workspace_id)?;
        let token = WorkspaceToken {
            id: new_id("wst"),
            workspace_id: workspace_id.to_string(),
            label: label.to_string(),
            created_at_unix: now_unix(),
        };
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO workspace_tokens
                (id, workspace_id, label, token_hash, created_at, revoked_at)
             VALUES (?1,?2,?3,?4,?5,NULL)",
            params![
                token.id,
                token.workspace_id,
                token.label,
                token_hash,
                token.created_at_unix
            ],
        )
        .map_err(internal)?;
        Ok(token)
    }

    pub fn active_workspace_for_token_hash(&self, token_hash: &str) -> Result<Option<String>> {
        self.with(|conn| {
            conn.query_row(
                "SELECT workspace_id FROM workspace_tokens
                  WHERE token_hash=?1 AND revoked_at IS NULL",
                params![token_hash],
                |row| row.get(0),
            )
            .optional()
        })
    }

    pub fn workspace_tokens(&self, workspace_id: &str) -> Result<Vec<WorkspaceToken>> {
        self.with(|conn| {
            let mut statement = conn.prepare(
                "SELECT id, workspace_id, label, created_at
                   FROM workspace_tokens
                  WHERE workspace_id=?1 AND revoked_at IS NULL
                  ORDER BY created_at, id",
            )?;
            let rows = statement
                .query_map(params![workspace_id], |row| {
                    Ok(WorkspaceToken {
                        id: row.get(0)?,
                        workspace_id: row.get(1)?,
                        label: row.get(2)?,
                        created_at_unix: row.get(3)?,
                    })
                })?
                .collect();
            rows
        })
    }

    pub fn revoke_workspace_token(&self, workspace_id: &str, token_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let changed = conn
            .execute(
                "UPDATE workspace_tokens SET revoked_at=?3
                  WHERE id=?1 AND workspace_id=?2 AND revoked_at IS NULL",
                params![token_id, workspace_id, now_unix()],
            )
            .map_err(internal)?;
        if changed == 0 {
            return Err(ApiError::new(
                ErrorCode::NotFound,
                "workspace token not found",
            ));
        }
        Ok(())
    }

    pub fn workspace_belongs_to_organization(
        &self,
        workspace_id: &str,
        organization_id: &str,
    ) -> Result<bool> {
        self.with(|conn| {
            conn.query_row(
                "SELECT EXISTS(
                    SELECT 1
                      FROM workspaces w
                      JOIN accounts a ON a.id=w.account_id
                     WHERE w.id=?1
                       AND a.workos_organization_id=?2
                       AND a.status='active'
                 )",
                params![workspace_id, organization_id],
                |row| row.get(0),
            )
        })
    }

    pub fn billing_account_id_for_workspace(&self, workspace_id: &str) -> Result<String> {
        Ok(self
            .workspace_scope(workspace_id)?
            .account
            .billing_account_id)
    }

    /// The single ledger that owns a Workspace's balance. Every Workspace in an
    /// Account shares that Account's Billing Account, so a Workspace is never
    /// itself a billing owner.
    pub fn billing_ledger_for_workspace(&self, workspace_id: &str) -> Result<BillingLedgerRecord> {
        let scope = self.workspace_scope(workspace_id)?;
        Ok(BillingLedgerRecord {
            billing_account_id: scope.account.billing_account_id,
            account_id: scope.account.id,
            signup_credit_nanos: if scope.account.kind == AccountKind::Personal {
                10_000_000_000
            } else {
                0
            },
        })
    }

    /// Every Workspace in the deployment, for the admin console and for machine
    /// tokens resolving an `account/workspace` locator to its immutable ID.
    pub fn list_all_workspace_views(&self) -> Result<Vec<Workspace>> {
        let accounts = self.with(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, slug, display_name, kind, workos_organization_id,
                        billing_account_id, personal_owner_user_id, status
                   FROM accounts ORDER BY slug",
            )?;
            let rows = stmt
                .query_map([], row_to_account)?
                .collect::<rusqlite::Result<Vec<_>>>();
            rows
        })?;
        let mut views = Vec::new();
        for account in accounts {
            for workspace in self.workspaces_for_account(&account.id)? {
                views.push(workspace_view(&account, workspace, None));
            }
        }
        Ok(views)
    }

    pub fn account_and_workspace_views(
        &self,
        organization_id: &str,
        role: Option<&str>,
        permissions: &[String],
    ) -> Result<Option<(Account, Vec<Workspace>)>> {
        let Some(account) = self.account_for_organization(organization_id)? else {
            return Ok(None);
        };
        if account.status != "active" {
            return Ok(None);
        }
        let workspaces = self
            .workspaces_for_account(&account.id)?
            .into_iter()
            .map(|workspace| workspace_view(&account, workspace, role))
            .collect();
        Ok(Some((
            Account {
                id: account.id.clone(),
                slug: account.slug.clone(),
                display_name: account.display_name.clone(),
                kind: account.kind,
                organization_id: account.workos_organization_id.clone(),
                billing_account_id: account.billing_account_id.clone(),
                role: role.map(str::to_string),
                permissions: permissions.to_vec(),
            },
            workspaces,
        )))
    }

    pub fn record_invitation(
        &self,
        invitation: &AccountInvitation,
        workos_organization_id: &str,
    ) -> Result<()> {
        self.with(|conn| {
            conn.execute(
                "INSERT INTO account_invitations (
                    workos_invitation_id, account_id, workos_organization_id,
                    email, role_slug, state, expires_at, updated_at
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
                 ON CONFLICT(workos_invitation_id) DO UPDATE SET
                    email=excluded.email, role_slug=excluded.role_slug,
                    state=excluded.state, expires_at=excluded.expires_at,
                    updated_at=excluded.updated_at",
                params![
                    invitation.id,
                    invitation.account_id,
                    workos_organization_id,
                    invitation.email,
                    invitation.role_slug,
                    invitation.state,
                    invitation.expires_at,
                    now_unix()
                ],
            )?;
            Ok(())
        })
    }

    pub fn upsert_membership_shadow(
        &self,
        membership_id: &str,
        account_id: &str,
        workos_user_id: &str,
        role_slug: &str,
        status: &str,
    ) -> Result<()> {
        self.with(|conn| {
            conn.execute(
                "INSERT INTO account_membership_shadow (
                    workos_membership_id, account_id, workos_user_id,
                    role_slug, status, updated_at
                 ) VALUES (?1,?2,?3,?4,?5,?6)
                 ON CONFLICT(account_id, workos_user_id) DO UPDATE SET
                    workos_membership_id=excluded.workos_membership_id,
                    role_slug=excluded.role_slug, status=excluded.status,
                    updated_at=excluded.updated_at",
                params![
                    membership_id,
                    account_id,
                    workos_user_id,
                    role_slug,
                    status,
                    now_unix()
                ],
            )?;
            Ok(())
        })
    }
}

fn find_account_by_organization(
    conn: &Connection,
    organization_id: &str,
) -> rusqlite::Result<Option<AccountRecord>> {
    conn.query_row(
        "SELECT id, slug, display_name, kind, workos_organization_id,
                billing_account_id, personal_owner_user_id, status
           FROM accounts WHERE workos_organization_id=?1",
        params![organization_id],
        row_to_account,
    )
    .optional()
}

fn find_account_by_personal_owner(
    conn: &Connection,
    workos_user_id: &str,
) -> rusqlite::Result<Option<AccountRecord>> {
    conn.query_row(
        "SELECT id, slug, display_name, kind, workos_organization_id,
                billing_account_id, personal_owner_user_id, status
           FROM accounts WHERE personal_owner_user_id=?1",
        params![workos_user_id],
        row_to_account,
    )
    .optional()
}

fn default_workspace_for_account(conn: &Connection, account_id: &str) -> Result<WorkspaceRecord> {
    conn.query_row(
        "SELECT id, account_id, slug, display_name, is_default
           FROM workspaces WHERE account_id=?1 AND is_default=1",
        params![account_id],
        row_to_workspace,
    )
    .map_err(internal)
}

fn unique_account_slug(conn: &Connection, requested: &str) -> Result<String> {
    for suffix in 0..10_000_u32 {
        let candidate = if suffix == 0 {
            requested.to_string()
        } else {
            format!("{requested}-{suffix}")
        };
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM accounts WHERE slug=?1)",
                params![candidate],
                |row| row.get(0),
            )
            .map_err(internal)?;
        if !exists {
            return Ok(candidate);
        }
    }
    Err(ApiError::conflict(
        "could not allocate a unique account slug",
    ))
}

/// Idempotently create one statically configured Organization Account and its
/// default Workspace. Called on every startup, so it must converge rather than
/// fail when the Account already exists.
fn ensure_configured_account(
    conn: &Connection,
    account_slug: &str,
    organization_id: &str,
) -> Result<()> {
    if let Some(account) = find_account_by_organization(conn, organization_id).map_err(internal)? {
        ensure_default_workspace(conn, &account.id)?;
        return Ok(());
    }
    let slug_taken: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM accounts WHERE slug=?1)",
            params![account_slug],
            |row| row.get(0),
        )
        .map_err(internal)?;
    if slug_taken {
        return Err(ApiError::conflict(format!(
            "account {account_slug} is already bound to a different WorkOS organization"
        )));
    }
    let account_id = new_id(ids::ACCOUNT_PREFIX);
    conn.execute(
        "INSERT INTO accounts (
            id, slug, display_name, kind, workos_organization_id,
            billing_account_id, status, created_at
         ) VALUES (?1,?2,?3,'organization',?4,?5,'active',?6)",
        params![
            account_id,
            account_slug,
            account_slug,
            organization_id,
            format!("billing_account/account/{account_id}"),
            now_unix()
        ],
    )
    .map_err(internal)?;
    ensure_default_workspace(conn, &account_id)
}

fn ensure_default_workspace(conn: &Connection, account_id: &str) -> Result<()> {
    let has_default: bool = conn
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM workspaces WHERE account_id=?1 AND is_default=1
             )",
            params![account_id],
            |row| row.get(0),
        )
        .map_err(internal)?;
    if has_default {
        return Ok(());
    }
    let slug = unique_workspace_slug(conn, account_id, "default")?;
    conn.execute(
        "INSERT INTO workspaces (
            id, account_id, slug, display_name, is_default, created_at
         ) VALUES (?1,?2,?3,'Default',1,?4)",
        params![new_id(ids::WORKSPACE_PREFIX), account_id, slug, now_unix()],
    )
    .map_err(internal)?;
    Ok(())
}

fn unique_workspace_slug(conn: &Connection, account_id: &str, requested: &str) -> Result<String> {
    for suffix in 0..10_000_u32 {
        let candidate = if suffix == 0 {
            requested.to_string()
        } else {
            format!("{requested}-{suffix}")
        };
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM workspaces WHERE account_id=?1 AND slug=?2
                 )",
                params![account_id, candidate],
                |row| row.get(0),
            )
            .map_err(internal)?;
        if !exists {
            return Ok(candidate);
        }
    }
    Err(ApiError::conflict(
        "could not allocate a unique workspace slug",
    ))
}

fn validate_workspace_slug(slug: &str) -> Result<()> {
    if slug.is_empty() || slug.len() > 48 || dns_slug(slug, 48) != slug || slug.starts_with('-') {
        return Err(ApiError::invalid(
            "workspace slug must be a lowercase DNS label up to 48 characters",
        ));
    }
    Ok(())
}

fn workspace_view(
    account: &AccountRecord,
    workspace: WorkspaceRecord,
    role: Option<&str>,
) -> Workspace {
    let locator = format!("{}/{}", account.slug, workspace.slug);
    Workspace {
        id: workspace.id,
        account_id: account.id.clone(),
        account_slug: account.slug.clone(),
        account_display_name: account.display_name.clone(),
        slug: workspace.slug,
        locator,
        display_name: workspace.display_name,
        kind: account.kind,
        organization_id: account.workos_organization_id.clone(),
        role: role.map(str::to_string),
        is_default: workspace.is_default,
    }
}
