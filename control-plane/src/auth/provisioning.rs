use super::*;

pub async fn provision_personal_account(
    state: &AppState,
    user_id: &str,
    display_name: &str,
) -> Result<crate::store::AccountRecord, ApiError> {
    let config = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let organization_id = config
        .ensure_personal_organization(user_id, display_name)
        .await?;
    let (account, _workspace) =
        state
            .store
            .ensure_personal_account(user_id, &organization_id, display_name)?;
    let grant_state =
        state
            .store
            .signup_grant_state(user_id, SIGNUP_CAMPAIGN, &account.billing_account_id)?;
    if grant_state == crate::store::SignupGrantState::Pending {
        state
            .credits
            .ensure_account(
                &account.billing_account_id,
                &account.id,
                "USD",
                SIGNUP_CREDIT_NANOS,
                crate::store::now_ms(),
            )
            .await
            .map_err(|error| {
                tracing::warn!(
                    error = %error,
                    user_id,
                    billing_account_id = account.billing_account_id,
                    "personal signup grant failed"
                );
                ApiError::unavailable("personal account credit is temporarily unavailable")
            })?;
        state.store.mark_signup_grant_applied(
            user_id,
            SIGNUP_CAMPAIGN,
            &account.billing_account_id,
        )?;
    }
    state.store.activate_account(&account.id)?;
    state.store.account_by_id(&account.id)
}
