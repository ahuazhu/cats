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
    let user_id = user_id.to_string();
    let grant_user_id = user_id.clone();
    let provision_user_id = user_id.clone();
    let display_name = display_name.to_string();
    let (account, grant_state) = state
        .store
        .execute(move |store| {
            let (account, _) = store.ensure_personal_account(
                &provision_user_id,
                &organization_id,
                &display_name,
            )?;
            let grant_state = store.signup_grant_state(
                &provision_user_id,
                SIGNUP_CAMPAIGN,
                &account.billing_account_id,
            )?;
            Ok((account, grant_state))
        })
        .await?;
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
        let billing_account_id = account.billing_account_id.clone();
        state
            .store
            .execute(move |store| {
                store.mark_signup_grant_applied(
                    &grant_user_id,
                    SIGNUP_CAMPAIGN,
                    &billing_account_id,
                )
            })
            .await?;
    }
    let account_id = account.id;
    state
        .store
        .execute(move |store| {
            store.activate_account(&account_id)?;
            store.account_by_id(&account_id)
        })
        .await
}
