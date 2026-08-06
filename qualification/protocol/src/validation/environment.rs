use crate::{CaseContract, CasePhase, EnvironmentProfile, ExecutionEnvironment};

use super::primitive::{is_scoped_id, require, require_digest, ValidationError};

pub(super) fn validate_execution_environment(
    environment: &ExecutionEnvironment,
    case: &CaseContract,
) -> Result<(), ValidationError> {
    let selected = selected_profile(case)?;
    require(
        environment.profile == selected,
        format!(
            "{} selected the wrong environment profile: expected {selected:?}",
            case.id
        ),
    )?;
    require(
        is_scoped_id(&environment.environment_id),
        "invalid environment_id",
    )?;
    require_digest(
        &environment.environment_manifest_sha256,
        "environment_manifest_sha256",
    )?;
    require(
        !environment.environment_is_production,
        "qualification environment must be explicitly non-production",
    )
}

pub(super) fn selected_profile(case: &CaseContract) -> Result<EnvironmentProfile, ValidationError> {
    match case.phase {
        CasePhase::Functional
            if case
                .environment_profiles
                .contains(&EnvironmentProfile::AwsF) =>
        {
            Ok(EnvironmentProfile::AwsF)
        }
        CasePhase::Functional if case.environment_profiles.len() == 1 => {
            let profile = case.environment_profiles[0];
            require(
                matches!(profile, EnvironmentProfile::Ci | EnvironmentProfile::Linux),
                format!("{} has no valid functional execution profile", case.id),
            )?;
            Ok(profile)
        }
        CasePhase::AwsPerformance | CasePhase::CostObservation => {
            require(
                case.environment_profiles
                    .contains(&EnvironmentProfile::AwsP),
                format!("{} has no AWS-P execution profile", case.id),
            )?;
            Ok(EnvironmentProfile::AwsP)
        }
        CasePhase::Functional => Err(ValidationError::new(format!(
            "{} functional profile selection is ambiguous",
            case.id
        ))),
    }
}
