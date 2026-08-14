use std::time::Instant;

use aws_config::SdkConfig;
use cats_api::runtime_reconciliation::ProviderScope;

/// Closed startup failures while proving that AWS clients address the exact
/// provisioned provider scope. STS is only a verifier: it never supplies
/// authority fields or replaces the configured [`ProviderScope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AwsProviderBindingError {
    DeadlineExceeded,
    ScopeMismatch,
    InvalidResponse,
    Unavailable,
}

/// Capability proving that an AWS SDK configuration matches a provisioned
/// partition/account/region. Production S3 and EC2 adapters can only be
/// constructed through this marker; raw clients cannot bypass the check.
#[derive(Clone)]
pub struct VerifiedAwsProviderBinding {
    sdk_config: SdkConfig,
    provider_scope: ProviderScope,
}

impl VerifiedAwsProviderBinding {
    pub async fn establish(
        sdk_config: &SdkConfig,
        expected: &ProviderScope,
        absolute_deadline: Instant,
    ) -> Result<Self, AwsProviderBindingError> {
        let configured_region = sdk_config
            .region()
            .map(|region| region.as_ref())
            .ok_or(AwsProviderBindingError::ScopeMismatch)?;
        if expected.provider.as_str() != "aws" || configured_region != expected.region.as_str() {
            return Err(AwsProviderBindingError::ScopeMismatch);
        }

        let remaining = absolute_deadline
            .checked_duration_since(Instant::now())
            .ok_or(AwsProviderBindingError::DeadlineExceeded)?;
        let response = tokio::time::timeout(
            remaining,
            aws_sdk_sts::Client::new(sdk_config)
                .get_caller_identity()
                .send(),
        )
        .await
        .map_err(|_| AwsProviderBindingError::DeadlineExceeded)?
        .map_err(|_| AwsProviderBindingError::Unavailable)?;
        let account = response
            .account()
            .ok_or(AwsProviderBindingError::InvalidResponse)?;
        let arn = response
            .arn()
            .ok_or(AwsProviderBindingError::InvalidResponse)?;
        validate_resolved_identity(expected, configured_region, account, arn)?;

        Ok(Self {
            sdk_config: sdk_config.clone(),
            provider_scope: expected.clone(),
        })
    }

    pub fn provider_scope(&self) -> &ProviderScope {
        &self.provider_scope
    }

    pub(crate) fn s3_client(&self) -> aws_sdk_s3::Client {
        aws_sdk_s3::Client::new(&self.sdk_config)
    }

    pub(crate) fn ec2_client(&self) -> aws_sdk_ec2::Client {
        aws_sdk_ec2::Client::new(&self.sdk_config)
    }
}

fn validate_resolved_identity(
    expected: &ProviderScope,
    configured_region: &str,
    account: &str,
    arn: &str,
) -> Result<(), AwsProviderBindingError> {
    let mut parts = arn.splitn(6, ':');
    let arn_prefix = parts.next();
    let partition = parts.next();
    let service = parts.next();
    let arn_region = parts.next();
    let arn_account = parts.next();
    let resource = parts.next();
    if arn_prefix != Some("arn")
        || !matches!(service, Some("iam" | "sts"))
        || arn_region != Some("")
        || resource.is_none_or(str::is_empty)
        || configured_region != expected.region.as_str()
        || partition != Some(expected.partition.as_str())
        || account != expected.account_id.as_str()
        || arn_account != Some(account)
    {
        return Err(AwsProviderBindingError::ScopeMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use cats_api::runtime_reconciliation::{Id, ProviderScope};

    use super::{validate_resolved_identity, AwsProviderBindingError};

    fn id(value: &str) -> Id {
        Id::new(value).expect("test Id")
    }

    fn scope() -> ProviderScope {
        ProviderScope {
            provider: id("aws"),
            partition: id("aws-us-gov"),
            account_id: id("123456789012"),
            region: id("us-gov-west-1"),
        }
    }

    #[test]
    fn exact_partition_account_and_region_are_required() {
        let expected = scope();
        assert_eq!(
            validate_resolved_identity(
                &expected,
                "us-gov-west-1",
                "123456789012",
                "arn:aws-us-gov:sts::123456789012:assumed-role/gateway/session",
            ),
            Ok(())
        );
        for (region, account, arn) in [
            (
                "us-gov-east-1",
                "123456789012",
                "arn:aws-us-gov:sts::123456789012:assumed-role/gateway/session",
            ),
            (
                "us-gov-west-1",
                "999999999999",
                "arn:aws-us-gov:sts::999999999999:assumed-role/gateway/session",
            ),
            (
                "us-gov-west-1",
                "123456789012",
                "arn:aws:sts::123456789012:assumed-role/gateway/session",
            ),
        ] {
            assert_eq!(
                validate_resolved_identity(&expected, region, account, arn),
                Err(AwsProviderBindingError::ScopeMismatch)
            );
        }
    }

    #[test]
    fn malformed_or_cross_account_arns_fail_closed() {
        let expected = scope();
        for arn in [
            "not-an-arn",
            "arn:aws-us-gov:s3::123456789012:bucket/example",
            "arn:aws-us-gov:sts:us-gov-west-1:123456789012:assumed-role/gateway/session",
            "arn:aws-us-gov:sts::999999999999:assumed-role/gateway/session",
            "arn:aws-us-gov:sts::123456789012:",
        ] {
            assert_eq!(
                validate_resolved_identity(&expected, "us-gov-west-1", "123456789012", arn,),
                Err(AwsProviderBindingError::ScopeMismatch)
            );
        }
    }
}
