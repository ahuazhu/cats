mock_provider "aws" {}

override_data {
  target = data.aws_partition.current
  values = { partition = "aws" }
}

override_data {
  target = data.aws_caller_identity.current
  values = {
    account_id = "123456789012"
    arn        = "arn:aws:iam::123456789012:role/offline-fixture"
    user_id    = "offline-fixture"
  }
}

override_data {
  target = data.aws_region.current
  values = { region = "us-east-1" }
}

override_resource {
  target          = aws_sns_topic.alerts
  override_during = plan
  values = {
    arn  = "arn:aws:sns:us-east-1:123456789012:cats-production-alerts"
    name = "cats-production-alerts"
  }
}

override_module {
  target = module.network
  outputs = {
    vpc_id             = "vpc-0123456789abcdef0"
    public_subnet_ids  = ["subnet-00000000000000001", "subnet-00000000000000002"]
    private_subnet_ids = ["subnet-00000000000000003", "subnet-00000000000000004"]
    nat_public_ips     = ["192.0.2.1", "192.0.2.2"]
  }
}

override_module {
  target = module.cluster
  outputs = {
    cluster_name              = "cats-production"
    cluster_arn               = "arn:aws:eks:us-east-1:123456789012:cluster/cats-production"
    cluster_endpoint          = "https://cluster.example.invalid"
    cluster_security_group_id = "sg-0123456789abcdef0"
    node_role_name            = "cats-production-node"
  }
}

override_module {
  target = module.database
  outputs = {
    endpoint                               = "cats.fixture.us-east-1.rds.amazonaws.com:5432"
    proxy_endpoint                         = "cats.proxy-fixture.us-east-1.rds.amazonaws.com"
    database_name                          = "cats"
    master_username                        = "cats"
    master_user_secret_arn                 = "arn:aws:secretsmanager:us-east-1:123456789012:secret:cats-fixture"
    postgresql_log_group_name              = "/aws/rds/instance/cats-fixture/postgresql"
    proxy_connection_setup_alarm_name      = "cats-production-proxy-connection-setup-failed"
    proxy_client_authentication_alarm_name = "cats-production-proxy-client-authentication-failed"
    proxy_pool_saturation_alarm_name       = "cats-production-proxy-pool-saturation"
  }
}

override_module {
  target = module.dns
  outputs = {
    zone_id         = "Z00000000000000000001"
    name_servers    = ["ns-1.example.invalid", "ns-2.example.invalid"]
    certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/11111111-2222-3333-4444-555555555555"
  }
}

override_module {
  target = module.github_release
  outputs = {
    release_role_arn  = "arn:aws:iam::123456789012:role/cats-production-github-release"
    release_role_name = "cats-production-github-release"
  }
}

override_data {
  target = data.aws_iam_policy_document.github_application_deploy
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

override_data {
  target = data.aws_iam_policy_document.chunkstore_tls_only
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

override_data {
  target = data.aws_iam_policy_document.metal_worker_assume
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

override_data {
  target = data.aws_iam_policy_document.metal_worker_chunkstore
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

override_data {
  target = data.aws_iam_policy_document.object_write_gateway_assume
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

override_data {
  target = data.aws_iam_policy_document.object_write_gateway_chunkstore
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

override_data {
  target = data.aws_iam_policy_document.host_fence_provider_assume
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

override_data {
  target = data.aws_iam_policy_document.host_fence_provider
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

override_data {
  target = data.aws_iam_policy_document.efs_csi_assume
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

override_data {
  target = data.aws_iam_policy_document.efs_csi_static
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

variables {
  expected_account_id = "123456789012"
  alert_email_recipients = {
    primary_oncall = "sentinel-recipient-e5@example.invalid"
  }
  github_actions_application_state_bucket_arn = "arn:aws:s3:::cats-production-state-fixture"
  chunkstore_bucket_name                      = "cats-production-chunkstore-fixture"
  chunkstore_prefix                           = "cats-fresh"
  metal_worker_ami                            = "ami-0123456789abcdef0"
}

run "uses_only_opaque_recipient_addresses" {
  command = plan

  assert {
    condition = (
      length(aws_sns_topic_subscription.alert_email) == 1 &&
      contains(keys(aws_sns_topic_subscription.alert_email), "primary_oncall")
    )
    error_message = "subscription resource addresses must use only the opaque recipient ID"
  }

  assert {
    condition = (
      output.alert_sns_topic_arn == "arn:aws:sns:us-east-1:123456789012:cats-production-alerts" &&
      output.alert_sns_topic_name == "cats-production-alerts"
    )
    error_message = "platform outputs must expose the exact deterministic alert topic identity"
  }
}

run "allows_no_recipients_outside_production" {
  command = plan

  override_resource {
    target = aws_sns_topic.alerts
    values = {
      arn  = "arn:aws:sns:us-east-1:123456789012:cats-development-alerts"
      name = "cats-development-alerts"
    }
  }

  variables {
    environment            = "development"
    alert_email_recipients = {}
  }
}

run "rejects_no_recipients_in_production" {
  command = plan

  variables {
    alert_email_recipients = {}
  }

  expect_failures = [var.alert_email_recipients]
}

run "rejects_duplicate_recipient_values" {
  command = plan

  variables {
    alert_email_recipients = {
      primary_oncall   = "duplicate-recipient@example.invalid"
      secondary_oncall = "duplicate-recipient@example.invalid"
    }
  }

  expect_failures = [var.alert_email_recipients]
}

run "rejects_an_email_resource_key" {
  command = plan

  variables {
    alert_email_recipients = {
      "email-key@example.invalid" = "another-recipient@example.invalid"
    }
  }

  expect_failures = [var.alert_email_recipients]
}

run "checks_the_resolved_platform_account" {
  command = plan

  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "999999999999"
      arn        = "arn:aws:iam::999999999999:role/offline-fixture"
      user_id    = "offline-fixture"
    }
  }

  expect_failures = [terraform_data.aws_target]
}

run "checks_the_resolved_platform_partition" {
  command = plan

  override_data {
    target = data.aws_partition.current
    values = { partition = "aws-us-gov" }
  }

  expect_failures = [terraform_data.aws_target]
}

run "checks_the_resolved_platform_region" {
  command = plan

  override_data {
    target = data.aws_region.current
    values = { region = "us-west-2" }
  }

  expect_failures = [terraform_data.aws_target]
}
