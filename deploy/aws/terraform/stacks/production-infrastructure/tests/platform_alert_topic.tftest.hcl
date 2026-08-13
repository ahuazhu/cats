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

override_data {
  target = module.usage_infrastructure.data.aws_iam_policy_document.archive_tls_only
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

override_data {
  target = module.usage_infrastructure.data.aws_iam_policy_document.producer
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

override_data {
  target = module.usage_infrastructure.data.aws_iam_policy_document.consumer
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

override_data {
  target = module.usage_infrastructure.data.aws_iam_policy_document.replay
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

override_data {
  target = module.usage_infrastructure.data.aws_iam_policy_document.pod_identity_trust
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

override_data {
  target = module.usage_infrastructure.data.aws_iam_policy_document.image_manifest_reader
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

variables {
  eks_cluster_name             = "cats-production"
  expected_account_id          = "123456789012"
  expected_aws_partition       = "aws"
  usage_archive_bucket_name    = "cats-production-usage-fixture"
  chunkstore_bucket_name       = "cats-production-chunkstore-fixture"
  chunkstore_prefix            = "cats-fresh"
  platform_alert_sns_topic_arn = "arn:aws:sns:us-east-1:123456789012:cats-production-alerts"
  worker_artifact_bucket_name  = "cats-production-worker-fixture"
  metal_worker_enabled         = false
}

run "accepts_the_platform_output_seam" {
  command = plan
}

run "rejects_a_non_topic_value" {
  command = plan

  variables {
    platform_alert_sns_topic_arn = "REPLACE_WITH_PLATFORM_OUTPUT"
  }

  expect_failures = [var.platform_alert_sns_topic_arn]
}

run "rejects_a_topic_in_the_wrong_account" {
  command = plan

  variables {
    platform_alert_sns_topic_arn = "arn:aws:sns:us-east-1:999999999999:cats-production-alerts"
  }

  expect_failures = [var.platform_alert_sns_topic_arn]
}

run "rejects_a_topic_in_the_wrong_partition" {
  command = plan

  variables {
    platform_alert_sns_topic_arn = "arn:aws-us-gov:sns:us-east-1:123456789012:cats-production-alerts"
  }

  expect_failures = [var.platform_alert_sns_topic_arn]
}

run "rejects_a_topic_in_the_wrong_region" {
  command = plan

  variables {
    platform_alert_sns_topic_arn = "arn:aws:sns:us-west-2:123456789012:cats-production-alerts"
  }

  expect_failures = [var.platform_alert_sns_topic_arn]
}

run "rejects_a_similarly_named_topic" {
  command = plan

  variables {
    platform_alert_sns_topic_arn = "arn:aws:sns:us-east-1:123456789012:cats-production-alerts-copy"
  }

  expect_failures = [var.platform_alert_sns_topic_arn]
}

run "rejects_a_malformed_expected_account" {
  command = plan

  variables {
    expected_account_id = "not-an-account"
  }

  expect_failures = [var.expected_account_id]
}

run "rejects_a_malformed_expected_partition" {
  command = plan

  variables {
    expected_aws_partition = "not-a-partition"
  }

  expect_failures = [var.expected_aws_partition]
}

run "rejects_a_malformed_region" {
  command = plan

  variables {
    aws_region = "not a region"
  }

  expect_failures = [var.aws_region]
}

run "checks_the_resolved_account_at_plan" {
  command = plan

  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "999999999999"
      arn        = "arn:aws:iam::999999999999:role/offline-fixture"
      user_id    = "offline-fixture"
    }
  }

  expect_failures = [terraform_data.platform_alert_topic_identity]
}

run "checks_the_resolved_partition_at_plan" {
  command = plan

  override_data {
    target = data.aws_partition.current
    values = { partition = "aws-us-gov" }
  }

  expect_failures = [terraform_data.platform_alert_topic_identity]
}

run "checks_the_resolved_region_at_plan" {
  command = plan

  override_data {
    target = data.aws_region.current
    values = { region = "us-west-2" }
  }

  expect_failures = [terraform_data.platform_alert_topic_identity]
}

run "accepts_the_exact_revision_one_route_secret" {
  command = plan

  variables {
    route_v2_node_artifact_secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:cats-production-route-v2-node-r1-ABC123"
  }
}

run "rejects_a_route_secret_in_the_wrong_account" {
  command = plan

  variables {
    route_v2_node_artifact_secret_arn = "arn:aws:secretsmanager:us-east-1:999999999999:secret:cats-production-route-v2-node-r1-ABC123"
  }

  expect_failures = [var.route_v2_node_artifact_secret_arn]
}

run "rejects_a_route_secret_in_the_wrong_partition" {
  command = plan

  variables {
    route_v2_node_artifact_secret_arn = "arn:aws-us-gov:secretsmanager:us-east-1:123456789012:secret:cats-production-route-v2-node-r1-ABC123"
  }

  expect_failures = [var.route_v2_node_artifact_secret_arn]
}

run "rejects_a_route_secret_in_the_wrong_region" {
  command = plan

  variables {
    route_v2_node_artifact_secret_arn = "arn:aws:secretsmanager:us-west-2:123456789012:secret:cats-production-route-v2-node-r1-ABC123"
  }

  expect_failures = [var.route_v2_node_artifact_secret_arn]
}

run "rejects_a_similarly_named_route_secret" {
  command = plan

  variables {
    route_v2_node_artifact_secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:cats-production-route-v2-node-r10-ABC123"
  }

  expect_failures = [var.route_v2_node_artifact_secret_arn]
}
