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

variables {
  eks_cluster_name             = "cats-production"
  expected_account_id          = "123456789012"
  expected_aws_partition       = "aws"
  usage_archive_bucket_name    = "cats-production-usage-fixture"
  chunkstore_bucket_name       = "cats-production-chunkstore-fixture"
  chunkstore_prefix            = "cats-fresh"
  control_postgres_schema      = "cats_fresh"
  platform_alert_sns_topic_arn = "arn:aws:sns:us-east-1:123456789012:cats-production-alerts"
  worker_artifact_bucket_name  = "cats-production-worker-fixture"
  metal_worker_enabled         = false
}

run "fresh_disabled_by_default_yields_null_outputs" {
  command = plan

  assert {
    condition     = output.fresh_usage_kinesis_stream == null
    error_message = "fresh_usage_kinesis_stream must be null while fresh_usage_enabled is false."
  }

  assert {
    condition     = output.fresh_usage_checkpoint_table == null
    error_message = "fresh_usage_checkpoint_table must be null while fresh_usage_enabled is false."
  }

  assert {
    condition     = output.fresh_usage_archive_bucket == null
    error_message = "fresh_usage_archive_bucket must be null while fresh_usage_enabled is false."
  }
}

run "fresh_set_derives_disjoint_names" {
  command = plan

  variables {
    fresh_usage_enabled             = true
    fresh_usage_archive_bucket_name = "cats-production-usage-fresh-fixture"
  }

  assert {
    condition     = output.fresh_usage_kinesis_stream == "cats-fresh-production-usage"
    error_message = "The fresh Kinesis stream name must derive from the suffixed prefix."
  }

  assert {
    condition     = output.fresh_usage_kinesis_stream != output.usage_stream_name
    error_message = "Fresh and old Kinesis stream names must be distinct; the reset executor rejects the collision."
  }

  assert {
    condition     = output.fresh_usage_checkpoint_table == "cats-fresh-production-usage-consumer-leases"
    error_message = "The fresh checkpoint table name must derive from the suffixed prefix."
  }

  assert {
    condition     = output.fresh_usage_checkpoint_table != output.usage_consumer_lease_table_name
    error_message = "Fresh and old checkpoint table names must be distinct; the reset executor rejects the collision."
  }
}

run "rejects_fresh_without_archive_bucket" {
  command = plan

  variables {
    fresh_usage_enabled = true
  }

  expect_failures = [terraform_data.fresh_usage_inputs]
}

run "rejects_fresh_archive_reusing_the_old_bucket" {
  command = plan

  variables {
    fresh_usage_enabled             = true
    fresh_usage_archive_bucket_name = "cats-production-usage-fixture"
  }

  expect_failures = [terraform_data.fresh_usage_inputs]
}

run "rejects_fresh_reusing_the_old_service_account" {
  command = plan

  variables {
    fresh_usage_enabled              = true
    fresh_usage_archive_bucket_name  = "cats-production-usage-fresh-fixture"
    fresh_usage_service_account_name = "cats-controld"
  }

  expect_failures = [terraform_data.fresh_usage_inputs]
}
