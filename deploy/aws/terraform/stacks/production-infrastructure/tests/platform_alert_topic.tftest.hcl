mock_provider "aws" {}

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
  usage_archive_bucket_name    = "cats-production-usage-fixture"
  chunkstore_bucket_name       = "cats-production-chunkstore-fixture"
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
