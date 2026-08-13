mock_provider "aws" {}

# The mock provider cannot synthesize a valid IAM policy document. Keep the
# probe calibrated by replacing only provider-derived JSON; the real module
# graph and variable validation still plan normally.
override_data {
  target = data.aws_iam_policy_document.archive_tls_only
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

override_data {
  target = data.aws_iam_policy_document.producer
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

override_data {
  target = data.aws_iam_policy_document.consumer
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

override_data {
  target = data.aws_iam_policy_document.replay
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

override_data {
  target = data.aws_iam_policy_document.pod_identity_trust
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

override_data {
  target = data.aws_iam_policy_document.image_manifest_reader
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

variables {
  name_prefix                     = "cats"
  environment                     = "production"
  archive_bucket_name             = "cats-production-usage-fixture"
  eks_cluster_name                = "cats-production"
  chunkstore_manifest_bucket_name = "cats-production-chunkstore-fixture"
  alarm_action_arns = [
    "arn:aws:sns:us-east-1:123456789012:cats-production-alerts",
  ]
}

run "accepts_a_real_alarm_destination" {
  command = plan
}

run "rejects_an_empty_alarm_destination" {
  command = plan

  variables {
    alarm_action_arns = []
  }

  expect_failures = [var.alarm_action_arns]
}
