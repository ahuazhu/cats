mock_provider "aws" {}

override_data {
  target = data.aws_partition.current
  values = { partition = "aws" }
}

variables {
  name_prefix                              = "cats"
  environment                              = "production"
  expected_account_id                      = "123456789012"
  expected_aws_partition                   = "aws"
  aws_region                               = "us-east-1"
  artifact_bucket_name                     = "cats-production-worker-fixture"
  chunkstore_prefix                        = "cats-fresh"
  control_postgres_schema                  = "cats_fresh"
  worker_bundle_path                       = "/dev/null"
  worker_bundle_sha256                     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  instances                                = { metal-1 = "i-0123456789abcdef0" }
  instance_role_name                       = "cats-production-worker"
  worker_runtime_secret_data               = {}
  route_v2_node_artifact_secret_arn        = "arn:aws:secretsmanager:us-east-1:123456789012:secret:cats-production-route-v2-node-r1-ABC123"
  route_v2_node_artifact_secret_version_id = "12345678901234567890123456789012"
}

run "accepts_the_exact_revision_one_secret" {
  command = plan
}

run "rejects_a_secret_in_the_wrong_account" {
  command = plan

  variables {
    route_v2_node_artifact_secret_arn = "arn:aws:secretsmanager:us-east-1:999999999999:secret:cats-production-route-v2-node-r1-ABC123"
  }

  expect_failures = [var.route_v2_node_artifact_secret_arn]
}

run "rejects_a_secret_in_the_wrong_partition" {
  command = plan

  variables {
    route_v2_node_artifact_secret_arn = "arn:aws-cn:secretsmanager:us-east-1:123456789012:secret:cats-production-route-v2-node-r1-ABC123"
  }

  expect_failures = [var.route_v2_node_artifact_secret_arn]
}

run "rejects_a_secret_in_the_wrong_region" {
  command = plan

  variables {
    route_v2_node_artifact_secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:cats-production-route-v2-node-r1-ABC123"
  }

  expect_failures = [var.route_v2_node_artifact_secret_arn]
}

run "rejects_a_successor_revision_name" {
  command = plan

  variables {
    route_v2_node_artifact_secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:cats-production-route-v2-node-r2-ABC123"
  }

  expect_failures = [var.route_v2_node_artifact_secret_arn]
}
