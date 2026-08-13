mock_provider "aws" {}
mock_provider "kubernetes" {}

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

override_module {
  target = module.cats_kubernetes
  outputs = {
    namespace                      = "cats"
    control_plane_service          = "cats-controld"
    control_plane_route_v2_service = "cats-controld-route-v2"
    gateway_service                = "cats-gatewayd"
    ingress_name                   = "cats-public"
  }
}

variables {
  kubeconfig_path                       = "/tmp/cats-fixture-kubeconfig"
  kubeconfig_context                    = "cats-production"
  expected_account_id                   = "123456789012"
  expected_aws_partition                = "aws"
  aws_region                            = "us-east-1"
  control_plane_image                   = "123456789012.dkr.ecr.us-east-1.amazonaws.com/cats/control@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  gateway_image                         = "123456789012.dkr.ecr.us-east-1.amazonaws.com/cats/gateway@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  route_v2_control_artifact_secret_name = "cats-route-v2-control-r1"
  route_v2_gateway_artifact_secret_name = "cats-route-v2-gateway-r1"
  runtime_secret_data                   = {}
  route_grant_private_key_pem           = "fixture-private"
  route_grant_public_key_pem            = "fixture-public"
  runtime_provisioner_trust_bundle_json = "{}"
  storage_postgres_url                  = "postgresql://fixture.invalid/cats"
  chunkstore_bucket_name                = "cats-production-chunkstore-fixture"
  usage_postgres_url                    = "postgresql://fixture.invalid/cats_usage"
  rds_ca_pem                            = "fixture-ca"
  acm_certificate_arn                   = "arn:aws:acm:us-east-1:123456789012:certificate/11111111-2222-3333-4444-555555555555"
  public_subnet_ids                     = ["subnet-00000000000000001", "subnet-00000000000000002"]
}

run "accepts_the_exact_aws_target" {
  command = plan
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

  expect_failures = [terraform_data.aws_target]
}

run "checks_the_resolved_partition_at_plan" {
  command = plan

  override_data {
    target = data.aws_partition.current
    values = { partition = "aws-us-gov" }
  }

  expect_failures = [terraform_data.aws_target]
}

run "checks_the_resolved_region_at_plan" {
  command = plan

  override_data {
    target = data.aws_region.current
    values = { region = "us-west-2" }
  }

  expect_failures = [terraform_data.aws_target]
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
