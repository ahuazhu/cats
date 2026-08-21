# The stack's public ingress, Route v2 Services and DNS records all depend on
# this module completing. The ObjectWrite Gateway daemon in this release cannot
# become ready -- its PostgreSQL startup check ends in an unconditional
# FailedPrecondition until the E13 qualification lock is composed -- so waiting
# for its rollout would fail every apply on a gap this stack cannot close.
# Guard which Deployments block an apply and which do not.

mock_provider "kubernetes" {}

variables {
  control_plane_image                        = "123456789012.dkr.ecr.us-east-1.amazonaws.com/cats/control-plane@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  gateway_image                              = "123456789012.dkr.ecr.us-east-1.amazonaws.com/cats/control-plane@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  object_write_gateway_image                 = "123456789012.dkr.ecr.us-east-1.amazonaws.com/cats/control-plane@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  object_write_gateway_tls_secret_name       = "cats-object-write-gateway-tls-r1"
  object_write_gateway_nlb_security_group_id = "sg-0123456789abcdef0"
  object_write_gateway_private_subnet_ids    = ["subnet-0123456789abcdef0", "subnet-0123456789abcdef1"]
  object_write_spool_file_system_id          = "fs-0123456789abcdef0"
  object_write_spool_access_point_id         = "fsap-0123456789abcdef0"
  object_write_provider_partition            = "aws"
  object_write_provider_account_id           = "123456789012"
  route_v2_control_artifact_secret_name      = "cats-route-v2-control-r1"
  route_v2_control_artifact_signer_revision  = 1
  route_v2_control_artifact_secret_sha256    = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  route_v2_gateway_artifact_secret_name      = "cats-route-v2-gateway-r1"
  runtime_secret_data = {
    CATS_AUTH_TOKEN  = "0000000000000000000000000000000000000000"
    CATS_ADMIN_TOKEN = "1111111111111111111111111111111111111111"
  }
  production_cutover_operator_trust_bundle_json = "{\"version\":1}"
  runtime_provisioner_trust_bundle_json         = "{\"version\":1}"
  storage_postgres_url                          = "postgres://fixture/cats?sslmode=verify-full&options=-csearch_path%3Dcats_fresh"
  control_postgres_schema                       = "cats_fresh"
  chunkstore_bucket_name                        = "cats-fixture"
  chunkstore_region                             = "us-east-1"
  usage_postgres_url                            = "postgres://fixture/usage?sslmode=verify-full"
  rds_ca_pem                                    = <<-PEM
    -----BEGIN CERTIFICATE-----
    fixture
    -----END CERTIFICATE-----
  PEM
}

run "the_apply_blocks_on_the_components_that_can_become_ready" {
  command = plan

  assert {
    condition     = kubernetes_deployment_v1.control_plane.wait_for_rollout
    error_message = "the control plane must block the apply: a deploy that does not wait cannot report a failed rollout."
  }

  assert {
    condition     = kubernetes_deployment_v1.gateway.wait_for_rollout
    error_message = "the Gateway must block the apply: a deploy that does not wait cannot report a failed rollout."
  }

  assert {
    condition     = !kubernetes_deployment_v1.object_write_gateway.wait_for_rollout
    error_message = "the ObjectWrite Gateway must not block the apply while its E13 qualification lock is absent: its daemon cannot become ready, so waiting would fail every apply of the ingress, Route v2 Services and DNS records that depend on this module."
  }
}
