# The production module contains only the new Control deployment. A successful
# Terraform apply must therefore wait for that deployment to become ready.

mock_provider "kubernetes" {}

variables {
  control_plane_image = "123456789012.dkr.ecr.us-east-1.amazonaws.com/cats/control-plane@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
}
