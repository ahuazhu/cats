mock_provider "aws" {}

override_data {
  target = data.aws_partition.current
  values = { partition = "aws" }
}

override_data {
  target = data.aws_iam_policy_document.artifacts_tls_only
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

override_data {
  target = data.aws_iam_policy_document.artifact_reader
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

override_resource {
  target = aws_iam_policy.artifact_reader
  values = { arn = "arn:aws:iam::123456789012:policy/cats-fixture-worker" }
}

variables {
  environment             = "fixture"
  expected_account_id     = "123456789012"
  expected_aws_partition  = "aws"
  aws_region              = "us-east-1"
  artifact_bucket_name    = "cats-worker-fixture"
  chunkstore_prefix       = "cats-fixture"
  control_postgres_schema = "cats_fixture"
  worker_bundle_path      = "/fixture/cats-worker.tar.zst"
  worker_bundle_sha256    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  instances               = { metal-1 = "i-0123456789abcdef0" }
  instance_role_name      = "cats-fixture-worker"
  worker_runtime_secret_data = {
    CATS_AUTH_TOKEN = "fixture-token-value"
  }
}

run "renders_memory_as_decimal_bytes" {
  command = apply

  assert {
    condition = strcontains(
      local.deployment_script,
      "printf \"%.0f\\n\", $2 * 1024",
    )
    error_message = "The deployment command must give awk one newline escape after the memory byte count."
  }

  assert {
    condition = !strcontains(
      local.deployment_script,
      "printf \"%.0f\\\\n\", $2 * 1024",
    )
    error_message = "A doubled awk escape reaches worker.env as a literal backslash and systemd turns it into a trailing n."
  }
}
