locals {
  volume_kms_alias     = "alias/${var.qualification_namespace}-build-volume"
  volume_kms_alias_arn = "arn:${data.aws_partition.current.partition}:kms:${var.aws_region}:${var.expected_account_id}:${local.volume_kms_alias}"

  bootstrap_components_sha256 = {
    bootstrap         = filesha256("${path.module}/bootstrap/bootstrap.sh")
    checkout          = filesha256("${path.module}/bootstrap/checkout-exact-sha.sh")
    imds_guard        = filesha256("${path.module}/bootstrap/imds-guard.sh")
    immutable_receipt = filesha256("${path.module}/bootstrap/immutable-receipt.sh")
    publish           = filesha256("${path.module}/bootstrap/publish-content-addressed.sh")
    readiness         = filesha256("${path.module}/bootstrap/verify-readiness.py")
    run_build         = filesha256("${path.module}/bootstrap/run-build.sh")
    stage_output      = filesha256("${path.module}/bootstrap/stage-build-output.py")
    toolchain_lock    = filesha256("${path.module}/bootstrap/toolchain-lock-v1.json")
  }

  bootstrap_identity = {
    schema_version             = 1
    account_id                 = var.expected_account_id
    region                     = var.aws_region
    namespace                  = var.qualification_namespace
    cell_id                    = var.qualification_cell_id
    environment_is_production  = false
    ami_id                     = local.canonical_ami.image_id
    instance_type              = local.instance_type
    artifact_bucket            = local.artifact_bucket_name
    artifact_kms_alias_arn     = local.artifact_kms_alias_arn
    source_repository_identity = "https://github.com/ahuazhu/cats.git"
    source_delivery_mode       = "controller-content-addressed-git-bundle-v1"
    source_bucket              = local.source_bucket_name
    source_kms_alias_arn       = local.source_kms_alias_arn
    apt_snapshot_id            = jsondecode(file("${path.module}/bootstrap/toolchain-lock-v1.json")).apt_snapshot.snapshot_id
    toolchain_lock_sha256      = filesha256("${path.module}/bootstrap/toolchain-lock-v1.json")
    bootstrap_payload_sha256   = sha256(jsonencode(local.bootstrap_components_sha256))
  }

  cloud_init = templatefile("${path.module}/bootstrap/cloud-init.yaml.tftpl", {
    identity_json       = jsonencode(local.bootstrap_identity)
    toolchain_lock      = file("${path.module}/bootstrap/toolchain-lock-v1.json")
    bootstrap_script    = file("${path.module}/bootstrap/bootstrap.sh")
    imds_guard_script   = file("${path.module}/bootstrap/imds-guard.sh")
    checkout_script     = file("${path.module}/bootstrap/checkout-exact-sha.sh")
    immutable_receipt   = file("${path.module}/bootstrap/immutable-receipt.sh")
    publish_script      = file("${path.module}/bootstrap/publish-content-addressed.sh")
    run_build_script    = file("${path.module}/bootstrap/run-build.sh")
    stage_output_script = file("${path.module}/bootstrap/stage-build-output.py")
    readiness_script    = file("${path.module}/bootstrap/verify-readiness.py")
  })
  cloud_init_base64 = base64gzip(local.cloud_init)
}

check "ec2_user_data_size" {
  assert {
    # Terraform strings must be UTF-8, so base64decode cannot represent gzip
    # bytes. 21,844 base64 characters conservatively proves <=16,383 bytes.
    condition     = length(local.cloud_init_base64) <= 21844
    error_message = "gzip-compressed EC2 user data exceeds the 16 KiB RunInstances limit."
  }
}

data "aws_iam_policy_document" "volume_key" {
  statement {
    sid       = "EnableAccountIAMPermissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${var.expected_account_id}:root"]
    }
  }
}

resource "aws_kms_key" "build_volume" {
  description             = "Qualification build-host EBS volume only"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.volume_key.json

  tags = {
    Name      = "${local.name_prefix}-volume"
    Component = "build-host"
  }
}

resource "aws_kms_alias" "build_volume" {
  name          = local.volume_kms_alias
  target_key_id = aws_kms_key.build_volume.key_id
}

resource "aws_instance" "build" {
  ami                                  = local.canonical_ami.image_id
  instance_type                        = local.instance_type
  subnet_id                            = aws_subnet.private_build.id
  vpc_security_group_ids               = [aws_security_group.build_host.id]
  iam_instance_profile                 = aws_iam_instance_profile.build.name
  associate_public_ip_address          = false
  disable_api_termination              = true
  force_destroy                        = false
  instance_initiated_shutdown_behavior = "stop"
  ebs_optimized                        = true
  monitoring                           = true
  user_data_base64                     = local.cloud_init_base64
  user_data_replace_on_change          = true

  metadata_options {
    http_endpoint               = "enabled"
    http_protocol_ipv6          = "disabled"
    http_put_response_hop_limit = 1
    http_tokens                 = "required"
    instance_metadata_tags      = "enabled"
  }

  maintenance_options {
    auto_recovery = "default"
  }

  root_block_device {
    delete_on_termination = true
    encrypted             = true
    kms_key_id            = aws_kms_key.build_volume.arn
    volume_size           = local.root_volume.size_gib
    volume_type           = local.root_volume.type
    iops                  = local.root_volume.iops
    throughput            = local.root_volume.throughput

    tags = merge(local.required_tags, {
      Name      = "${local.name_prefix}-root"
      Component = "build-host"
    })
  }

  tags = {
    Name      = "${local.name_prefix}-host"
    Component = "build-host"
  }

  depends_on = [
    aws_iam_role_policy.build,
    aws_route_table_association.private_build,
    aws_route_table_association.public_egress,
    aws_s3_bucket_policy.artifacts,
    aws_s3_bucket_policy.source,
    aws_kms_alias.source,
    aws_vpc_endpoint.ssm,
  ]
}

check "canonical_ami_contract" {
  assert {
    condition = local.canonical_ami == {
      architecture        = "x86_64"
      creation_date       = "2026-07-14T11:54:50.000Z"
      image_id            = "ami-052355af2a014bd2c"
      name                = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-20260714"
      owner_id            = "099720109477"
      platform_details    = "Linux/UNIX"
      root_device_name    = "/dev/sda1"
      source_snapshot_id  = "snap-0b0be23c49c254dd6"
      virtualization_type = "hvm"
    }
    error_message = "Canonical Ubuntu AMI manifest differs from the independently reviewed image."
  }
}

check "frozen_host_shape" {
  assert {
    condition = (
      local.instance_type == "c7i.12xlarge" &&
      local.root_volume == {
        size_gib   = 500
        type       = "gp3"
        iops       = 6000
        throughput = 500
      } &&
      local.availability_zone_id == "use1-az1"
    )
    error_message = "build host compute, storage, or AZ shape differs from the reviewed contract."
  }
}
