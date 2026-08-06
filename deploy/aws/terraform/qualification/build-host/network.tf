resource "aws_vpc" "build" {
  cidr_block           = local.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  instance_tenancy     = "default"

  tags = {
    Name      = "${local.name_prefix}-vpc"
    Component = "build-network"
  }
}

resource "aws_internet_gateway" "build" {
  vpc_id = aws_vpc.build.id

  tags = {
    Name      = "${local.name_prefix}-igw"
    Component = "build-egress"
  }
}

resource "aws_subnet" "public_egress" {
  vpc_id                  = aws_vpc.build.id
  cidr_block              = local.public_subnet_cidr
  availability_zone_id    = local.availability_zone_id
  map_public_ip_on_launch = false

  tags = {
    Name      = "${local.name_prefix}-public-egress"
    Component = "build-egress"
  }
}

resource "aws_subnet" "private_build" {
  vpc_id                  = aws_vpc.build.id
  cidr_block              = local.private_subnet_cidr
  availability_zone_id    = local.availability_zone_id
  map_public_ip_on_launch = false

  tags = {
    Name      = "${local.name_prefix}-private"
    Component = "build-host"
  }
}

resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name      = "${local.name_prefix}-nat"
    Component = "build-egress"
  }

  depends_on = [aws_internet_gateway.build]
}

resource "aws_nat_gateway" "build" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_egress.id

  tags = {
    Name      = "${local.name_prefix}-nat"
    Component = "build-egress"
  }

  depends_on = [aws_internet_gateway.build]
}

resource "aws_route_table" "public_egress" {
  vpc_id = aws_vpc.build.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.build.id
  }

  tags = {
    Name      = "${local.name_prefix}-public-egress"
    Component = "build-egress"
  }
}

resource "aws_route_table_association" "public_egress" {
  subnet_id      = aws_subnet.public_egress.id
  route_table_id = aws_route_table.public_egress.id
}

resource "aws_route_table" "private_build" {
  vpc_id = aws_vpc.build.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.build.id
  }

  tags = {
    Name      = "${local.name_prefix}-private"
    Component = "build-host"
  }
}

resource "aws_route_table_association" "private_build" {
  subnet_id      = aws_subnet.private_build.id
  route_table_id = aws_route_table.private_build.id
}

# This group deliberately has no ingress rules. Operators reach the host only
# through SSM, and the host has no public IP or SSH key.
resource "aws_security_group" "build_host" {
  name        = "${local.name_prefix}-host"
  description = "No ingress; minimum build-host egress"
  vpc_id      = aws_vpc.build.id

  egress {
    description = "TLS package, source, and AWS API access"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS over UDP to the VPC resolver"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [local.vpc_resolver_cidr]
  }

  egress {
    description = "DNS over TCP to the VPC resolver"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [local.vpc_resolver_cidr]
  }

  egress {
    description = "AWS Time Sync Service"
    from_port   = 123
    to_port     = 123
    protocol    = "udp"
    cidr_blocks = [local.time_sync_cidr]
  }

  tags = {
    Name      = "${local.name_prefix}-host"
    Component = "build-host"
  }
}

resource "aws_security_group" "ssm_endpoints" {
  name        = "${local.name_prefix}-ssm-endpoints"
  description = "TLS from the build host to private SSM endpoints only"
  vpc_id      = aws_vpc.build.id

  ingress {
    description     = "SSM TLS from the build host"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.build_host.id]
  }

  tags = {
    Name      = "${local.name_prefix}-ssm-endpoints"
    Component = "build-management"
  }
}

locals {
  ssm_endpoint_services = toset([
    "ssm",
    "ssmmessages",
  ])
}

resource "aws_vpc_endpoint" "ssm" {
  for_each = local.ssm_endpoint_services

  vpc_id              = aws_vpc.build.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [aws_subnet.private_build.id]
  security_group_ids  = [aws_security_group.ssm_endpoints.id]

  tags = {
    Name      = "${local.name_prefix}-${each.value}"
    Component = "build-management"
  }
}

data "aws_iam_policy_document" "build_storage_endpoint" {
  statement {
    sid    = "QualificationArtifactsOnly"
    effect = "Allow"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:PutObject"]
    resources = [
      "${local.artifact_bucket_arn}/artifacts/sha256/*",
      "${local.artifact_bucket_arn}/evidence/sha256/*",
    ]
  }

  statement {
    sid    = "QualificationSourceOnly"
    effect = "Allow"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
    ]
    resources = [
      "${local.source_bucket_arn}/source/bundles/sha256/*",
      "${local.source_bucket_arn}/source/manifests/sha256/*",
    ]
  }
}

resource "aws_vpc_endpoint" "build_storage" {
  vpc_id            = aws_vpc.build.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private_build.id]
  policy            = data.aws_iam_policy_document.build_storage_endpoint.json

  tags = {
    Name      = "${local.name_prefix}-storage"
    Component = "build-storage"
  }
}

moved {
  from = aws_vpc_endpoint.artifacts
  to   = aws_vpc_endpoint.build_storage
}
