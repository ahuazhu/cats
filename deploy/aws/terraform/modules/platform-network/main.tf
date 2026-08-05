# Cats production VPC.
#
# The account this replaces ran EKS, RDS and the bare-metal workers in the
# region's default VPC, which is why none of it was representable in Terraform.
# This module owns the network outright so ADR-0012 holds from the first apply.
#
# Layout per availability zone:
#   public  - the EKS Auto Mode ALB and the NAT gateway
#   private - EKS nodes, bare-metal workers and RDS
#
# Egress defaults to one NAT gateway per zone so losing one availability zone
# does not strand otherwise healthy private-subnet workers or EKS nodes. A
# single shared gateway is an explicit cost-saving override, not a production
# high-availability shape.

data "aws_availability_zones" "available" {
  state = "available"

  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

locals {
  name = "${var.name_prefix}-${var.environment}"

  azs = slice(data.aws_availability_zones.available.names, 0, var.availability_zone_count)

  # /20 public and /20 private per zone out of the /16.
  public_subnets  = [for i, _ in local.azs : cidrsubnet(var.vpc_cidr, 4, i)]
  private_subnets = [for i, _ in local.azs : cidrsubnet(var.vpc_cidr, 4, i + 8)]

  nat_gateway_count = var.one_nat_gateway_per_az ? length(local.azs) : 1
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(var.tags, { Name = "${local.name}-vpc" })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, { Name = "${local.name}-igw" })
}

# `kubernetes.io/role/elb` is what lets EKS Auto Mode place the public ALB.
# Without it ingress reconciles forever with no address.
resource "aws_subnet" "public" {
  for_each = { for i, az in local.azs : az => i }

  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.key
  cidr_block              = local.public_subnets[each.value]
  map_public_ip_on_launch = true

  tags = merge(var.tags, {
    Name                     = "${local.name}-public-${each.key}"
    "kubernetes.io/role/elb" = "1"
  })
}

resource "aws_subnet" "private" {
  for_each = { for i, az in local.azs : az => i }

  vpc_id            = aws_vpc.this.id
  availability_zone = each.key
  cidr_block        = local.private_subnets[each.value]

  tags = merge(var.tags, {
    Name                              = "${local.name}-private-${each.key}"
    "kubernetes.io/role/internal-elb" = "1"
  })
}

resource "aws_eip" "nat" {
  count = local.nat_gateway_count

  domain = "vpc"

  tags = merge(var.tags, { Name = "${local.name}-nat-${count.index}" })

  depends_on = [aws_internet_gateway.this]
}

resource "aws_nat_gateway" "this" {
  count = local.nat_gateway_count

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[local.azs[count.index]].id

  tags = merge(var.tags, { Name = "${local.name}-nat-${count.index}" })

  depends_on = [aws_internet_gateway.this]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, { Name = "${local.name}-public" })
}

resource "aws_route" "public_default" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  for_each = aws_subnet.public

  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  for_each = { for i, az in local.azs : az => i }

  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, { Name = "${local.name}-private-${each.key}" })
}

resource "aws_route" "private_default" {
  for_each = { for i, az in local.azs : az => i }

  route_table_id         = aws_route_table.private[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[var.one_nat_gateway_per_az ? each.value : 0].id
}

resource "aws_route_table_association" "private" {
  for_each = aws_subnet.private

  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
}

# ChunkStore traffic is the dominant egress path. A gateway endpoint keeps S3
# reads and writes off the NAT gateway, which is both faster and removes the
# per-GB NAT data charge from every Cat's cold restore.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"

  route_table_ids = concat(
    [aws_route_table.public.id],
    [for rt in aws_route_table.private : rt.id],
  )

  tags = merge(var.tags, { Name = "${local.name}-s3" })
}
