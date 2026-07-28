# Shared-storage PostgreSQL.
#
# Holds the authoritative ChunkStore roots, leases and fencing epochs, plus the
# rebuildable `cats_usage` projection. It is reachable from both the EKS pods
# and the bare-metal workers, which is the whole reason this metadata is
# PostgreSQL and not the control plane's local SQLite.
#
# Not publicly accessible. Access is by security group reference, never CIDR,
# so a subnet renumbering cannot silently widen it.

locals {
  name = "${var.name_prefix}-${var.environment}"
}

resource "aws_db_subnet_group" "this" {
  name       = local.name
  subnet_ids = var.private_subnet_ids

  tags = merge(var.tags, { Name = local.name })
}

resource "aws_security_group" "this" {
  name        = "${local.name}-postgres"
  description = "Cats shared-storage PostgreSQL"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, { Name = "${local.name}-postgres" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "from_source_groups" {
  for_each = toset(var.allowed_security_group_ids)

  security_group_id            = aws_security_group.this.id
  referenced_security_group_id = each.value
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "PostgreSQL from ${each.value}"
}

resource "aws_db_instance" "this" {
  identifier = local.name

  engine         = "postgres"
  engine_version = var.engine_version
  instance_class = var.instance_class

  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true

  db_name  = var.initial_database_name
  username = var.master_username

  # The password is generated and rotated in Secrets Manager instead of passing
  # through Terraform state.
  manage_master_user_password = true

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.this.id]
  publicly_accessible    = false
  multi_az               = var.multi_az

  backup_retention_period = var.backup_retention_days
  copy_tags_to_snapshot   = true

  auto_minor_version_upgrade = true
  apply_immediately          = var.apply_immediately

  deletion_protection       = var.deletion_protection
  skip_final_snapshot       = var.skip_final_snapshot
  final_snapshot_identifier = var.skip_final_snapshot ? null : "${local.name}-final"

  performance_insights_enabled = var.performance_insights_enabled

  tags = merge(var.tags, { Name = local.name })
}
