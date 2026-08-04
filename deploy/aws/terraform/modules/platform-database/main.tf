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
  name             = "${var.name_prefix}-${var.environment}"
  metric_namespace = "Cats/Database"
}

# An alarm with no action changes colour in a console nobody is looking at. The
# existing usage-pipeline alarms are already in that state, which is part of why
# a credential failure went unnoticed for thirteen hours.
check "the_credential_alarm_reaches_someone" {
  assert {
    condition     = length(var.alarm_action_arns) > 0
    error_message = "alarm_action_arns is empty, so ${local.name}-password-authentication-failed will notify nobody. Point it at an SNS topic with a confirmed subscription."
  }
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
  for_each = var.allowed_security_group_ids

  security_group_id            = aws_security_group.this.id
  referenced_security_group_id = each.value
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "PostgreSQL from ${each.key}"
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

  # The error log is where a credential failure is stated plainly, and it was
  # not leaving the instance. Export it so the metric filter below can see it.
  enabled_cloudwatch_logs_exports = ["postgresql"]

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

  # RDS creates this log group itself the first time it exports, with no
  # retention. Owning it here sets a retention and makes the export's
  # destination explicit; the instance must not race Terraform to create it.
  depends_on = [aws_cloudwatch_log_group.postgresql]
}

# Why this alarm exists.
#
# PostgreSQL authenticates on connect. When the managed master password rotated
# and every consumer still held a static copy, established connections kept
# working and only new ones failed, so the fleet stayed healthy for hours and
# the first visible symptom was component-shaped -- "creating a Cat fails", not
# "the database is unreachable". It read as connection exhaustion and was
# treated as such, which cost twelve healthy Guests.
#
# The server had said it plainly the whole time:
#
#   FATAL: password authentication failed for user "catsadmin"
#
# This is the cheapest detector for that failure and it fires on the first
# rejected connection, hours before a user notices.

resource "aws_cloudwatch_log_group" "postgresql" {
  name              = "/aws/rds/instance/${local.name}/postgresql"
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, { Name = "${local.name}-postgresql" })
}

resource "aws_cloudwatch_log_metric_filter" "password_authentication_failed" {
  name           = "${local.name}-password-authentication-failed"
  log_group_name = aws_cloudwatch_log_group.postgresql.name

  # Matches the server's own wording, as in
  #   ...:catsadmin@cats:[1234]:FATAL:  password authentication failed for user "catsadmin"
  # The quotes make this a literal substring match rather than a term list, so
  # an unrelated line mentioning only "authentication" does not count.
  pattern = "\"password authentication failed\""

  metric_transformation {
    name      = "PasswordAuthenticationFailures"
    namespace = local.metric_namespace
    value     = "1"
    # Publish a zero for non-matching lines so the alarm can return to OK on
    # its own instead of sitting in INSUFFICIENT_DATA after a real failure.
    default_value = "0"
    unit          = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "password_authentication_failed" {
  alarm_name        = "${local.name}-password-authentication-failed"
  alarm_description = "PostgreSQL rejected a connection's credentials. A consumer is holding a password the instance no longer accepts -- most likely a copy left behind by a managed master-password rotation. Established connections keep working, so the fleet will look healthy while every new connection fails."

  namespace   = local.metric_namespace
  metric_name = aws_cloudwatch_log_metric_filter.password_authentication_failed.metric_transformation[0].name
  statistic   = "Sum"

  period             = 60
  evaluation_periods = 1
  # Deliberately sensitive: one rejected connection against this instance is
  # already worth waking someone. There is no benign steady state to filter out.
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  # The log is silent when nothing connects badly, and silence is the good case.
  treat_missing_data = "notBreaching"

  alarm_actions = var.alarm_action_arns
  ok_actions    = var.alarm_action_arns

  tags = merge(var.tags, { Name = "${local.name}-password-authentication-failed" })
}
