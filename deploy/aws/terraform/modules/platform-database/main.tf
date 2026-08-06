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
  name                       = "${var.name_prefix}-${var.environment}"
  metric_namespace           = "Cats/Database"
  unsupported_proxy_zone_ids = toset(["use1-az3", "usw1-az2"])
  proxy_subnet_ids = [
    for subnet in data.aws_subnet.private : subnet.id
    if !contains(local.unsupported_proxy_zone_ids, subnet.availability_zone_id)
  ]
}

data "aws_partition" "current" {}

data "aws_region" "current" {}

data "aws_kms_key" "secrets_manager" {
  key_id = "alias/aws/secretsmanager"
}

data "aws_subnet" "private" {
  count = length(var.private_subnet_ids)
  id    = var.private_subnet_ids[count.index]
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

resource "aws_security_group" "proxy" {
  name        = "${local.name}-postgres-proxy"
  description = "Cats shared-storage RDS Proxy"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, { Name = "${local.name}-postgres-proxy" })

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

resource "aws_vpc_security_group_ingress_rule" "proxy_from_source_groups" {
  for_each = var.allowed_security_group_ids

  security_group_id            = aws_security_group.proxy.id
  referenced_security_group_id = each.value
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "PostgreSQL proxy from ${each.key}"
}

resource "aws_vpc_security_group_egress_rule" "proxy_to_database" {
  security_group_id            = aws_security_group.proxy.id
  referenced_security_group_id = aws_security_group.this.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "RDS Proxy to PostgreSQL"
}

resource "aws_vpc_security_group_ingress_rule" "database_from_proxy" {
  security_group_id            = aws_security_group.this.id
  referenced_security_group_id = aws_security_group.proxy.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "PostgreSQL from RDS Proxy"
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

# Each blockd deliberately keeps separate metadata and lease sessions so a
# commit cannot starve lease renewal. RDS Proxy preserves those client-facing
# sessions while bounding the backend connections consumed on this small RDS
# instance. It is AWS-managed and spans two supported AZs; no Cats process is a
# new connection authority or a dependency of a running blockd.

data "aws_iam_policy_document" "proxy_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "proxy" {
  name               = "${local.name}-rds-proxy"
  assume_role_policy = data.aws_iam_policy_document.proxy_assume.json

  tags = merge(var.tags, { Name = "${local.name}-rds-proxy" })
}

data "aws_iam_policy_document" "proxy_secret" {
  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_db_instance.this.master_user_secret[0].secret_arn]
  }

  statement {
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [data.aws_kms_key.secrets_manager.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values = [
        "secretsmanager.${data.aws_region.current.region}.${data.aws_partition.current.dns_suffix}",
      ]
    }
  }
}

resource "aws_iam_role_policy" "proxy_secret" {
  name   = "${local.name}-rds-proxy-secret"
  role   = aws_iam_role.proxy.id
  policy = data.aws_iam_policy_document.proxy_secret.json
}

resource "aws_db_proxy" "this" {
  name                   = "${local.name}-postgres"
  engine_family          = "POSTGRESQL"
  idle_client_timeout    = 1800
  require_tls            = true
  role_arn               = aws_iam_role.proxy.arn
  vpc_security_group_ids = [aws_security_group.proxy.id]
  vpc_subnet_ids         = local.proxy_subnet_ids

  auth {
    auth_scheme = "SECRETS"
    iam_auth    = "DISABLED"
    secret_arn  = aws_db_instance.this.master_user_secret[0].secret_arn
  }

  tags = merge(var.tags, { Name = "${local.name}-postgres" })

  depends_on = [aws_iam_role_policy.proxy_secret]

  lifecycle {
    precondition {
      condition     = length(local.proxy_subnet_ids) >= 2
      error_message = "RDS Proxy needs private subnets in at least two supported AZs. use1-az3 and usw1-az2 are excluded by AWS."
    }
  }
}

resource "aws_db_proxy_default_target_group" "this" {
  db_proxy_name = aws_db_proxy.this.name

  connection_pool_config {
    connection_borrow_timeout    = var.proxy_connection_borrow_timeout_seconds
    init_query                   = "SET statement_timeout = '5s'; SET lock_timeout = '2s'"
    max_connections_percent      = var.proxy_max_connections_percent
    max_idle_connections_percent = var.proxy_max_idle_connections_percent
  }
}

resource "aws_db_proxy_target" "this" {
  db_instance_identifier = aws_db_instance.this.identifier
  db_proxy_name          = aws_db_proxy.this.name
  target_group_name      = aws_db_proxy_default_target_group.this.name
}

resource "aws_cloudwatch_metric_alarm" "proxy_connection_setup_failed" {
  alarm_name        = "${local.name}-postgres-proxy-connection-setup-failed"
  alarm_description = "RDS Proxy could not establish a backend PostgreSQL connection."

  namespace   = "AWS/RDS"
  metric_name = "DatabaseConnectionsSetupFailed"
  statistic   = "Sum"
  dimensions = {
    ProxyName = aws_db_proxy.this.name
  }

  period              = 60
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  alarm_actions = var.alarm_action_arns
  ok_actions    = var.alarm_action_arns

  tags = merge(var.tags, { Name = "${local.name}-postgres-proxy-connection-setup-failed" })
}

resource "aws_cloudwatch_metric_alarm" "proxy_client_authentication_failed" {
  alarm_name        = "${local.name}-postgres-proxy-client-authentication-failed"
  alarm_description = "RDS Proxy rejected a client authentication attempt. The client may hold a password that no longer matches the managed secret."

  namespace   = "AWS/RDS"
  metric_name = "ClientConnectionsSetupFailedAuth"
  statistic   = "Sum"
  dimensions = {
    ProxyName = aws_db_proxy.this.name
  }

  period              = 60
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  alarm_actions = var.alarm_action_arns
  ok_actions    = var.alarm_action_arns

  tags = merge(var.tags, { Name = "${local.name}-postgres-proxy-client-authentication-failed" })
}

resource "aws_cloudwatch_metric_alarm" "proxy_pool_saturation" {
  alarm_name        = "${local.name}-postgres-proxy-pool-saturation"
  alarm_description = "RDS Proxy borrowed backend connections exceeded 80% of its allowed pool for three minutes. This is an operational headroom threshold, not a product SLA."

  comparison_operator = "GreaterThanThreshold"
  threshold           = 80
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  treat_missing_data  = "notBreaching"

  metric_query {
    id          = "borrowed"
    return_data = false

    metric {
      namespace   = "AWS/RDS"
      metric_name = "DatabaseConnectionsCurrentlyBorrowed"
      dimensions = {
        ProxyName = aws_db_proxy.this.name
      }
      period = 60
      stat   = "Sum"
    }
  }

  metric_query {
    id          = "allowed"
    return_data = false

    metric {
      namespace   = "AWS/RDS"
      metric_name = "MaxDatabaseConnectionsAllowed"
      dimensions = {
        ProxyName = aws_db_proxy.this.name
      }
      period = 60
      stat   = "Sum"
    }
  }

  metric_query {
    id          = "utilization"
    expression  = "IF(allowed > 0, 100 * borrowed / allowed, 0)"
    label       = "RDS Proxy backend pool utilization percent"
    return_data = true
  }

  alarm_actions = var.alarm_action_arns
  ok_actions    = var.alarm_action_arns

  tags = merge(var.tags, { Name = "${local.name}-postgres-proxy-pool-saturation" })
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
