output "instance_identifier" {
  value = aws_db_instance.this.identifier
}

output "endpoint" {
  description = "host:port"
  value       = aws_db_instance.this.endpoint
}

output "address" {
  value = aws_db_instance.this.address
}

output "port" {
  value = aws_db_instance.this.port
}

output "proxy_endpoint" {
  description = "TLS-only RDS Proxy hostname for the storage/control DSN. Usage and rollback clients retain the direct instance endpoint."
  value       = aws_db_proxy.this.endpoint
}

output "proxy_security_group_id" {
  value = aws_security_group.proxy.id
}

output "database_name" {
  value = aws_db_instance.this.db_name
}

output "master_username" {
  value = aws_db_instance.this.username
}

# Read the generated password from here to assemble storage_postgres_url and
# usage_postgres_url for the application stack. The value never enters this
# state.
output "master_user_secret_arn" {
  value = aws_db_instance.this.master_user_secret[0].secret_arn
}

output "security_group_id" {
  value = aws_security_group.this.id
}

output "postgresql_log_group_name" {
  description = "Where the server states a connection failure plainly. Read this first when new connections fail while established ones keep working."
  value       = aws_cloudwatch_log_group.postgresql.name
}

output "password_authentication_alarm_name" {
  value = aws_cloudwatch_metric_alarm.password_authentication_failed.alarm_name
}

output "proxy_connection_setup_alarm_name" {
  value = aws_cloudwatch_metric_alarm.proxy_connection_setup_failed.alarm_name
}

output "proxy_client_authentication_alarm_name" {
  value = aws_cloudwatch_metric_alarm.proxy_client_authentication_failed.alarm_name
}

output "proxy_pool_saturation_alarm_name" {
  value = aws_cloudwatch_metric_alarm.proxy_pool_saturation.alarm_name
}
