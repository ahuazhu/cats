output "kinesis_stream_name" {
  description = "Usage checkpoint Kinesis stream name."
  value       = aws_kinesis_stream.usage.name
}

output "kinesis_stream_arn" {
  description = "Usage checkpoint Kinesis stream ARN."
  value       = aws_kinesis_stream.usage.arn
}

output "archive_bucket_name" {
  description = "Immutable raw usage archive bucket."
  value       = aws_s3_bucket.archive.id
}

output "archive_bucket_arn" {
  description = "Immutable raw usage archive bucket ARN."
  value       = aws_s3_bucket.archive.arn
}

output "consumer_lease_table_name" {
  description = "DynamoDB projector checkpoint table; multi-consumer leases are not implemented yet."
  value       = aws_dynamodb_table.consumer_leases.name
}

output "producer_policy_arn" {
  description = "Attach to the service role that publishes usage checkpoints."
  value       = aws_iam_policy.producer.arn
}

output "consumer_policy_arn" {
  description = "Attach to the usage projector/archive-writer service role."
  value       = aws_iam_policy.consumer.arn
}

output "replay_policy_arn" {
  description = "Attach only to controlled replay/reconciliation jobs."
  value       = aws_iam_policy.replay.arn
}

output "pipeline_role_arn" {
  description = "EKS Pod Identity role for the usage producer/projector."
  value       = aws_iam_role.pipeline.arn
}

output "pod_identity_association_id" {
  description = "EKS Pod Identity association for cats-controld."
  value       = aws_eks_pod_identity_association.pipeline.association_id
}
