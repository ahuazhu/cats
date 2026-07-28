output "zone_id" {
  value = aws_route53_zone.this.zone_id
}

output "zone_name" {
  value = aws_route53_zone.this.name
}

# Set these four at the registrar to complete the cutover.
output "name_servers" {
  value = aws_route53_zone.this.name_servers
}

output "certificate_arn" {
  description = "Feed this to the application stack's acm_certificate_arn."
  value       = aws_acm_certificate.this.arn
}

output "certificate_status" {
  value = aws_acm_certificate.this.status
}

output "certificate_domains" {
  value = concat([aws_acm_certificate.this.domain_name], aws_acm_certificate.this.subject_alternative_names)
}
