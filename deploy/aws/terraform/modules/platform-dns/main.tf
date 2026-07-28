# Public DNS zone and the ALB certificate.
#
# A Route 53 hosted zone cannot move between accounts, so this creates a new
# zone with new name servers. The domain is registered outside Route 53, which
# means the cutover step is a registrar change, not an AWS operation.
#
# Ordering matters. ACM's DNS validation can only succeed once the registrar
# points at this zone's name servers, so `wait_for_validation` defaults to
# false: the first apply creates the zone, requests the certificate and writes
# the validation records without blocking. Read `name_servers`, change them at
# the registrar, then re-apply with the flag set (or simply wait — ACM polls
# and issues on its own).

resource "aws_route53_zone" "this" {
  name    = var.domain_name
  comment = "Cats ${var.environment}"

  tags = merge(var.tags, { Name = var.domain_name })
}

resource "aws_acm_certificate" "this" {
  domain_name               = var.domain_name
  subject_alternative_names = ["*.${var.domain_name}"]
  validation_method         = "DNS"

  tags = merge(var.tags, { Name = var.domain_name })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "validation" {
  for_each = {
    for o in aws_acm_certificate.this.domain_validation_options : o.domain_name => {
      name  = o.resource_record_name
      type  = o.resource_record_type
      value = o.resource_record_value
    }
  }

  zone_id         = aws_route53_zone.this.zone_id
  name            = each.value.name
  type            = each.value.type
  records         = [each.value.value]
  ttl             = 60
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "this" {
  count = var.wait_for_validation ? 1 : 0

  certificate_arn         = aws_acm_certificate.this.arn
  validation_record_fqdns = [for r in aws_route53_record.validation : r.fqdn]

  timeouts {
    create = var.validation_timeout
  }
}
