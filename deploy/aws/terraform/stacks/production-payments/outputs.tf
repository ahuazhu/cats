output "topup_price_ids" {
  description = "Map of USD cents to immutable Stripe Price IDs."
  value = {
    for amount, price in stripe_price.topup : amount => price.id
  }
}

output "webhook_endpoint_id" {
  value = stripe_webhook_endpoint.billing.id
}

output "webhook_secret" {
  description = "Stripe signing secret. Pass to the application stack through an approved secret channel."
  value       = stripe_webhook_endpoint.billing.secret
  sensitive   = true
}
