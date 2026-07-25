locals {
  topup_amounts = {
    for amount in var.topup_amounts_cents : tostring(amount) => amount
  }
}

resource "stripe_product" "prepaid_credit" {
  name        = "Cats prepaid credit"
  description = "Prepaid USD credit for Cats compute usage."

  metadata = {
    product = "cats"
    purpose = "prepaid-credit"
  }
}

resource "stripe_price" "topup" {
  for_each = local.topup_amounts

  product     = stripe_product.prepaid_credit.id
  currency    = "usd"
  unit_amount = each.value
  nickname    = format("Cats $%.2f prepaid credit", each.value / 100)

  metadata = {
    product             = "cats"
    purpose             = "prepaid-topup"
    credit_amount_cents = tostring(each.value)
  }
}

resource "stripe_webhook_endpoint" "billing" {
  url         = var.webhook_url
  description = "Cats prepaid credit settlement and reversal"
  enabled_events = [
    "checkout.session.completed",
    "checkout.session.async_payment_succeeded",
    "refund.created",
    "refund.updated",
  ]

  metadata = {
    product = "cats"
    owner   = "billing"
  }
}
