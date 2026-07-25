variable "topup_amounts_cents" {
  description = "Fixed USD prepaid top-up amounts exposed by Cats Checkout."
  type        = set(number)
  default     = [1000, 2500, 5000, 10000]

  validation {
    condition = (
      length(var.topup_amounts_cents) > 0 &&
      alltrue([
        for amount in var.topup_amounts_cents :
        amount >= 500 && amount <= 100000 && floor(amount) == amount
      ])
    )
    error_message = "topup_amounts_cents must contain integer USD-cent amounts from 500 through 100000."
  }
}

variable "webhook_url" {
  description = "Public Cats endpoint that receives signed Stripe events."
  type        = string
  default     = "https://cats.run/v1/billing/stripe/webhook"

  validation {
    condition     = startswith(var.webhook_url, "https://")
    error_message = "webhook_url must use HTTPS."
  }
}
