locals {
  labels = {
    "app.kubernetes.io/part-of"    = "cats"
    "app.kubernetes.io/managed-by" = "terraform"
  }

  runtime_secret_data = merge(
    var.runtime_secret_data,
    {
      CATS_POSTGRES_URL           = var.storage_postgres_url
      CATS_USAGE_STORE_ADAPTER    = "postgres"
      CATS_USAGE_POSTGRES_URL     = var.usage_postgres_url
      CATS_USAGE_POSTGRES_SCHEMA  = var.usage_postgres_schema
      CATS_USAGE_POSTGRES_WORKERS = tostring(var.usage_postgres_workers)
      CATS_USAGE_POSTGRES_CA_FILE = "/etc/cats/rds-ca.pem"
      CATS_USAGE_DELIVERY_ADAPTER = var.usage_delivery_adapter
      CATS_USAGE_AWS_REGION       = var.usage_aws_region
      CATS_USAGE_KINESIS_STREAM   = var.usage_kinesis_stream
      CATS_USAGE_ARCHIVE_BUCKET   = var.usage_archive_bucket
      CATS_USAGE_CHECKPOINT_TABLE = var.usage_checkpoint_table
    },
    var.stripe_enabled ? {
      STRIPE_SECRET_KEY                = coalesce(var.stripe_secret_key, "")
      STRIPE_WEBHOOK_SECRET            = coalesce(var.stripe_webhook_secret, "")
      CATS_STRIPE_TOPUP_PRICES         = join(",", [for amount, price_id in var.stripe_topup_price_ids : "${amount}=${price_id}"])
      CATS_STRIPE_CHECKOUT_SUCCESS_URL = var.stripe_checkout_success_url
      CATS_STRIPE_CHECKOUT_CANCEL_URL  = var.stripe_checkout_cancel_url
      CATS_STRIPE_LIVEMODE             = tostring(var.stripe_livemode)
      CATS_BILLING_ENFORCEMENT_ENABLED = "true"
    } : {}
  )

  gateway_secret_data = {
    CATS_AUTH_TOKEN = var.runtime_secret_data["CATS_AUTH_TOKEN"]
  }

  rds_ca_pem = "${trimspace(var.rds_ca_pem)}\n"

  ingress_routes = concat(
    [
      for host in var.control_plane_hosts : {
        host         = host
        service_name = "cats-controld"
        service_port = 7300
      }
    ],
    [{
      host         = var.endpoint_wildcard_host
      service_name = "cats-gatewayd"
      service_port = 7400
    }]
  )
}

check "usage_delivery_configuration" {
  assert {
    condition = var.usage_delivery_adapter != "aws-kinesis" || alltrue([
      length(trimspace(var.usage_aws_region)) > 0,
      length(trimspace(var.usage_kinesis_stream)) > 0,
      length(trimspace(var.usage_archive_bucket)) > 0,
      length(trimspace(var.usage_checkpoint_table)) > 0,
    ])
    error_message = "aws-kinesis usage delivery requires region, stream, archive bucket and checkpoint table."
  }
}

check "stripe_configuration" {
  assert {
    condition = !var.stripe_enabled || (
      var.stripe_secret_key != null &&
      var.stripe_webhook_secret != null &&
      length(var.stripe_topup_price_ids) > 0 &&
      startswith(coalesce(var.stripe_webhook_secret, ""), "whsec_") &&
      (
        var.stripe_livemode
        ? can(regex("^(sk|rk)_live_", coalesce(var.stripe_secret_key, "")))
        : can(regex("^(sk|rk)_test_", coalesce(var.stripe_secret_key, "")))
      ) &&
      alltrue([
        for amount, price_id in var.stripe_topup_price_ids :
        try(tonumber(amount) > 0, false) && startswith(price_id, "price_")
      ])
    )
    error_message = "Stripe requires secret/webhook keys and at least one cents-to-price mapping."
  }
}

resource "kubernetes_namespace_v1" "cats" {
  metadata {
    name = var.namespace
    labels = merge(local.labels, {
      "cats.run/ingress" = "enabled"
    })
  }
}

resource "kubernetes_storage_class_v1" "control_data" {
  metadata {
    name   = var.control_data_storage_class
    labels = local.labels
  }

  storage_provisioner    = "ebs.csi.eks.amazonaws.com"
  volume_binding_mode    = "WaitForFirstConsumer"
  allow_volume_expansion = true

  allowed_topologies {
    match_label_expressions {
      key    = "eks.amazonaws.com/compute-type"
      values = ["auto"]
    }
  }

  parameters = {
    type               = "gp3"
    encrypted          = "true"
    tagSpecification_1 = "Project=Cats"
  }
}

resource "kubernetes_persistent_volume_claim_v1" "control_data" {
  metadata {
    name      = "cats-control-data"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels    = local.labels
  }

  # The storage class binds WaitForFirstConsumer, so the claim stays Pending
  # until a Pod schedules against it. Waiting for Bound here deadlocks: the
  # claim waits for the Deployment and Terraform waits for the claim. This only
  # shows up on a fresh cluster -- an imported claim is already bound.
  wait_until_bound = false

  spec {
    access_modes       = ["ReadWriteOnce"]
    storage_class_name = kubernetes_storage_class_v1.control_data.metadata[0].name

    resources {
      requests = {
        storage = var.control_data_size
      }
    }
  }
}

resource "kubernetes_service_account_v1" "control_plane" {
  metadata {
    name      = "cats-controld"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels = merge(local.labels, {
      "app.kubernetes.io/name" = "cats-controld"
    })
  }

  automount_service_account_token = false
}

resource "kubernetes_secret_v1" "runtime" {
  metadata {
    name      = "cats-runtime"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels    = local.labels
  }

  type = "Opaque"
  data = local.runtime_secret_data
}

resource "kubernetes_secret_v1" "gateway_runtime" {
  metadata {
    name      = "cats-gateway-runtime"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels    = local.labels
  }

  type = "Opaque"
  data = local.gateway_secret_data
}

resource "kubernetes_config_map_v1" "rds_ca" {
  metadata {
    name      = "cats-rds-ca"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels    = local.labels
  }

  data = {
    "rds-ca.pem" = local.rds_ca_pem
  }
}

resource "kubernetes_deployment_v1" "control_plane" {
  metadata {
    name      = "cats-controld"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels = merge(local.labels, {
      "app.kubernetes.io/name" = "cats-controld"
    })
  }

  spec {
    replicas = 1

    strategy {
      type = "Recreate"
    }

    selector {
      match_labels = {
        "app.kubernetes.io/name" = "cats-controld"
      }
    }

    template {
      metadata {
        labels = merge(local.labels, {
          "app.kubernetes.io/name" = "cats-controld"
        })
        annotations = {
          "cats.run/runtime-secret-sha256" = sha256(jsonencode(local.runtime_secret_data))
          "cats.run/rds-ca-sha256"         = sha256(local.rds_ca_pem)
        }
      }

      spec {
        automount_service_account_token  = false
        enable_service_links             = false
        service_account_name             = kubernetes_service_account_v1.control_plane.metadata[0].name
        termination_grace_period_seconds = 5

        security_context {
          fs_group               = 10001
          fs_group_change_policy = "OnRootMismatch"
        }

        node_selector = {
          "kubernetes.io/arch" = "amd64"
        }

        container {
          name              = "controld"
          image             = var.control_plane_image
          image_pull_policy = "IfNotPresent"

          args = [
            "--listen",
            "0.0.0.0:7300",
            "--db-path",
            "/var/lib/cats/control/control.db",
            "--metadata-store-adapter",
            "postgres",
            "--metadata-store-option",
            "ca-file=/etc/cats/rds-ca.pem",
          ]

          env {
            name  = "CATS_AUTO_WARM_AFTER_SECONDS"
            value = tostring(var.auto_warm_after_seconds)
          }

          env {
            name  = "CATS_AUTO_COLD_AFTER_SECONDS"
            value = tostring(var.auto_cold_after_seconds)
          }

          env_from {
            secret_ref {
              name = kubernetes_secret_v1.runtime.metadata[0].name
            }
          }

          port {
            name           = "http"
            container_port = 7300
          }

          resources {
            requests = {
              cpu    = "100m"
              memory = "512Mi"
            }
            limits = {
              cpu    = "1"
              memory = "2Gi"
            }
          }

          startup_probe {
            http_get {
              path = "/healthz"
              port = "http"
            }
            failure_threshold = 30
            period_seconds    = 5
          }

          readiness_probe {
            http_get {
              path = "/healthz"
              port = "http"
            }
            period_seconds = 5
          }

          liveness_probe {
            http_get {
              path = "/healthz"
              port = "http"
            }
            period_seconds = 15
          }

          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            run_as_non_root            = true
            run_as_user                = 10001

            capabilities {
              drop = ["ALL"]
            }
          }

          volume_mount {
            name       = "control-data"
            mount_path = "/var/lib/cats/control"
          }

          volume_mount {
            name       = "rds-ca"
            mount_path = "/etc/cats/rds-ca.pem"
            sub_path   = "rds-ca.pem"
            read_only  = true
          }
        }

        volume {
          name = "control-data"

          persistent_volume_claim {
            claim_name = kubernetes_persistent_volume_claim_v1.control_data.metadata[0].name
          }
        }

        volume {
          name = "rds-ca"

          config_map {
            name = kubernetes_config_map_v1.rds_ca.metadata[0].name
          }
        }
      }
    }
  }

  wait_for_rollout = true
}

resource "kubernetes_service_v1" "control_plane" {
  metadata {
    name      = "cats-controld"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels    = local.labels
  }

  spec {
    selector = {
      "app.kubernetes.io/name" = "cats-controld"
    }

    port {
      name        = "http"
      port        = 7300
      target_port = "http"
    }
  }
}

resource "kubernetes_deployment_v1" "gateway" {
  metadata {
    name      = "cats-gatewayd"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels = merge(local.labels, {
      "app.kubernetes.io/name" = "cats-gatewayd"
    })
  }

  spec {
    replicas = var.gateway_replicas

    selector {
      match_labels = {
        "app.kubernetes.io/name" = "cats-gatewayd"
      }
    }

    template {
      metadata {
        labels = merge(local.labels, {
          "app.kubernetes.io/name" = "cats-gatewayd"
        })
        annotations = {
          "cats.run/runtime-secret-sha256" = sha256(jsonencode(local.gateway_secret_data))
        }
      }

      spec {
        automount_service_account_token = false
        enable_service_links            = false

        node_selector = {
          "kubernetes.io/arch" = "amd64"
        }

        container {
          name              = "gatewayd"
          image             = var.gateway_image
          image_pull_policy = "IfNotPresent"
          command           = ["/usr/local/bin/cats-gatewayd"]

          args = [
            "--listen",
            "0.0.0.0:7400",
            "--control-plane-url",
            "http://cats-controld:7300",
          ]

          env_from {
            secret_ref {
              name = kubernetes_secret_v1.gateway_runtime.metadata[0].name
            }
          }

          port {
            name           = "http"
            container_port = 7400
          }

          resources {
            requests = {
              cpu    = "50m"
              memory = "64Mi"
            }
            limits = {
              cpu    = "500m"
              memory = "256Mi"
            }
          }

          readiness_probe {
            http_get {
              path = "/healthz"
              port = "http"
            }
            period_seconds = 5
          }

          liveness_probe {
            http_get {
              path = "/healthz"
              port = "http"
            }
            period_seconds = 15
          }

          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            run_as_non_root            = true
            run_as_user                = 10001

            capabilities {
              drop = ["ALL"]
            }
          }
        }
      }
    }
  }

  wait_for_rollout = true
}

resource "kubernetes_service_v1" "gateway" {
  metadata {
    name      = "cats-gatewayd"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels    = local.labels
  }

  spec {
    selector = {
      "app.kubernetes.io/name" = "cats-gatewayd"
    }

    port {
      name        = "http"
      port        = 7400
      target_port = "http"
    }
  }
}

resource "kubernetes_manifest" "ingress_class_params" {
  for_each = var.enable_public_ingress ? toset(["enabled"]) : toset([])

  manifest = {
    apiVersion = "eks.amazonaws.com/v1"
    kind       = "IngressClassParams"
    metadata = {
      name = var.ingress_class_name
    }
    spec = {
      scheme        = "internet-facing"
      targetType    = "ip"
      ipAddressType = "ipv4"
      certificateARNs = [
        var.acm_certificate_arn,
      ]
      listeners = [
        {
          protocol = "HTTP"
          port     = 80
        },
        {
          protocol = "HTTPS"
          port     = 443
        },
      ]
      namespaceSelector = {
        matchLabels = {
          "cats.run/ingress" = "enabled"
        }
      }
      subnets = {
        ids = var.public_subnet_ids
      }
    }
  }
}

resource "kubernetes_ingress_class_v1" "public" {
  count = var.enable_public_ingress ? 1 : 0

  metadata {
    name   = var.ingress_class_name
    labels = local.labels
  }

  spec {
    controller = "eks.amazonaws.com/alb"

    parameters {
      api_group = "eks.amazonaws.com"
      kind      = "IngressClassParams"
      name      = var.ingress_class_name
    }
  }

  depends_on = [kubernetes_manifest.ingress_class_params]
}

resource "kubernetes_ingress_v1" "public" {
  count = var.enable_public_ingress ? 1 : 0

  metadata {
    name      = "cats-public"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels    = local.labels
    annotations = {
      "alb.ingress.kubernetes.io/healthcheck-path" = "/healthz"
      "alb.ingress.kubernetes.io/ssl-redirect"     = "443"
    }
  }

  spec {
    ingress_class_name = kubernetes_ingress_class_v1.public[0].metadata[0].name

    dynamic "rule" {
      for_each = local.ingress_routes

      content {
        host = rule.value.host

        http {
          path {
            path      = "/"
            path_type = "Prefix"

            backend {
              service {
                name = rule.value.service_name

                port {
                  number = rule.value.service_port
                }
              }
            }
          }
        }
      }
    }
  }

  depends_on = [
    kubernetes_deployment_v1.control_plane,
    kubernetes_deployment_v1.gateway,
  ]
}
