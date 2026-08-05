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

check "oci_deploy_sync_wait_fits_under_the_edge" {
  assert {
    condition     = var.oci_deploy_sync_wait_ms < var.public_ingress_idle_timeout_seconds * 1000
    error_message = "oci_deploy_sync_wait_ms must be below the ALB idle timeout, or the ALB answers 504 before the control plane can answer 202."
  }
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

          env {
            name  = "CATS_OCI_DEPLOY_SYNC_WAIT_MS"
            value = tostring(var.oci_deploy_sync_wait_ms)
          }

          # The control store reads its DSN from CATS_POSTGRES_URL (delivered
          # by the runtime Secret below) and verifies RDS TLS with this CA.
          env {
            name  = "CATS_CONTROL_POSTGRES_CA_FILE"
            value = "/etc/cats/rds-ca.pem"
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
            name       = "rds-ca"
            mount_path = "/etc/cats/rds-ca.pem"
            sub_path   = "rds-ca.pem"
            read_only  = true
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
      # Without this the ALB keeps the AWS default of 60 s and cuts off longer
      # requests with a 504 that misreports work which is still running.
      "alb.ingress.kubernetes.io/load-balancer-attributes" = "idle_timeout.timeout_seconds=${var.public_ingress_idle_timeout_seconds}"
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

# In-cluster reconciliation of the database credential (ADR-0029, #77).
#
# The deployment composes the DSNs from the RDS managed master secret, so a
# deploy can no longer carry a stale password forward. This closes the window
# the deploy cannot: RDS rotates on a schedule, and a Pod that restarts for any
# other reason before the next deploy -- OOM, eviction, node drain -- would read
# a Secret nobody refreshed and crash-loop.
#
# The AWS identity is a Pod Identity association created in the infrastructure
# state, deliberately not here: the automated deployment's IAM permissions are
# scoped tightly and should not grow the ability to mint roles.
#
# Set credential_refresher_image to enable it. Left null, none of this exists.

resource "kubernetes_service_account_v1" "credential_refresher" {
  count = var.credential_refresher_image == null ? 0 : 1

  metadata {
    name      = var.credential_refresher_service_account
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels = merge(local.labels, {
      "app.kubernetes.io/name" = "cats-credential-refresher"
    })
  }
}

# get and patch, on one Secret, by name. It cannot list Secrets, cannot reach
# another namespace, and cannot create or delete anything.
resource "kubernetes_role_v1" "credential_refresher" {
  count = var.credential_refresher_image == null ? 0 : 1

  metadata {
    name      = "cats-credential-refresher"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels    = local.labels
  }

  rule {
    api_groups     = [""]
    resources      = ["secrets"]
    resource_names = [kubernetes_secret_v1.runtime.metadata[0].name]
    verbs          = ["get", "patch"]
  }
}

resource "kubernetes_role_binding_v1" "credential_refresher" {
  count = var.credential_refresher_image == null ? 0 : 1

  metadata {
    name      = "cats-credential-refresher"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels    = local.labels
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role_v1.credential_refresher[0].metadata[0].name
  }

  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account_v1.credential_refresher[0].metadata[0].name
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
  }
}

resource "kubernetes_cron_job_v1" "credential_refresher" {
  count = var.credential_refresher_image == null ? 0 : 1

  metadata {
    name      = "cats-credential-refresher"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels    = local.labels
  }

  spec {
    schedule                      = var.credential_refresher_schedule
    concurrency_policy            = "Forbid"
    starting_deadline_seconds     = 300
    successful_jobs_history_limit = 3
    failed_jobs_history_limit     = 3

    job_template {
      metadata {
        labels = local.labels
      }

      spec {
        backoff_limit = 2
        # Bounded so a hung run cannot block the next window forever.
        active_deadline_seconds = 240

        template {
          metadata {
            labels = merge(local.labels, {
              "app.kubernetes.io/name" = "cats-credential-refresher"
            })
            annotations = {
              "cats.run/rds-ca-sha256" = sha256(local.rds_ca_pem)
            }
          }

          spec {
            restart_policy = "Never"
            # Unlike the control plane, this Pod needs its token: the Secret
            # patch goes through the Kubernetes API, authenticated as this
            # ServiceAccount. AWS credentials arrive out of band, through the
            # Pod Identity agent.
            service_account_name = kubernetes_service_account_v1.credential_refresher[0].metadata[0].name
            enable_service_links = false

            node_selector = {
              "kubernetes.io/arch" = "amd64"
            }

            container {
              name              = "refresher"
              image             = var.credential_refresher_image
              image_pull_policy = "IfNotPresent"

              env {
                name  = "CATS_POSTGRES_SECRET_ARN"
                value = var.database_master_user_secret_arn
              }

              env {
                name  = "CATS_RUNTIME_SECRET_NAME"
                value = kubernetes_secret_v1.runtime.metadata[0].name
              }

              # `report` verifies everything and writes nothing. Prove it judges
              # correctly against the real instance before granting it the write
              # (ADR-0029 staging); then flip this to `patch`.
              env {
                name  = "CATS_REFRESH_MODE"
                value = var.credential_refresher_mode
              }

              env {
                name  = "AWS_REGION"
                value = var.usage_aws_region
              }

              env {
                name  = "CATS_POSTGRES_CA_FILE"
                value = "/etc/cats/rds-ca.pem"
              }

              volume_mount {
                name       = "rds-ca"
                mount_path = "/etc/cats/rds-ca.pem"
                sub_path   = "rds-ca.pem"
                read_only  = true
              }

              resources {
                requests = {
                  cpu    = "50m"
                  memory = "128Mi"
                }
                limits = {
                  memory = "256Mi"
                }
              }

              security_context {
                allow_privilege_escalation = false
                read_only_root_filesystem  = false
                capabilities {
                  drop = ["ALL"]
                }
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
    }
  }
}

# An image without the secret it reconciles against would deploy a CronJob that
# fails on every run. Refuse at plan time instead.
check "the_refresher_knows_its_authority" {
  assert {
    condition = (
      var.credential_refresher_image == null ||
      var.database_master_user_secret_arn != null
    )
    error_message = "credential_refresher_image is set but database_master_user_secret_arn is not; the refresher would have nothing to reconcile against."
  }
}
