locals {
  # Kubernetes marks a terminating Pod unready and starts preStop before it
  # sends SIGTERM. Keep the HTTP server alive while the EndpointSlice and EKS
  # Auto Mode ALB remove that target; otherwise the ALB can route to a process
  # that has already exited during the propagation window.
  public_target_pre_stop_delay_seconds           = 15
  public_target_termination_grace_period_seconds = 60

  labels = {
    "app.kubernetes.io/part-of"    = "cats"
    "app.kubernetes.io/managed-by" = "terraform"
  }

  effective_control_plane_replicas = var.maintenance_mode ? 0 : var.control_plane_replicas
  effective_public_ingress         = var.enable_public_ingress && !var.maintenance_mode

  # These immutable pre-created Secrets carry two different SECURITY DEFINER
  # caller roles. Terraform receives only their fixed names, never either DSN.
  runtime_secret_data = merge(
    var.runtime_secret_data,
    {
      # Node authenticates this direct Control-to-Node protocol as
      # CATS_AUTH_TOKEN. Control names the same credential by its purpose so
      # it cannot be confused with the client-facing API token argument.
      CATS_NODED_SERVICE_TOKEN     = var.runtime_secret_data["CATS_AUTH_TOKEN"]
      CATS_BOOT_IMAGE              = var.default_boot_image_digest
      CATS_USER_SITE_URL           = "https://cats.run/user/"
      CATS_ADMIN_SITE_URL          = "https://ops.cats.run/"
      CATS_POSTGRES_URL            = var.storage_postgres_url
      CATS_USAGE_STORE_ADAPTER     = "postgres"
      CATS_USAGE_POSTGRES_URL      = var.usage_postgres_url
      CATS_USAGE_POSTGRES_URL_FILE = "/etc/cats/runtime/CATS_USAGE_POSTGRES_URL"
      CATS_USAGE_POSTGRES_SCHEMA   = var.usage_postgres_schema
      CATS_USAGE_POSTGRES_WORKERS  = tostring(var.usage_postgres_workers)
      CATS_USAGE_POSTGRES_CA_FILE  = "/etc/cats/rds-ca.pem"
      CATS_USAGE_DELIVERY_ADAPTER  = var.usage_delivery_adapter
      CATS_USAGE_AWS_REGION        = var.usage_aws_region
      CATS_USAGE_KINESIS_STREAM    = var.usage_kinesis_stream
      CATS_USAGE_ARCHIVE_BUCKET    = var.usage_archive_bucket
      CATS_USAGE_CHECKPOINT_TABLE  = var.usage_checkpoint_table
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

  rds_ca_pem = "${trimspace(var.rds_ca_pem)}\n"

  ingress_routes = [
    for host in var.control_plane_hosts : {
      host         = host
      service_name = "cats-controld"
      service_port = 7300
    }
  ]
}

check "public_target_drain_fits_termination_grace" {
  assert {
    condition     = local.public_target_pre_stop_delay_seconds + 30 <= local.public_target_termination_grace_period_seconds
    error_message = "public target termination grace must leave at least 30 seconds after preStop for commit-resolution shutdown."
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

check "control_postgres_search_path" {
  assert {
    condition = (
      length(regexall("(^|[?&])options=", var.storage_postgres_url)) == 1 &&
      length(regexall("(^|[?&])options=-csearch_path%3D${var.control_postgres_schema}(&|$)", var.storage_postgres_url)) == 1
    )
    error_message = "storage_postgres_url must select exactly control_postgres_schema through one canonical options=-csearch_path%3D<schema> query item."
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
      "cats.run/ingress" = local.effective_public_ingress ? "enabled" : "disabled"
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

# Public deployment-provisioner trust is a rollout-pinned artifact, not a
# credential. A subPath bind mount gives the process one root-owned regular
# 0644 file instead of Kubernetes' symlink-based projected-volume entry; the
# A23 descriptor reader deliberately rejects symlinks and hot reload.
resource "kubernetes_config_map_v1" "runtime_provisioner_trust" {
  metadata {
    name      = "cats-runtime-provisioner-trust"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels    = local.labels
  }

  data = {
    "runtime-provisioner-trust.v1.json" = var.runtime_provisioner_trust_bundle_json
  }
}

# Release-bound public E13 operator trust. cats-controld loads this at startup
# through the same reader as the provisioner trust and refuses to start without
# it, so it is a deployment input rather than an optional extra.
resource "kubernetes_config_map_v1" "production_cutover_operator_trust" {
  metadata {
    name      = "cats-production-cutover-operator-trust"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels    = local.labels
  }

  data = {
    "production-cutover-operator-trust.v1.json" = var.production_cutover_operator_trust_bundle_json
  }
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
    replicas = local.effective_control_plane_replicas

    strategy {
      type = "RollingUpdate"

      rolling_update {
        max_surge       = "1"
        max_unavailable = "0"
      }
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
          "cats.run/runtime-secret-sha256"                    = sha256(jsonencode(local.runtime_secret_data))
          "cats.run/runtime-provisioner-trust-sha256"         = sha256(var.runtime_provisioner_trust_bundle_json)
          "cats.run/production-cutover-operator-trust-sha256" = sha256(var.production_cutover_operator_trust_bundle_json)
          "cats.run/rds-ca-sha256"                            = sha256(local.rds_ca_pem)
        }
      }

      spec {
        automount_service_account_token  = false
        enable_service_links             = false
        service_account_name             = kubernetes_service_account_v1.control_plane.metadata[0].name
        termination_grace_period_seconds = local.public_target_termination_grace_period_seconds

        node_selector = {
          "kubernetes.io/arch" = "amd64"
        }

        affinity {
          pod_anti_affinity {
            required_during_scheduling_ignored_during_execution {
              topology_key = "kubernetes.io/hostname"

              label_selector {
                match_labels = {
                  "app.kubernetes.io/name" = "cats-controld"
                }
              }
            }
          }
        }

        topology_spread_constraint {
          max_skew           = 1
          topology_key       = "kubernetes.io/hostname"
          when_unsatisfiable = "DoNotSchedule"

          label_selector {
            match_labels = {
              "app.kubernetes.io/name" = "cats-controld"
            }
          }
        }


        container {
          name              = "controld"
          image             = var.control_plane_image
          image_pull_policy = "IfNotPresent"

          # Pin the binary rather than trusting the image ENTRYPOINT: a
          # mis-targeted image build must not get to choose what runs as the
          # control plane (issue #117).
          command = ["/usr/local/bin/cats-controld"]

          args = [
            "--listen",
            "0.0.0.0:7300",
            "--control-store-url-file",
            "/etc/cats/runtime/CATS_POSTGRES_URL",
            "--guest-runtime-profile-receipt-file",
            "/opt/cats/release/guest-runtime-profile.v1.json",
            "--runtime-provisioner-trust-file",
            "/etc/cats/identity/runtime-provisioner-trust.v1.json",
            "--object-store-adapter",
            "aws-s3",
            "--object-store-option",
            "bucket=${var.chunkstore_bucket_name}",
            "--object-store-option",
            "region=${var.chunkstore_region}",
            "--object-store-option",
            "prefix=${var.chunkstore_prefix}",
          ]

          # All PostgreSQL clients verify RDS TLS with this CA. Their DSNs are
          # mounted as files below so reconnects observe credential rotation.
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

          lifecycle {
            pre_stop {
              exec {
                command = ["/bin/sh", "-c", "sleep ${local.public_target_pre_stop_delay_seconds}"]
              }
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
            run_as_non_root            = false
            run_as_user                = 0

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

          # Mount the whole Secret, never a subPath: kubelet updates projected
          # Secret files in place, while a subPath mount remains frozen.
          volume_mount {
            name       = "runtime-secret"
            mount_path = "/etc/cats/runtime"
            read_only  = true
          }

          volume_mount {
            name       = "runtime-provisioner-trust"
            mount_path = "/etc/cats/identity/runtime-provisioner-trust.v1.json"
            sub_path   = "runtime-provisioner-trust.v1.json"
            read_only  = true
          }

          volume_mount {
            name       = "production-cutover-operator-trust"
            mount_path = "/etc/cats/production-cutover-operator-trust.v1.json"
            sub_path   = "production-cutover-operator-trust.v1.json"
            read_only  = true
          }
        }

        volume {
          name = "rds-ca"

          config_map {
            name = kubernetes_config_map_v1.rds_ca.metadata[0].name
          }
        }

        volume {
          name = "runtime-secret"

          secret {
            secret_name = kubernetes_secret_v1.runtime.metadata[0].name
          }
        }

        volume {
          name = "runtime-provisioner-trust"

          config_map {
            name         = kubernetes_config_map_v1.runtime_provisioner_trust.metadata[0].name
            default_mode = "0644"
          }
        }

        volume {
          name = "production-cutover-operator-trust"

          config_map {
            name         = kubernetes_config_map_v1.production_cutover_operator_trust.metadata[0].name
            default_mode = "0644"
          }
        }
      }
    }
  }

  wait_for_rollout = true
}

resource "kubernetes_pod_disruption_budget_v1" "control_plane" {
  metadata {
    name      = "cats-controld"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels    = local.labels
  }

  spec {
    min_available = var.maintenance_mode ? "0" : "1"

    selector {
      match_labels = {
        "app.kubernetes.io/name" = "cats-controld"
      }
    }
  }
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

resource "kubernetes_manifest" "ingress_class_params" {
  for_each = local.effective_public_ingress ? toset(["enabled"]) : toset([])

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
  count = local.effective_public_ingress ? 1 : 0

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
  count = local.effective_public_ingress ? 1 : 0

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
    suspend                       = var.maintenance_mode
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
