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

  effective_control_plane_replicas        = var.maintenance_mode ? 0 : var.control_plane_replicas
  effective_gateway_replicas              = var.maintenance_mode ? 0 : var.gateway_replicas
  effective_object_write_gateway_replicas = var.maintenance_mode ? 0 : var.object_write_gateway_replicas
  effective_public_ingress                = var.enable_public_ingress && !var.maintenance_mode

  # These immutable pre-created Secrets carry two different SECURITY DEFINER
  # caller roles. Terraform receives only their fixed names, never either DSN.
  object_write_gateway_postgres_secret_name = "cats-object-write-gateway-postgres"
  host_fence_provider_postgres_secret_name  = "cats-host-fence-provider-postgres"

  runtime_secret_data = merge(
    var.runtime_secret_data,
    {
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

  # Control hosts retain their exact API routing. The one wildcard Endpoint
  # host is admitted only by the terminal Route v2 Gateway; it never reaches a
  # legacy in-process Gateway or a Control public handler.
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
      service_port = 8080
    }],
  )
}

# This state/plan object is deliberately non-secret. It makes a reviewed saved
# plan bind the immutable Secret identity, manifest digest, and descriptor
# revision as one rollout coordinate; the secret-channel bytes never enter
# Terraform state.
resource "terraform_data" "route_v2_control_artifact" {
  input = {
    secret_name     = var.route_v2_control_artifact_secret_name
    secret_sha256   = var.route_v2_control_artifact_secret_sha256
    signer_revision = var.route_v2_control_artifact_signer_revision
  }
}

check "public_target_drain_fits_termination_grace" {
  assert {
    condition     = local.public_target_pre_stop_delay_seconds + 30 <= local.public_target_termination_grace_period_seconds
    error_message = "public target termination grace must leave at least 30 seconds after preStop for commit-resolution shutdown."
  }
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

check "control_postgres_search_path" {
  assert {
    condition = (
      length(regexall("(^|[?&])options=", var.storage_postgres_url)) == 1 &&
      length(regexall("(^|[?&])options=-csearch_path%3D${var.control_postgres_schema}(&|$)", var.storage_postgres_url)) == 1
    )
    error_message = "storage_postgres_url must select exactly control_postgres_schema through one canonical options=-csearch_path%3D<schema> query item."
  }
}

check "provider_database_credentials_are_separate" {
  assert {
    condition     = local.object_write_gateway_postgres_secret_name != local.host_fence_provider_postgres_secret_name
    error_message = "ObjectWrite Gateway and HostFence provider must use distinct dedicated PostgreSQL role Secrets."
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

resource "kubernetes_service_account_v1" "gateway" {
  metadata {
    name      = "cats-gatewayd"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels = merge(local.labels, {
      "app.kubernetes.io/name" = "cats-gatewayd"
    })
  }

  automount_service_account_token = false
}

resource "kubernetes_service_account_v1" "object_write_gateway" {
  metadata {
    name      = "cats-object-write-gateway"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels = merge(local.labels, {
      "app.kubernetes.io/name" = "cats-object-write-gateway"
    })
  }

  # EKS Pod Identity injects its own short-lived projected token. The default
  # Kubernetes API token is neither needed nor mounted.
  automount_service_account_token = false
}

# Terraform receives only the immutable Secret name. Certificate/private-key
# bytes are release artifacts and never enter state.
resource "kubernetes_persistent_volume_v1" "object_write_spool" {
  metadata {
    name = "cats-object-write-spool"
    labels = merge(local.labels, {
      "app.kubernetes.io/name" = "cats-object-write-gateway"
    })
  }

  spec {
    capacity = {
      storage = "1Ti"
    }
    access_modes                     = ["ReadWriteMany"]
    persistent_volume_reclaim_policy = "Retain"
    storage_class_name               = ""
    mount_options                    = ["tls", "iam"]

    persistent_volume_source {
      csi {
        driver        = "efs.csi.aws.com"
        volume_handle = "${var.object_write_spool_file_system_id}::${var.object_write_spool_access_point_id}"
        volume_attributes = {
          encryptInTransit = "true"
        }
      }
    }
  }
}

resource "kubernetes_persistent_volume_claim_v1" "object_write_spool" {
  metadata {
    name      = "cats-object-write-spool"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels = merge(local.labels, {
      "app.kubernetes.io/name" = "cats-object-write-gateway"
    })
  }

  spec {
    access_modes       = ["ReadWriteMany"]
    storage_class_name = ""
    volume_name        = kubernetes_persistent_volume_v1.object_write_spool.metadata[0].name

    resources {
      requests = {
        storage = "1Ti"
      }
    }
  }

  wait_until_bound = true
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

# Separate from runtime credentials so the signing key is mounted as a file
# only in cats-controld. The future v2 Gateway receives no private signing key.
# The matching public half lets every replica prove the pair before Ready.
resource "kubernetes_secret_v1" "route_grant_signing" {
  metadata {
    name      = "cats-route-grant-signing"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels    = local.labels
  }

  type = "Opaque"
  data = {
    "private.pem" = var.route_grant_private_key_pem
    "public.pem"  = var.route_grant_public_key_pem
  }
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
          "cats.run/runtime-secret-sha256"                   = sha256(jsonencode(local.runtime_secret_data))
          "cats.run/route-grant-key-sha256"                  = sha256("${var.route_grant_private_key_pem}\n${var.route_grant_public_key_pem}")
          "cats.run/route-v2-control-artifact-secret"        = terraform_data.route_v2_control_artifact.output.secret_name
          "cats.run/route-v2-control-artifact-secret-sha256" = terraform_data.route_v2_control_artifact.output.secret_sha256
          "cats.run/route-v2-control-signer-revision"        = tostring(terraform_data.route_v2_control_artifact.output.signer_revision)
          "cats.run/runtime-provisioner-trust-sha256"        = sha256(var.runtime_provisioner_trust_bundle_json)
          "cats.run/rds-ca-sha256"                           = sha256(local.rds_ca_pem)
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

        # Kubernetes Secret projections expose symlink entries, while the
        # frozen installed-artifact reader requires one real root-owned 0700
        # directory with single-link regular files. Copy the closed key set to
        # an in-memory emptyDir before the main process starts. The projected
        # source is never mounted into the main container.
        init_container {
          name              = "route-v2-artifact-renderer"
          image             = var.control_plane_image
          image_pull_policy = "IfNotPresent"
          command           = ["/bin/sh", "-ceu"]
          args = [<<-EOT
            expected='gateway-workload-authority.v1.json gateway-client-ca-bundle.pem control-machine-server-certificate.pem control-machine-server-private-key.pem signer.v1.json public-key-ring.v1.json rotation-operator-trust.v1.json signer-private-key.pem'
            actual_count=$(find -L /var/run/cats/route-v2-source -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')
            test "$actual_count" = 8
            install -d -o 0 -g 0 -m 0700 /etc/cats/route-v2
            for name in $expected; do
              test -f "/var/run/cats/route-v2-source/$name"
              mode=0644
              case "$name" in
                control-machine-server-private-key.pem|signer-private-key.pem) mode=0600 ;;
              esac
              install -o 0 -g 0 -m "$mode" "/var/run/cats/route-v2-source/$name" "/etc/cats/route-v2/$name"
            done
            sync /etc/cats/route-v2
          EOT
          ]

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
            name       = "route-v2-control-artifact-source"
            mount_path = "/var/run/cats/route-v2-source"
            read_only  = true
          }

          volume_mount {
            name       = "route-v2-control-artifacts"
            mount_path = "/etc/cats/route-v2"
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
            "--route-v2-machine-listen",
            "0.0.0.0:7443",
            "--route-v2-rotation-listen",
            "0.0.0.0:7444",
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

          env {
            name  = "CATS_ROUTE_GRANT_PRIVATE_KEY_FILE"
            value = "/etc/cats/route-grant/private.pem"
          }

          env {
            name  = "CATS_ROUTE_GRANT_PUBLIC_KEY_FILE"
            value = "/etc/cats/route-grant/public.pem"
          }

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

          port {
            name           = "route-v2"
            container_port = 7443
          }

          port {
            name           = "route-rotation"
            container_port = 7444
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
            name       = "route-grant-signing"
            mount_path = "/etc/cats/route-grant"
            read_only  = true
          }

          volume_mount {
            name       = "route-v2-control-artifacts"
            mount_path = "/etc/cats/route-v2"
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
          name = "route-grant-signing"

          secret {
            secret_name = kubernetes_secret_v1.route_grant_signing.metadata[0].name
          }
        }

        volume {
          name = "route-v2-control-artifact-source"

          secret {
            secret_name  = terraform_data.route_v2_control_artifact.output.secret_name
            default_mode = "0400"
            optional     = false
          }
        }

        volume {
          name = "route-v2-control-artifacts"

          empty_dir {
            medium = "Memory"
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

# Machine-only mTLS listener. It is intentionally a distinct ClusterIP
# Service: no public Ingress rule can route to this port.
resource "kubernetes_service_v1" "control_plane_route_v2" {
  metadata {
    name      = "cats-controld-route-v2"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels = merge(local.labels, {
      "app.kubernetes.io/name" = "cats-controld"
    })
  }

  spec {
    selector = {
      "app.kubernetes.io/name" = "cats-controld"
    }

    port {
      name        = "route-v2"
      port        = 7443
      target_port = "route-v2"
    }
  }
}

# Signed Route rotation and public successor/current discovery remain reachable
# while a disabled Control replica intentionally fails its public readiness
# probe. This server-authenticated TLS Service has no public Ingress and does
# not carry the mandatory Gateway client-certificate principal.
resource "kubernetes_service_v1" "control_plane_route_v2_rotation" {
  metadata {
    name      = "cats-controld-route-rotation"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels = merge(local.labels, {
      "app.kubernetes.io/name" = "cats-controld"
    })
  }

  spec {
    publish_not_ready_addresses = true

    selector = {
      "app.kubernetes.io/name" = "cats-controld"
    }

    port {
      name        = "route-rotation"
      port        = 7444
      target_port = "route-rotation"
    }
  }
}


resource "kubernetes_deployment_v1" "object_write_gateway" {
  metadata {
    name      = "cats-object-write-gateway"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels = merge(local.labels, {
      "app.kubernetes.io/name" = "cats-object-write-gateway"
    })
  }

  spec {
    replicas = local.effective_object_write_gateway_replicas

    strategy {
      type = "RollingUpdate"

      rolling_update {
        max_surge       = "1"
        max_unavailable = "0"
      }
    }

    selector {
      match_labels = {
        "app.kubernetes.io/name" = "cats-object-write-gateway"
      }
    }

    template {
      metadata {
        labels = merge(local.labels, {
          "app.kubernetes.io/name" = "cats-object-write-gateway"
        })
        annotations = {
          "cats.run/object-write-tls-artifact-secret" = var.object_write_gateway_tls_secret_name
          "cats.run/object-write-spool-access-point"  = var.object_write_spool_access_point_id
          "cats.run/rds-ca-sha256"                    = sha256(local.rds_ca_pem)
        }
      }

      spec {
        automount_service_account_token  = false
        enable_service_links             = false
        service_account_name             = kubernetes_service_account_v1.object_write_gateway.metadata[0].name
        termination_grace_period_seconds = 120

        node_selector = {
          "kubernetes.io/arch" = "amd64"
        }

        affinity {
          pod_anti_affinity {
            required_during_scheduling_ignored_during_execution {
              topology_key = "kubernetes.io/hostname"

              label_selector {
                match_labels = {
                  "app.kubernetes.io/name" = "cats-object-write-gateway"
                }
              }
            }
          }
        }

        topology_spread_constraint {
          max_skew           = 1
          topology_key       = "topology.kubernetes.io/zone"
          when_unsatisfiable = "DoNotSchedule"

          label_selector {
            match_labels = {
              "app.kubernetes.io/name" = "cats-object-write-gateway"
            }
          }
        }

        # Projected Secrets are symlink trees. Render the closed two-file TLS
        # artifact into a private in-memory directory before gateway startup so
        # the process opens stable regular files and never sees a hot rotation.
        init_container {
          name              = "object-write-tls-renderer"
          image             = var.object_write_gateway_image
          image_pull_policy = "IfNotPresent"
          command           = ["/bin/sh", "-ceu"]
          args = [<<-EOT
            expected='object-write-server-certificate.pem object-write-server-private-key.pem'
            actual_count=$(find -L /var/run/cats/object-write-tls-source -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')
            test "$actual_count" = 2
            install -d -o 0 -g 0 -m 0700 /etc/cats/object-write-tls
            for name in $expected; do
              test -f "/var/run/cats/object-write-tls-source/$name"
              mode=0644
              test "$name" != object-write-server-private-key.pem || mode=0600
              install -o 0 -g 0 -m "$mode" "/var/run/cats/object-write-tls-source/$name" "/etc/cats/object-write-tls/$name"
            done
            sync /etc/cats/object-write-tls
          EOT
          ]

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
            name       = "object-write-tls-source"
            mount_path = "/var/run/cats/object-write-tls-source"
            read_only  = true
          }

          volume_mount {
            name       = "object-write-tls"
            mount_path = "/etc/cats/object-write-tls"
          }
        }

        container {
          name              = "object-write-gateway"
          image             = var.object_write_gateway_image
          image_pull_policy = "IfNotPresent"
          command           = ["/usr/local/bin/cats-object-write-gatewayd"]
          args = [
            "--listen",
            "0.0.0.0:7443",
            "--control-store-url-file",
            "/run/cats/object-write-gateway/postgres/url",
            "--control-store-ca-file",
            "/etc/cats/rds-ca.pem",
            "--control-store-schema",
            var.control_postgres_schema,
            "--server-certificate-file",
            "/etc/cats/object-write-tls/object-write-server-certificate.pem",
            "--server-private-key-file",
            "/etc/cats/object-write-tls/object-write-server-private-key.pem",
            "--durable-spool-root",
            "/var/lib/cats/object-write-spool",
            "--provider",
            "aws",
            "--partition",
            var.object_write_provider_partition,
            "--account-id",
            var.object_write_provider_account_id,
            "--region",
            var.chunkstore_region,
            "--bucket",
            var.chunkstore_bucket_name,
            "--prefix",
            var.chunkstore_prefix,
            "--object-store-scope-id",
            "arn:${var.object_write_provider_partition}:s3:::${var.chunkstore_bucket_name}/${var.chunkstore_prefix}",
          ]

          port {
            name           = "https"
            container_port = 7443
            protocol       = "TCP"
          }

          resources {
            requests = {
              cpu    = "250m"
              memory = "256Mi"
            }
            limits = {
              cpu    = "2"
              memory = "1Gi"
            }
          }

          startup_probe {
            http_get {
              path   = "/healthz"
              port   = "https"
              scheme = "HTTPS"
            }
            failure_threshold = 30
            period_seconds    = 5
          }

          readiness_probe {
            http_get {
              path   = "/healthz"
              port   = "https"
              scheme = "HTTPS"
            }
            period_seconds = 5
          }

          liveness_probe {
            http_get {
              path   = "/healthz"
              port   = "https"
              scheme = "HTTPS"
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
            name       = "object-write-database"
            mount_path = "/run/cats/object-write-gateway/postgres"
            read_only  = true
          }

          volume_mount {
            name       = "rds-ca"
            mount_path = "/etc/cats/rds-ca.pem"
            sub_path   = "rds-ca.pem"
            read_only  = true
          }

          volume_mount {
            name       = "object-write-tls"
            mount_path = "/etc/cats/object-write-tls"
            read_only  = true
          }

          volume_mount {
            name       = "object-write-spool"
            mount_path = "/var/lib/cats/object-write-spool"
          }
        }

        volume {
          name = "object-write-database"

          secret {
            secret_name  = local.object_write_gateway_postgres_secret_name
            default_mode = "0400"
            optional     = false

            items {
              key  = "url"
              path = "url"
              mode = "0400"
            }
          }
        }

        volume {
          name = "rds-ca"

          config_map {
            name = kubernetes_config_map_v1.rds_ca.metadata[0].name
          }
        }

        volume {
          name = "object-write-tls-source"

          secret {
            secret_name  = var.object_write_gateway_tls_secret_name
            default_mode = "0400"
            optional     = false
          }
        }

        volume {
          name = "object-write-tls"

          empty_dir {
            medium = "Memory"
          }
        }

        volume {
          name = "object-write-spool"

          persistent_volume_claim {
            claim_name = kubernetes_persistent_volume_claim_v1.object_write_spool.metadata[0].name
            read_only  = false
          }
        }
      }
    }
  }

  wait_for_rollout = true
}

resource "kubernetes_pod_disruption_budget_v1" "object_write_gateway" {
  metadata {
    name      = "cats-object-write-gateway"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels    = local.labels
  }

  spec {
    min_available = var.maintenance_mode ? "0" : "1"

    selector {
      match_labels = {
        "app.kubernetes.io/name" = "cats-object-write-gateway"
      }
    }
  }
}

# The NLB is VPC-internal and carries TCP unchanged: TLS terminates only in the
# Pod against the release-bound node-server-CA leaf. Its custom frontend SG is
# provisioned in the platform state with exactly one worker-SG ingress rule.
resource "kubernetes_service_v1" "object_write_gateway" {
  metadata {
    name      = "cats-object-write-gateway"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels = merge(local.labels, {
      "app.kubernetes.io/name" = "cats-object-write-gateway"
    })
    annotations = {
      "service.beta.kubernetes.io/aws-load-balancer-scheme"                              = "internal"
      "service.beta.kubernetes.io/aws-load-balancer-nlb-target-type"                     = "ip"
      "service.beta.kubernetes.io/aws-load-balancer-security-groups"                     = var.object_write_gateway_nlb_security_group_id
      "service.beta.kubernetes.io/aws-load-balancer-manage-backend-security-group-rules" = "true"
      "service.beta.kubernetes.io/aws-load-balancer-subnets"                             = join(",", var.object_write_gateway_private_subnet_ids)
      "service.beta.kubernetes.io/aws-load-balancer-healthcheck-protocol"                = "TCP"
    }
  }

  spec {
    selector = {
      "app.kubernetes.io/name" = "cats-object-write-gateway"
    }
    type                = "LoadBalancer"
    load_balancer_class = "eks.amazonaws.com/nlb"

    port {
      name        = "tls"
      port        = 443
      target_port = "https"
      protocol    = "TCP"
    }
  }

  wait_for_load_balancer = true
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
    replicas = local.effective_gateway_replicas

    strategy {
      type = "RollingUpdate"

      rolling_update {
        max_surge       = "1"
        max_unavailable = "0"
      }
    }

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
          # The immutable, versioned Secret name is the rollout identity. Its
          # bytes never enter Terraform state or Pod environment variables.
          "cats.run/route-v2-gateway-artifact-secret" = var.route_v2_gateway_artifact_secret_name
        }
      }

      spec {
        automount_service_account_token  = false
        enable_service_links             = false
        service_account_name             = kubernetes_service_account_v1.gateway.metadata[0].name
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
                  "app.kubernetes.io/name" = "cats-gatewayd"
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
              "app.kubernetes.io/name" = "cats-gatewayd"
            }
          }
        }

        init_container {
          name              = "route-v2-artifact-renderer"
          image             = var.gateway_image
          image_pull_policy = "IfNotPresent"
          command           = ["/bin/sh", "-ceu"]
          args = [<<-EOT
            expected='node-server-ca-bundle.pem gateway-machine-client-certificate.pem gateway-machine-client-private-key.pem'
            actual_count=$(find -L /var/run/cats/route-v2-source -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')
            test "$actual_count" = 3
            install -d -o 0 -g 0 -m 0700 /etc/cats/route-v2
            for name in $expected; do
              test -f "/var/run/cats/route-v2-source/$name"
              mode=0644
              test "$name" != gateway-machine-client-private-key.pem || mode=0600
              install -o 0 -g 0 -m "$mode" "/var/run/cats/route-v2-source/$name" "/etc/cats/route-v2/$name"
            done
            sync /etc/cats/route-v2
          EOT
          ]

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
            name       = "route-v2-gateway-artifact-source"
            mount_path = "/var/run/cats/route-v2-source"
            read_only  = true
          }

          volume_mount {
            name       = "route-v2-gateway-artifacts"
            mount_path = "/etc/cats/route-v2"
          }
        }

        container {
          name              = "gatewayd"
          image             = var.gateway_image
          image_pull_policy = "IfNotPresent"
          command           = ["/usr/local/bin/cats-gatewayd"]
          args = [
            "--listen",
            "0.0.0.0:8080",
            "--control-plane-url",
            "https://${kubernetes_service_v1.control_plane_route_v2.metadata[0].name}.${var.namespace}.svc.cluster.local:7443",
          ]

          port {
            name           = "http"
            container_port = 8080
          }

          resources {
            requests = {
              cpu    = "100m"
              memory = "128Mi"
            }
            limits = {
              cpu    = "1"
              memory = "512Mi"
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
            name       = "route-v2-gateway-artifacts"
            mount_path = "/etc/cats/route-v2"
            read_only  = true
          }
        }

        volume {
          name = "route-v2-gateway-artifact-source"

          secret {
            secret_name  = var.route_v2_gateway_artifact_secret_name
            default_mode = "0400"
            optional     = false
          }
        }

        volume {
          name = "route-v2-gateway-artifacts"

          empty_dir {
            medium = "Memory"
          }
        }
      }
    }
  }

  wait_for_rollout = true
}

resource "kubernetes_pod_disruption_budget_v1" "gateway" {
  metadata {
    name      = "cats-gatewayd"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels    = local.labels
  }

  spec {
    min_available = var.maintenance_mode ? "0" : "1"

    selector {
      match_labels = {
        "app.kubernetes.io/name" = "cats-gatewayd"
      }
    }
  }
}

resource "kubernetes_service_v1" "gateway" {
  metadata {
    name      = "cats-gatewayd"
    namespace = kubernetes_namespace_v1.cats.metadata[0].name
    labels = merge(local.labels, {
      "app.kubernetes.io/name" = "cats-gatewayd"
    })
  }

  spec {
    selector = {
      "app.kubernetes.io/name" = "cats-gatewayd"
    }

    port {
      name        = "http"
      port        = 8080
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
