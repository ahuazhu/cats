#!/usr/bin/env bash
# Validate one targeted emergency ingress-close Terraform show JSON.
set -euo pipefail

cats_e3_validate_emergency_close_plan() {
  local plan_json=$1
  [[ $plan_json == /* && -f $plan_json && ! -L $plan_json ]] || return 64
  jq -e '
    def resources:
      [.root_module | recurse(.child_modules[]?) | .resources[]?];
    def is_public_ingress_address:
      . == "module.cats_kubernetes.kubernetes_manifest.ingress_class_params[\"enabled\"]"
      or . == "module.cats_kubernetes.kubernetes_ingress_class_v1.public[0]"
      or . == "module.cats_kubernetes.kubernetes_ingress_v1.public[0]"
      or (startswith("aws_route53_record.public[") and endswith("]"));
    (.prior_state.values | resources) as $prior
    | (.planned_values | resources) as $planned
    | [.resource_changes[]?
        | select(.mode == "managed" and .change.actions != ["no-op"])] as $changes
    | ([.resource_changes[]?
        | select(.mode == "managed")
        | .change.after_unknown | .. | booleans]
      | all(. == false))
    and ([$planned[]
      | select(.address == "module.cats_kubernetes.kubernetes_namespace_v1.cats")
      | .values.metadata[0].labels["cats.run/ingress"]] == ["disabled"])
    and ([$planned[] | select(.address | is_public_ingress_address)] | length == 0)
    and (($changes | length) != 0
      or (([$prior[]
          | select(.address == "module.cats_kubernetes.kubernetes_namespace_v1.cats")
          | .values.metadata[0].labels["cats.run/ingress"]] == ["disabled"])
        and ([$prior[] | select(.address | is_public_ingress_address)] | length == 0)))
    and all($changes[];
      if .address == "module.cats_kubernetes.kubernetes_namespace_v1.cats" then
        .change.actions == ["update"]
        and .change.before.metadata[0].labels["cats.run/ingress"] == "enabled"
        and .change.after.metadata[0].labels["cats.run/ingress"] == "disabled"
        and ((.change.before
          | setpath(["metadata",0,"labels","cats.run/ingress"]; "disabled")) == .change.after)
      elif (.address | is_public_ingress_address) then
        .change.actions == ["delete"] and .change.after == null
      else false end)
  ' "$plan_json" >/dev/null
}

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then
  return 0
fi

[[ $# -eq 1 ]] || exit 64
cats_e3_validate_emergency_close_plan "$1"
