#!/usr/bin/env bash
set -euo pipefail

cats_e3_ingress_close_plan_fixture_run() {
  local validator=$1 scratch valid closed candidate
  scratch=$(mktemp -d)
  fixture_scratch=$scratch
  trap 'rm -r -- "$fixture_scratch"' EXIT
  valid=$scratch/valid.json
  closed=$scratch/already-closed.json
  candidate=$scratch/candidate.json

  jq -n '
    def ns($state):
      {address:"module.cats_kubernetes.kubernetes_namespace_v1.cats",mode:"managed",
       values:{metadata:[{labels:{"cats.run/ingress":$state,stable:"same"}}]}};
    def public($address): {address:$address,mode:"managed",values:{stable:"same"}};
    def deletion($address):
      {address:$address,mode:"managed",
       change:{actions:["delete"],before:{stable:"same"},after:null,after_unknown:false}};
    ["module.cats_kubernetes.kubernetes_manifest.ingress_class_params[\"enabled\"]",
     "module.cats_kubernetes.kubernetes_ingress_class_v1.public[0]",
     "module.cats_kubernetes.kubernetes_ingress_v1.public[0]",
     "aws_route53_record.public[\"e3.example.test\"]"] as $public
    | {prior_state:{values:{root_module:{resources:
          ([ns("enabled")] + [$public[] | public(.)])}}},
       planned_values:{root_module:{resources:[ns("disabled")]}},
       resource_changes:
         [{address:"module.cats_kubernetes.kubernetes_namespace_v1.cats",mode:"managed",
           change:{actions:["update"],
             before:{metadata:[{labels:{"cats.run/ingress":"enabled",stable:"same"}}]},
             after:{metadata:[{labels:{"cats.run/ingress":"disabled",stable:"same"}}]},
             after_unknown:false}}]
         + [$public[] | deletion(.)]}
  ' >"$valid"
  "$validator" "$valid"

  jq -n '
    def ns:
      {address:"module.cats_kubernetes.kubernetes_namespace_v1.cats",mode:"managed",
       values:{metadata:[{labels:{"cats.run/ingress":"disabled",stable:"same"}}]}};
    {prior_state:{values:{root_module:{resources:[ns]}}},
     planned_values:{root_module:{resources:[ns]}},
     resource_changes:[
       {address:"module.cats_kubernetes.kubernetes_namespace_v1.cats",mode:"managed",
        change:{actions:["no-op"],before:ns.values,after:ns.values,after_unknown:false}}]}
  ' >"$closed"
  "$validator" "$closed"

  expect_rejected() {
    if "$validator" "$candidate"; then
      return 1
    fi
  }

  jq '.resource_changes += [{address:"module.cats_kubernetes.kubernetes_deployment_v1.gateway",mode:"managed",change:{actions:["update"],before:{},after:{},after_unknown:false}}]' \
    "$valid" >"$candidate"
  expect_rejected
  jq '(.resource_changes[1].change) = {actions:["create"],before:null,after:{},after_unknown:false}' \
    "$valid" >"$candidate"
  expect_rejected
  jq '(.resource_changes[1].change) = {actions:["delete","create"],before:{},after:{},after_unknown:false}' \
    "$valid" >"$candidate"
  expect_rejected
  jq '(.resource_changes[0].change.before.metadata[0].labels["cats.run/ingress"]) = "disabled"
      | (.resource_changes[0].change.after.metadata[0].labels["cats.run/ingress"]) = "enabled"' \
    "$valid" >"$candidate"
  expect_rejected
  jq '.planned_values.root_module.resources += [.prior_state.values.root_module.resources[2]]' \
    "$valid" >"$candidate"
  expect_rejected
  jq '.resource_changes[0].change.after_unknown = {metadata:[{labels:{"cats.run/ingress":true}}]}' \
    "$valid" >"$candidate"
  expect_rejected
}

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then
  return 0
fi

[[ $# -eq 1 ]] || exit 64
cats_e3_ingress_close_plan_fixture_run "$1"
