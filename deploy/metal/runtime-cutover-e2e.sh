#!/usr/bin/env bash
# Deterministic evidence orchestrator for an already-provisioned qualification
# host inside the runbook's bounded schedulable/ingress window. It never
# provisions infrastructure, applies Terraform, or installs a long-lived service.
set -euo pipefail

# Testable boundary after all production authority checks and stable staging.
# Executing this file always enters the root-only main path below; sourcing it
# only exposes this deterministic case/evidence loop to repository tests.
cats_e3_run_cases_post_preflight() {
  local phase=${1:-fixture-all}
  case "$phase" in
    product|source) ;;
    fixture-all)
      [[ ${CATS_E3_FIXTURE_MODE:-} == enabled ]] || return 125
      ;;
    *) return 125 ;;
  esac
  atomic_copy() {
    local source=$1 destination=$2 temporary
    temporary=$(mktemp "$output_dir/.${destination}.XXXXXX")
    cp "$source" "$temporary"
    chmod 0600 "$temporary"
    mv -f "$temporary" "$output_dir/$destination"
  }

  run_filtered() {
    local action=$1 case_id=$2 deadline=$3 destination=$4 case_dir=$5 kill_after=$6
    local statuses command_status filter_status
    set +e
    "$timeout_bin" --signal=TERM --kill-after="$kill_after" "$deadline" \
      "$scenario_driver" "$action" "$case_id" "$block_path" "$case_dir" 2>&1 \
      | "$filter" --mode text --max-bytes 16384 >"$destination"
    statuses=("${PIPESTATUS[@]}")
    set -e
    command_status=${statuses[0]:-125}
    filter_status=${statuses[1]:-125}
    if [[ $filter_status -ne 0 ]]; then
      printf '%s\n' '[evidence filter failed closed]' >"$destination"
      return 125
    fi
    return "$command_status"
  }

  append_summary() {
    local case_id=$1 phase=$2 source=$3 bounded
    printf '=== %s %s ===\n' "$case_id" "$phase" >>"$journal_work"
    cat "$source" >>"$journal_work"
    printf '\n' >>"$journal_work"
    bounded=$scratch/component-journal-summary.bounded
    "$filter" --mode text --max-bytes 131072 <"$journal_work" >"$bounded" || \
      printf '%s\n' '[evidence filter failed closed]' >"$bounded"
    mv -f "$bounded" "$journal_work"
    atomic_copy "$journal_work" component-journal-summary.txt
  }

  persist_case_evidence() {
    local case_id=$1 case_dir=$2 required_evidence=$3 exact_set_required=$4
    local candidate filename kind filtered entry digest size actual_json expected_json
    local candidates=() actual_names=() evidence_names=()
    expected_json=$(jq -c '[.[].filename] | sort' <<<"$required_evidence") || return 125
    shopt -s nullglob
    candidates=("$case_dir"/*)
    shopt -u nullglob
    for candidate in "${candidates[@]}"; do
      [[ -f $candidate && ! -L $candidate ]] || continue
      filename=${candidate##*/}
      if [[ $case_id == route-v2-rotation-disable-live-delivery ]]; then
        if jq -e --arg filename "$filename" \
          'any(.[]; .filename == $filename)' <<<"$required_evidence" >/dev/null; then
          actual_names+=("$filename")
        fi
        continue
      fi
      case "$filename" in
        *receipt*.json|*.node-acks.json|*.transcript.log) actual_names+=("$filename") ;;
        *)
          if jq -e --arg filename "$filename" \
            'any(.[]; .filename == $filename)' <<<"$required_evidence" >/dev/null; then
            actual_names+=("$filename")
          fi
          ;;
      esac
    done

    if [[ $exact_set_required == true ]]; then
      if [[ ${#actual_names[@]} -eq 0 ]]; then
        actual_json='[]'
      else
        actual_json=$(printf '%s\n' "${actual_names[@]}" | LC_ALL=C sort | jq -Rsc 'split("\n")[:-1]') || return 125
      fi
      [[ $actual_json == "$expected_json" ]] || return 125
      while IFS= read -r filename; do
        evidence_names+=("$filename")
      done < <(jq -r '.[].filename' <<<"$required_evidence")
    else
      evidence_names=("${actual_names[@]}")
    fi

    for filename in "${evidence_names[@]}"; do
      candidate=$case_dir/$filename
      [[ -f $candidate && ! -L $candidate ]] || return 125
      if [[ $exact_set_required == true ]]; then
        kind=$(jq -r --arg filename "$filename" \
          '.[] | select(.filename == $filename) | .kind' <<<"$required_evidence") || return 125
      else
        case "$filename" in
          *.json) kind=json ;;
          *.log) kind=text ;;
          *) return 125 ;;
        esac
      fi
      filtered=$(mktemp "$scratch/.case-evidence.XXXXXX")
      case "$kind" in
        json)
          if ! "$filter" --mode inventory --max-bytes 1048576 <"$candidate" >"$filtered"; then
            rm -f "$filtered"
            return 125
          fi
          ;;
        text)
          if ! "$filter" --mode text --max-bytes 131072 <"$candidate" >"$filtered"; then
            rm -f "$filtered"
            return 125
          fi
          ;;
        *)
          rm -f "$filtered"
          return 125
          ;;
      esac
      digest=$(sha256sum "$filtered" | awk '{print $1}')
      size=$(wc -c <"$filtered" | tr -d ' ')
      entry=$(mktemp "$scratch/.case-evidence-entry.XXXXXX")
      if [[ $kind == json ]]; then
        if ! jq -S -c -n --arg case_id "$case_id" --arg filename "$filename" \
          --arg kind "$kind" --arg sha256 "sha256:$digest" --argjson size_bytes "$size" \
          --slurpfile content "$filtered" \
          '{case_id:$case_id,filename:$filename,kind:$kind,sha256:$sha256,
            size_bytes:$size_bytes,content:$content[0]}' >"$entry"; then
          rm -f "$filtered" "$entry"
          return 125
        fi
      elif ! jq -S -c -n --arg case_id "$case_id" --arg filename "$filename" \
        --arg kind "$kind" --arg sha256 "sha256:$digest" --argjson size_bytes "$size" \
        --rawfile content "$filtered" \
        '{case_id:$case_id,filename:$filename,kind:$kind,sha256:$sha256,
          size_bytes:$size_bytes,content:$content}' >"$entry"; then
        rm -f "$filtered" "$entry"
        return 125
      fi
      cat "$entry" >>"$evidence_work"
      rm -f "$filtered" "$entry"
    done
    atomic_copy "$evidence_work" case-evidence.jsonl
  }

  if [[ $phase == fixture-all ]]; then
    failed_cases=0
    blocked_cases=0
    passed_cases=0
  elif [[ $phase == product ]]; then
    failed_cases=0
    blocked_cases=0
    passed_cases=${first_incomplete_case_index:-0}
  else
    [[ ${qualification_terminalized:-false} == true ]] || return 125
    jq -e --arg run_id "$run_id" --arg workspace_id "$workspace_id" \
      --arg exact_commit "$exact_commit" \
      --arg catalog_sha256 "sha256:$qualification_catalog_authority_sha256" '
      .kind == "cats.production-mutation-qualification-terminal-receipt.v1"
      and .version == 1 and .qualification_id == $run_id
      and .workspace_id == $workspace_id and .source_commit_sha == $exact_commit
      and .qualification_catalog_sha256 == $catalog_sha256
      and .close_kind == "end_qualification"
      and .terminal_outcome == "qualified_closed"
      and .active_guard_count == 0 and .product_resource_count == 0
      and .residue_count == 0' \
      "$output_dir/production-mutation-qualification-terminal.receipt.json" >/dev/null || \
      return 125
  fi
  for index in "${!case_ids[@]}"; do
    case_id=${case_ids[$index]}
    if [[ $phase == product && $case_id == usage-source-terminal-receipts ]]; then
      continue
    fi
    if [[ $phase == source && $case_id != usage-source-terminal-receipts ]]; then
      continue
    fi
    if [[ $phase == product && $index -lt ${first_incomplete_case_index:-0} ]]; then
      continue
    fi
    deadline=${case_deadlines[$index]}
    cleanup_deadline=${case_cleanup_deadlines[$index]}
    expected_outcome=${case_expected_outcomes[$index]}
    required_evidence=${case_required_evidence[$index]}
    kill_after=5
    if [[ $case_id == route-v2-rotation-disable-live-delivery ]]; then
      kill_after=30
    fi
    if [[ $phase != fixture-all && -n ${persistent_cases_dir:-} ]]; then
      case_dir=$(printf '%s/%02d-%s' "$persistent_cases_dir" "$index" "$case_id")
      cats_e3_private_state_subdirectory "$case_dir" || return 125
    else
      case_dir=$scratch/case-$case_id
      mkdir -m 0700 "$case_dir"
    fi
    run_summary=$case_dir/run-summary.txt
    cleanup_summary=$case_dir/cleanup-summary.txt
    diagnostic_summary=$case_dir/diagnostic-summary.txt
    case_started=$(date +%s)

    if run_filtered run "$case_id" "$deadline" "$run_summary" "$case_dir" "$kill_after"; then
      run_code=0
    else
      run_code=$?
    fi
    append_summary "$case_id" run "$run_summary"

    diagnostic_code=0
    if [[ $run_code -ne 0 ]]; then
      if run_filtered diagnostics "$case_id" 30 "$diagnostic_summary" "$case_dir" 5; then
        diagnostic_code=0
      else
        diagnostic_code=$?
      fi
      append_summary "$case_id" diagnostics "$diagnostic_summary"
    fi

    if run_filtered cleanup "$case_id" "$cleanup_deadline" "$cleanup_summary" "$case_dir" "$kill_after"; then
      cleanup_code=0
    else
      cleanup_code=$?
    fi
    append_summary "$case_id" cleanup "$cleanup_summary"

    exact_set_required=false
    if [[ $run_code -eq 0 && $cleanup_code -eq 0 ]]; then
      exact_set_required=true
    fi
    if persist_case_evidence "$case_id" "$case_dir" "$required_evidence" "$exact_set_required"; then
      evidence_code=0
    else
      evidence_code=$?
    fi

    case_ended=$(date +%s)
    observed_outcome=passed
    if [[ $cleanup_code -ne 0 || $evidence_code -ne 0 ]]; then
      observed_outcome=failed
    elif [[ $run_code -eq 124 ]]; then
      observed_outcome=timed_out
    elif [[ $run_code -eq 78 ]]; then
      if [[ -f $case_dir/blocked-receipt.json ]] && jq -e \
        --arg case_id "$case_id" --arg block_path "$block_path" \
        '.version == 1 and .status == "blocked" and .case_id == $case_id
          and .block_path == $block_path and (.reason | type == "string" and length > 0)' \
        "$case_dir/blocked-receipt.json" >/dev/null; then
        observed_outcome=blocked
      else
        observed_outcome=failed
        evidence_code=125
      fi
    elif [[ $run_code -ne 0 ]]; then
      observed_outcome=failed
    fi
    expected_kind=$(jq -r '.kind' <<<"$expected_outcome") || return 125
    outcome_matches=false
    status=failed
    if [[ $observed_outcome == "$expected_kind" ]]; then
      outcome_matches=true
      status=passed
      passed_cases=$((passed_cases + 1))
    else
      failed_cases=$((failed_cases + 1))
      [[ $observed_outcome != blocked ]] || blocked_cases=$((blocked_cases + 1))
    fi
    jq -S -c -n \
      --arg case_id "$case_id" \
      --arg status "$status" \
      --arg observed_outcome "$observed_outcome" \
      --argjson expected_outcome "$expected_outcome" \
      --argjson outcome_matches "$outcome_matches" \
      --argjson deadline_seconds "$deadline" \
      --argjson cleanup_deadline_seconds "$cleanup_deadline" \
      --argjson started_at_unix_seconds "$case_started" \
      --argjson ended_at_unix_seconds "$case_ended" \
      --argjson run_exit_code "$run_code" \
      --argjson diagnostic_exit_code "$diagnostic_code" \
      --argjson cleanup_exit_code "$cleanup_code" \
      --argjson evidence_exit_code "$evidence_code" \
      '{case_id:$case_id,status:$status,observed_outcome:$observed_outcome,
        expected_outcome:$expected_outcome,outcome_matches:$outcome_matches,
        deadline_seconds:$deadline_seconds,cleanup_deadline_seconds:$cleanup_deadline_seconds,
        started_at_unix_seconds:$started_at_unix_seconds,
        ended_at_unix_seconds:$ended_at_unix_seconds,run_exit_code:$run_exit_code,
        diagnostic_exit_code:$diagnostic_exit_code,cleanup_exit_code:$cleanup_exit_code,
        evidence_exit_code:$evidence_exit_code}' \
      >>"$results_work"
    atomic_copy "$results_work" scenario-results.jsonl
    if [[ $phase == product && -n ${persistent_case_prefix_dir:-} ]]; then
      if [[ $status != passed ]]; then
        break
      fi
      cats_e3_persist_case_prefix "$index" "$case_id" || return 125
      first_incomplete_case_index=$((index + 1))
      atomic_copy "$persistent_runtime_state" runtime-state.json
    fi
  done

  if [[ $phase == fixture-all ]]; then
    cats_e3_collect_final_inventory
  fi
}

cats_e3_collect_final_inventory() {
  inventory_work=$scratch/final-inventory.json
  set +e
  "$timeout_bin" --signal=TERM --kill-after=5 180 \
    "$scenario_driver" inventory final "$block_path" "$scratch" 2>/dev/null \
    | "$filter" --mode inventory --max-bytes 1048576 >"$inventory_work"
  inventory_statuses=("${PIPESTATUS[@]}")
  set -e
  inventory_command_status=${inventory_statuses[0]:-125}
  inventory_filter_status=${inventory_statuses[1]:-125}
  if [[ $inventory_command_status -ne 0 || $inventory_filter_status -ne 0 ]]; then
    failed_cases=$((failed_cases + 1))
    printf '%s\n' '{"status":"unavailable"}' >"$inventory_work"
    printf '%s\n' '[final inventory command or evidence filter failed closed]' >"$scratch/inventory-diagnostic.txt"
    if declare -F append_summary >/dev/null; then
      append_summary final-inventory diagnostics "$scratch/inventory-diagnostic.txt"
    fi
  fi
  atomic_copy "$inventory_work" final-inventory.json
}

cats_e3_run_qualification_operator() {
  local command_name=$1 output expected_receipt receipt receipt_sha256 actual_sha256
  shift
  case "$command_name" in
    qualification-begin)
      expected_receipt=$output_dir/production-mutation-qualification-begin.receipt.json
      ;;
    qualification-close)
      expected_receipt=$qualification_operator_state/production-mutation-qualification-final-admission-state.json
      ;;
    qualification-product-inventory)
      expected_receipt=$output_dir/production-mutation-qualification-product-inventory.receipt.json
      ;;
    qualification-terminalize)
      expected_receipt=$output_dir/production-mutation-qualification-terminal.receipt.json
      ;;
    *) return 125 ;;
  esac
  output=$(mktemp "$scratch/.production-mutation-admission.XXXXXX")
  if ! PYTHONDONTWRITEBYTECODE=1 "$qualification_operator" "$command_name" \
    "${qualification_common_args[@]}" "$@" >"$output"; then
    rm -f "$output"
    return 1
  fi
  jq -e '
    keys == ["receipt","sha256"]
    and (.receipt | type == "string" and startswith("/"))
    and (.sha256 | test("^sha256:[0-9a-f]{64}$"))' \
    "$output" >/dev/null || {
      rm -f "$output"
      return 1
    }
  receipt=$(jq -er '.receipt' "$output") || {
    rm -f "$output"
    return 1
  }
  receipt_sha256=$(jq -er '.sha256' "$output") || {
    rm -f "$output"
    return 1
  }
  [[ $receipt == "$expected_receipt" && -f $receipt && ! -L $receipt && -O $receipt && \
    $(stat -c '%u:%g:%a:%h' "$receipt") == 0:0:600:1 ]] || {
    rm -f "$output"
    return 1
  }
  actual_sha256=sha256:$(sha256sum "$receipt" | awk '{print $1}')
  [[ $actual_sha256 == "$receipt_sha256" ]] || {
    rm -f "$output"
    return 1
  }
  if [[ $command_name == qualification-close ]]; then
    local evidence_state=$output_dir/production-mutation-qualification-final-admission-state.json
    [[ -f $evidence_state && ! -L $evidence_state && -O $evidence_state && \
      $(stat -c '%u:%g:%a:%h' "$evidence_state") == 0:0:600:1 && \
      sha256:$(sha256sum "$evidence_state" | awk '{print $1}') == "$actual_sha256" ]] || {
      rm -f "$output"
      return 1
    }
  fi
  rm -f "$output"
}

cats_e3_qualification_begin() {
  qualification_lifecycle_attempted=true
  cats_e3_run_qualification_operator qualification-begin \
    --private-key-file "$production_cutover_operator_private_key_file" \
    --command-lifetime-seconds 240 || return $?
  qualification_begin_applied=true
}

cats_e3_resolve_existing_qualification_begin() {
  qualification_lifecycle_attempted=true
  cats_e3_run_qualification_operator qualification-begin \
    --private-key-file "$production_cutover_operator_private_key_file" \
    --command-lifetime-seconds 240 \
    --existing-pending-only || return $?
  qualification_begin_applied=true
}

cats_e3_qualification_close() {
  local close_kind=$1
  qualification_close_attempted=true
  cats_e3_run_qualification_operator qualification-close \
    --private-key-file "$production_cutover_operator_private_key_file" \
    --command-lifetime-seconds 240 \
    --close-kind "$close_kind" || return $?
  qualification_close_applied=true
}

cats_e3_qualification_product_inventory() {
  local close_kind=$1
  cats_e3_run_qualification_operator qualification-product-inventory \
    --close-kind "$close_kind"
}

cats_e3_publish_qualification_zero_wrappers() {
  local inventory=$output_dir/final-inventory.json
  local product=$output_dir/production-mutation-qualification-product-inventory.receipt.json
  local fleet=$output_dir/production-mutation-qualification-final-fleet-closed.receipt.json
  local cleanup=$output_dir/production-mutation-qualification-cleanup-inventory.receipt.json
  local fleet_source=$scratch/production-mutation-qualification-final-fleet.source.json
  local cleanup_source=$scratch/production-mutation-qualification-cleanup.source.json
  local fleet_sha256 product_sha256 product_evaluated now_ms evaluated
  jq -e --arg commit "$exact_commit" --arg block_path "$block_path" \
    --slurpfile expected_nodes "$expected_nodes_work" '
    keys == ["block_path","current_runtime_observation_count","desired_runtime_count",
      "nodes","release_commit_sha","version"]
    and .version == 1 and .release_commit_sha == $commit and .block_path == $block_path
    and .desired_runtime_count == 0 and .current_runtime_observation_count == 0
    and ([.nodes[].node_id] == $expected_nodes[0])
    and all(.nodes[];
      keys == ["active_guard_count","assigned_desired_count","cancellation_pending_count",
        "complete_inventory","lifecycle_open_count","node_id","quarantined_condition_count",
        "residue_count","route_active_count","route_closed_count","runtime_count"]
      and .complete_inventory == true
      and .assigned_desired_count == 0 and .runtime_count == 0
      and .residue_count == 0 and .lifecycle_open_count == 0
      and .route_active_count == 0 and .route_closed_count == 0
      and .active_guard_count == 0 and .cancellation_pending_count == 0
      and .quarantined_condition_count == 0)' \
    "$inventory" >/dev/null || return 1
  jq -e --arg run_id "$run_id" --arg workspace_id "$workspace_id" \
    --arg exact_commit "$exact_commit" \
    --arg catalog_sha256 "sha256:$qualification_catalog_authority_sha256" '
    .kind == "cats.production-mutation-qualification-product-inventory.v1"
    and .version == 1 and .qualification_id == $run_id
    and .workspace_id == $workspace_id and .source_commit_sha == $exact_commit
    and .qualification_catalog_sha256 == $catalog_sha256
    and .complete == true and .product_resource_count == 0
    and (.evaluated_at_unix_ms | type == "number" and . > 0 and floor == .)' \
    "$product" >/dev/null || return 1
  fleet_sha256=sha256:$(sha256sum "$inventory" | awk '{print $1}')
  product_sha256=sha256:$(sha256sum "$product" | awk '{print $1}')
  product_evaluated=$(jq -er '.evaluated_at_unix_ms' "$product")
  now_ms=$(python3 - <<'PY'
import time
print(time.time_ns() // 1_000_000)
PY
  )
  evaluated=$now_ms
  (( evaluated >= product_evaluated )) || evaluated=$product_evaluated
  jq -S -c -n \
    --arg qualification_id "$run_id" --arg workspace_id "$workspace_id" \
    --arg source_commit_sha "$exact_commit" --arg block_path "$block_path" \
    --argjson evaluated_at_unix_ms "$evaluated" \
    --arg fleet_verification_receipt_sha256 "$fleet_sha256" \
    --slurpfile expected_node_ids "$expected_nodes_work" '
    {active_guard_count:0,block_path:$block_path,complete:true,
     current_runtime_observation_count:0,desired_runtime_count:0,
     evaluated_at_unix_ms:$evaluated_at_unix_ms,
     expected_node_ids:$expected_node_ids[0],
     fleet_verification_receipt_sha256:$fleet_verification_receipt_sha256,
     kind:"cats.production-mutation-qualification-final-fleet-closed.v1",
     qualification_id:$qualification_id,residue_count:0,
     source_commit_sha:$source_commit_sha,version:1,workspace_id:$workspace_id}' \
    >"$fleet_source"
  atomic_copy "$fleet_source" "${fleet##*/}"
  jq -S -c -n \
    --arg qualification_id "$run_id" --arg workspace_id "$workspace_id" \
    --arg source_commit_sha "$exact_commit" --arg block_path "$block_path" \
    --argjson evaluated_at_unix_ms "$evaluated" \
    --arg product_inventory_receipt_sha256 "$product_sha256" '
    {active_guard_count:0,block_path:$block_path,complete:true,
     current_runtime_observation_count:0,desired_runtime_count:0,
     evaluated_at_unix_ms:$evaluated_at_unix_ms,
     kind:"cats.production-mutation-qualification-cleanup-inventory.v1",
     product_inventory_receipt_sha256:$product_inventory_receipt_sha256,
     product_resource_count:0,qualification_id:$qualification_id,residue_count:0,
     source_commit_sha:$source_commit_sha,version:1,workspace_id:$workspace_id}' \
    >"$cleanup_source"
  atomic_copy "$cleanup_source" "${cleanup##*/}"
}

cats_e3_qualification_terminalize() {
  local close_kind=$1
  cats_e3_run_qualification_operator qualification-terminalize \
    --close-kind "$close_kind" \
    --fleet-closed-receipt \
      "$output_dir/production-mutation-qualification-final-fleet-closed.receipt.json" \
    --product-inventory-receipt \
      "$output_dir/production-mutation-qualification-product-inventory.receipt.json" \
    --cleanup-inventory-receipt \
      "$output_dir/production-mutation-qualification-cleanup-inventory.receipt.json" || return $?
  qualification_terminalized=true
}

cats_e3_close_on_exit() {
  [[ ${qualification_cleanup_disarmed:-false} != true && \
    ${qualification_lifecycle_attempted:-false} == true && \
    ${qualification_terminalized:-false} != true && \
    ${qualification_close_forbidden:-false} != true ]] || return 0
  local decision=$state_directory/qualification-close-decision.v1.json
  local begin_status=0 cleanup_status=0 close_status=0 proof_status=0
  if [[ ${qualification_begin_applied:-false} != true ]]; then
    if cats_e3_resolve_existing_qualification_begin >/dev/null 2>&1; then
      begin_status=0
    else
      begin_status=$?
    fi
  fi
  [[ $begin_status -eq 0 ]] || return "$begin_status"
  if [[ -z ${qualification_close_kind:-} ]]; then
    if [[ -e $decision || -L $decision ]]; then
      qualification_close_kind=$(cats_e3_load_close_decision) || return 1
    else
      qualification_close_kind=emergency_close
    fi
  fi
  cats_e3_persist_close_decision "$qualification_close_kind" >/dev/null 2>&1 || close_status=125
  [[ $close_status -eq 0 ]] || return "$close_status"
  if cats_e3_forward_recover_g3_on_exit; then
    cleanup_status=0
  else
    cleanup_status=$?
  fi
  [[ $cleanup_status -eq 0 ]] || return "$cleanup_status"
  if [[ $close_status -eq 0 && ${qualification_close_applied:-false} != true ]]; then
    if cats_e3_qualification_close "$qualification_close_kind" >/dev/null 2>&1; then
      close_status=0
    else
      close_status=$?
    fi
  fi
  if [[ $close_status -eq 0 ]]; then
    cats_e3_qualification_product_inventory "$qualification_close_kind" \
      >/dev/null 2>&1 || proof_status=$?
    cats_e3_collect_final_inventory
  fi
  if [[ $close_status -eq 0 && $proof_status -eq 0 ]]; then
    cats_e3_publish_qualification_zero_wrappers >/dev/null 2>&1 || proof_status=$?
  fi
  if [[ $close_status -eq 0 && $proof_status -eq 0 ]]; then
    cats_e3_qualification_terminalize "$qualification_close_kind" \
      >/dev/null 2>&1 || proof_status=$?
  fi
  [[ $cleanup_status -eq 0 && $close_status -eq 0 && $proof_status -eq 0 ]]
}

cats_e3_forward_recover_g3_on_exit() {
  local summary statuses command_status filter_status
  [[ -n ${persistent_route_case_dir:-} && -d $persistent_route_case_dir && \
    -n ${scenario_driver:-} && -x $scenario_driver && -n ${timeout_bin:-} && \
    -n ${filter:-} && -x $filter ]] || return 0
  summary=$persistent_route_case_dir/exit-forward-cleanup-summary.txt
  set +e
  "$timeout_bin" --signal=TERM --kill-after=30 1800 \
    "$scenario_driver" cleanup route-v2-rotation-disable-live-delivery \
      "$block_path" "$persistent_route_case_dir" 2>&1 \
    | "$filter" --mode text --max-bytes 16384 >"$summary"
  statuses=("${PIPESTATUS[@]}")
  set -e
  chmod 0600 "$summary"
  sync -f "$persistent_route_case_dir" || return 125
  command_status=${statuses[0]:-125}
  filter_status=${statuses[1]:-125}
  [[ $command_status -eq 0 && $filter_status -eq 0 ]]
}

cats_e3_clear_ambient() {
  local environment_name
  while IFS='=' read -r environment_name _; do
    case "$environment_name" in
      CATS_CONFIG_DIR|CATS_TOKEN|CATS_E3_*) unset "$environment_name" ;;
    esac
  done < <(env)
}

cats_e3_export_qualification_environment() {
  export CATS_E3_WORKER_SERVICE=cats-worker.service
  export CATS_E3_INSTALLED_NODED_PATH=$installed_noded_path
  export CATS_E3_TOKEN_FILE=$token_file
  export CATS_E3_CONTROL_ORIGIN=$control_origin
  export CATS_E3_WORKSPACE_ID=$workspace_id
  export CATS_E3_QUALIFICATION_NODE_ID=$qualification_node
  export CATS_E3_CAT_NAME=$cat_name
  export CATS_E3_BOOT_IMAGE_DIGEST=$boot_image_digest
  export CATS_E3_ENDPOINT_NAME=$endpoint_name
  export CATS_E3_ENDPOINT_HOSTNAME=$endpoint_hostname
  export CATS_E3_PUBLIC_ORIGIN=https://$endpoint_hostname
  printf -v CATS_E3_EXPECTED_NODES '%s,' "${expected_nodes[@]}"
  CATS_E3_EXPECTED_NODES=${CATS_E3_EXPECTED_NODES%,}
  export CATS_E3_EXPECTED_NODES
  export CATS_E3_ROUTE_ROTATION_OPERATOR_AUTHORITY_ID=${route_rotation_operator_authority_id:-}
  export CATS_E3_ROUTE_ROTATION_OPERATOR_ROUTE_DEPLOYMENT_ID=${route_rotation_operator_route_deployment_id:-}
  export CATS_E3_ROUTE_ROTATION_OPERATOR_TRUST_SHA256=${route_rotation_operator_trust_sha256:-}
  if [[ -n ${qualification_catalog_authority_sha256:-} ]]; then
    export CATS_E3_QUALIFICATION_CATALOG_SHA256=sha256:$qualification_catalog_authority_sha256
  else
    unset CATS_E3_QUALIFICATION_CATALOG_SHA256
  fi
}

cats_e3_environment_labels_are_unique() {
  local reserve_sha256=$1 entry label environment_label derived_name seen
  shift
  [[ $reserve_sha256 == true || $reserve_sha256 == false ]] || return 1
  seen='|'
  for entry in "$@"; do
    label=${entry%%=*}
    [[ $label != "$entry" && $label =~ ^[a-z][a-z0-9_-]{0,31}$ ]] || return 1
    environment_label=$(printf '%s' "$label" | tr '[:lower:]-' '[:upper:]_')
    derived_name=$environment_label
    case "$seen" in *"|$derived_name|"*) return 1 ;; esac
    seen+="$derived_name|"
    if [[ $reserve_sha256 == true ]]; then
      derived_name=${environment_label}_SHA256
      case "$seen" in *"|$derived_name|"*) return 1 ;; esac
      seen+="$derived_name|"
    fi
  done
}

# Validate every component from / through one existing directory, then retain
# the exact checked inode in this shell.  Production runs as root, so the
# actor-or-root rule below collapses to root:root for every component.  Tests
# exercise the same walk as their unprivileged actor.
cats_e3_pin_private_directory() {
  local path=$1 fd_variable=$2 alias_variable=$3 final_policy=${4:-private}
  local expected_identity descriptor alias
  [[ $fd_variable =~ ^[A-Za-z_][A-Za-z0-9_]*$ && \
    $alias_variable =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
  expected_identity=$(python3 - "$path" "$final_policy" <<'PY'
import os
import stat
import sys


path, final_policy = sys.argv[1:]
if (
    not path.startswith("/")
    or path == "/"
    or path != os.path.normpath(path)
    or final_policy not in {"private", "ancestor"}
):
    raise SystemExit(1)
components = path.split("/")[1:]
flags = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
effective_uid = os.geteuid()
effective_gid = os.getegid()


def permitted_owner(value):
    if effective_uid == 0:
        return (value.st_uid, value.st_gid) == (0, 0)
    return (value.st_uid, value.st_gid) in {(0, 0), (effective_uid, effective_gid)}


directory = os.open("/", flags)
try:
    root = os.fstat(directory)
    if not stat.S_ISDIR(root.st_mode) or not permitted_owner(root) or root.st_mode & 0o022:
        raise SystemExit(1)
    for index, component in enumerate(components):
        if component in {"", ".", ".."}:
            raise SystemExit(1)
        child = os.open(component, flags, dir_fd=directory)
        value = os.fstat(child)
        final = index == len(components) - 1
        valid_mode = not value.st_mode & 0o022
        if final and final_policy == "private":
            valid_mode = stat.S_IMODE(value.st_mode) == 0o700
        if (
            not stat.S_ISDIR(value.st_mode)
            or not permitted_owner(value)
            or not valid_mode
        ):
            os.close(child)
            raise SystemExit(1)
        os.close(directory)
        directory = child
    value = os.fstat(directory)
    print(f"{value.st_dev}:{value.st_ino}")
finally:
    os.close(directory)
PY
  ) || return 1
  exec {descriptor}<"$path" || return 1
  if ! python3 - "$descriptor" "$expected_identity" "$final_policy" <<'PY'
import os
import stat
import sys


descriptor = int(sys.argv[1])
expected_identity = sys.argv[2]
final_policy = sys.argv[3]
value = os.fstat(descriptor)
effective_uid = os.geteuid()
effective_gid = os.getegid()
owner = (
    (value.st_uid, value.st_gid) == (0, 0)
    if effective_uid == 0
    else (value.st_uid, value.st_gid) in {(0, 0), (effective_uid, effective_gid)}
)
mode = stat.S_IMODE(value.st_mode)
if (
    not stat.S_ISDIR(value.st_mode)
    or not owner
    or mode & 0o022
    or (final_policy == "private" and mode != 0o700)
    or f"{value.st_dev}:{value.st_ino}" != expected_identity
):
    raise SystemExit(1)
PY
  then
    exec {descriptor}<&-
    return 1
  fi
  if [[ -d /proc/self/fd ]]; then
    alias=/proc/self/fd/$descriptor
  else
    alias=$(python3 - "$descriptor" <<'PY'
import fcntl
import sys
try:
    raw = fcntl.fcntl(int(sys.argv[1]), 50, b"\0" * 1024)
except (AttributeError, OSError):
    raise SystemExit(1)
print(raw.split(b"\0", 1)[0].decode("utf-8"))
PY
    ) || {
      exec {descriptor}<&-
      return 1
    }
  fi
  printf -v "$fd_variable" '%s' "$descriptor"
  printf -v "$alias_variable" '%s' "$alias"
}

cats_e3_fd_directory_identity() {
  python3 - "$1" <<'PY'
import os
import stat
import sys
value = os.fstat(int(sys.argv[1]))
if not stat.S_ISDIR(value.st_mode):
    raise SystemExit(1)
print(f"{value.st_dev}:{value.st_ino}")
PY
}

cats_e3_open_pinned_state_lock() {
  local directory_fd=$1 directory_alias=$2 fd_variable=$3
  local expected_identity descriptor
  [[ $directory_fd =~ ^[0-9]+$ && $fd_variable =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
  expected_identity=$(python3 - "$directory_fd" <<'PY'
import os
import stat
import sys


directory_fd = int(sys.argv[1])
flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(".runtime-cutover.lock", flags, 0o600, dir_fd=directory_fd)
try:
    os.fchmod(descriptor, 0o600)
    value = os.fstat(descriptor)
    expected_owner = (os.geteuid(), os.getegid())
    if os.geteuid() == 0:
        expected_owner = (0, 0)
    if (
        not stat.S_ISREG(value.st_mode)
        or (value.st_uid, value.st_gid) != expected_owner
        or stat.S_IMODE(value.st_mode) != 0o600
        or value.st_nlink != 1
    ):
        raise SystemExit(1)
    os.fsync(descriptor)
    os.fsync(directory_fd)
    print(f"{value.st_dev}:{value.st_ino}")
finally:
    os.close(descriptor)
PY
  ) || return 1
  exec {descriptor}<>"$directory_alias/.runtime-cutover.lock" || return 1
  if ! python3 - "$descriptor" "$expected_identity" <<'PY'
import os
import stat
import sys
value = os.fstat(int(sys.argv[1]))
expected_owner = (os.geteuid(), os.getegid())
if os.geteuid() == 0:
    expected_owner = (0, 0)
if (
    not stat.S_ISREG(value.st_mode)
    or (value.st_uid, value.st_gid) != expected_owner
    or stat.S_IMODE(value.st_mode) != 0o600
    or value.st_nlink != 1
    or f"{value.st_dev}:{value.st_ino}" != sys.argv[2]
):
    raise SystemExit(1)
PY
  then
    exec {descriptor}<&-
    return 1
  fi
  printf -v "$fd_variable" '%s' "$descriptor"
}

cats_e3_create_pinned_output_directory() {
  local parent_fd=$1 parent_alias=$2 name=$3 fd_variable=$4 alias_variable=$5
  local expected_identity descriptor alias
  [[ $parent_fd =~ ^[0-9]+$ && -n $name && $name != . && $name != .. && \
    $name != */* && ${#name} -le 255 ]] || return 1
  expected_identity=$(python3 - "$parent_fd" "$name" <<'PY'
import os
import stat
import sys


parent_fd = int(sys.argv[1])
name = sys.argv[2]
os.mkdir(name, 0o700, dir_fd=parent_fd)
os.fsync(parent_fd)
flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(name, flags, dir_fd=parent_fd)
try:
    value = os.fstat(descriptor)
    expected_owner = (os.geteuid(), os.getegid())
    if os.geteuid() == 0:
        expected_owner = (0, 0)
    if (
        not stat.S_ISDIR(value.st_mode)
        or (value.st_uid, value.st_gid) != expected_owner
        or stat.S_IMODE(value.st_mode) != 0o700
    ):
        raise SystemExit(1)
    print(f"{value.st_dev}:{value.st_ino}")
finally:
    os.close(descriptor)
PY
  ) || return 1
  exec {descriptor}<"$parent_alias/$name" || return 1
  if [[ $(cats_e3_fd_directory_identity "$descriptor") != "$expected_identity" ]]; then
    exec {descriptor}<&-
    return 1
  fi
  if [[ -d /proc/self/fd ]]; then
    alias=/proc/self/fd/$descriptor
  else
    alias=$(python3 - "$descriptor" <<'PY'
import fcntl
import sys
try:
    raw = fcntl.fcntl(int(sys.argv[1]), 50, b"\0" * 1024)
except (AttributeError, OSError):
    raise SystemExit(1)
print(raw.split(b"\0", 1)[0].decode("utf-8"))
PY
    ) || {
      exec {descriptor}<&-
      return 1
    }
  fi
  printf -v "$fd_variable" '%s' "$descriptor"
  printf -v "$alias_variable" '%s' "$alias"
}

cats_e3_validate_private_key_input() {
  python3 - "$1" <<'PY'
import os
import stat
import sys


def fail():
    raise SystemExit(1)


def open_checked(name, flags, *, dir_fd=None):
    try:
        return os.open(name, flags, dir_fd=dir_fd)
    except OSError:
        fail()


path = sys.argv[1]
if (
    not path.startswith("/")
    or path != os.path.normpath(path)
    or path == "/"
):
    fail()

components = path.split("/")[1:]
directory_flags = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
effective_owner = (os.geteuid(), os.getegid())
if effective_owner[0] == 0 and effective_owner != (0, 0):
    fail()


def actor_owned(metadata):
    return metadata.st_uid == effective_owner[0] and (
        effective_owner[0] != 0 or metadata.st_gid == 0
    )


directory = open_checked("/", directory_flags)
try:
    for component in components[:-1]:
        if component in {"", ".", ".."}:
            fail()
        child = open_checked(component, directory_flags, dir_fd=directory)
        metadata = os.fstat(child)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or not (metadata.st_uid == 0 or actor_owned(metadata))
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            os.close(child)
            fail()
        os.close(directory)
        directory = child

    parent = os.fstat(directory)
    if (
        not stat.S_ISDIR(parent.st_mode)
        or not actor_owned(parent)
        or stat.S_IMODE(parent.st_mode) & 0o022
    ):
        fail()
    descriptor = open_checked(components[-1], file_flags, dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_uid,
            value.st_gid,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or not actor_owned(before)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 1 <= before.st_size <= 16_384
        ):
            fail()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 16_384))
            if not chunk:
                fail()
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            fail()
        if identity(os.fstat(descriptor)) != identity(before):
            fail()
    finally:
        os.close(descriptor)
finally:
    os.close(directory)
PY
}

cats_e3_stage_route_rotation_operator_key() {
  python3 - "$1" "$2" <<'PY'
import os
import stat
import sys


def fail():
    raise SystemExit(1)


def open_checked(name, flags, *, mode=None, dir_fd=None):
    try:
        if mode is None:
            return os.open(name, flags, dir_fd=dir_fd)
        return os.open(name, flags, mode, dir_fd=dir_fd)
    except OSError:
        fail()


def identity(value):
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def open_parent(path):
    if not path.startswith("/") or path != os.path.normpath(path) or path == "/":
        fail()
    components = path.split("/")[1:]
    if not components or components[-1] in {"", ".", ".."}:
        fail()
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    directory = open_checked("/", flags)
    try:
        for index, component in enumerate(components[:-1]):
            if component in {"", ".", ".."}:
                fail()
            child = open_checked(component, flags, dir_fd=directory)
            metadata = os.fstat(child)
            direct_parent = index == len(components) - 2
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or (metadata.st_uid, metadata.st_gid) != (0, 0)
                or (
                    stat.S_IMODE(metadata.st_mode) != 0o700
                    if direct_parent
                    else stat.S_IMODE(metadata.st_mode) & 0o022 != 0
                )
            ):
                os.close(child)
                fail()
            os.close(directory)
            directory = child
        parent = os.fstat(directory)
        if (
            not stat.S_ISDIR(parent.st_mode)
            or (parent.st_uid, parent.st_gid) != (0, 0)
            or stat.S_IMODE(parent.st_mode) != 0o700
        ):
            fail()
        return directory, components[-1]
    except BaseException:
        os.close(directory)
        raise


source_path, destination_path = sys.argv[1:]
source_parent, source_name = open_parent(source_path)
destination_parent = -1
source = -1
destination = -1
destination_created = False
try:
    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    source = open_checked(source_name, source_flags, dir_fd=source_parent)
    before = os.fstat(source)
    if (
        not stat.S_ISREG(before.st_mode)
        or (before.st_uid, before.st_gid) != (0, 0)
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
        or not 1 <= before.st_size <= 65_536
    ):
        fail()
    remaining = before.st_size
    chunks = []
    while remaining:
        chunk = os.read(source, min(remaining, 65_536))
        if not chunk:
            fail()
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(source, 1) or identity(os.fstat(source)) != identity(before):
        fail()
    data = b"".join(chunks)

    destination_parent, destination_name = open_parent(destination_path)
    destination_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    destination = open_checked(
        destination_name,
        destination_flags,
        mode=0o600,
        dir_fd=destination_parent,
    )
    destination_created = True
    os.fchmod(destination, 0o600)
    written = 0
    while written < len(data):
        count = os.write(destination, data[written:])
        if count <= 0:
            fail()
        written += count
    os.fsync(destination)
    staged = os.fstat(destination)
    if (
        not stat.S_ISREG(staged.st_mode)
        or (staged.st_uid, staged.st_gid) != (0, 0)
        or staged.st_nlink != 1
        or stat.S_IMODE(staged.st_mode) != 0o600
        or staged.st_size != before.st_size
    ):
        fail()
    os.fsync(destination_parent)
except BaseException:
    if destination >= 0:
        os.close(destination)
        destination = -1
    if destination_created:
        try:
            os.unlink(destination_name, dir_fd=destination_parent)
            os.fsync(destination_parent)
        except OSError:
            pass
    raise
finally:
    if destination >= 0:
        os.close(destination)
    if source >= 0:
        os.close(source)
    if destination_parent >= 0:
        os.close(destination_parent)
    os.close(source_parent)
PY
}

cats_e3_recover_persistent_state_link() {
  local directory=$1 name=$2 directory_fd=-1
  if [[ -n ${state_directory_fd:-} && $directory == "$state_directory" ]]; then
    directory_fd=$state_directory_fd
  fi
  python3 - "$directory" "$name" "$directory_fd" <<'PY'
import os
import stat
import sys


directory, name = sys.argv[1:3]
inherited_directory_fd = int(sys.argv[3])
if name not in {
    "qualification-state-binding.v1.json",
    "runtime-state.json",
    "qualification-close-decision.v1.json",
}:
    raise SystemExit(1)
if inherited_directory_fd >= 0:
    directory_fd = os.dup(inherited_directory_fd)
else:
    directory_fd = os.open(
        directory,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
effective_uid = os.geteuid()
prefix = f".{name}."


def actor_owned(value):
    return value.st_uid == effective_uid and (effective_uid != 0 or value.st_gid == 0)


try:
    descriptor = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=directory_fd,
    )
    try:
        canonical = os.fstat(descriptor)
        if (
            not stat.S_ISREG(canonical.st_mode)
            or not actor_owned(canonical)
            or stat.S_IMODE(canonical.st_mode) != 0o600
            or canonical.st_nlink not in {1, 2}
        ):
            raise SystemExit(1)
        temporaries = []
        for candidate in os.listdir(directory_fd):
            if not candidate.startswith(prefix):
                continue
            value = os.stat(candidate, dir_fd=directory_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(value.st_mode)
                or not actor_owned(value)
                or stat.S_IMODE(value.st_mode) != 0o600
            ):
                raise SystemExit(1)
            temporaries.append((candidate, value))
        if canonical.st_nlink == 1:
            if temporaries:
                raise SystemExit(1)
            raise SystemExit(0)
        matches = [
            candidate
            for candidate, value in temporaries
            if (value.st_dev, value.st_ino) == (canonical.st_dev, canonical.st_ino)
            and value.st_nlink == 2
        ]
        if len(temporaries) != 1 or len(matches) != 1:
            raise SystemExit(1)
        os.unlink(matches[0], dir_fd=directory_fd)
        os.fsync(directory_fd)
        after = os.fstat(descriptor)
        if (
            after.st_nlink != 1
            or (after.st_dev, after.st_ino) != (canonical.st_dev, canonical.st_ino)
            or after.st_size != canonical.st_size
            or after.st_mtime_ns != canonical.st_mtime_ns
        ):
            raise SystemExit(1)
    finally:
        os.close(descriptor)
finally:
    os.close(directory_fd)
PY
}

cats_e3_bind_persistent_state() {
  local directory=$1 source=$2 name=${3:-qualification-state-binding.v1.json} directory_fd=-1
  if [[ -n ${state_directory_fd:-} && $directory == "$state_directory" ]]; then
    directory_fd=$state_directory_fd
  fi
  python3 - "$directory" "$source" "$name" "$directory_fd" <<'PY'
import os
from pathlib import Path
import re
import stat
import sys
import tempfile


directory = Path(sys.argv[1])
source = Path(sys.argv[2])
name = sys.argv[3]
inherited_directory_fd = int(sys.argv[4])
effective_uid = os.geteuid()


def actor_owned(metadata):
    return metadata.st_uid == effective_uid and (effective_uid != 0 or metadata.st_gid == 0)


fixed_names = {
    "qualification-state-binding.v1.json",
    "qualification-close-decision.v1.json",
    "runtime-state.json",
}
case_prefix = re.fullmatch(r"[0-9]{2}-[a-z0-9][a-z0-9-]{0,63}\.v1\.json", name)
if name not in fixed_names and case_prefix is None:
    raise SystemExit(1)
prefix = f".{name}."
expected = source.read_bytes()
maximum = 16 * 1024 * 1024 if case_prefix is not None else 65536
if not 1 <= len(expected) <= maximum:
    raise SystemExit(1)
if inherited_directory_fd >= 0:
    directory_fd = os.dup(inherited_directory_fd)
else:
    directory_fd = os.open(
        directory,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )


def identity(value):
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def read_existing():
    descriptor = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=directory_fd,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not actor_owned(before)
            or before.st_nlink not in {1, 2}
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size != len(expected)
        ):
            raise SystemExit(1)
        if before.st_nlink == 2:
            siblings = []
            for candidate in os.listdir(directory_fd):
                if not candidate.startswith(prefix):
                    continue
                metadata = os.stat(candidate, dir_fd=directory_fd, follow_symlinks=False)
                if (
                    stat.S_ISREG(metadata.st_mode)
                    and (metadata.st_dev, metadata.st_ino) == (before.st_dev, before.st_ino)
                ):
                    siblings.append(candidate)
            if len(siblings) != 1:
                raise SystemExit(1)
            os.unlink(siblings[0], dir_fd=directory_fd)
            os.fsync(directory_fd)
            before = os.fstat(descriptor)
            if before.st_nlink != 1:
                raise SystemExit(1)
        data = b""
        while len(data) < before.st_size:
            chunk = os.read(descriptor, before.st_size - len(data))
            if not chunk:
                raise SystemExit(1)
            data += chunk
        if os.read(descriptor, 1) or identity(os.fstat(descriptor)) != identity(before):
            raise SystemExit(1)
        if data != expected:
            raise SystemExit(1)
    finally:
        os.close(descriptor)


temporary_fd = -1
temporary_name = None
try:
    try:
        read_existing()
    except FileNotFoundError:
        temporary_fd, temporary_name = tempfile.mkstemp(prefix=prefix, dir=directory)
        os.fchmod(temporary_fd, 0o600)
        offset = 0
        while offset < len(expected):
            offset += os.write(temporary_fd, expected[offset:])
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = -1
        try:
            os.link(
                temporary_name,
                name,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            read_existing()
        else:
            os.unlink(temporary_name)
            temporary_name = None
            os.fsync(directory_fd)
            read_existing()
finally:
    if temporary_fd >= 0:
        os.close(temporary_fd)
    if temporary_name is not None:
        try:
            os.unlink(temporary_name)
            os.fsync(directory_fd)
        except FileNotFoundError:
            pass
    os.close(directory_fd)
PY
}

cats_e3_load_close_decision() {
  local decision=$state_directory/qualification-close-decision.v1.json
  local canonical=$scratch/qualification-close-decision.canonical.json
  local state_binding_sha256
  cats_e3_recover_persistent_state_link "$state_directory" \
    qualification-close-decision.v1.json || return 1
  state_binding_sha256=sha256:$(
    sha256sum "$state_directory/qualification-state-binding.v1.json" | awk '{print $1}'
  )
  [[ -f $decision && ! -L $decision && -O $decision && \
    $(stat -c '%u:%g:%a:%h' "$decision") == 0:0:600:1 ]] || return 1
  jq -S -c . "$decision" >"$canonical" || return 125
  cmp -s "$decision" "$canonical" || return 125
  jq -er --arg run_id "$run_id" --arg block_path "$block_path" \
    --arg binding_sha256 "$qualification_binding_sha256" \
    --arg state_binding_sha256 "$state_binding_sha256" '
    keys == ["block_path","close_kind","kind","qualification_binding_sha256",
      "qualification_state_binding_sha256","run_id","version"]
    and .kind == "cats.production-mutation-qualification-close-decision.v1"
    and .version == 1 and .run_id == $run_id and .block_path == $block_path
    and .qualification_binding_sha256 == $binding_sha256
    and .qualification_state_binding_sha256 == $state_binding_sha256
    and (.close_kind == "end_qualification" or .close_kind == "emergency_close")' \
    "$decision" >/dev/null || return 125
  jq -er '.close_kind' "$decision"
}

cats_e3_persist_close_decision() {
  local close_kind=$1 source=$scratch/qualification-close-decision.v1.json
  local state_binding_sha256
  case "$close_kind" in end_qualification|emergency_close) ;; *) return 125 ;; esac
  state_binding_sha256=sha256:$(
    sha256sum "$state_directory/qualification-state-binding.v1.json" | awk '{print $1}'
  )
  jq -S -c -n --arg run_id "$run_id" --arg block_path "$block_path" \
    --arg close_kind "$close_kind" --arg binding_sha256 "$qualification_binding_sha256" \
    --arg state_binding_sha256 "$state_binding_sha256" '
    {block_path:$block_path,close_kind:$close_kind,
     kind:"cats.production-mutation-qualification-close-decision.v1",
     qualification_binding_sha256:$binding_sha256,
     qualification_state_binding_sha256:$state_binding_sha256,
     run_id:$run_id,version:1}' \
    >"$source"
  chmod 0600 "$source"
  cats_e3_bind_persistent_state "$state_directory" "$source" \
    qualification-close-decision.v1.json
}

cats_e3_persist_case_prefix() {
  local case_index=$1 case_id=$2 marker_name marker_source
  local qualification_state_sha256 runtime_state_sha256
  marker_name=$(printf '%02d-%s.v1.json' "$case_index" "$case_id")
  marker_source=$scratch/$marker_name
  qualification_state_sha256=sha256:$(
    sha256sum "$state_directory/qualification-state-binding.v1.json" | awk '{print $1}'
  )
  runtime_state_sha256=sha256:$(sha256sum "$persistent_runtime_state" | awk '{print $1}')
  jq -S -c -n \
    --arg block_path "$block_path" --arg case_id "$case_id" \
    --arg exact_commit "$exact_commit" --arg run_id "$run_id" \
    --arg workspace_id "$workspace_id" \
    --arg qualification_catalog_sha256 "sha256:$qualification_catalog_authority_sha256" \
    --arg qualification_state_sha256 "$qualification_state_sha256" \
    --arg runtime_state_sha256 "$runtime_state_sha256" \
    --argjson case_index "$case_index" \
    --slurpfile results "$results_work" --slurpfile evidence "$evidence_work" \
    --rawfile journal_summary "$journal_work" \
    --slurpfile runtime_state "$persistent_runtime_state" '
    {block_path:$block_path,case_id:$case_id,case_index:$case_index,
     completed_case_ids:[$results[].case_id],evidence:$evidence,
     exact_commit:$exact_commit,journal_summary:$journal_summary,
     kind:"cats.runtime-cutover-case-prefix.v1",
     qualification_catalog_sha256:$qualification_catalog_sha256,
     qualification_state_sha256:$qualification_state_sha256,results:$results,
     run_id:$run_id,runtime_state:$runtime_state[0],
     runtime_state_sha256:$runtime_state_sha256,version:1,workspace_id:$workspace_id}' \
    >"$marker_source"
  chmod 0600 "$marker_source"
  cats_e3_bind_persistent_state "$persistent_case_prefix_dir" "$marker_source" "$marker_name"
}

cats_e3_restore_case_prefix() {
  cats_e3_recover_persistent_state_link "$state_directory" \
    qualification-state-binding.v1.json || return 1
  cats_e3_recover_persistent_state_link "$state_directory" runtime-state.json || return 1
  python3 - \
    "$persistent_case_prefix_dir" \
    "$state_directory/qualification-state-binding.v1.json" \
    "$persistent_runtime_state" \
    "$persistent_cases_dir" \
    "$catalog_work" \
    "$results_work" "$evidence_work" "$journal_work" \
    "$run_id" "$block_path" "$workspace_id" "$exact_commit" \
    "sha256:$qualification_catalog_authority_sha256" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


(
    prefix_path,
    qualification_state_path,
    runtime_state_path,
    cases_path,
    catalog_path,
    results_path,
    evidence_path,
    journal_path,
    run_id,
    block_path,
    workspace_id,
    exact_commit,
    catalog_sha256,
) = sys.argv[1:]
marker_pattern = re.compile(r"([0-9]{2})-([a-z0-9][a-z0-9-]{0,63})\.v1\.json\Z")
temporary_pattern = re.compile(
    r"\.([0-9]{2}-[a-z0-9][a-z0-9-]{0,63}\.v1\.json)\..+\Z"
)
digest_pattern = re.compile(r"sha256:[0-9a-f]{64}\Z")
id_pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
maximum_marker_bytes = 16 * 1024 * 1024
effective_uid = os.geteuid()


def actor_owned(metadata):
    return metadata.st_uid == effective_uid and (effective_uid != 0 or metadata.st_gid == 0)


def identity(value):
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def canonical(value):
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def stable_read_at(directory_fd, name, maximum):
    descriptor = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=directory_fd,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not actor_owned(before)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 1 <= before.st_size <= maximum
        ):
            raise SystemExit(1)
        raw = b""
        while len(raw) < before.st_size:
            chunk = os.read(descriptor, before.st_size - len(raw))
            if not chunk:
                raise SystemExit(1)
            raw += chunk
        if os.read(descriptor, 1) or identity(os.fstat(descriptor)) != identity(before):
            raise SystemExit(1)
        return raw
    finally:
        os.close(descriptor)


def stable_read_path(path, maximum):
    directory = os.path.dirname(path)
    name = os.path.basename(path)
    directory_fd = os.open(
        directory,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        return stable_read_at(directory_fd, name, maximum)
    finally:
        os.close(directory_fd)


def decode(raw, label):
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"invalid {label}") from error
    if raw != canonical(value):
        raise SystemExit(f"noncanonical {label}")
    return value


def closed_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def validate_runtime_state(value):
    if (
        not isinstance(value, dict)
        or set(value)
        != {"block_path", "cat_id", "exact_commit", "run_id", "version"}
        or type(value["version"]) is not int
        or value["version"] != 1
        or value["exact_commit"] != exact_commit
        or value["block_path"] != block_path
        or value["run_id"] != run_id
        or (
            value["cat_id"] is not None
            and (
                not isinstance(value["cat_id"], str)
                or id_pattern.fullmatch(value["cat_id"]) is None
            )
        )
    ):
        raise SystemExit(1)
    return value


prefix_fd = os.open(
    prefix_path,
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0),
)
try:
    entries = os.listdir(prefix_fd)
    destinations = {entry for entry in entries if marker_pattern.fullmatch(entry)}
    temporary_by_destination = {}
    for entry in entries:
        if entry in destinations:
            continue
        match = temporary_pattern.fullmatch(entry)
        if match is None:
            raise SystemExit(1)
        destination = match.group(1)
        temporary_by_destination.setdefault(destination, []).append(entry)
    for destination, temporaries in temporary_by_destination.items():
        if len(temporaries) != 1:
            raise SystemExit(1)
        temporary = temporaries[0]
        temporary_metadata = os.stat(
            temporary,
            dir_fd=prefix_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(temporary_metadata.st_mode)
            or not actor_owned(temporary_metadata)
            or stat.S_IMODE(temporary_metadata.st_mode) != 0o600
            or temporary_metadata.st_nlink not in {1, 2}
        ):
            raise SystemExit(1)
        if destination in destinations:
            destination_metadata = os.stat(
                destination,
                dir_fd=prefix_fd,
                follow_symlinks=False,
            )
            if (
                temporary_metadata.st_nlink != 2
                or (temporary_metadata.st_dev, temporary_metadata.st_ino)
                != (destination_metadata.st_dev, destination_metadata.st_ino)
            ):
                raise SystemExit(1)
        elif temporary_metadata.st_nlink != 1:
            raise SystemExit(1)
        os.unlink(temporary, dir_fd=prefix_fd)
    if temporary_by_destination:
        os.fsync(prefix_fd)
    marker_names = sorted(
        entry for entry in os.listdir(prefix_fd) if marker_pattern.fullmatch(entry)
    )

    catalog_records = []
    for line in Path(catalog_path).read_text(encoding="utf-8").splitlines():
        value = json.loads(line)
        if value["case_id"] != "usage-source-terminal-receipts":
            catalog_records.append(value)
    expected_names = [
        f"{index:02d}-{record['case_id']}.v1.json"
        for index, record in enumerate(catalog_records)
    ]
    if marker_names != expected_names[: len(marker_names)]:
        raise SystemExit(1)
    create_indices = [
        index
        for index, record in enumerate(catalog_records)
        if record["case_id"] == "cat-create-running"
    ]
    if len(create_indices) != 1:
        raise SystemExit(1)
    create_index = create_indices[0]

    qualification_state_raw = stable_read_path(qualification_state_path, 65_536)
    qualification_state_sha256 = "sha256:" + hashlib.sha256(
        qualification_state_raw
    ).hexdigest()
    runtime_state_raw = stable_read_path(runtime_state_path, 65_536)
    runtime_state = validate_runtime_state(decode(runtime_state_raw, "runtime state"))

    previous_results = []
    previous_evidence = []
    expected_cat_id = None
    last = None
    for index, marker_name in enumerate(marker_names):
        raw = stable_read_at(prefix_fd, marker_name, maximum_marker_bytes)
        value = decode(raw, "case prefix")
        expected_keys = {
            "block_path",
            "case_id",
            "case_index",
            "completed_case_ids",
            "evidence",
            "exact_commit",
            "journal_summary",
            "kind",
            "qualification_catalog_sha256",
            "qualification_state_sha256",
            "results",
            "run_id",
            "runtime_state",
            "runtime_state_sha256",
            "version",
            "workspace_id",
        }
        expected_case_ids = [record["case_id"] for record in catalog_records[: index + 1]]
        if (
            not isinstance(value, dict)
            or set(value) != expected_keys
            or value["kind"] != "cats.runtime-cutover-case-prefix.v1"
            or type(value["version"]) is not int
            or value["version"] != 1
            or type(value["case_index"]) is not int
            or value["case_index"] != index
            or value["case_id"] != expected_case_ids[-1]
            or value["completed_case_ids"] != expected_case_ids
            or value["run_id"] != run_id
            or value["block_path"] != block_path
            or value["workspace_id"] != workspace_id
            or value["exact_commit"] != exact_commit
            or value["qualification_catalog_sha256"] != catalog_sha256
            or value["qualification_state_sha256"] != qualification_state_sha256
            or not isinstance(value["journal_summary"], str)
            or len(value["journal_summary"].encode("utf-8")) > 131_072
            or "\0" in value["journal_summary"]
        ):
            raise SystemExit(1)
        results = value["results"]
        evidence = value["evidence"]
        if (
            not isinstance(results, list)
            or len(results) != index + 1
            or [result.get("case_id") for result in results] != expected_case_ids
            or results[: len(previous_results)] != previous_results
            or not isinstance(evidence, list)
            or evidence[: len(previous_evidence)] != previous_evidence
        ):
            raise SystemExit(1)
        result_keys = {
            "case_id",
            "cleanup_deadline_seconds",
            "cleanup_exit_code",
            "deadline_seconds",
            "diagnostic_exit_code",
            "ended_at_unix_seconds",
            "evidence_exit_code",
            "expected_outcome",
            "observed_outcome",
            "outcome_matches",
            "run_exit_code",
            "started_at_unix_seconds",
            "status",
        }
        for result_index, result in enumerate(results):
            catalog_record = catalog_records[result_index]
            if (
                not isinstance(result, dict)
                or set(result) != result_keys
                or result["case_id"] != catalog_record["case_id"]
                or result["expected_outcome"] != catalog_record["expected_outcome"]
                or result["deadline_seconds"] != catalog_record["deadline_seconds"]
                or result["cleanup_deadline_seconds"]
                != catalog_record["cleanup_deadline_seconds"]
                or result["status"] != "passed"
                or result["observed_outcome"] != "passed"
                or result["outcome_matches"] is not True
                or result["run_exit_code"] != 0
                or result["diagnostic_exit_code"] != 0
                or result["cleanup_exit_code"] != 0
                or result["evidence_exit_code"] != 0
                or type(result["started_at_unix_seconds"]) is not int
                or type(result["ended_at_unix_seconds"]) is not int
                or result["started_at_unix_seconds"] < 0
                or result["ended_at_unix_seconds"] < result["started_at_unix_seconds"]
            ):
                raise SystemExit(1)
            for field in (
                "cleanup_deadline_seconds",
                "cleanup_exit_code",
                "deadline_seconds",
                "diagnostic_exit_code",
                "ended_at_unix_seconds",
                "evidence_exit_code",
                "run_exit_code",
                "started_at_unix_seconds",
            ):
                if type(result[field]) is not int or result[field] < 0:
                    raise SystemExit(1)
            if (
                result_index > 0
                and result["started_at_unix_seconds"]
                < results[result_index - 1]["ended_at_unix_seconds"]
            ):
                raise SystemExit(1)
        evidence_keys = {"case_id", "content", "filename", "kind", "sha256", "size_bytes"}
        expected_evidence = [
            (record["case_id"], required["filename"], required["kind"])
            for record in catalog_records[: index + 1]
            for required in record["required_evidence"]
        ]
        actual_evidence = [
            (row.get("case_id"), row.get("filename"), row.get("kind"))
            if isinstance(row, dict)
            else None
            for row in evidence
        ]
        if actual_evidence != expected_evidence or len(set(actual_evidence)) != len(actual_evidence):
            raise SystemExit(1)
        for row in evidence:
            if (
                not isinstance(row, dict)
                or set(row) != evidence_keys
                or not isinstance(row["filename"], str)
                or not isinstance(row["sha256"], str)
                or digest_pattern.fullmatch(row["sha256"]) is None
                or type(row["size_bytes"]) is not int
                or row["size_bytes"] <= 0
            ):
                raise SystemExit(1)
            if row["kind"] == "json":
                content = canonical(row["content"])
            elif isinstance(row["content"], str):
                content = row["content"].encode("utf-8")
            else:
                raise SystemExit(1)
            if (
                len(content) != row["size_bytes"]
                or "sha256:" + hashlib.sha256(content).hexdigest() != row["sha256"]
            ):
                raise SystemExit(1)
        marker_runtime = validate_runtime_state(value["runtime_state"])
        marker_runtime_raw = canonical(marker_runtime)
        if (
            "sha256:" + hashlib.sha256(marker_runtime_raw).hexdigest()
            != value["runtime_state_sha256"]
        ):
            raise SystemExit(1)
        marker_cat_id = marker_runtime["cat_id"]
        if index < create_index:
            if marker_cat_id is not None:
                raise SystemExit(1)
        else:
            if marker_cat_id is None:
                raise SystemExit(1)
            if expected_cat_id is None:
                expected_cat_id = marker_cat_id
            elif marker_cat_id != expected_cat_id:
                raise SystemExit(1)
        previous_results = results
        previous_evidence = evidence
        last = value

    if last is not None:
        last_runtime = canonical(last["runtime_state"])
        if runtime_state_raw != last_runtime:
            allow_incomplete_create = (
                len(marker_names) == create_index
                and last["runtime_state"].get("cat_id") is None
                and runtime_state.get("cat_id") is not None
            )
            response = (
                Path(cases_path)
                / f"{create_index:02d}-cat-create-running"
                / "create-response.json"
            )
            if not allow_incomplete_create or not response.is_file() or response.is_symlink():
                raise SystemExit(1)
            response_raw = stable_read_path(str(response), 65_536)
            try:
                response_value = json.loads(
                    response_raw.decode("utf-8"), object_pairs_hook=closed_object
                )
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
                raise SystemExit(1) from error
            if (
                response_value.get("cat_id") != runtime_state["cat_id"]
                or not isinstance(response_value.get("operation_id"), str)
                or id_pattern.fullmatch(response_value["operation_id"]) is None
            ):
                raise SystemExit(1)
        results = last["results"]
        evidence = last["evidence"]
        journal = last["journal_summary"]
    else:
        if runtime_state["cat_id"] is not None:
            raise SystemExit(1)
        results = []
        evidence = []
        journal = ""

    Path(results_path).write_bytes(b"".join(canonical(value) for value in results))
    Path(evidence_path).write_bytes(b"".join(canonical(value) for value in evidence))
    Path(journal_path).write_text(journal, encoding="utf-8")
    print(len(marker_names))
finally:
    os.close(prefix_fd)
PY
}

cats_e3_private_state_subdirectory() {
  local path=$1 parent base parent_fd parent_alias relative
  [[ $path == /* && $path != */. && $path != */.. ]] || return 1
  if [[ -n ${state_directory_fd:-} && $path == "$state_directory"/* ]]; then
    relative=${path#"$state_directory"/}
    python3 - "$state_directory_fd" "$relative" <<'PY'
import os
import stat
import sys


directory_fd = os.dup(int(sys.argv[1]))
components = sys.argv[2].split("/")
effective_uid = os.geteuid()
effective_gid = os.getegid()
if not components or any(component in {"", ".", ".."} for component in components):
    raise SystemExit(1)
flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def valid(value):
    owner = (value.st_uid, value.st_gid) == (effective_uid, effective_gid)
    if effective_uid == 0:
        owner = (value.st_uid, value.st_gid) == (0, 0)
    return stat.S_ISDIR(value.st_mode) and owner and stat.S_IMODE(value.st_mode) == 0o700


try:
    for index, component in enumerate(components):
        final = index == len(components) - 1
        if final:
            try:
                os.mkdir(component, 0o700, dir_fd=directory_fd)
                os.fsync(directory_fd)
            except FileExistsError:
                pass
        child = os.open(component, flags, dir_fd=directory_fd)
        if not valid(os.fstat(child)):
            os.close(child)
            raise SystemExit(1)
        os.close(directory_fd)
        directory_fd = child
finally:
    os.close(directory_fd)
PY
    return
  fi
  parent=${path%/*}
  base=${path##*/}
  [[ -n $parent && -n $base ]] || return 1
  cats_e3_pin_private_directory "$parent" parent_fd parent_alias ancestor || return 1
  if ! python3 - "$parent_fd" "$base" <<'PY'
import os
import stat
import sys


parent_fd = int(sys.argv[1])
name = sys.argv[2]
effective_uid = os.geteuid()
effective_gid = os.getegid()
try:
    os.mkdir(name, 0o700, dir_fd=parent_fd)
    os.fsync(parent_fd)
except FileExistsError:
    pass
descriptor = os.open(
    name,
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    dir_fd=parent_fd,
)
try:
    value = os.fstat(descriptor)
    owner = (value.st_uid, value.st_gid) == (effective_uid, effective_gid)
    if effective_uid == 0:
        owner = (value.st_uid, value.st_gid) == (0, 0)
    if not stat.S_ISDIR(value.st_mode) or not owner or stat.S_IMODE(value.st_mode) != 0o700:
        raise SystemExit(1)
finally:
    os.close(descriptor)
PY
  then
    exec {parent_fd}<&-
    return 1
  fi
  exec {parent_fd}<&-
}

cats_e3_private_stage=
cats_e3_remove_private_stage() {
  local parent=$1
  python3 - "$parent" <<'PY'
import os
import stat
import sys


parent = sys.argv[1]
name = "invocation-secrets"
effective_uid = os.geteuid()
inherited = None
for prefix in ("/proc/self/fd/", "/dev/fd/"):
    if parent.startswith(prefix) and parent[len(prefix):].isdigit():
        inherited = int(parent[len(prefix):])
        break
if inherited is None:
    parent_fd = os.open(
        parent,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
else:
    parent_fd = os.dup(inherited)
try:
    try:
        directory_fd = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
    except FileNotFoundError:
        raise SystemExit(0)
    try:
        directory = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid != effective_uid
            or (effective_uid == 0 and directory.st_gid != 0)
            or stat.S_IMODE(directory.st_mode) != 0o700
        ):
            raise SystemExit(1)
        allowed = {
            "control-token",
            "production-cutover-operator-key",
            "route-rotation-operator-key",
        }
        entries = os.listdir(directory_fd)
        if not set(entries) <= allowed:
            raise SystemExit(1)
        for entry in entries:
            metadata = os.stat(entry, dir_fd=directory_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != effective_uid
                or (effective_uid == 0 and metadata.st_gid != 0)
                or metadata.st_nlink != 1
            ):
                raise SystemExit(1)
            os.unlink(entry, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    os.rmdir(name, dir_fd=parent_fd)
    os.fsync(parent_fd)
finally:
    os.close(parent_fd)
PY
}

cats_e3_cleanup_private_stage() {
  local status=$?
  trap - EXIT INT TERM
  if ! cats_e3_close_on_exit; then
    [[ $status -ne 0 ]] || status=125
  fi
  if [[ -n $cats_e3_private_stage ]]; then
    cats_e3_remove_private_stage "${cats_e3_private_stage%/*}" || status=125
    cats_e3_private_stage=
  fi
  exit "$status"
}

cats_e3_prepare_private_stage() {
  local parent=$1
  [[ -z $cats_e3_private_stage && $parent == /* && -d $parent && ! -L $parent ]] || return 1
  cats_e3_remove_private_stage "$parent" || return 1
  cats_e3_private_stage=$parent/invocation-secrets
  mkdir -m 0700 "$cats_e3_private_stage" || return 1
  cats_e3_private_state_subdirectory "$cats_e3_private_stage" || return 1
  sync -f "$parent" || return 1
  trap cats_e3_cleanup_private_stage EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
}

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then
  return 0
fi

usage() {
  cat >&2 <<'EOF'
usage: runtime-cutover-e2e.sh \
  --exact-commit <40 lowercase hex> \
  --block-path <kernel-nbd|vhost-user> \
  --run-id <stable-id> \
  --output-dir </absolute/new/directory> \
  --state-directory </absolute/persistent/root-only/directory> \
  --build-receipt </absolute/build-receipt.json> \
  --release-manifest </absolute/release-manifest.json> \
  --release-manifest-sha256 <sha256:64hex> \
  --installer-receipt </absolute/installer-receipt.json> \
  --token-file </absolute/root-only/control-token> \
  --production-cutover-operator-private-key-file </absolute/root-only/private-key.pem> \
  --control-origin <canonical-https-origin> \
  --workspace-id <runtime-id> \
  --expected-node <runtime-id> [--expected-node ...] \
  --qualification-node <one-expected-node-id> \
  --cat-name <bounded-name> \
  --boot-image-digest <sha256:64hex> \
  --endpoint-name <bounded-name> \
  --endpoint-hostname <lowercase-dns-name> \
  --guest-kernel <nonsecret-release-string> \
  --binary <label=/absolute/path> [--binary ...] \
  --config <label=/absolute/path> [--config ...] \
  --key-fingerprint <label=sha256:64hex> [--key-fingerprint ...] \
  --scenario-driver </absolute/repo-owned/executable>
EOF
  exit 64
}

fail() {
  printf 'runtime cutover e2e: %s\n' "$*" >&2
  exit 64
}

exact_commit=
block_path=
run_id=
output_dir=
state_directory=
build_receipt=
release_manifest=
release_manifest_sha256=
installer_receipt=
token_file=
production_cutover_operator_private_key_file=
production_cutover_operator_private_key_file_count=0
control_origin=
workspace_id=
qualification_node=
cat_name=
boot_image_digest=
endpoint_name=
endpoint_hostname=
guest_kernel=
scenario_driver=
expected_nodes=()
binary_entries=()
config_entries=()
key_fingerprint_entries=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --production-cutover-operator-private-key-file)
      [[ $# -ge 2 ]] || usage
      production_cutover_operator_private_key_file=$2
      production_cutover_operator_private_key_file_count=$((production_cutover_operator_private_key_file_count + 1))
      shift 2
      ;;
    --exact-commit|--block-path|--run-id|--output-dir|--state-directory|--build-receipt|--release-manifest|--release-manifest-sha256|--installer-receipt|--token-file|--control-origin|--workspace-id|--qualification-node|--cat-name|--boot-image-digest|--endpoint-name|--endpoint-hostname|--guest-kernel|--scenario-driver)
      [[ $# -ge 2 ]] || usage
      name=${1#--}
      name=${name//-/_}
      printf -v "$name" '%s' "$2"
      shift 2
      ;;
    --expected-node)
      [[ $# -ge 2 ]] || usage
      expected_nodes+=("$2")
      shift 2
      ;;
    --binary)
      [[ $# -ge 2 ]] || usage
      binary_entries+=("$2")
      shift 2
      ;;
    --config)
      [[ $# -ge 2 ]] || usage
      config_entries+=("$2")
      shift 2
      ;;
    --key-fingerprint)
      [[ $# -ge 2 ]] || usage
      key_fingerprint_entries+=("$2")
      shift 2
      ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

[[ $exact_commit =~ ^[0-9a-f]{40}$ ]] || fail "--exact-commit must be one 40-character lowercase commit ID, not a branch or tag"
case "$block_path" in kernel-nbd|vhost-user) ;; *) fail "--block-path must be kernel-nbd or vhost-user" ;; esac
[[ $run_id =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]] || fail "--run-id is not canonical"
[[ $output_dir == /* ]] || fail "--output-dir must be an absolute output path"
[[ $state_directory == /* ]] || fail "--state-directory must be absolute"
[[ -n $build_receipt && $build_receipt == /* ]] || fail "--build-receipt must be absolute"
[[ -n $release_manifest && $release_manifest == /* ]] || fail "--release-manifest must be absolute"
[[ $release_manifest_sha256 =~ ^sha256:[0-9a-f]{64}$ ]] || \
  fail "--release-manifest-sha256 must be one independently approved sha256 digest"
[[ $installer_receipt == /opt/cats/release/worker-installation-receipt.v1.json ]] || \
  fail "--installer-receipt must be the canonical production installation receipt"
[[ $token_file == /* ]] || fail "--token-file must be absolute"
[[ $production_cutover_operator_private_key_file_count -eq 1 ]] || \
  fail "--production-cutover-operator-private-key-file is required exactly once"
[[ $production_cutover_operator_private_key_file == /* ]] || \
  fail "--production-cutover-operator-private-key-file must be absolute"
[[ $control_origin =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || \
  fail "--control-origin must be one canonical HTTPS origin"
for coordinate in workspace_id qualification_node cat_name endpoint_name; do
  value=${!coordinate}
  [[ $value =~ ^[A-Za-z0-9._:-]{1,128}$ ]] || fail "--${coordinate//_/-} is not canonical"
done
[[ $boot_image_digest =~ ^sha256:[0-9a-f]{64}$ ]] || \
  fail "--boot-image-digest must be one SHA-256 digest"
[[ $endpoint_hostname =~ ^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$ ]] || \
  fail "--endpoint-hostname is not one bounded lowercase DNS name"
[[ ${#expected_nodes[@]} -gt 0 ]] || fail "at least one --expected-node is required"
seen_expected_nodes='|'
qualification_node_matches=0
for node in "${expected_nodes[@]}"; do
  [[ $node =~ ^[A-Za-z0-9._:-]{1,128}$ ]] || fail "--expected-node is not canonical"
  case "$seen_expected_nodes" in *"|$node|"*) fail "--expected-node $node is repeated" ;; esac
  seen_expected_nodes+="$node|"
  [[ $node != "$qualification_node" ]] || qualification_node_matches=$((qualification_node_matches + 1))
done
expected_nodes_sorted=$(printf '%s\n' "${expected_nodes[@]}" | LC_ALL=C sort -u)
[[ $expected_nodes_sorted == "$(printf '%s\n' "${expected_nodes[@]}")" ]] || \
  fail "--expected-node values must be unique and C-sorted"
[[ $qualification_node_matches -eq 1 ]] || \
  fail "--qualification-node must equal exactly one --expected-node"
[[ $guest_kernel =~ ^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$ ]] || fail "--guest-kernel is not a bounded nonsecret release string"
[[ -n $scenario_driver && $scenario_driver == /* ]] || fail "--scenario-driver must be absolute"
[[ ${#binary_entries[@]} -gt 0 ]] || fail "at least one --binary is required"
[[ ${#config_entries[@]} -gt 0 ]] || fail "at least one --config is required"
[[ ${#key_fingerprint_entries[@]} -gt 0 ]] || fail "at least one --key-fingerprint is required"
cats_e3_environment_labels_are_unique true "${binary_entries[@]}" || \
  fail "binary labels collide after environment normalization"
cats_e3_environment_labels_are_unique false "${config_entries[@]}" || \
  fail "config labels collide after environment normalization"
[[ $EUID -eq 0 ]] || fail "production E3 qualification must run as root"
cats_e3_validate_private_key_input "$production_cutover_operator_private_key_file" || \
  fail "production cutover operator private key is not protected root-only input"

for command_name in cmp flock git jq python3 sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required"
done

# The scenario driver may execute only binaries/configs named by this exact
# invocation.  Do not let a caller's ambient environment smuggle an unrecorded
# executable or config past the manifest-backed --binary/--config boundary.
cats_e3_clear_ambient

script_dir=$(cd "$(dirname "$0")" && pwd -P)
repo=$(cd "$script_dir/../.." && pwd -P)
filter=$script_dir/runtime-cutover-evidence-filter.py
runner=$script_dir/runtime-cutover-e2e.sh
qualification_catalog=$script_dir/runtime-cutover-e2e-catalog.v1.json
qualification_operator=$repo/deploy/aws/production-mutation-admission.py

canonical_existing() {
  local path=$1
  [[ $path == /* && -e $path && ! -L $path ]] || return 1
  python3 - "$path" <<'PY'
import os
import sys
print(os.path.realpath(sys.argv[1]))
PY
}

build_receipt=$(canonical_existing "$build_receipt") || fail "build receipt must be a regular non-symlink file"
release_manifest=$(canonical_existing "$release_manifest") || fail "release manifest must be a regular non-symlink file"
installer_receipt=$(canonical_existing "$installer_receipt") || fail "installer receipt must be a regular non-symlink file"
token_file=$(canonical_existing "$token_file") || fail "token file must be a regular non-symlink file"
state_directory_requested=$state_directory
cats_e3_pin_private_directory "$state_directory_requested" \
  state_directory_fd state_directory_fd_path private || \
  fail "state directory and every ancestor must be pinned protected root-only directories"
state_directory_display=$state_directory_requested
[[ $installer_receipt == /opt/cats/release/worker-installation-receipt.v1.json ]] || \
  fail "installer receipt path must resolve to the canonical production path"
scenario_driver=$(canonical_existing "$scenario_driver") || fail "scenario driver must be a regular non-symlink file"
qualification_catalog=$(canonical_existing "$qualification_catalog") || \
  fail "qualification catalog must be the fixed regular non-symlink repository file"
output_dir_display=$output_dir
output_parent_display=${output_dir_display%/*}
output_base=${output_dir_display##*/}
[[ -n $output_parent_display && -n $output_base && $output_base != . && $output_base != .. ]] || \
  fail "output directory has no bounded parent/name split"
python3 - "$output_dir_display" <<'PY' || fail "output directory path must be canonical"
import os
import sys
path = sys.argv[1]
if not path.startswith("/") or path != os.path.normpath(path):
    raise SystemExit(1)
PY
cats_e3_pin_private_directory "$output_parent_display" \
  output_parent_fd output_parent_fd_path ancestor || \
  fail "output parent and every ancestor must be pinned protected root-only directories"
python3 - "$output_parent_fd" "$output_base" <<'PY' || \
  fail "output directory already exists; refusing to overwrite evidence"
import os
import sys
try:
    os.stat(sys.argv[2], dir_fd=int(sys.argv[1]), follow_symlinks=False)
except FileNotFoundError:
    raise SystemExit(0)
raise SystemExit(1)
PY
case "$output_dir_display/" in "$state_directory_display/"*) fail "output directory must not be inside persistent state" ;; esac
case "$state_directory_display/" in "$output_dir_display/"*) fail "persistent state must not be inside output evidence" ;; esac
state_directory=$state_directory_fd_path
cats_e3_open_pinned_state_lock "$state_directory_fd" "$state_directory_fd_path" \
  state_lock_fd || fail "persistent state lock is not protected descriptor-relative state"
flock -n "$state_lock_fd" || fail "another runner owns this persistent qualification state"

[[ $(git -C "$repo" rev-parse HEAD) == "$exact_commit" ]] || fail "checkout HEAD does not equal the exact commit"
[[ $(git -C "$repo" rev-parse "${exact_commit}^{commit}") == "$exact_commit" ]] || fail "exact commit is not a commit object"

verify_exact_repo_blob() {
  local path=$1 relative expected_blob actual_blob
  case "$path" in "$repo"/*) ;; *) fail "runner authority inputs must be repo-owned" ;; esac
  relative=${path#"$repo"/}
  expected_blob=$(git -C "$repo" rev-parse "${exact_commit}:${relative}" 2>/dev/null) || fail "$relative is not tracked by the exact commit"
  actual_blob=$(git -C "$repo" hash-object "$path")
  [[ $actual_blob == "$expected_blob" ]] || fail "$relative differs from the exact commit"
  [[ -f $path && ! -L $path ]] || fail "$relative must be a regular non-symlink file"
}

verify_exact_repo_file() {
  local path=$1
  verify_exact_repo_blob "$path"
  [[ -f $path && -x $path && ! -L $path ]] || fail "$path must be an executable regular file"
}

verify_exact_repo_file "$runner"
verify_exact_repo_file "$filter"
verify_exact_repo_file "$scenario_driver"
verify_exact_repo_file "$qualification_operator"
verify_exact_repo_blob "$qualification_catalog"

python3 - "$qualification_catalog" <<'PY' || fail "qualification catalog is not canonical or violates its closed schema"
import json
from pathlib import Path
import re
import sys


class DuplicateKey(ValueError):
    pass


def closed_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKey
        value[key] = item
    return value


raw = Path(sys.argv[1]).read_bytes()
if not 1 <= len(raw) <= 65536:
    raise SystemExit(1)
try:
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=closed_object)
except (UnicodeDecodeError, json.JSONDecodeError, DuplicateKey):
    raise SystemExit(1)
canonical = (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode()
if raw != canonical or not isinstance(value, dict):
    raise SystemExit(1)
if set(value) != {
    "cases",
    "framework_required_evidence",
    "post_block_path_cases",
    "qualification_admission_required_evidence",
    "version",
} or value["version"] != 1:
    raise SystemExit(1)

filename_pattern = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
case_pattern = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")


def validate_evidence(items):
    if not isinstance(items, list) or not items or len(items) > 32:
        raise SystemExit(1)
    names = []
    for item in items:
        if not isinstance(item, dict) or set(item) != {"filename", "kind"}:
            raise SystemExit(1)
        filename = item["filename"]
        if not isinstance(filename, str) or filename_pattern.fullmatch(filename) is None:
            raise SystemExit(1)
        if filename in {".", ".."} or item["kind"] not in {"json", "text"}:
            raise SystemExit(1)
        if item["kind"] == "json" and not filename.endswith(".json"):
            raise SystemExit(1)
        if item["kind"] == "text" and not filename.endswith(".log"):
            raise SystemExit(1)
        names.append(filename)
    if len(names) != len(set(names)):
        raise SystemExit(1)
    return set(names)


framework_names = validate_evidence(value["framework_required_evidence"])
if value["framework_required_evidence"] != [
    {"filename": "cleanup-receipt.json", "kind": "json"}
]:
    raise SystemExit(1)
qualification_admission_names = validate_evidence(
    value["qualification_admission_required_evidence"]
)
if value["qualification_admission_required_evidence"] != [
    {
        "filename": "production-mutation-qualification-begin.receipt.json",
        "kind": "json",
    },
    {
        "filename": "production-mutation-qualification-terminal.receipt.json",
        "kind": "json",
    },
] or qualification_admission_names & framework_names:
    raise SystemExit(1)
cases = value["cases"]
if not isinstance(cases, list) or not cases:
    raise SystemExit(1)
expected_cases = [
    "control-startup-schema",
    "node-registration-full-inventory",
    "cat-create-running",
    "durable-write-flush",
    "route-http-ws",
    "route-v2-rotation-disable-live-delivery",
    "agent-restart-adoption",
    "volume-init-matrix",
    "v3-aws-host-fence-authority",
    "delete-cleanup",
    "usage-source-terminal-receipts",
]
case_ids = []
for case in cases:
    if not isinstance(case, dict) or set(case) != {
        "case_id",
        "cleanup_deadline_seconds",
        "deadline_seconds",
        "expected_outcome",
        "required_evidence",
    }:
        raise SystemExit(1)
    case_id = case["case_id"]
    if not isinstance(case_id, str) or case_pattern.fullmatch(case_id) is None:
        raise SystemExit(1)
    deadline = case["deadline_seconds"]
    if type(deadline) is not int or not 1 <= deadline <= 3600:
        raise SystemExit(1)
    cleanup_deadline = case["cleanup_deadline_seconds"]
    expected_cleanup_deadline = (
        1800 if case_id == "route-v2-rotation-disable-live-delivery" else 60
    )
    if (
        type(cleanup_deadline) is not int
        or cleanup_deadline != expected_cleanup_deadline
    ):
        raise SystemExit(1)
    if case["expected_outcome"] != {"kind": "passed"}:
        raise SystemExit(1)
    if validate_evidence(case["required_evidence"]) & framework_names:
        raise SystemExit(1)
    case_ids.append(case_id)
if len(case_ids) != len(set(case_ids)) or case_ids != expected_cases:
    raise SystemExit(1)

post_cases = value["post_block_path_cases"]
if not isinstance(post_cases, list) or len(post_cases) != 1:
    raise SystemExit(1)
post_case = post_cases[0]
if not isinstance(post_case, dict) or set(post_case) != {
    "case_id",
    "deadline_seconds",
    "expected_outcome",
    "required_evidence",
}:
    raise SystemExit(1)
if (
    post_case["case_id"] != "usage-target-terminal-receipt"
    or post_case["deadline_seconds"] != 600
    or post_case["expected_outcome"] != {"kind": "passed"}
    or validate_evidence(post_case["required_evidence"])
    != {
        "usage-target-terminal-request.json",
        "usage-target-terminal-receipt.json",
        "usage-target-terminal-verification.receipt.json",
    }
    or validate_evidence(post_case["required_evidence"]) & framework_names
):
    raise SystemExit(1)
PY

qualification_catalog_sha256=$(sha256sum "$qualification_catalog" | awk '{print $1}')
qualification_catalog_size=$(wc -c <"$qualification_catalog" | tr -d ' ')
qualification_operator_sha256=$(sha256sum "$qualification_operator" | awk '{print $1}')
qualification_operator_size=$(wc -c <"$qualification_operator" | tr -d ' ')

[[ $(wc -c <"$build_receipt") -le 1048576 ]] || fail "build receipt is too large"
[[ $(wc -c <"$release_manifest") -le 1048576 ]] || fail "release manifest is too large"
[[ $(wc -c <"$installer_receipt") -le 1048576 ]] || fail "installer receipt is too large"
jq -e --arg commit "$exact_commit" \
  '.source_sha == $commit and .exit_status == 0 and .output_frozen == true' \
  "$build_receipt" >/dev/null || fail "build receipt does not prove a successful frozen build of the exact commit"
jq -e --arg commit "$exact_commit" \
  --arg catalog_sha256 "sha256:$qualification_catalog_sha256" \
  --argjson catalog_size "$qualification_catalog_size" \
  --arg operator_sha256 "sha256:$qualification_operator_sha256" \
  --argjson operator_size "$qualification_operator_size" \
  '.version == 1 and .source.commit == $commit
    and (.artifacts.worker.bundle_sha256 | test("^sha256:[0-9a-f]{64}$"))
    and (.artifacts.worker.members | type == "object" and length > 0)
    and .build_inputs.files.qualification_catalog
      == {sha256:$catalog_sha256,size_bytes:$catalog_size}
    and .build_inputs.files.production_mutation_admission_operator
      == {sha256:$operator_sha256,size_bytes:$operator_size}' \
  "$release_manifest" >/dev/null || fail "release manifest does not bind the exact commit"
approved_release_manifest_sha256=${release_manifest_sha256#sha256:}
[[ $(sha256sum "$release_manifest" | awk '{print $1}') == "$approved_release_manifest_sha256" ]] || \
  fail "release manifest differs from the independently approved sha256"
jq -e '
  (keys == ["host_tools","members","service","version","worker_bundle_sha256"])
  and .version == 1 and .service == "cats-worker.service"
  and (.worker_bundle_sha256 | test("^sha256:[0-9a-f]{64}$"))
  and (.members | keys) == ["cats","cats-blockd","cats-e3-guest-workload","cats-guest-agent","cats-noded","cats-route-v2-node-r1-validator","cats-runtime-e3-probe","cats-usage-schema-v16-verifier","cats-usage-terminal-receipt-verifier","cats-vmm-launcher"]
  and (.host_tools | keys) == ["curl","journalctl","systemctl","timeout"]
  and all(.members[];
    (keys == ["path","sha256","size_bytes"])
    and (.path | type == "string" and startswith("/"))
    and (.sha256 | test("^sha256:[0-9a-f]{64}$"))
    and (.size_bytes | type == "number" and . > 0 and floor == .))
  and all(.host_tools[];
    (keys == ["path","sha256","size_bytes"])
    and (.path | type == "string" and startswith("/"))
    and (.sha256 | test("^sha256:[0-9a-f]{64}$"))
    and (.size_bytes | type == "number" and . > 0 and floor == .))' \
  "$installer_receipt" >/dev/null || fail "installer receipt has the wrong closed shape"
python3 - "$installer_receipt" <<'PY' || fail "installer receipt or its parent is not protected production evidence"
import os
import stat
import sys
value = os.stat(sys.argv[1], follow_symlinks=False)
parent = os.stat(os.path.dirname(sys.argv[1]), follow_symlinks=False)
assert stat.S_ISREG(value.st_mode)
assert value.st_uid == 0
assert value.st_gid == 0
assert value.st_nlink == 1
assert stat.S_IMODE(value.st_mode) in (0o600, 0o644)
assert stat.S_ISDIR(parent.st_mode)
assert parent.st_uid == 0
assert parent.st_gid == 0
assert stat.S_IMODE(parent.st_mode) & 0o022 == 0
PY
protected_token_file() {
  python3 - "$1" <<'PY'
import os
import stat
import sys
value = os.stat(sys.argv[1], follow_symlinks=False)
parent = os.stat(os.path.dirname(sys.argv[1]), follow_symlinks=False)
assert stat.S_ISREG(value.st_mode)
assert value.st_uid == 0
assert value.st_gid == 0
assert value.st_nlink == 1
assert stat.S_IMODE(value.st_mode) == 0o600
assert 0 < value.st_size <= 16384
assert stat.S_ISDIR(parent.st_mode)
assert parent.st_uid == 0
assert parent.st_gid == 0
assert stat.S_IMODE(parent.st_mode) & 0o022 == 0
raw = open(sys.argv[1], "rb").read()
if raw.endswith(b"\n"):
    raw = raw[:-1]
assert raw and b"\n" not in raw and b"\r" not in raw and b"\0" not in raw
PY
}
protected_token_file "$token_file" || fail "token file or its parent is not protected root-only input"
manifest_worker_bundle_sha256=$(jq -er '.artifacts.worker.bundle_sha256' "$release_manifest")
installer_worker_bundle_sha256=$(jq -er '.worker_bundle_sha256' "$installer_receipt")
[[ $installer_worker_bundle_sha256 == "$manifest_worker_bundle_sha256" ]] || \
  fail "installer receipt is not bound to the approved worker bundle"

schema_version=$(git -C "$repo" show "${exact_commit}:storage/src/authority.rs" |
  sed -nE 's/^pub const AUTHORITY_RELEASE_SCHEMA_VERSION: i64 = ([0-9]+);$/\1/p')
[[ $schema_version == 16 ]] || fail "exact source must expose the one frozen authority schema version 16"

cats_e3_create_pinned_output_directory "$output_parent_fd" "$output_parent_fd_path" \
  "$output_base" output_dir_fd output_dir_fd_path || \
  fail "create and pin descriptor-relative output directory"
output_dir=$output_dir_fd_path
scratch=$output_dir/.scratch
mkdir -m 0700 "$scratch"
stage=$scratch/stage
mkdir -m 0700 "$stage" "$stage/binaries" "$stage/configs"
results_work=$scratch/scenario-results.jsonl
journal_work=$scratch/component-journal-summary.txt
catalog_work=$scratch/scenario-catalog.jsonl
binaries_work=$scratch/binaries.jsonl
configs_work=$scratch/configs.jsonl
fingerprints_work=$scratch/key-fingerprints.jsonl
evidence_work=$scratch/case-evidence.jsonl
: >"$results_work"
: >"$journal_work"
: >"$catalog_work"
: >"$binaries_work"
: >"$configs_work"
: >"$fingerprints_work"
: >"$evidence_work"

original_labels=()
original_paths=()
original_digests=()

remember_original() {
  original_labels+=("$1")
  original_paths+=("$2")
  original_digests+=("$3")
}

stage_input() {
  local label=$1 source=$2 destination=$3 mode=$4 expected=$5 before after
  before=$(sha256sum "$source" | awk '{print $1}')
  [[ $before == "$expected" ]] || fail "$label changed before its stable-stage copy"
  cp "$source" "$destination"
  chmod "$mode" "$destination"
  after=$(sha256sum "$destination" | awk '{print $1}')
  [[ $after == "$expected" ]] || fail "stable-stage copy changed $label"
  remember_original "$label" "$source" "$expected"
}

atomic_copy() {
  local source=$1 destination=$2 temporary
  temporary=$(mktemp "$output_dir/.${destination}.XXXXXX")
  cp "$source" "$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$output_dir/$destination"
}

atomic_text() {
  local destination=$1 value=$2 temporary
  temporary=$(mktemp "$output_dir/.${destination}.XXXXXX")
  printf '%s' "$value" >"$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$output_dir/$destination"
}

scenario_driver_original=$scenario_driver
qualification_catalog_original=$qualification_catalog
filter_original=$filter
runner_authority_sha256=$(sha256sum "$runner" | awk '{print $1}')
filter_authority_sha256=$(sha256sum "$filter" | awk '{print $1}')
scenario_driver_authority_sha256=$(sha256sum "$scenario_driver" | awk '{print $1}')
qualification_catalog_authority_sha256=$(sha256sum "$qualification_catalog" | awk '{print $1}')
qualification_operator_authority_sha256=$(sha256sum "$qualification_operator" | awk '{print $1}')
build_receipt_authority_sha256=$(sha256sum "$build_receipt" | awk '{print $1}')
installer_receipt_authority_sha256=$(sha256sum "$installer_receipt" | awk '{print $1}')
token_file_original=$token_file
token_file_authority_sha256=$(sha256sum "$token_file" | awk '{print $1}')
verify_exact_repo_file "$runner"
verify_exact_repo_file "$filter"
verify_exact_repo_file "$scenario_driver"
stage_input runner "$runner" "$stage/runtime-cutover-e2e.sh" 0700 "$runner_authority_sha256"
stage_input evidence-filter "$filter" "$stage/runtime-cutover-evidence-filter.py" 0700 "$filter_authority_sha256"
stage_input scenario-driver "$scenario_driver" "$stage/runtime-cutover-v2-scenarios.sh" 0700 "$scenario_driver_authority_sha256"
stage_input production-mutation-admission-operator "$qualification_operator" \
  "$stage/production-mutation-admission.py" 0700 "$qualification_operator_authority_sha256"
stage_input qualification-catalog "$qualification_catalog" "$stage/qualification-catalog.v1.json" 0600 "$qualification_catalog_authority_sha256"
stage_input build-receipt "$build_receipt" "$stage/build-receipt.json" 0600 "$build_receipt_authority_sha256"
stage_input release-manifest "$release_manifest" "$stage/release-manifest.json" 0600 "$approved_release_manifest_sha256"
stage_input installer-receipt "$installer_receipt" "$stage/installer-receipt.json" 0600 "$installer_receipt_authority_sha256"
cats_e3_prepare_private_stage "$state_directory" || \
  fail "create root-only invocation secret stage"
production_cutover_operator_private_key_file_original=$production_cutover_operator_private_key_file
production_cutover_operator_private_key_file=$cats_e3_private_stage/production-cutover-operator-key
cats_e3_stage_route_rotation_operator_key \
  "$production_cutover_operator_private_key_file_original" \
  "$production_cutover_operator_private_key_file" || \
  fail "stage the protected ProductionCutoverOperator private key"
token_file=$cats_e3_private_stage/control-token
token_before=$(sha256sum "$token_file_original" | awk '{print $1}')
[[ $token_before == "$token_file_authority_sha256" ]] || fail "token changed before its private stable-stage copy"
cp "$token_file_original" "$token_file"
chmod 0600 "$token_file"
[[ $(sha256sum "$token_file" | awk '{print $1}') == "$token_file_authority_sha256" ]] || \
  fail "private stable-stage copy changed token"
verify_staged_repo_file() {
  local original=$1 staged=$2 relative expected_blob actual_blob
  relative=${original#"$repo"/}
  expected_blob=$(git -C "$repo" rev-parse "${exact_commit}:${relative}") || \
    fail "$relative has no exact-commit blob"
  actual_blob=$(git -C "$repo" hash-object "$staged")
  [[ $actual_blob == "$expected_blob" ]] || fail "stable-stage $relative differs from the exact commit"
}
verify_staged_repo_file "$runner" "$stage/runtime-cutover-e2e.sh"
verify_staged_repo_file "$filter" "$stage/runtime-cutover-evidence-filter.py"
verify_staged_repo_file "$scenario_driver" "$stage/runtime-cutover-v2-scenarios.sh"
verify_staged_repo_file "$qualification_operator" "$stage/production-mutation-admission.py"
verify_staged_repo_file "$qualification_catalog" "$stage/qualification-catalog.v1.json"
filter=$stage/runtime-cutover-evidence-filter.py
scenario_driver=$stage/runtime-cutover-v2-scenarios.sh
qualification_operator=$stage/production-mutation-admission.py
qualification_catalog=$stage/qualification-catalog.v1.json

jq -e --arg commit "$exact_commit" \
  '.source_sha == $commit and .exit_status == 0 and .output_frozen == true' \
  "$stage/build-receipt.json" >/dev/null || fail "staged build receipt changed authority"
jq -e --arg commit "$exact_commit" \
  --arg catalog_sha256 "sha256:$qualification_catalog_authority_sha256" \
  --argjson catalog_size "$qualification_catalog_size" \
  --arg operator_sha256 "sha256:$qualification_operator_authority_sha256" \
  --argjson operator_size "$qualification_operator_size" \
  '.version == 1 and .source.commit == $commit
    and .build_inputs.files.qualification_catalog
      == {sha256:$catalog_sha256,size_bytes:$catalog_size}
    and .build_inputs.files.production_mutation_admission_operator
      == {sha256:$operator_sha256,size_bytes:$operator_size}' \
  "$stage/release-manifest.json" >/dev/null || fail "staged release manifest changed authority"
jq -e '
  (keys == ["host_tools","members","service","version","worker_bundle_sha256"])
  and .version == 1 and .service == "cats-worker.service"' \
  "$stage/installer-receipt.json" >/dev/null || fail "staged installer receipt changed authority"

jq -e -n --slurpfile manifest "$stage/release-manifest.json" \
  --slurpfile receipt "$stage/installer-receipt.json" \
  '($manifest[0].artifacts.worker.members | keys) == ($receipt[0].members | keys)
    and all($manifest[0].artifacts.worker.members | to_entries[];
      . as $member
      | $member.value.sha256 == $receipt[0].members[$member.key].sha256
        and $member.value.size_bytes == $receipt[0].members[$member.key].size_bytes)' \
  >/dev/null || fail "installer receipt members differ from the approved worker manifest"

seen_binary_labels='|'
seen_binary_environment_labels='|'
installed_noded_path=
timeout_bin=
timeout_bin_original=
for entry in "${binary_entries[@]}"; do
  label=${entry%%=*}
  path=${entry#*=}
  [[ $label != "$entry" && $label =~ ^[a-z][a-z0-9_-]{0,31}$ ]] || fail "binary label is not canonical"
  case "$seen_binary_labels" in *"|$label|"*) fail "binary label $label is repeated" ;; esac
  seen_binary_labels+="$label|"
  environment_label=$(printf '%s' "$label" | tr '[:lower:]-' '[:upper:]_')
  case "$seen_binary_environment_labels" in
    *"|$environment_label|"*) fail "binary label $label collides after environment normalization" ;;
  esac
  seen_binary_environment_labels+="$environment_label|"
  [[ $path != *@sha256:* ]] || fail "binary $label digest must come from the approved manifest and installer receipt"
  canonical=$(canonical_existing "$path") || fail "binary $label must name a regular non-symlink file"
  [[ -f $canonical && -x $canonical ]] || fail "binary $label is not executable"
  artifact_name=${canonical##*/}
  authority=$(jq -er --arg name "$artifact_name" '
    if .members[$name] != null then "worker-member"
    elif .host_tools[$name] != null then "installer-host-tool"
    else empty end' "$stage/installer-receipt.json") || \
    fail "binary $label is absent from the installer receipt"
  case "$authority" in
    worker-member)
      expected_path=$(jq -er --arg name "$artifact_name" '.members[$name].path' "$stage/installer-receipt.json")
      expected_sha256=$(jq -er --arg name "$artifact_name" '.members[$name].sha256' "$stage/installer-receipt.json")
      expected_size=$(jq -er --arg name "$artifact_name" '.members[$name].size_bytes' "$stage/installer-receipt.json")
      manifest_sha256=$(jq -er --arg name "$artifact_name" '.artifacts.worker.members[$name].sha256' "$stage/release-manifest.json")
      manifest_size=$(jq -er --arg name "$artifact_name" '.artifacts.worker.members[$name].size_bytes' "$stage/release-manifest.json")
      [[ $expected_sha256 == "$manifest_sha256" && $expected_size == "$manifest_size" ]] || \
        fail "installed worker member $artifact_name differs from the approved manifest"
      ;;
    installer-host-tool)
      expected_path=$(jq -er --arg name "$artifact_name" '.host_tools[$name].path' "$stage/installer-receipt.json")
      expected_sha256=$(jq -er --arg name "$artifact_name" '.host_tools[$name].sha256' "$stage/installer-receipt.json")
      expected_size=$(jq -er --arg name "$artifact_name" '.host_tools[$name].size_bytes' "$stage/installer-receipt.json")
      ;;
    *) fail "binary $label has no closed installer authority" ;;
  esac
  [[ $expected_path == /* && $expected_sha256 =~ ^sha256:[0-9a-f]{64}$ && $expected_size =~ ^[1-9][0-9]*$ ]] || \
    fail "installer receipt entry for $artifact_name is invalid"
  canonical_expected=$(canonical_existing "$expected_path") || \
    fail "installer receipt path for $artifact_name is not a real regular file"
  [[ $canonical == "$canonical_expected" ]] || fail "binary $label path differs from the installer receipt"
  digest=$(sha256sum "$canonical" | awk '{print $1}')
  size=$(wc -c <"$canonical" | tr -d ' ')
  [[ sha256:$digest == "$expected_sha256" && $size == "$expected_size" ]] || \
    fail "binary $label bytes differ from the installer receipt"
  staged=$stage/binaries/$label
  stage_input "binary:$label" "$canonical" "$staged" 0700 "$digest"
  jq -S -c -n --arg label "$label" --arg artifact_name "$artifact_name" \
    --arg authority "$authority" --arg path "$canonical" --arg staged_path "$staged" \
    --arg sha256 "$digest" --argjson size_bytes "$size" \
    '{label:$label,artifact_name:$artifact_name,authority:$authority,path:$path,
      staged_path:$staged_path,sha256:$sha256,size_bytes:$size_bytes}' >>"$binaries_work"
  printf -v "CATS_E3_BINARY_${environment_label}" '%s' "$staged"
  export "CATS_E3_BINARY_${environment_label}"
  printf -v "CATS_E3_BINARY_${environment_label}_SHA256" '%s' "$digest"
  export "CATS_E3_BINARY_${environment_label}_SHA256"
  if [[ $artifact_name == cats-noded ]]; then
    installed_noded_path=$canonical
  fi
  if [[ $label == timeout ]]; then
    [[ $artifact_name == timeout && $authority == installer-host-tool ]] || \
      fail "--binary timeout must be the installer-recorded Host timeout"
    timeout_bin=$staged
    timeout_bin_original=$canonical
    timeout_bin_sha256=$digest
  fi
done
for required_binding in \
  cats=cats \
  runtime-e3-probe=cats-runtime-e3-probe \
  e3-guest-workload=cats-e3-guest-workload \
  curl=curl \
  systemctl=systemctl \
  journalctl=journalctl \
  timeout=timeout; do
  required_label=${required_binding%%=*}
  required_artifact=${required_binding#*=}
  jq -e --arg label "$required_label" --arg artifact "$required_artifact" \
    'select(.label == $label and .artifact_name == $artifact)' "$binaries_work" >/dev/null || \
    fail "--binary $required_label must bind installer-recorded $required_artifact"
done
[[ -n $installed_noded_path ]] || fail "the installed cats-noded worker member must be an explicit --binary"
[[ -n $timeout_bin ]] || fail "--binary timeout is required"

seen_config_labels='|'
seen_config_environment_labels='|'
route_rotation_operator_authority_id=
route_rotation_operator_route_deployment_id=
route_rotation_operator_trust_sha256=
route_rotation_operator_key_seen=false
for entry in "${config_entries[@]}"; do
  label=${entry%%=*}
  path=${entry#*=}
  [[ $label != "$entry" && $label =~ ^[a-z][a-z0-9_-]{0,31}$ ]] || fail "config label is not canonical"
  case "$seen_config_labels" in *"|$label|"*) fail "config label $label is repeated" ;; esac
  seen_config_labels+="$label|"
  environment_label=$(printf '%s' "$label" | tr '[:lower:]-' '[:upper:]_')
  case "$seen_config_environment_labels" in
    *"|$environment_label|"*) fail "config label $label collides after environment normalization" ;;
  esac
  seen_config_environment_labels+="$environment_label|"
  if [[ $label == route-rotation-operator-key ]]; then
    staged=$cats_e3_private_stage/route-rotation-operator-key
    cats_e3_stage_route_rotation_operator_key "$path" "$staged" || \
      fail "route-rotation-operator-key is not one protected root-only secret input"
    CATS_E3_CONFIG_ROUTE_ROTATION_OPERATOR_KEY=$staged
    export CATS_E3_CONFIG_ROUTE_ROTATION_OPERATOR_KEY
    route_rotation_operator_key_seen=true
    continue
  fi
  canonical=$(canonical_existing "$path") || fail "config $label must name a regular non-symlink file"
  [[ -f $canonical ]] || fail "config $label is not a regular file"
  digest=$(sha256sum "$canonical" | awk '{print $1}')
  size=$(wc -c <"$canonical" | tr -d ' ')
  if [[ $label == route-rotation-operator-trust ]]; then
    [[ $path == /etc/cats/route-v2/rotation-operator-trust.v1.json && $canonical == "$path" ]] || \
      fail "route-rotation-operator-trust must use the canonical installed path"
    if ! route_rotation_operator_coordinates=$(python3 - "$canonical" "$exact_commit" <<'PY'
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


class DuplicateKey(ValueError):
    pass


def closed_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKey
        value[key] = item
    return value


path = Path(sys.argv[1])
exact_commit = sys.argv[2]
raw = path.read_bytes()
if not 1 <= len(raw) <= 16384:
    raise SystemExit(1)
try:
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=closed_object)
except (UnicodeDecodeError, json.JSONDecodeError, DuplicateKey):
    raise SystemExit(1)
if not isinstance(value, dict) or list(value) != [
    "version",
    "authority_id",
    "route_deployment_id",
    "release_commit_sha",
    "threshold",
    "credentials",
]:
    raise SystemExit(1)
canonical = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()
if (
    raw != canonical
    or type(value["version"]) is not int
    or value["version"] != 1
    or value["release_commit_sha"] != exact_commit
):
    raise SystemExit(1)
id_pattern = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
digest_pattern = re.compile(r"sha256:[0-9a-f]{64}\Z")
base64url_pattern = re.compile(r"[A-Za-z0-9_-]+\Z")
if (
    not isinstance(value["authority_id"], str)
    or id_pattern.fullmatch(value["authority_id"]) is None
    or not isinstance(value["route_deployment_id"], str)
    or id_pattern.fullmatch(value["route_deployment_id"]) is None
):
    raise SystemExit(1)
credentials = value["credentials"]
threshold = value["threshold"]
if (
    not isinstance(credentials, list)
    or not 1 <= len(credentials) <= 8
    or type(threshold) is not int
    or not 1 <= threshold <= len(credentials)
):
    raise SystemExit(1)
credential_ids = []
spki_digests = set()
ed25519_spki_prefix = bytes.fromhex("302a300506032b6570032100")
for credential in credentials:
    if not isinstance(credential, dict) or list(credential) != [
        "credential_id",
        "public_key_spki",
        "public_key_spki_sha256",
    ]:
        raise SystemExit(1)
    credential_id = credential["credential_id"]
    public_key_spki = credential["public_key_spki"]
    public_key_spki_sha256 = credential["public_key_spki_sha256"]
    if (
        not isinstance(credential_id, str)
        or id_pattern.fullmatch(credential_id) is None
        or not isinstance(public_key_spki, str)
        or base64url_pattern.fullmatch(public_key_spki) is None
        or not isinstance(public_key_spki_sha256, str)
        or digest_pattern.fullmatch(public_key_spki_sha256) is None
    ):
        raise SystemExit(1)
    try:
        padding = "=" * ((4 - len(public_key_spki) % 4) % 4)
        spki = base64.b64decode(public_key_spki + padding, altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error):
        raise SystemExit(1)
    if len(spki) != 44 or not spki.startswith(ed25519_spki_prefix):
        raise SystemExit(1)
    if "sha256:" + hashlib.sha256(spki).hexdigest() != public_key_spki_sha256:
        raise SystemExit(1)
    credential_ids.append(credential_id)
    spki_digests.add(public_key_spki_sha256)
if credential_ids != sorted(set(credential_ids)) or len(spki_digests) != len(credentials):
    raise SystemExit(1)
metadata = os.stat(path, follow_symlinks=False)
parent = os.stat(path.parent, follow_symlinks=False)
if (
    not stat.S_ISREG(metadata.st_mode)
    or metadata.st_uid != 0
    or metadata.st_gid != 0
    or metadata.st_nlink != 1
    or stat.S_IMODE(metadata.st_mode) != 0o644
    or not stat.S_ISDIR(parent.st_mode)
    or parent.st_uid != 0
    or parent.st_gid != 0
    or stat.S_IMODE(parent.st_mode) != 0o700
):
    raise SystemExit(1)
print(value["authority_id"] + "\t" + value["route_deployment_id"])
PY
    ); then
      fail "route-rotation-operator-trust is not the exact canonical release trust"
    fi
    IFS=$'\t' read -r route_rotation_operator_authority_id \
      route_rotation_operator_route_deployment_id <<<"$route_rotation_operator_coordinates"
    [[ -n $route_rotation_operator_authority_id && -n $route_rotation_operator_route_deployment_id ]] || \
      fail "route-rotation-operator-trust does not expose exact coordinates"
    route_rotation_operator_trust_sha256=sha256:$digest
  fi
  if [[ $label == production-cutover-operator-trust ]]; then
    [[ $path == /etc/cats/production-cutover-operator-trust.v1.json && \
      $canonical == "$path" ]] || \
      fail "production-cutover-operator-trust must use the canonical installed path"
  fi
  staged=$stage/configs/$label
  stage_input "config:$label" "$canonical" "$staged" 0600 "$digest"
  jq -S -c -n --arg label "$label" --arg path "$canonical" --arg staged_path "$staged" \
    --arg sha256 "$digest" --argjson size_bytes "$size" \
    '{label:$label,path:$path,staged_path:$staged_path,sha256:$sha256,size_bytes:$size_bytes}' >>"$configs_work"
  printf -v "CATS_E3_CONFIG_${environment_label}" '%s' "$staged"
  export "CATS_E3_CONFIG_${environment_label}"
done

for required_config in \
  qualification-ingress-open-plan \
  qualification-ingress-close-plan \
  production-cutover-operator-trust \
  production-mutation-qualification-binding \
  production-qualification-cell-manifest \
  route-rotation-operator-trust \
  route-rotation-command-bundle \
  route-rotation-recovery \
  route-rotation-server-ca \
  usage-terminal-targets; do
  jq -e --arg label "$required_config" 'select(.label == $label)' "$configs_work" >/dev/null || \
    fail "--config $required_config is required by the production qualification contract"
done
[[ $route_rotation_operator_key_seen == true ]] || \
  fail "--config route-rotation-operator-key is required by the production qualification contract"

usage_terminal_targets=$stage/configs/usage-terminal-targets
jq -e '
  (keys == ["fresh_target","old_target","shards","version"])
  and .version == 1
  and ([.old_target,.fresh_target] | all(.;
    keys == ["archive_bucket_arn","archive_bucket_name","aws_account_id","aws_region",
      "checkpoint_table_arn","checkpoint_table_name","stream_arn","stream_name","usage_schema"]
    and all(.[]; type == "string" and length > 0)))
  and (.shards | type == "array" and length > 0)
  and all(.shards[];
    keys == ["explicit_hash_key","shard_id"]
    and (.shard_id | test("^shardId-[0-9]{12}$"))
    and (.explicit_hash_key | test("^(0|[1-9][0-9]{0,38})$")))
  and ([.shards[].shard_id] == ([.shards[].shard_id] | sort | unique))' \
  "$usage_terminal_targets" >/dev/null || \
  fail "--config usage-terminal-targets has the wrong closed E9 target shape"

cats_e3_export_qualification_environment
seen_key_fingerprint_labels='|'
for entry in "${key_fingerprint_entries[@]}"; do
  label=${entry%%=*}
  fingerprint=${entry#*=}
  [[ $label != "$entry" && $label =~ ^[a-z][a-z0-9_-]{0,31}$ ]] || fail "key fingerprint label is not canonical"
  case "$seen_key_fingerprint_labels" in
    *"|$label|"*) fail "key fingerprint label $label is repeated" ;;
  esac
  seen_key_fingerprint_labels+="$label|"
  [[ $fingerprint =~ ^sha256:[0-9a-f]{64}$ ]] || fail "key fingerprint must be a nonsecret sha256 value"
  jq -S -c -n --arg label "$label" --arg fingerprint "$fingerprint" \
    '{label:$label,fingerprint:$fingerprint}' >>"$fingerprints_work"
done

case_ids=()
case_deadlines=()
case_cleanup_deadlines=()
case_expected_outcomes=()
case_required_evidence=()
while IFS= read -r case_record; do
  case_ids+=("$(jq -r '.case_id' <<<"$case_record")")
  case_deadlines+=("$(jq -r '.deadline_seconds' <<<"$case_record")")
  case_cleanup_deadlines+=("$(jq -r '.cleanup_deadline_seconds' <<<"$case_record")")
  case_expected_outcomes+=("$(jq -c '.expected_outcome' <<<"$case_record")")
  case_required_evidence+=("$(jq -c '.required_evidence' <<<"$case_record")")
  printf '%s\n' "$case_record" >>"$catalog_work"
done < <(jq -S -c '
  .framework_required_evidence as $framework
  | .cases[]
  | .required_evidence = (.required_evidence + $framework)' "$qualification_catalog")
[[ ${#case_ids[@]} -gt 0 ]] || fail "qualification catalog contains no cases"
product_case_count=0
route_rotation_case_index=
for index in "${!case_ids[@]}"; do
  case_id=${case_ids[$index]}
  if [[ $case_id == usage-source-terminal-receipts ]]; then
    continue
  fi
  product_case_count=$((product_case_count + 1))
  if [[ $case_id == route-v2-rotation-disable-live-delivery ]]; then
    route_rotation_case_index=$index
  fi
done
[[ $product_case_count -gt 0 && $route_rotation_case_index =~ ^[0-9]+$ ]] || \
  fail "qualification catalog has no exact product/G3 case prefix"
expected_nodes_work=$scratch/expected-nodes.json
printf '%s\n' "${expected_nodes[@]}" | jq -Rsc 'split("\n")[:-1]' >"$expected_nodes_work"

runtime_state_initial=$scratch/runtime-state.initial.json
jq -S -c -n \
  --arg exact_commit "$exact_commit" --arg block_path "$block_path" --arg run_id "$run_id" \
  '{version:1,exact_commit:$exact_commit,block_path:$block_path,run_id:$run_id,cat_id:null}' \
  >"$runtime_state_initial"
initial_runtime_state_sha256=sha256:$(sha256sum "$runtime_state_initial" | awk '{print $1}')
configuration_manifest=$scratch/qualification-nonsecret-config-manifest.json
jq -s -S -c '
  sort_by(.label)
  | map({label,sha256:("sha256:" + .sha256),size_bytes})' \
  "$configs_work" >"$configuration_manifest"
configuration_manifest_sha256=sha256:$(sha256sum "$configuration_manifest" | awk '{print $1}')
qualification_binding_sha256=sha256:$(
  sha256sum "$stage/configs/production-mutation-qualification-binding" | awk '{print $1}'
)
qualification_cell_manifest_sha256=sha256:$(
  sha256sum "$stage/configs/production-qualification-cell-manifest" | awk '{print $1}'
)
production_cutover_operator_trust_sha256=sha256:$(
  sha256sum "$stage/configs/production-cutover-operator-trust" | awk '{print $1}'
)
route_rotation_command_bundle_sha256=sha256:$(
  sha256sum "$stage/configs/route-rotation-command-bundle" | awk '{print $1}'
)
route_rotation_recovery_sha256=sha256:$(
  sha256sum "$stage/configs/route-rotation-recovery" | awk '{print $1}'
)
route_rotation_server_ca_sha256=sha256:$(
  sha256sum "$stage/configs/route-rotation-server-ca" | awk '{print $1}'
)
host_kernel=$(uname -r)
[[ $host_kernel =~ ^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$ ]] || \
  fail "Host kernel release is not a bounded nonsecret string"
if [[ -e $state_directory/qualification-state-binding.v1.json || \
  -L $state_directory/qualification-state-binding.v1.json ]]; then
  cats_e3_recover_persistent_state_link "$state_directory" \
    qualification-state-binding.v1.json || \
    fail "persistent qualification binding has an unsafe interrupted adoption"
fi
started_at_unix_seconds=$(python3 - \
  "$state_directory/qualification-state-binding.v1.json" \
  "$run_id" "$block_path" "$workspace_id" "$exact_commit" <<'PY'
import json
import os
from pathlib import Path
import stat
import sys
import time


path = Path(sys.argv[1])
run_id, block_path, workspace_id, exact_commit = sys.argv[2:]
now = int(time.time())
if not path.exists() and not path.is_symlink():
    print(now)
    raise SystemExit(0)
parent_fd = os.open(
    path.parent,
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0),
)
try:
    descriptor = os.open(
        path.name,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=parent_fd,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_gid != 0
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 1 <= before.st_size <= 65_536
        ):
            raise SystemExit(1)
        raw = b""
        while len(raw) < before.st_size:
            chunk = os.read(descriptor, before.st_size - len(raw))
            if not chunk:
                raise SystemExit(1)
            raw += chunk
        if os.read(descriptor, 1):
            raise SystemExit(1)
        after = os.fstat(descriptor)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_uid,
            value.st_gid,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if identity(before) != identity(after):
            raise SystemExit(1)
    finally:
        os.close(descriptor)
finally:
    os.close(parent_fd)
try:
    value = json.loads(raw.decode("utf-8"))
except (UnicodeDecodeError, json.JSONDecodeError):
    raise SystemExit(1)
canonical = (
    json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    + "\n"
).encode("utf-8")
started = value.get("run_started_at_unix_seconds") if isinstance(value, dict) else None
if (
    raw != canonical
    or value.get("kind") != "cats.runtime-cutover-persistent-state.v1"
    or value.get("version") != 1
    or value.get("run_id") != run_id
    or value.get("block_path") != block_path
    or value.get("workspace_id") != workspace_id
    or value.get("exact_commit") != exact_commit
    or type(started) is not int
    or not 1 <= started <= now
):
    raise SystemExit(1)
print(started)
PY
) || fail "persistent run start is unsafe or belongs to another run"
qualification_state_binding=$scratch/qualification-state-binding.v1.json
jq -S -c -n \
  --arg block_path "$block_path" --arg exact_commit "$exact_commit" \
  --arg run_id "$run_id" --arg workspace_id "$workspace_id" \
  --arg control_origin "$control_origin" --arg guest_kernel "$guest_kernel" \
  --arg host_kernel "$host_kernel" \
  --arg build_receipt_sha256 "sha256:$build_receipt_authority_sha256" \
  --arg installer_receipt_sha256 "sha256:$installer_receipt_authority_sha256" \
  --arg runner_sha256 "sha256:$runner_authority_sha256" \
  --arg evidence_filter_sha256 "sha256:$filter_authority_sha256" \
  --arg scenario_driver_sha256 "sha256:$scenario_driver_authority_sha256" \
  --arg qualification_operator_sha256 "sha256:$qualification_operator_authority_sha256" \
  --arg qualification_node_id "$qualification_node" --arg cat_name "$cat_name" \
  --arg boot_image_digest "$boot_image_digest" --arg endpoint_name "$endpoint_name" \
  --arg endpoint_hostname "$endpoint_hostname" \
  --arg release_manifest_sha256 "sha256:$approved_release_manifest_sha256" \
  --arg worker_bundle_sha256 "$manifest_worker_bundle_sha256" \
  --arg qualification_catalog_sha256 "sha256:$qualification_catalog_authority_sha256" \
  --arg qualification_binding_sha256 "$qualification_binding_sha256" \
  --arg qualification_cell_manifest_sha256 "$qualification_cell_manifest_sha256" \
  --arg production_cutover_operator_trust_sha256 "$production_cutover_operator_trust_sha256" \
  --arg route_rotation_operator_authority_id "$route_rotation_operator_authority_id" \
  --arg route_rotation_route_deployment_id "$route_rotation_operator_route_deployment_id" \
  --arg route_rotation_operator_trust_sha256 "$route_rotation_operator_trust_sha256" \
  --arg route_rotation_command_bundle_sha256 "$route_rotation_command_bundle_sha256" \
  --arg route_rotation_recovery_sha256 "$route_rotation_recovery_sha256" \
  --arg route_rotation_server_ca_sha256 "$route_rotation_server_ca_sha256" \
  --arg configuration_manifest_sha256 "$configuration_manifest_sha256" \
  --arg initial_runtime_state_sha256 "$initial_runtime_state_sha256" \
  --argjson authority_schema_version "$schema_version" \
  --argjson run_started_at_unix_seconds "$started_at_unix_seconds" \
  --slurpfile expected_node_ids "$expected_nodes_work" '
  {authority_schema_version:$authority_schema_version,block_path:$block_path,
   boot_image_digest:$boot_image_digest,build_receipt_sha256:$build_receipt_sha256,
   case_id:"route-v2-rotation-disable-live-delivery",cat_name:$cat_name,
   cats_cli_recovery_namespace:"cats-cli",
   configuration_manifest_sha256:$configuration_manifest_sha256,control_origin:$control_origin,
   endpoint_hostname:$endpoint_hostname,endpoint_name:$endpoint_name,
   evidence_filter_sha256:$evidence_filter_sha256,
   exact_commit:$exact_commit,expected_node_ids:$expected_node_ids[0],
   guest_kernel:$guest_kernel,host_kernel:$host_kernel,
   initial_runtime_state_sha256:$initial_runtime_state_sha256,
   installer_receipt_sha256:$installer_receipt_sha256,
   kind:"cats.runtime-cutover-persistent-state.v1",
   production_cutover_operator_trust_sha256:$production_cutover_operator_trust_sha256,
   qualification_binding_sha256:$qualification_binding_sha256,
   qualification_catalog_sha256:$qualification_catalog_sha256,
   qualification_cell_manifest_sha256:$qualification_cell_manifest_sha256,
   qualification_node_id:$qualification_node_id,
   qualification_operator_sha256:$qualification_operator_sha256,
   release_manifest_sha256:$release_manifest_sha256,run_id:$run_id,version:1,
   run_started_at_unix_seconds:$run_started_at_unix_seconds,
   route_rotation_command_bundle_sha256:$route_rotation_command_bundle_sha256,
   route_rotation_operator_authority_id:$route_rotation_operator_authority_id,
   route_rotation_operator_trust_sha256:$route_rotation_operator_trust_sha256,
   route_rotation_recovery_sha256:$route_rotation_recovery_sha256,
   route_rotation_route_deployment_id:$route_rotation_route_deployment_id,
   route_rotation_server_ca_sha256:$route_rotation_server_ca_sha256,
   runner_sha256:$runner_sha256,scenario_driver_sha256:$scenario_driver_sha256,
   worker_bundle_sha256:$worker_bundle_sha256,workspace_id:$workspace_id}' \
  >"$qualification_state_binding"
chmod 0600 "$qualification_state_binding"
cats_e3_bind_persistent_state "$state_directory" "$qualification_state_binding" || \
  fail "persistent qualification state belongs to different run coordinates"
qualification_operator_state=$state_directory/production-mutation-admission
persistent_cases_dir=$state_directory/cases
persistent_case_prefix_dir=$state_directory/case-prefix
persistent_runtime_state=$state_directory/runtime-state.json
persistent_cli_state_dir=$state_directory/cats-cli
persistent_route_case_dir=$(printf '%s/%02d-%s' "$persistent_cases_dir" \
  "$route_rotation_case_index" route-v2-rotation-disable-live-delivery)
cats_e3_private_state_subdirectory "$qualification_operator_state" || \
  fail "production mutation admission state is not protected"
cats_e3_private_state_subdirectory "$persistent_cases_dir" || \
  fail "persistent case state is not protected"
cats_e3_private_state_subdirectory "$persistent_case_prefix_dir" || \
  fail "persistent case prefix is not protected"
cats_e3_private_state_subdirectory "$persistent_cli_state_dir" || \
  fail "persistent Cats CLI recovery state is not protected"
export CATS_CONFIG_DIR=$persistent_cli_state_dir
if [[ ! -e $persistent_runtime_state && ! -L $persistent_runtime_state ]]; then
  cats_e3_bind_persistent_state "$state_directory" "$runtime_state_initial" runtime-state.json || \
    fail "initialize persistent runtime state"
fi
first_incomplete_case_index=$(cats_e3_restore_case_prefix) || \
  fail "persistent case prefix or Cat runtime state is invalid"
[[ $first_incomplete_case_index =~ ^[0-9]+$ && \
  $first_incomplete_case_index -le $product_case_count ]] || \
  fail "persistent case prefix is outside the exact catalog"
qualification_common_args=(
  --origin "$control_origin"
  --trust-file "$stage/configs/production-cutover-operator-trust"
  --binding-file "$stage/configs/production-mutation-qualification-binding"
  --cell-manifest-file "$stage/configs/production-qualification-cell-manifest"
  --release-manifest-file "$stage/release-manifest.json"
  --qualification-catalog-file "$qualification_catalog"
  --state-directory "$qualification_operator_state"
  --evidence-directory "$output_dir"
  --run-id "$run_id"
  --workspace-id "$workspace_id"
  --exact-commit "$exact_commit"
  --block-path "$block_path"
  --resolution-timeout-seconds 120
)
qualification_lifecycle_attempted=false
qualification_begin_applied=false
qualification_close_attempted=false
qualification_close_applied=false
qualification_close_forbidden=false
qualification_terminalized=false
qualification_cleanup_disarmed=false

build_receipt_sha256=$(sha256sum "$build_receipt" | awk '{print $1}')
release_manifest_sha256=$(sha256sum "$release_manifest" | awk '{print $1}')
installer_receipt_sha256=$(sha256sum "$installer_receipt" | awk '{print $1}')
scenario_driver_sha256=$(sha256sum "$scenario_driver" | awk '{print $1}')
scenario_catalog_sha256=$(sha256sum "$catalog_work" | awk '{print $1}')

write_manifest() {
  local state=$1 exit_value=$2 ended=$3 temporary case_evidence_sha256 case_evidence_count
  local qualification_admission_required_evidence='[]' begin_file terminal_file begin_sha terminal_sha
  case_evidence_sha256=$(sha256sum "$evidence_work" | awk '{print $1}')
  case_evidence_count=$(wc -l <"$evidence_work" | tr -d ' ')
  begin_file=$output_dir/production-mutation-qualification-begin.receipt.json
  terminal_file=$output_dir/production-mutation-qualification-terminal.receipt.json
  if [[ -f $begin_file && ! -L $begin_file && -f $terminal_file && ! -L $terminal_file ]]; then
    begin_sha=sha256:$(sha256sum "$begin_file" | awk '{print $1}')
    terminal_sha=sha256:$(sha256sum "$terminal_file" | awk '{print $1}')
    qualification_admission_required_evidence=$(jq -S -c -n \
      --arg begin_sha "$begin_sha" --arg terminal_sha "$terminal_sha" \
      --argjson begin_size "$(wc -c <"$begin_file" | tr -d ' ')" \
      --argjson terminal_size "$(wc -c <"$terminal_file" | tr -d ' ')" '
      [{filename:"production-mutation-qualification-begin.receipt.json",kind:"json",
        sha256:$begin_sha,size_bytes:$begin_size},
       {filename:"production-mutation-qualification-terminal.receipt.json",kind:"json",
        sha256:$terminal_sha,size_bytes:$terminal_size}]')
  fi
  temporary=$(mktemp "$output_dir/.manifest.json.XXXXXX")
  jq -S -c -n \
    --arg state "$state" \
    --arg exact_commit "$exact_commit" \
    --arg block_path "$block_path" \
    --arg run_id "$run_id" \
    --arg host_kernel "$host_kernel" \
    --arg guest_kernel "$guest_kernel" \
    --argjson schema_version "$schema_version" \
    --arg build_receipt "$build_receipt" \
    --arg build_receipt_sha256 "$build_receipt_sha256" \
    --arg release_manifest "$release_manifest" \
    --arg release_manifest_sha256 "$release_manifest_sha256" \
    --arg approved_release_manifest_sha256 "$approved_release_manifest_sha256" \
    --arg installer_receipt "$installer_receipt" \
    --arg installer_receipt_sha256 "$installer_receipt_sha256" \
    --arg worker_bundle_sha256 "$manifest_worker_bundle_sha256" \
    --arg control_origin "$control_origin" \
    --arg workspace_id "$workspace_id" \
    --arg qualification_node "$qualification_node" \
    --arg cat_name "$cat_name" \
    --arg boot_image_digest "$boot_image_digest" \
    --arg endpoint_name "$endpoint_name" \
    --arg endpoint_hostname "$endpoint_hostname" \
    --arg scenario_driver "$scenario_driver_original" \
    --arg scenario_driver_sha256 "$scenario_driver_sha256" \
    --arg qualification_catalog "$qualification_catalog_original" \
    --arg qualification_catalog_sha256 "sha256:$qualification_catalog_authority_sha256" \
    --argjson qualification_catalog_size_bytes "$qualification_catalog_size" \
    --arg timeout_binary "$timeout_bin_original" \
    --arg timeout_binary_sha256 "$timeout_bin_sha256" \
    --arg scenario_catalog_sha256 "$scenario_catalog_sha256" \
    --arg case_evidence_sha256 "sha256:$case_evidence_sha256" \
    --argjson case_evidence_count "$case_evidence_count" \
    --arg route_rotation_operator_authority_id "$route_rotation_operator_authority_id" \
    --arg route_rotation_operator_route_deployment_id "$route_rotation_operator_route_deployment_id" \
    --arg route_rotation_operator_trust_sha256 "$route_rotation_operator_trust_sha256" \
    --argjson started_at_unix_seconds "$started_at_unix_seconds" \
    --argjson ended_at_unix_seconds "$ended" \
    --argjson exit_code "$exit_value" \
    --argjson qualification_admission_required_evidence \
      "$qualification_admission_required_evidence" \
    --slurpfile binaries "$binaries_work" \
    --slurpfile configs "$configs_work" \
    --slurpfile key_fingerprints "$fingerprints_work" \
    --slurpfile expected_nodes "$expected_nodes_work" \
    --slurpfile scenarios "$catalog_work" \
    '{version:1,state:$state,exact_commit:$exact_commit,block_path:$block_path,
      run_id:$run_id,schema_version:$schema_version,kernels:{host:$host_kernel,guest:$guest_kernel},
      build_receipt:{path:$build_receipt,sha256:$build_receipt_sha256},
      release_manifest:{path:$release_manifest,sha256:$release_manifest_sha256,
        approved_sha256:$approved_release_manifest_sha256},
      installer_receipt:{path:$installer_receipt,sha256:$installer_receipt_sha256,
        worker_bundle_sha256:$worker_bundle_sha256},
      scenario_driver:{path:$scenario_driver,sha256:$scenario_driver_sha256},
      qualification_catalog:{path:$qualification_catalog,sha256:$qualification_catalog_sha256,
        size_bytes:$qualification_catalog_size_bytes},
      route_v2_rotation_operator:{config_label:"route-rotation-operator-trust",
        authority_id:$route_rotation_operator_authority_id,
        route_deployment_id:$route_rotation_operator_route_deployment_id,
        trust_sha256:$route_rotation_operator_trust_sha256},
      case_evidence:{sha256:$case_evidence_sha256,count:$case_evidence_count},
      timeout_binary:{path:$timeout_binary,sha256:$timeout_binary_sha256},
      qualification:{control_origin:$control_origin,workspace_id:$workspace_id,
        expected_nodes:$expected_nodes[0],qualification_node_id:$qualification_node,
        cat_name:$cat_name,boot_image_digest:$boot_image_digest,endpoint_name:$endpoint_name,
        endpoint_hostname:$endpoint_hostname,public_origin:("https://" + $endpoint_hostname)},
      scenario_catalog_sha256:$scenario_catalog_sha256,binaries:$binaries,configs:$configs,
      key_fingerprints:$key_fingerprints,scenarios:$scenarios,
      qualification_admission_required_evidence:$qualification_admission_required_evidence,
      started_at_unix_seconds:$started_at_unix_seconds,
      ended_at_unix_seconds:$ended_at_unix_seconds,exit_code:$exit_code}' \
    >"$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$output_dir/manifest.json"
}

write_manifest running -1 0
atomic_copy "$results_work" scenario-results.jsonl
atomic_copy "$journal_work" component-journal-summary.txt
atomic_copy "$evidence_work" case-evidence.jsonl
atomic_copy "$qualification_catalog" qualification-catalog.v1.json

export CATS_E3_EXACT_COMMIT=$exact_commit
export CATS_E3_BLOCK_PATH=$block_path
export CATS_E3_RUN_ID=$run_id
export CATS_E3_OUTPUT_DIR=$output_dir
export CATS_E3_RUNTIME_STATE=$persistent_runtime_state
export CATS_E3_RUN_STARTED_AT_UNIX_MS=$((started_at_unix_seconds * 1000))
export CATS_E3_WORKER_BUNDLE_SHA256=${manifest_worker_bundle_sha256#sha256:}

atomic_copy "$persistent_runtime_state" runtime-state.json

failed_cases=0
blocked_cases=0
passed_cases=0
qualification_begin_ok=false
qualification_close_ok=false
qualification_inventory_ok=false
qualification_wrappers_ok=false
qualification_close_kind=
qualification_close_decision=$state_directory/qualification-close-decision.v1.json
if [[ -e $qualification_close_decision || -L $qualification_close_decision ]]; then
  qualification_close_kind=$(cats_e3_load_close_decision) || \
    fail "persistent qualification close decision is unsafe or belongs to another run"
fi
if cats_e3_qualification_begin; then
  qualification_begin_ok=true
  if [[ -z $qualification_close_kind ]]; then
    cats_e3_run_cases_post_preflight product
    qualification_close_kind=emergency_close
    if [[ $failed_cases -eq 0 && $blocked_cases -eq 0 && \
      $first_incomplete_case_index -eq $product_case_count ]]; then
      qualification_close_kind=end_qualification
    fi
    cats_e3_persist_close_decision "$qualification_close_kind" || \
      fail "could not durably bind the qualification close decision"
  elif [[ $qualification_close_kind == end_qualification && \
    $first_incomplete_case_index -ne $product_case_count ]]; then
    qualification_close_attempted=true
    qualification_close_forbidden=true
    fail "EndQualification decision exists without the exact closed product case prefix"
  fi
  if [[ $qualification_close_kind == emergency_close && \
    $failed_cases -eq 0 && $blocked_cases -eq 0 ]]; then
    failed_cases=$((failed_cases + 1))
  fi
else
  failed_cases=$((failed_cases + 1))
fi

if [[ $qualification_begin_ok == true ]]; then
  if cats_e3_qualification_close "$qualification_close_kind"; then
    qualification_close_ok=true
  else
    failed_cases=$((failed_cases + 1))
  fi
fi
if [[ $qualification_close_ok == true ]]; then
  if cats_e3_qualification_product_inventory "$qualification_close_kind"; then
    qualification_inventory_ok=true
  else
    failed_cases=$((failed_cases + 1))
  fi
fi

# This is the sole post-close Fleet read.  It is copied byte-for-byte into the
# exact19 bundle and its digest is the final Fleet wrapper's authority.
cats_e3_collect_final_inventory
if [[ $qualification_inventory_ok == true ]] && \
  cats_e3_publish_qualification_zero_wrappers; then
  qualification_wrappers_ok=true
else
  failed_cases=$((failed_cases + 1))
fi
if [[ $qualification_wrappers_ok == true ]]; then
  if ! cats_e3_qualification_terminalize "$qualification_close_kind"; then
    failed_cases=$((failed_cases + 1))
  fi
fi

# Usage source closure is read-only and is intentionally absent from the
# product loop.  It becomes reachable only after the exact EndQualification
# successor and its qualified_closed terminal receipt are durable.
if [[ $qualification_close_kind == end_qualification && \
  $qualification_terminalized == true && $failed_cases -eq 0 && $blocked_cases -eq 0 ]]; then
  cats_e3_run_cases_post_preflight source
fi
atomic_copy "$persistent_runtime_state" runtime-state.json

input_rehash_work=$scratch/input-rehash-diagnostic.txt
: >"$input_rehash_work"
for index in "${!original_paths[@]}"; do
  original=${original_paths[$index]}
  expected=${original_digests[$index]}
  actual=unavailable
  if [[ -f $original && ! -L $original ]]; then
    actual=$(sha256sum "$original" | awk '{print $1}')
  fi
  if [[ $actual != "$expected" ]]; then
    printf 'stable input changed label=%s expected_sha256=%s actual_sha256=%s\n' \
      "${original_labels[$index]}" "$expected" "$actual" >>"$input_rehash_work"
  fi
done
if [[ -s $input_rehash_work ]]; then
  failed_cases=$((failed_cases + 1))
  append_summary stable-inputs diagnostics "$input_rehash_work"
fi

coordinate_recheck=$scratch/qualification-coordinate-diagnostic.txt
: >"$coordinate_recheck"
[[ ${CATS_E3_CONTROL_ORIGIN:-} == "$control_origin" ]] || printf '%s\n' 'control origin changed' >>"$coordinate_recheck"
[[ ${CATS_E3_WORKSPACE_ID:-} == "$workspace_id" ]] || printf '%s\n' 'workspace ID changed' >>"$coordinate_recheck"
[[ ${CATS_E3_EXPECTED_NODES:-} == "$(IFS=,; printf '%s' "${expected_nodes[*]}")" ]] || \
  printf '%s\n' 'expected Node set changed' >>"$coordinate_recheck"
[[ ${CATS_E3_QUALIFICATION_NODE_ID:-} == "$qualification_node" ]] || \
  printf '%s\n' 'qualification Node changed' >>"$coordinate_recheck"
[[ ${CATS_E3_CAT_NAME:-} == "$cat_name" ]] || printf '%s\n' 'Cat name changed' >>"$coordinate_recheck"
[[ ${CATS_E3_BOOT_IMAGE_DIGEST:-} == "$boot_image_digest" ]] || \
  printf '%s\n' 'boot image digest changed' >>"$coordinate_recheck"
[[ ${CATS_E3_ENDPOINT_NAME:-} == "$endpoint_name" ]] || printf '%s\n' 'Endpoint name changed' >>"$coordinate_recheck"
[[ ${CATS_E3_ENDPOINT_HOSTNAME:-} == "$endpoint_hostname" ]] || \
  printf '%s\n' 'Endpoint hostname changed' >>"$coordinate_recheck"
[[ ${CATS_E3_PUBLIC_ORIGIN:-} == "https://$endpoint_hostname" ]] || \
  printf '%s\n' 'public origin changed' >>"$coordinate_recheck"
[[ ${CATS_E3_QUALIFICATION_CATALOG_SHA256:-} == "sha256:$qualification_catalog_authority_sha256" ]] || \
  printf '%s\n' 'qualification catalog digest changed' >>"$coordinate_recheck"
[[ -f $token_file_original && ! -L $token_file_original ]] && \
  protected_token_file "$token_file_original" >/dev/null 2>&1 && \
  [[ $(sha256sum "$token_file_original" | awk '{print $1}') == "$token_file_authority_sha256" ]] || \
  printf '%s\n' 'root-only token input changed' >>"$coordinate_recheck"
if [[ -s $coordinate_recheck ]]; then
  failed_cases=$((failed_cases + 1))
  append_summary qualification-coordinates diagnostics "$coordinate_recheck"
fi

# Resolve any ambiguous Begin/close or interrupted post-close proof sequence
# while the private signing input and scratch evidence workspace still exist.
if ! cats_e3_close_on_exit; then
  failed_cases=$((failed_cases + 1))
fi

final_exit=0
final_state=passed
if [[ $failed_cases -ne 0 || $blocked_cases -ne 0 || \
  $qualification_close_kind != end_qualification || \
  $qualification_terminalized != true ]]; then
  final_exit=1
  final_state=failed
fi
atomic_text exit-code "$final_exit"$'\n'
ended_at_unix_seconds=$(date +%s)
write_manifest "$final_state" "$final_exit" "$ended_at_unix_seconds"

qualification_cleanup_disarmed=true
rm -rf "$scratch"
checksums_tmp=$(mktemp "$output_dir/.SHA256SUMS.XXXXXX")
expected_output_names=(
  case-evidence.jsonl
  component-journal-summary.txt
  exit-code
  final-inventory.json
  manifest.json
  production-mutation-qualification-begin.command-receipt.json
  production-mutation-qualification-begin.pending.json
  production-mutation-qualification-begin.receipt.json
  production-mutation-qualification-cleanup-inventory.receipt.json
  production-mutation-qualification-close.command-receipt.json
  production-mutation-qualification-close.pending.json
  production-mutation-qualification-final-admission-state.json
  production-mutation-qualification-final-fleet-closed.receipt.json
  production-mutation-qualification-product-inventory.receipt.json
  production-mutation-qualification-terminal.receipt.json
  qualification-catalog.v1.json
  runtime-state.json
  scenario-results.jsonl
)
checksum_names=()
shopt -s nullglob dotglob
for output_entry in "$output_dir"/*; do
  output_name=${output_entry##*/}
  [[ $output_name != SHA256SUMS && $output_entry != "$checksums_tmp" ]] || continue
  [[ -f $output_entry && ! -L $output_entry && -O $output_entry && \
    $(stat -c '%u:%g:%a:%h' "$output_entry") == 0:0:600:1 ]] || \
    fail "output evidence contains an unsafe direct child"
  checksum_names+=("$output_name")
done
shopt -u nullglob dotglob
IFS=$'\n' checksum_names=($(printf '%s\n' "${checksum_names[@]}" | LC_ALL=C sort))
unset IFS
if [[ $final_state == passed ]]; then
  [[ $(printf '%s\n' "${checksum_names[@]}") == \
    "$(printf '%s\n' "${expected_output_names[@]}")" ]] || \
    fail "passed qualification output is not the exact18 closed file set"
fi
(
  cd "$output_dir"
  LC_ALL=C sha256sum "${checksum_names[@]}"
) >"$checksums_tmp"
chmod 0600 "$checksums_tmp"
mv -f "$checksums_tmp" "$output_dir/SHA256SUMS"

exit "$final_exit"
