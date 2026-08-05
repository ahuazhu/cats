#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )); then
  echo "usage: $0 <controld-pods-json>" >&2
  exit 64
fi

pods_file=$1
if [[ ! -r "$pods_file" ]]; then
  echo "controld Pod inventory is not readable" >&2
  exit 66
fi

# psql -tA emits one line per granted owner row. Empty lines carry no usable
# address and are ignored; the query spells a local connection as <local> so a
# real owner row is never silently converted into zero rows.
mapfile -t raw_owner_rows
owner_rows=()
for row in "${raw_owner_rows[@]}"; do
  row=${row%$'\r'}
  if [[ -n "$row" ]]; then
    owner_rows+=("$row")
  fi
done

if (( ${#owner_rows[@]} != 1 )); then
  echo "owner_rows=${#owner_rows[@]} pod_ip_matches=0 host_ip_matches=0 address_union_matches=0 ready_union_matches=0" >&2
  exit 65
fi

owner_address=${owner_rows[0]}
report="$(
  jq -ce --arg owner "$owner_address" '
    def strictly_ready:
      (.metadata.deletionTimestamp == null)
      and (.status.phase == "Running")
      and any(.status.conditions[]?;
        .type == "Ready" and .status == "True")
      and (((.status.containerStatuses // []) | length) > 0)
      and all(.status.containerStatuses[]; .ready == true);

    if (.items | type) != "array" then
      error("Pod inventory must contain an items array")
    else
      [.items[] | select(.status.podIP == $owner)] as $pod_matches
      | [.items[] | select(.status.hostIP == $owner)] as $host_matches
      | (($pod_matches + $host_matches) | unique_by(.metadata.uid)) as $matches
      | [$matches[] | select(strictly_ready)] as $ready_matches
      | {
          pod_ip_matches: ($pod_matches | length),
          host_ip_matches: ($host_matches | length),
          address_union_matches: ($matches | length),
          ready_union_matches: ($ready_matches | length),
          selection: (
            if ($matches | length) == 1 and ($ready_matches | length) == 1 then
              $ready_matches[0] as $match
              | {
                  name: $match.metadata.name,
                  uid: $match.metadata.uid,
                  address_kind: (
                    if $match.status.podIP == $owner and $match.status.hostIP == $owner then
                      "pod-and-host-ip"
                    elif $match.status.podIP == $owner then
                      "pod-ip"
                    else
                      "host-ip"
                    end
                  )
                }
            else null end
          )
        }
    end
  ' "$pods_file"
)"

pod_matches="$(jq -r '.pod_ip_matches' <<<"$report")"
host_matches="$(jq -r '.host_ip_matches' <<<"$report")"
union_matches="$(jq -r '.address_union_matches' <<<"$report")"
ready_matches="$(jq -r '.ready_union_matches' <<<"$report")"
if (( union_matches != 1 || ready_matches != 1 )); then
  echo "owner_rows=1 pod_ip_matches=$pod_matches host_ip_matches=$host_matches address_union_matches=$union_matches ready_union_matches=$ready_matches" >&2
  exit 65
fi

selection="$(jq -ce '
  .selection
  | select(
      (.name | type) == "string" and (.name | length) > 0
      and (.uid | type) == "string" and (.uid | length) > 0
      and (.address_kind | type) == "string" and (.address_kind | length) > 0
    )
' <<<"$report")"
if [[ -z "$selection" ]]; then
  echo "owner_rows=1 pod_ip_matches=$pod_matches host_ip_matches=$host_matches address_union_matches=1 ready_union_matches=1 invalid_selection=1" >&2
  exit 65
fi
printf '%s\n' "$selection"
