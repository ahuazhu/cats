#!/usr/bin/env bash

write_immutable_receipt() {
  if [[ $# -ne 2 || ! -f $1 ]]; then
    echo "write_immutable_receipt requires a prepared file and target path" >&2
    return 64
  fi

  local prepared_file="$1"
  local target_file="$2"
  chmod 0444 "${prepared_file}"

  if ln -- "${prepared_file}" "${target_file}" 2>/dev/null; then
    rm -- "${prepared_file}"
    return 0
  fi

  if [[ -f "${target_file}" ]] && cmp -s -- "${prepared_file}" "${target_file}"; then
    rm -- "${prepared_file}"
    return 0
  fi

  rm -- "${prepared_file}"
  echo "immutable receipt already exists with different content: ${target_file}" >&2
  return 73
}
