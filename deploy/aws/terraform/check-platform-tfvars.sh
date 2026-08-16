#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <production-platform.tfvars>" >&2
  exit 2
fi

tfvars=$1
if [[ ! -f "$tfvars" ]]; then
  echo "production platform tfvars is not a regular file: $tfvars" >&2
  exit 1
fi

awk '
  {
    line = $0
    sub(/[[:space:]]*(#|\/\/).*$/, "", line)
    if (line ~ /^[[:space:]]*one_nat_gateway_per_az[[:space:]]*=/) {
      matches += 1
      sub(/^[[:space:]]*one_nat_gateway_per_az[[:space:]]*=[[:space:]]*/, "", line)
      sub(/[[:space:]]*$/, "", line)
      if (line == "true") {
        safe += 1
      }
    }
  }
  END {
    if (matches != 1 || safe != 1) {
      print "production platform tfvars must contain exactly one literal one_nat_gateway_per_az = true assignment" > "/dev/stderr"
      exit 1
    }
  }
' "$tfvars"
