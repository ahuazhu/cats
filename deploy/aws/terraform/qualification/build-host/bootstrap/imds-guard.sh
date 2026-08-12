#!/usr/bin/env bash
set -euo pipefail

readonly imds="169.254.169.254/32"
readonly build_uid="2000"

if ! iptables -w -C OUTPUT -m owner --uid-owner "${build_uid}" -d "${imds}" -j REJECT 2>/dev/null; then
  iptables -w -I OUTPUT 1 -m owner --uid-owner "${build_uid}" -d "${imds}" -j REJECT
fi
if ! iptables -w -C FORWARD -d "${imds}" -j REJECT 2>/dev/null; then
  iptables -w -I FORWARD 1 -d "${imds}" -j REJECT
fi

test "$(iptables -w -S OUTPUT | grep -F -- "-A OUTPUT -d ${imds} -m owner --uid-owner ${build_uid} -j REJECT" | wc -l)" -eq 1
test "$(iptables -w -S FORWARD | grep -F -- "-A FORWARD -d ${imds} -j REJECT" | wc -l)" -eq 1
