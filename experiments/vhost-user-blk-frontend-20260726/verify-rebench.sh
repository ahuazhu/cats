#!/bin/bash
# Is the benchmark data complete? Run this BEFORE destroying the box.
#
# Exists because two separate runs were lost to phases that logged themselves as
# finished while producing nothing -- once because fio was missing from the Guest,
# once because CATS_TOKEN was silently empty. A phase header in the log is not
# evidence that the phase measured anything, so this counts actual data rows.
#
#   experiments/vhost-user-blk-frontend-20260726/verify-rebench.sh
D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/raw"
main=$D/metal-rebench.log
p4=$D/metal-rebench-phase4.log
miss=0
have() { # description   file   pattern   min-count
  n=$(grep -cE "$3" "$2" 2>/dev/null || echo 0)
  if [ "$n" -ge "$4" ]; then printf '  ok    %-52s %s\n' "$1" "$n"
  else printf '  MISS  %-52s got %s need %s\n' "$1" "$n" "$4"; miss=$((miss+1)); fi
}
echo "== storage layer"
have "flush cost, sparse rows (both backends)"  "$main" '^ +(1|8|16|32|48) +(1|8|16|32|48) +[0-9]' 10
have "flush cost, dense rows (both backends)"   "$main" '^ +(8|32|48) +(32|128|192)\.00' 6
have "cold read by chain length (both backends)" "$main" '^ +(0|1|2|4) +(16|32|48|80) ' 8
have "golden root, one create (both backends)"   "$main" '^ +(64|256|512) +(copy|reference)' 12
have "golden root, N concurrent (both backends)" "$main" '^ +(1|4|10) +(copy|reference)' 12
echo "== guest fio: 3 configs x 2 rounds x 6 workloads = 36"
have "fio rows"                                  "$main" '^(kernel-nbd|kernel-nbd-direct|vhost-user),' 36
have "fio rows that are not empty"               "$main" '^(kernel-nbd|kernel-nbd-direct|vhost-user),[a-z0-9-]+,[a-z]+,[0-9a-z]+,[0-9]+,[0-9]+,' 36
have "kernel-nbd-direct present"                 "$main" '^kernel-nbd-direct,' 12
echo "== end to end"
have "concurrent create CSV rows"                "$main" '^[a-z-]+,create,10,' 2
have "acceptance verdicts"                       "$main" 'metal e2e: [0-9]+ passed' 2
echo "== phase 4"
have "warm restore timings"                      "$p4"   'warm restore phase timings' 4
have "reclaim object counts"                     "$p4"   'objects=[0-9]+ bytes=[0-9]+' 6
have "fstrim ran"                                "$p4"   'fstrim|trimmed' 1
have "GC report"                                 "$p4"   'garbage collected|data_deleted' 1
have "concurrent create on S3"                   "$p4"   '^vhost-user-s3,create,10,' 1
echo "== failures that would invalidate a phase"
n=$(grep -cE 'not logged in|could not create|WRONG ' "$main" "$p4" 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
[ "${n:-0}" -eq 0 ] && echo "  ok    no auth/environment failures" || { echo "  MISS  $n auth/environment failures"; miss=$((miss+1)); }
echo
[ "$miss" -eq 0 ] && echo "COMPLETE" || echo "$miss GAPS -- do not destroy the box yet"
