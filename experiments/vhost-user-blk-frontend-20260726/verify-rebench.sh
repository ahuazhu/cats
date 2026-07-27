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
# Each check names the artifact that is actually authoritative for it. The first
# version pointed everything at metal-rebench.log and reported three false gaps,
# because that log is the superseded first pass: its fio rows predate the exec
# timeout fix and its auth failures are historical.
storage=$D/metal-rebench.log            # storage benches, both backends
fio=$D/metal-fio-matrix.log             # fio after the exec fix, local store
fio_s3=$D/metal-fio-s3.log              # the same fio against S3
c5=$D/c5-storage.log                    # the EBS-only machine
e2e=$D/metal-final-e2e.log              # acceptance after the dash fix
conc=$D/metal-concurrent-s3.log         # concurrent create on S3
warm=$D/metal-rebench-phase4.log        # warm restore telemetry
reclaim=$D/metal-reclaim.log            # GC and TRIM
miss=0
have() { # description   file   pattern   min-count
  n=$(grep -cE "$3" "$2" 2>/dev/null | head -1)
  n=${n:-0}
  if [ "$n" -ge "$4" ]; then printf '  ok    %-52s %s\n' "$1" "$n"
  else printf '  MISS  %-52s got %s need %s\n' "$1" "${n}" "$4"; miss=$((miss+1)); fi
}
echo "== storage layer, i4i (local NVMe and S3)"
have "flush cost, sparse rows"                   "$storage" '^ +(1|8|16|32|48) +(1|8|16|32|48) +[0-9]' 10
have "flush cost, dense rows"                    "$storage" '^ +(8|32|48) +(32|128|192)\.00' 6
have "cold read by chain length"                 "$storage" '^ +(0|1|2|4) +(16|32|48|80) ' 8
have "golden root, one create"                   "$storage" '^ +(64|256|512) +(copy|reference)' 12
have "golden root, N concurrent"                 "$storage" '^ +(1|4|10) +(copy|reference)' 12
echo "== storage layer, c5 (EBS only, the cross-machine comparison)"
have "flush cost, dense rows"                    "$c5" '^ +(8|32|48) +(32|128|192)\.00' 6
have "cold read by chain length"                 "$c5" '^ +(0|1|2|4) +(16|32|48|80) ' 8
echo "== guest fio"
have "local store: 3 configs x 2 rounds x 6"     "$fio" '^[a-z-]+,[a-z0-9-]+,[a-z]+,[0-9a-zA-Z]+,[0-9]+,[0-9]+,' 36
n=$(grep -cE '^[a-z-]+,[a-z0-9-]+,[a-z]+,[0-9a-zA-Z]+,[0-9]+,,' "$fio" 2>/dev/null); n=${n:-0}
[ "$n" -eq 0 ] && printf '  ok    %-52s %s\n' "local store: no empty rows" 0 ||
  { printf '  MISS  %-52s %s empty\n' "local store: no empty rows" "$n"; miss=$((miss+1)); }
have "kernel-nbd-direct present"                 "$fio" '^kernel-nbd-direct,' 12
have "S3 pair for the backend comparison"        "$fio_s3" '^[a-z0-9-]+,[a-z0-9-]+,[a-z]+,[0-9a-zA-Z]+,[0-9]+,[0-9]+,' 12
echo "== end to end"
have "acceptance fully green"                    "$e2e" 'metal e2e: 23 passed, 0 failed' 1
have "concurrent create on S3"                   "$conc" 'batch wall [0-9]+ ms' 1
echo "== new features on real hardware"
have "warm restore telemetry"                    "$warm" 'warm restore phase timings' 4
have "reclaim object counts"                     "$reclaim" 'objects=[0-9]+ +size=[0-9]+ MiB' 6
have "fstrim ran"                                "$reclaim" 'fstrim reported' 1
have "GC deleted objects"                        "$reclaim" 'data_deleted=[1-9]' 1
have "images/ survived GC"                       "$reclaim" 'images/. still holds' 1
echo
[ "$miss" -eq 0 ] && echo "COMPLETE" || echo "$miss GAPS -- do not destroy the box yet"
