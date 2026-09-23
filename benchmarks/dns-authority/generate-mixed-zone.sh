#!/bin/sh
# 권위 exact·NXDOMAIN·wildcard·ENT·DNAME 혼합 workload를 만든다.
# usage: sh generate-mixed-zone.sh WORKDIR [OWNERS=100000]
set -eu
W=${1:?workdir}
OWNERS=${2:-100000}
mkdir -p "$W"

{
  echo '$TTL 3600'
  echo '@ IN SOA ns1.bench.test. hostmaster.bench.test. 1 3600 600 86400 300'
  echo '@ IN NS ns1.bench.test.'
  echo 'ns1 IN A 127.0.0.1'
  echo '*.wild IN A 198.51.100.77'
  echo 'leaf.empty IN A 198.51.100.88'
  echo 'old IN DNAME target.example.'
  awk -v n="$OWNERS" 'BEGIN {
    for (i = 0; i < n; i++) printf "h%06d IN A 192.0.2.%d\n", i, (i % 254) + 1
  }'
} > "$W/db.mixed.bench.test"

{
  echo 'h000000.bench.test. A'
  awk -v n="$OWNERS" 'BEGIN {
    for (i = 1; i < n; i++) {
      kind = i % 20
      if (kind == 0) printf "w%06d.wild.bench.test. A\n", i
      else if (kind == 1) print "empty.bench.test. A"
      else if (kind == 2) printf "d%06d.old.bench.test. A\n", i
      else if (kind < 10) printf "missing%06d.other.bench.test. A\n", i
      else printf "h%06d.bench.test. A\n", i
    }
  }'
} > "$W/queries-auth-mixed.txt"

printf 'zone=%s owners=%s queries=%s\n' \
  "$W/db.mixed.bench.test" "$OWNERS" "$(wc -l < "$W/queries-auth-mixed.txt")"
