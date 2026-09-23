#!/bin/sh
set -eu

out_dir=${1:-/home/ubuntu/onetdns-bench}
mkdir -p "$out_dir"

awk 'BEGIN {
    print "bench.test. 300 IN SOA ns.bench.test. hostmaster.bench.test. 1 3600 600 86400 300"
    print "bench.test. 300 IN NS ns.bench.test."
    print "ns.bench.test. 300 IN A 192.0.2.53"
    for (i = 0; i < 10000; i++) {
        printf "host%05d.bench.test. 300 IN A 192.0.2.%d\n", i, (i % 250) + 1
    }
}' >"$out_dir/bench.test.zone"

awk 'BEGIN {
    for (i = 0; i < 10000; i++) {
        printf "host%05d.bench.test. A\n", i
    }
}' >"$out_dir/queries.txt"
