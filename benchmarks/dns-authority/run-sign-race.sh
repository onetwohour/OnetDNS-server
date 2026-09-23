#!/bin/bash
# onetdns(알고리즘 13·15)와 Knot 3.3.4를 같은 축으로 측정한다:
# 프로세스 시작부터 서명된 응답이 나올 때까지의 벽시계.
set -u
OWNERS="${1:-100000}"
W="$HOME/signrace"
rm -rf "$W"; mkdir -p "$W"
pkill -f 'onetdns run --config .*signrace' 2>/dev/null
pkill -f 'knotd -c .*signrace' 2>/dev/null
sleep 1

gen_zone() {
  {
    echo '$TTL 300'
    echo 'bench.test. 300 IN SOA ns.bench.test. hostmaster.bench.test. 1 300 60 3600 60'
    echo 'bench.test. 300 IN NS ns.bench.test.'
    echo 'ns.bench.test. 300 IN A 192.0.2.53'
    awk -v n="$OWNERS" 'BEGIN{for(i=0;i<n;i++){printf "host%d.bench.test. 60 IN A 192.0.2.%d\n", i, (i%250)+1}}'
  } > "$1"
}

run_onetdns() {
  local alg="$1"
  local port="$2"
  local d="$W/onet-$alg"
  mkdir -p "$d"
  gen_zone "$d/z.zone"
  cat > "$d/c.toml" <<TOML
mode = "personal"
backend = "forward"
upstreams = ["1.1.1.1"]
listen = ["127.0.0.1:$port"]
zones = [{ origin = "bench.test", file = "$d/z.zone", dnssec_sign = true, dnssec_algorithm = "$alg" }]
TOML
  local bin="$HOME/ci-target-rel/release/onetdns"
  [ -x "$bin" ] || bin="$HOME/ci-target-test/debug/onetdns"
  local s e
  s=$(date +%s%N)
  "$bin" run --config "$d/c.toml" --no-web --no-supervisor > "$d/srv.log" 2>&1 &
  local pid=$!
  for _ in $(seq 1 2400); do
    dig -p "$port" @127.0.0.1 host7.bench.test A +dnssec +time=1 +tries=1 2>/dev/null | grep -q RRSIG && break
    sleep 0.05
  done
  e=$(date +%s%N)
  local sig
  sig=$(dig -p "$port" @127.0.0.1 host7.bench.test A +dnssec +time=2 +tries=1 2>/dev/null \
        | grep -oP 'RRSIG\s+A\s+\d+' | head -1)
  printf 'onetdns %-10s %6d ms   (%s)\n' "$alg" $(( (e - s) / 1000000 )) "${sig:-서명없음}"
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
}

run_knot() {
  local alg="$1"
  local port="$2"
  local d="$W/knot-$alg"
  mkdir -p "$d/storage" "$d/run" "$d/kasp"
  gen_zone "$d/storage/bench.test.zone"
  cat > "$d/knot.conf" <<CONF
server:
    rundir: "$d/run"
    listen: 127.0.0.1@$port
database:
    storage: "$d/storage"
    kasp-db: "$d/kasp"
log:
  - target: stdout
    any: info
policy:
  - id: pol
    algorithm: $alg
    single-type-signing: on
    nsec3: off
zone:
  - domain: bench.test
    file: "$d/storage/bench.test.zone"
    storage: "$d/storage"
    dnssec-signing: on
    dnssec-policy: pol
    zonefile-sync: -1
CONF
  local s e
  s=$(date +%s%N)
  knotd -c "$d/knot.conf" > "$d/knot.log" 2>&1 &
  local pid=$!
  for _ in $(seq 1 2400); do
    dig -p "$port" @127.0.0.1 host7.bench.test A +dnssec +time=1 +tries=1 2>/dev/null | grep -q RRSIG && break
    sleep 0.05
  done
  e=$(date +%s%N)
  local sig
  sig=$(dig -p "$port" @127.0.0.1 host7.bench.test A +dnssec +time=2 +tries=1 2>/dev/null \
        | grep -oP 'RRSIG\s+A\s+\d+' | head -1)
  printf 'Knot    %-10s %6d ms   (%s)\n' "$alg" $(( (e - s) / 1000000 )) "${sig:-서명없음}"
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
}

echo "10만 owner, NSEC, 시작~서명된 응답까지 (28코어)"
for round in 1 2; do
  echo "--- round $round ---"
  run_onetdns ecdsap256 15761
  run_onetdns ed25519   15762
  run_knot    ecdsap256sha256 15763
  run_knot    ed25519         15764
done
