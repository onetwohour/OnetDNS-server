#!/bin/sh
# 권한 TCP 질의와 대형 AXFR를 OnetDNS·BIND 9·NSD·Knot 사이에서 인터리브로 측정한다.
#
# usage: sh run-authority-tcp-xfr-interleave.sh WORKDIR ONETDNS_BIN [OWNERS=100000]
#
# 서버는 CPU 2, 부하기는 CPU 3에 고정한다. 각 레그는 TCP 정답과 AXFR의 양 끝 SOA,
# 전체 레코드 수를 먼저 검증하며, 어느 하나라도 틀리면 그 레그 수치를 무효화한다.
set -eu

W=${1:?workdir}
BIN=${2:?onetdns binary}
OWNERS=${3:-100000}
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
PORT=${AUTHORITY_TCP_PORT:-15454}
TCP_SECONDS=${AUTHORITY_TCP_SECONDS:-6}
TCP_WARMUP=${AUTHORITY_TCP_WARMUP:-1}
TCP_WARMUP_SETTLE=${AUTHORITY_TCP_WARMUP_SETTLE:-1}
TCP_CLIENTS=${AUTHORITY_TCP_CLIENTS:-4}
TCP_OUTSTANDING=${AUTHORITY_TCP_OUTSTANDING:-100}
AXFR_RUNS=${AUTHORITY_AXFR_RUNS:-5}
LEG_COOLDOWN=${AUTHORITY_LEG_COOLDOWN:-2}
SERVER_CPU=${AUTHORITY_SERVER_CPU:-2}
LOAD_CPU=${AUTHORITY_LOAD_CPU:-3}
EXPECTED_XFR=$((OWNERS + 4))
PIDS=""
ONET_TCP_QPS=""
rc=0

cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null || true; done
  for p in $PIDS; do wait "$p" 2>/dev/null || true; done
}
trap cleanup EXIT
trap 'trap - EXIT; cleanup; exit 130' HUP INT TERM

sh "$SRC/generate-zone.sh" "$W" "$OWNERS" >/dev/null
Q="$W/queries-auth.txt"
PROBE=$(awk 'NR==1{print $1}' "$Q")

cat > "$W/onetdns-auth-tcp.toml" <<EOF
mode = "personal"
backend = "forward"
listen = ["127.0.0.1:$PORT"]
workers = 1
do_udp = false
do_tcp = true
cache_enabled = false
querylog = false
xfr_allow = ["127.0.0.1/32"]
zones = [
  { origin = "bench.test", file = "$W/db.bench.test" },
]
EOF

cat > "$W/named-tcp.conf" <<EOF
options {
  directory "$W";
  listen-on port $PORT { 127.0.0.1; };
  listen-on-v6 { none; };
  pid-file "$W/named-tcp.pid";
  recursion no;
  querylog no;
  minimal-responses yes;
  dnssec-validation no;
};
zone "bench.test" {
  type primary;
  file "$W/db.bench.test";
  allow-transfer { 127.0.0.1; };
};
EOF

cat > "$W/nsd-tcp.conf" <<EOF
server:
  server-count: 1
  ip-address: 127.0.0.1@$PORT
  do-ip6: no
  username: ""
  zonesdir: "$W"
  pidfile: "$W/nsd-tcp.pid"
  database: ""
  logfile: "$W/nsd-tcp.log"
remote-control:
  control-enable: no
zone:
  name: "bench.test"
  zonefile: "db.bench.test"
  provide-xfr: 127.0.0.1 NOKEY
EOF

KNOT_STATE=${AUTHORITY_KNOT_STATE:-/tmp/onetdns-authority-knot-tcp-$$}
mkdir -p "$KNOT_STATE/run" "$KNOT_STATE/db"
cat > "$W/knot-tcp.conf" <<EOF
server:
  listen: 127.0.0.1@$PORT
  udp-workers: 1
  tcp-workers: 1
  rundir: "$KNOT_STATE/run"
log:
  - target: "$W/knot-tcp.log"
    any: error
database:
  storage: "$KNOT_STATE/db"
acl:
  - id: xfr
    address: 127.0.0.1
    action: transfer
template:
  - id: default
    storage: "$W"
    journal-content: none
zone:
  - domain: bench.test
    file: "$W/db.bench.test"
    acl: xfr
EOF

process_tree() {
  ps -eo pid=,ppid= 2>/dev/null | awk -v root="$1" '
    { parent[$1] = $2 }
    END {
      for (pid in parent) {
        current = pid
        while (current in parent) {
          if (current == root) { print pid; break }
          current = parent[current]
        }
      }
    }'
}

process_ticks() {
  total=0
  for process in $(process_tree "$1"); do
    ticks=$(sed 's/^[0-9][0-9]* (.*) //' "/proc/$process/stat" 2>/dev/null \
      | awk '{print $12 + $13}' || echo 0)
    total=$((total + ticks))
  done
  echo "$total"
}

process_rss() {
  total=0
  for process in $(process_tree "$1"); do
    rss=$(awk '/^VmRSS:/{print $2}' "/proc/$process/status" 2>/dev/null || echo 0)
    total=$((total + rss))
  done
  echo "$total"
}

leg() { # label cmd...
  nm=$1
  shift
  "$@" >"$W/$nm.tcp.log" 2>&1 &
  pid=$!
  PIDS="$PIDS $pid"

  ok=0
  i=0
  while [ "$i" -lt 60 ]; do
    ans=$(dig +tcp +short +timeout=1 +tries=1 @127.0.0.1 -p "$PORT" "$PROBE" A 2>/dev/null | head -1)
    case "$ans" in 192.0.2.*) ok=1; break ;; esac
    i=$((i + 1))
    sleep 0.5
  done
  if [ "$ok" != 1 ]; then
    printf '%s: TCP 정답 확인 실패(%s) — 이 레그는 무효다\n' "$nm" "$PROBE"
    rc=1
    LAST_TCP_QPS=0
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    sleep "$LEG_COOLDOWN"
    return 0
  fi

  xfr="$W/$nm.axfr.txt"
  if ! taskset -c "$LOAD_CPU" dig +tcp +timeout=10 +tries=1 +noall +answer +stats \
      @127.0.0.1 -p "$PORT" bench.test AXFR >"$xfr" 2>&1; then
    printf '%s: AXFR 완전성 질의 실패 — 이 레그는 무효다\n' "$nm"
    rc=1
    LAST_TCP_QPS=0
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    sleep "$LEG_COOLDOWN"
    return 0
  fi
  xfr_records=$(awk '$1 !~ /^;/ && NF {n++} END{print n + 0}' "$xfr")
  first_type=$(awk '$1 !~ /^;/ && NF {print $4; exit}' "$xfr")
  last_type=$(awk '$1 !~ /^;/ && NF {t=$4} END{print t}' "$xfr")
  xfr_stats=$(awk '/XFR size:/{sub(/^;; /, ""); print; exit}' "$xfr")
  xfr_bytes=$(awk '/XFR size:/{for(i=1;i<=NF;i++) if($i=="bytes") {gsub(/[^0-9]/, "", $(i+1)); print $(i+1); exit}}' "$xfr")
  if [ "$xfr_records" -ne "$EXPECTED_XFR" ] || [ "$first_type" != SOA ] || [ "$last_type" != SOA ] || [ -z "$xfr_bytes" ]; then
    printf '%s: AXFR 완전성 실패(records=%s expected=%s first=%s last=%s stats=%s) — 이 레그는 무효다\n' \
      "$nm" "$xfr_records" "$EXPECTED_XFR" "${first_type:-?}" "${last_type:-?}" "${xfr_stats:-?}"
    rc=1
    LAST_TCP_QPS=0
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    sleep "$LEG_COOLDOWN"
    return 0
  fi

  if [ "$TCP_WARMUP" -gt 0 ]; then
    taskset -c "$LOAD_CPU" dnsperf -m tcp -s 127.0.0.1 -p "$PORT" -d "$Q" \
      -c "$TCP_CLIENTS" -q "$TCP_OUTSTANDING" -T 1 -l "$TCP_WARMUP" >/dev/null 2>&1
    sleep "$TCP_WARMUP_SETTLE"
  fi
  rss0=$(process_rss "$pid")
  out=$(taskset -c "$LOAD_CPU" dnsperf -m tcp -s 127.0.0.1 -p "$PORT" -d "$Q" \
    -c "$TCP_CLIENTS" -q "$TCP_OUTSTANDING" -T 1 -l "$TCP_SECONDS" 2>/dev/null)
  tcp_qps=$(printf '%s\n' "$out" | awk '/Queries per second/{print $4}')
  tcp_latency=$(printf '%s\n' "$out" | awk '/Average Latency \(s\)/{print $4; exit}')
  tcp_lost=$(printf '%s\n' "$out" | awk 'tolower($0) ~ /queries lost/{print $3}')
  if [ -z "$tcp_qps" ] || [ "${tcp_lost:-1}" != 0 ]; then
    printf '%s: TCP 측정 불완전(qps=%s lost=%s)\n' "$nm" "${tcp_qps:-?}" "${tcp_lost:-?}"
    rc=1
  fi
  LAST_TCP_QPS=${tcp_qps:-0}

  times="$W/$nm.axfr-times.txt"
  : >"$times"
  ticks0=$(process_ticks "$pid")
  i=0
  while [ "$i" -lt "$AXFR_RUNS" ]; do
    /usr/bin/time -f '%e' -a -o "$times" taskset -c "$LOAD_CPU" \
      dig +tcp +timeout=10 +tries=1 +noall +stats @127.0.0.1 -p "$PORT" bench.test AXFR \
      >/dev/null 2>&1
    i=$((i + 1))
  done
  ticks1=$(process_ticks "$pid")
  hz=$(getconf CLK_TCK)
  axfr_wall_avg=$(awk '{s += $1; n++} END{if(n) printf "%.6f", s/n; else print "?"}' "$times")
  axfr_cpu=$(awk -v a="$ticks0" -v b="$ticks1" -v hz="$hz" 'BEGIN{printf "%.6f", (b-a)/hz}')
  axfr_per_cpu=$(awk -v n="$AXFR_RUNS" -v cpu="$axfr_cpu" 'BEGIN{if(cpu>0) printf "%.3f", n/cpu; else print "?"}')
  mib_per_cpu=$(awk -v n="$AXFR_RUNS" -v bytes="$xfr_bytes" -v cpu="$axfr_cpu" \
    'BEGIN{if(cpu>0) printf "%.3f", n*bytes/cpu/1048576; else print "?"}')
  rss1=$(process_rss "$pid")

  printf '%-9s tcp_qps=%s tcp_avg_latency_s=%s tcp_lost=%s rss_kib=%s->%s\n' \
    "$nm" "${tcp_qps:-0}" "${tcp_latency:-?}" "${tcp_lost:-?}" "$rss0" "$rss1"
  printf '%-9s axfr_records=%s %s runs=%s wall_avg_s=%s server_cpu_s=%s xfr_per_cpu_s=%s wire_mib_per_cpu_s=%s\n' \
    "$nm" "$xfr_records" "$xfr_stats" "$AXFR_RUNS" "$axfr_wall_avg" "$axfr_cpu" "$axfr_per_cpu" "$mib_per_cpu"

  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  sleep "$LEG_COOLDOWN"
}

onetdns() {
  leg "$1" taskset -c "$SERVER_CPU" "$BIN" --config "$W/onetdns-auth-tcp.toml" --no-web --no-supervisor
  ONET_TCP_QPS="$ONET_TCP_QPS $LAST_TCP_QPS"
}

if [ "${AUTHORITY_ONETDNS_ONLY:-0}" = 1 ]; then
  onetdns O1
  onetdns O2
  onetdns O3
  onetdns O4
else
  onetdns O1
  leg bind taskset -c "$SERVER_CPU" named -c "$W/named-tcp.conf" -f -g
  onetdns O2
  leg nsd taskset -c "$SERVER_CPU" nsd -c "$W/nsd-tcp.conf" -d
  onetdns O3
  leg knot taskset -c "$SERVER_CPU" knotd -c "$W/knot-tcp.conf"
  onetdns O4
fi

awk -v vals="$ONET_TCP_QPS" 'BEGIN {
  n = split(vals, a, " ")
  if (n < 2) { print "onetdns TCP drift: 레그가 부족해 판정 불가"; exit }
  lo = hi = a[1]; sum = 0
  for (i = 1; i <= n; i++) { if (a[i]+0 < lo+0) lo = a[i]; if (a[i]+0 > hi+0) hi = a[i]; sum += a[i] }
  mean = sum / n
  drift = (hi - lo) * 100 / mean
  printf "onetdns TCP legs=%d min=%.0f max=%.0f drift_pct=%.3f%s\n", n, lo, hi, drift,
    (drift > 5.0 ? "  ← 5% 게이트 초과: 배율 인용 금지" : "")
}'

echo "artifacts=$W"
exit "$rc"
