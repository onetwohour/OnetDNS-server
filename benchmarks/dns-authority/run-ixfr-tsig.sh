#!/bin/sh
# OnetDNS의 TSIG 필수 AXFR와 DDNS 뒤 IXFR를 실제 dig/nsupdate로 검증하고 측정한다.
#
# usage: sh run-ixfr-tsig.sh WORKDIR ONETDNS_BIN [OWNERS=10000]
set -eu

W=${1:?workdir}
BIN=${2:?onetdns binary}
OWNERS=${3:-10000}
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
PORT=${AUTHORITY_IXFR_PORT:-15456}
SERVER=${AUTHORITY_SERVER:-127.0.0.1}
LISTEN=${AUTHORITY_LISTEN:-127.0.0.1}
CLIENT_CIDR=${AUTHORITY_CLIENT_CIDR:-127.0.0.1/32}
RUNS=${AUTHORITY_IXFR_RUNS:-20}
SERVER_CPU=${AUTHORITY_SERVER_CPU:-2}
LOAD_CPU=${AUTHORITY_LOAD_CPU:-3}
SECRET=${AUTHORITY_TSIG_SECRET:-MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=}
KEY=${AUTHORITY_TSIG_KEY:-xfer-key}
ZONE_FILE=${AUTHORITY_ZONE_FILE:-$W/db.bench.test}
EXPECTED_AXFR=$((OWNERS + 5))
PID=""

cleanup() {
  if [ -n "$PID" ]; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'trap - EXIT; cleanup; exit 130' HUP INT TERM

sh "$SRC/generate-zone.sh" "$W" "$OWNERS" >/dev/null

cat >"$W/onetdns-ixfr-tsig.toml" <<EOF
mode = "personal"
backend = "forward"
listen = ["$LISTEN:$PORT"]
workers = 1
do_udp = true
do_tcp = true
cache_enabled = false
querylog = false
xfr_allow = ["$CLIENT_CIDR"]
xfr_tsig_required = true
update_allow = ["$CLIENT_CIDR"]
update_tsig_required = true
zones = [
  { origin = "bench.test", file = "$ZONE_FILE" },
]

[[tsig_keys]]
name = "$KEY"
secret = "$SECRET"
EOF

cat >"$W/named-tsig.conf" <<EOF
key "$KEY" {
  algorithm hmac-sha256;
  secret "$SECRET";
};
options {
  directory "$W";
  listen-on port $PORT { 127.0.0.1; };
  listen-on-v6 { none; };
  pid-file "$W/named-tsig.pid";
  recursion no;
  querylog no;
  minimal-responses yes;
  dnssec-validation no;
};
zone "bench.test" {
  type primary;
  file "$W/db.bench.test";
  allow-transfer { key "$KEY"; };
};
EOF

cat >"$W/nsd-tsig.conf" <<EOF
server:
  server-count: 1
  ip-address: 127.0.0.1@$PORT
  do-ip6: no
  username: ""
  zonesdir: "$W"
  pidfile: "$W/nsd-tsig.pid"
  database: ""
  logfile: "$W/nsd-tsig.log"
remote-control:
  control-enable: no
key:
  name: "$KEY"
  algorithm: hmac-sha256
  secret: "$SECRET"
zone:
  name: "bench.test"
  zonefile: "db.bench.test"
  provide-xfr: 127.0.0.1 $KEY
EOF

KNOT_STATE=${AUTHORITY_KNOT_STATE:-/tmp/onetdns-authority-knot-tsig-$$}
mkdir -p "$KNOT_STATE/run" "$KNOT_STATE/db"
cat >"$W/knot-tsig.conf" <<EOF
server:
  listen: 127.0.0.1@$PORT
  udp-workers: 1
  tcp-workers: 1
  rundir: "$KNOT_STATE/run"
log:
  - target: "$W/knot-tsig.log"
    any: error
database:
  storage: "$KNOT_STATE/db"
key:
  - id: $KEY
    algorithm: hmac-sha256
    secret: $SECRET
acl:
  - id: xfr
    address: 127.0.0.1
    key: $KEY
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

if [ "${AUTHORITY_PREPARE_ONLY:-0}" = 1 ]; then
  echo "prepared=$W/onetdns-ixfr-tsig.toml"
  exit 0
fi

if [ "${AUTHORITY_EXTERNAL_SERVER:-0}" != 1 ]; then
  if [ "${AUTHORITY_SERVER_NO_TASKSET:-0}" = 1 ]; then
    "$BIN" --config "$W/onetdns-ixfr-tsig.toml" --no-web --no-supervisor \
      >"$W/onetdns-ixfr-tsig.log" 2>&1 &
  else
    taskset -c "$SERVER_CPU" "$BIN" --config "$W/onetdns-ixfr-tsig.toml" \
      --no-web --no-supervisor >"$W/onetdns-ixfr-tsig.log" 2>&1 &
  fi
  PID=$!
fi

i=0
while [ "$i" -lt 60 ]; do
  if dig -y "hmac-sha256:$KEY:$SECRET" +short +timeout=1 +tries=1 \
      @"$SERVER" -p "$PORT" bench.test SOA 2>/dev/null | grep -q ' 1 '; then
    break
  fi
  i=$((i + 1))
  sleep 0.25
done
if [ "$i" -eq 60 ]; then
  echo "서명 SOA 준비 확인 실패"
  exit 1
fi

python3 "$SRC/probe-tsig-errors.py" "$SERVER" "$PORT" bench.test "$KEY" "$SECRET"

unsigned="$W/unsigned-axfr.txt"
dig +tcp +timeout=2 +tries=1 @"$SERVER" -p "$PORT" bench.test AXFR \
  >"$unsigned" 2>&1 || true
grep -q 'Transfer failed' "$unsigned" || {
  echo "비서명 AXFR가 거부되지 않았습니다"
  exit 1
}

serial_before=$(dig -y "hmac-sha256:$KEY:$SECRET" +short +timeout=2 +tries=1 \
  @"$SERVER" -p "$PORT" bench.test SOA | awk 'NR==1 {print $3}')
if [ "$serial_before" != 1 ]; then
  echo "초기 serial 불일치: $serial_before"
  exit 1
fi

nsupdate -y "hmac-sha256:$KEY:$SECRET" >"$W/nsupdate.txt" 2>&1 <<EOF
server $SERVER $PORT
zone bench.test.
update add ixfr-added.bench.test. 120 A 198.51.100.77
send
EOF

serial_after=$(dig -y "hmac-sha256:$KEY:$SECRET" +short +timeout=2 +tries=1 \
  @"$SERVER" -p "$PORT" bench.test SOA | awk 'NR==1 {print $3}')
if [ "$serial_after" != 2 ]; then
  echo "DDNS 뒤 serial 불일치: $serial_before -> $serial_after"
  exit 1
fi

axfr="$W/signed-axfr.txt"
taskset -c "$LOAD_CPU" dig -y "hmac-sha256:$KEY:$SECRET" +tcp +timeout=10 +tries=1 \
  +noall +answer +stats @"$SERVER" -p "$PORT" bench.test AXFR >"$axfr" 2>&1
axfr_records=$(awk '$1 !~ /^;/ && NF {n++} END {print n + 0}' "$axfr")
first_type=$(awk '$1 !~ /^;/ && NF {print $4; exit}' "$axfr")
last_type=$(awk '$1 !~ /^;/ && NF {type=$4} END {print type}' "$axfr")
if [ "$axfr_records" -ne "$EXPECTED_AXFR" ] || [ "$first_type" != SOA ] || [ "$last_type" != SOA ]; then
  echo "서명 AXFR 완전성 실패: records=$axfr_records expected=$EXPECTED_AXFR first=$first_type last=$last_type"
  exit 1
fi

ixfr="$W/signed-ixfr.txt"
taskset -c "$LOAD_CPU" dig -y "hmac-sha256:$KEY:$SECRET" +tcp +timeout=10 +tries=1 \
  +noall +answer +stats @"$SERVER" -p "$PORT" bench.test "IXFR=$serial_before" >"$ixfr" 2>&1
ixfr_records=$(awk '$1 !~ /^;/ && NF {n++} END {print n + 0}' "$ixfr")
ixfr_soas=$(awk '$1 !~ /^;/ && $4 == "SOA" {n++} END {print n + 0}' "$ixfr")
grep -q '^ixfr-added\.bench\.test\..*[[:space:]]A[[:space:]]198\.51\.100\.77$' "$ixfr" || {
  echo "IXFR에 DDNS 추가 레코드가 없습니다"
  exit 1
}
if [ "$ixfr_records" -ne 5 ] || [ "$ixfr_soas" -ne 4 ]; then
  echo "IXFR 증분 형식 불일치: records=$ixfr_records soas=$ixfr_soas"
  exit 1
fi

current="$W/current-ixfr.txt"
dig -y "hmac-sha256:$KEY:$SECRET" +tcp +timeout=2 +tries=1 +noall +answer \
  @"$SERVER" -p "$PORT" bench.test "IXFR=$serial_after" >"$current" 2>&1
current_records=$(awk '$1 !~ /^;/ && NF {n++} END {print n + 0}' "$current")
if [ "$current_records" -ne 1 ]; then
  echo "최신 IXFR가 단일 SOA가 아닙니다: records=$current_records"
  exit 1
fi

udp="$W/stale-udp-ixfr.txt"
dig -y "hmac-sha256:$KEY:$SECRET" +yaml +notcp +ignore +timeout=2 +tries=1 \
  @"$SERVER" -p "$PORT" bench.test "IXFR=$serial_before" >"$udp" 2>&1 || true
grep -q 'flags:.*tc' "$udp" || {
  echo "오래된 UDP IXFR가 TC를 설정하지 않았습니다"
  exit 1
}

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
  for process in $(process_tree "$PID"); do
    ticks=$(sed 's/^[0-9][0-9]* (.*) //' "/proc/$process/stat" 2>/dev/null \
      | awk '{print $12 + $13}' || echo 0)
    total=$((total + ticks))
  done
  echo "$total"
}

process_rss() {
  total=0
  for process in $(process_tree "$PID"); do
    rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$process/status" 2>/dev/null || echo 0)
    total=$((total + rss))
  done
  echo "$total"
}

measure() { # label qtype
  label=$1
  qtype=$2
  times="$W/$label-times.txt"
  : >"$times"
  ticks0=$(process_ticks)
  i=0
  while [ "$i" -lt "$RUNS" ]; do
    /usr/bin/time -f '%e' -a -o "$times" taskset -c "$LOAD_CPU" \
      dig -y "hmac-sha256:$KEY:$SECRET" +tcp +timeout=10 +tries=1 +noall +stats \
      @"$SERVER" -p "$PORT" bench.test "$qtype" >/dev/null 2>&1
    i=$((i + 1))
  done
  ticks1=$(process_ticks)
  hz=$(getconf CLK_TCK)
  wall=$(awk '{sum += $1; n++} END {printf "%.6f", sum/n}' "$times")
  cpu=$(awk -v a="$ticks0" -v b="$ticks1" -v hz="$hz" 'BEGIN {printf "%.6f", (b-a)/hz}')
  per_cpu=$(awk -v n="$RUNS" -v cpu="$cpu" 'BEGIN {if(cpu>0) printf "%.3f", n/cpu; else print "?"}')
  printf '%-11s runs=%s wall_avg_s=%s server_cpu_s=%s transfers_per_cpu_s=%s\n' \
    "$label" "$RUNS" "$wall" "$cpu" "$per_cpu"
}

if [ -z "$PID" ]; then
  printf 'semantics=ok serial=%s->%s axfr_records=%s ixfr_records=%s ixfr_soas=%s rss_kib=external\n' \
    "$serial_before" "$serial_after" "$axfr_records" "$ixfr_records" "$ixfr_soas"
  echo "artifacts=$W"
  exit 0
fi

rss=$(process_rss)
printf 'semantics=ok serial=%s->%s axfr_records=%s ixfr_records=%s ixfr_soas=%s rss_kib=%s\n' \
  "$serial_before" "$serial_after" "$axfr_records" "$ixfr_records" "$ixfr_soas" "$rss"
measure tsig_axfr AXFR
measure tsig_ixfr "IXFR=$serial_before"

competitor_leg() { # label command...
  label=$1
  shift
  "$@" >"$W/$label-server.log" 2>&1 &
  PID=$!
  i=0
  while [ "$i" -lt 60 ]; do
    if dig -y "hmac-sha256:$KEY:$SECRET" +short +timeout=1 +tries=1 \
        @127.0.0.1 -p "$PORT" bench.test SOA 2>/dev/null | grep -q " $serial_after "; then
      break
    fi
    i=$((i + 1))
    sleep 0.25
  done
  if [ "$i" -eq 60 ]; then
    echo "$label: 서명 SOA 준비 확인 실패"
    return 1
  fi
  probe="$W/$label-axfr.txt"
  dig -y "hmac-sha256:$KEY:$SECRET" +tcp +timeout=10 +tries=1 +noall +answer \
    @127.0.0.1 -p "$PORT" bench.test AXFR >"$probe" 2>&1
  records=$(awk '$1 !~ /^;/ && NF {n++} END {print n + 0}' "$probe")
  if [ "$records" -ne "$EXPECTED_AXFR" ]; then
    echo "$label: 서명 AXFR 완전성 실패(records=$records expected=$EXPECTED_AXFR)"
    return 1
  fi
  before=$(process_rss)
  measure "${label}_axfr" AXFR
  after=$(process_rss)
  printf '%-11s axfr_records=%s rss_kib=%s->%s\n' "$label" "$records" "$before" "$after"
  kill "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
  PID=""
  sleep 1
}

if [ "${AUTHORITY_TSIG_COMPETITORS:-0}" = 1 ]; then
  kill "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
  PID=""
  sleep 1
  competitor_leg bind taskset -c "$SERVER_CPU" named -c "$W/named-tsig.conf" -f -g
  competitor_leg nsd taskset -c "$SERVER_CPU" nsd -c "$W/nsd-tsig.conf" -d
  competitor_leg knot taskset -c "$SERVER_CPU" knotd -c "$W/knot-tsig.conf"
fi
echo "artifacts=$W"
