#!/bin/sh
# 권한 서빙 처리량을 OnetDNS·BIND 9·NSD·Knot 사이에서 인터리브로 측정한다.
#
# usage: sh run-authority-interleave.sh WORKDIR ONETDNS_BIN [OWNERS=100000]
#   AUTHORITY_MIXED=1: exact 50%·NXDOMAIN 35%·wildcard/ENT/DNAME 각 5%
#   AUTHORITY_RRSET=N: 이름당 A 레코드 N개(1~254). RRset 순회와 응답 인코딩이
#     지배하는 축을 측정한다. 기본 존은 이름당 하나라 이 비용이 거의 안 잡힌다.
#   AUTHORITY_AB_BIN=/path/to/baseline: 경쟁 엔진 대신 두 OnetDNS 바이너리를
#     라운드마다 순서를 뒤집어 직접 교차 측정
#   AUTHORITY_ROUNDS=N: 라운드 수(기본 2). 엔진마다 레그가 여럿이어야 드리프트를
#     판정할 수 있다.
#
# **netns로 감싸지 말 것.** 전부 높은 포트(15453)를 쓰므로 격리가 필요 없고, 비특권
# user namespace 안에서는 nsd/named가 권한 강하(setgroups)에 실패해 기동조차 못 한다.
#
# 규율은 다른 벤치와 같다 — 경쟁 엔진 사이사이에 OnetDNS 레그를 넣어 호스트 드리프트를
# 같은 창에서 함께 잡고, 각 레그는 측정 **직전에** dig로 정답을 확인한다. 정답이 틀리면
# 그 엔진의 수치는 내지 않는다(존을 못 읽은 채 SERVFAIL을 빠르게 뱉는 것이 가장 빠른
# 오답이기 때문이다).
#
# 판정 지표는 셋이다. **해석당 CPU**가 우선이다 — 이 호스트에서 QPS 레그 드리프트는
# 5~20%라 몇 %의 마진을 가릴 수 없다. **메모리는 프로세스 트리 전체의 Pss**로 측정한다:
# NSD는 자식을 fork하므로 하네스가 붙잡은 부모 PID의 VmRSS만 보면 80만 레코드 존에서
# 11 MiB로 나오는데 트리 전체는 88 MiB다(8배 과소).
set -eu
W=${1:?workdir}
BIN=${2:?onetdns binary}
OWNERS=${3:-100000}
MIXED=${AUTHORITY_MIXED:-0}
# 이름당 A 레코드 수. 0이면 기본 존(이름당 하나)을 쓴다.
RRSET=${AUTHORITY_RRSET:-0}
AB_BIN=${AUTHORITY_AB_BIN:-}
# 라운드 수. 2 이상이면 경쟁 엔진도 레그를 여럿 받아 드리프트 게이트에 걸린다.
ROUNDS=${AUTHORITY_ROUNDS:-2}
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$SRC/../lib/procmem.sh"
PORT=15453
PIDS=""
rc=0
TICKS=$(getconf CLK_TCK)
# 엔진별 레그 결과. 마지막에 엔진마다 드리프트를 판정한다. 존 생성기가 워크디렉터리를
# 만들지만 그보다 먼저 여기에 쓰므로 디렉터리를 여기서 보장한다.
mkdir -p "$W"
RESULTS="$W/legs.txt"
: >"$RESULTS"

# 트리의 모든 프로세스를 찍는다. 하나만 찍으면 fork하는 엔진에서 존을 가지고 있는 자식이
# 전부 빠져 진단이 오히려 틀린 그림을 준다.
dump_memory_map() {
  nm=$1
  needle=$2
  target=${AUTHORITY_DUMP_MEMORY:-0}
  [ "$target" = 1 ] || [ "$target" = "$nm" ] || return 0
  for pid in $(engine_pids "$needle"); do
    printf '%s[%s] memory status:\n' "$nm" "$pid"
    grep -E '^(VmRSS|VmHWM|VmData|VmStk|VmExe|VmLib|Threads):' "/proc/$pid/status"
    printf '%s[%s] memory rollup:\n' "$nm" "$pid"
    grep -E '^(Rss|Pss|Private_Clean|Private_Dirty|Anonymous):' "/proc/$pid/smaps_rollup"
    printf '%s[%s] memory map:\n' "$nm" "$pid"
    pmap -x "$pid"
  done
}

cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null || true; done
  for p in $PIDS; do wait "$p" 2>/dev/null || true; done
}
trap cleanup EXIT
trap 'trap - EXIT; cleanup; exit 130' HUP INT TERM

if [ "$MIXED" = 1 ]; then
  sh "$SRC/generate-mixed-zone.sh" "$W" "$OWNERS" >/dev/null
  ZONE_FILE=db.mixed.bench.test
  Q="$W/queries-auth-mixed.txt"
elif [ "$RRSET" != 0 ]; then
  sh "$SRC/generate-rrset-zone.sh" "$W" "$OWNERS" "$RRSET" >/dev/null
  ZONE_FILE=db.rrset.bench.test
  Q="$W/queries-auth-rrset.txt"
else
  sh "$SRC/generate-zone.sh" "$W" "$OWNERS" >/dev/null
  ZONE_FILE=db.bench.test
  Q="$W/queries-auth.txt"
fi
PROBE=$(awk 'NR==1{print $1}' "$Q")

verify_mixed() {
  exact=$(dig +noall +answer +timeout=1 +tries=1 @127.0.0.1 -p "$PORT" \
    h000010.bench.test A 2>/dev/null || true)
  printf '%s\n' "$exact" | awk '$2 == 3600 && $4 == "A" && $5 == "192.0.2.11" { ok=1 } END { exit !ok }' || return 1
  wildcard=$(dig +noall +answer +timeout=1 +tries=1 @127.0.0.1 -p "$PORT" \
    w000020.wild.bench.test A 2>/dev/null || true)
  printf '%s\n' "$wildcard" | awk '$2 == 3600 && $4 == "A" && $5 == "198.51.100.77" { ok=1 } END { exit !ok }' || return 1
  negative=$(dig +timeout=1 +tries=1 @127.0.0.1 -p "$PORT" \
    missing000003.other.bench.test A 2>/dev/null || true)
  printf '%s\n' "$negative" | grep -q 'status: NXDOMAIN' || return 1
  printf '%s\n' "$negative" | awk '$2 == 300 && $4 == "SOA" { ok=1 } END { exit !ok }' || return 1
  ent=$(dig +timeout=1 +tries=1 @127.0.0.1 -p "$PORT" empty.bench.test A 2>/dev/null || true)
  printf '%s\n' "$ent" | grep -q 'status: NOERROR' || return 1
  printf '%s\n' "$ent" | grep -q 'ANSWER: 0' || return 1
  printf '%s\n' "$ent" | awk '$2 == 300 && $4 == "SOA" { ok=1 } END { exit !ok }' || return 1
  dname=$(dig +timeout=1 +tries=1 @127.0.0.1 -p "$PORT" \
    d000002.old.bench.test A 2>/dev/null || true)
  printf '%s\n' "$dname" | grep -q 'status: NOERROR' || return 1
  printf '%s\n' "$dname" | grep -q '[[:space:]]DNAME[[:space:]]' || return 1
  printf '%s\n' "$dname" | awk '$2 == 3600 && $4 == "DNAME" { ok=1 } END { exit !ok }' || return 1
}

# --- 엔진별 설정 ---------------------------------------------------------------
cat > "$W/onetdns-auth.toml" <<EOF
mode = "personal"
backend = "forward"
listen = ["127.0.0.1:$PORT"]
workers = 1
do_udp = true
do_tcp = false
cache_enabled = false
querylog = false
zones = [
  { origin = "bench.test", file = "$W/$ZONE_FILE" },
]
EOF

cat > "$W/named.conf" <<EOF
options {
  directory "$W";
  listen-on port $PORT { 127.0.0.1; };
  listen-on-v6 { none; };
  pid-file "$W/named.pid";
  recursion no;
  querylog no;
  minimal-responses yes;
  dnssec-validation no;
};
zone "bench.test" { type primary; file "$W/$ZONE_FILE"; };
EOF

cat > "$W/nsd.conf" <<EOF
server:
  server-count: 1
  ip-address: 127.0.0.1@$PORT
  do-ip6: no
  username: ""
  zonesdir: "$W"
  pidfile: "$W/nsd.pid"
  database: ""
  logfile: "$W/nsd.log"
  # 처리량 비교에서는 반복 부정 응답을 버리는 기본 200 QPS RRL을 끈다.
  rrl-ratelimit: 0
  rrl-whitelist-ratelimit: 0
remote-control:
  control-enable: no
zone:
  name: "bench.test"
  zonefile: "$ZONE_FILE"
EOF

mkdir -p "$W/knot-run" "$W/knot-db"
cat > "$W/knot.conf" <<EOF
server:
  listen: 127.0.0.1@$PORT
  udp-workers: 1
  tcp-workers: 1
  rundir: "$W/knot-run"
log:
  - target: "$W/knot.log"
    any: error
database:
  storage: "$W/knot-db"
template:
  - id: default
    storage: "$W"
    journal-content: none
zone:
  - domain: bench.test
    file: "$W/$ZONE_FILE"
EOF

# /proc/PID/stat의 utime+stime. 프로세스 이름에 공백·괄호가 들어갈 수 있어 마지막
# ") "까지 잘라낸 뒤에 곳을 센다 — NSD가 실제로 "nsd: main" 꼴이라 자르지 않으면
# 엉뚱한 위치를 읽는다.
proc_cpu() { # pid
  stat=$(cat "/proc/$1/stat" 2>/dev/null || echo "")
  [ -n "$stat" ] || { echo 0; return; }
  printf '%s' "${stat##*") "}" | awk '{print $12 + $13}'
}

# 엔진 트리 전체의 CPU 틱. fork하는 엔진은 자식이 일을 하므로 부모만 보면 0이 나온다.
engine_cpu() { # needle
  total=0
  for p in $(engine_pids "$1"); do
    total=$((total + $(proc_cpu "$p")))
  done
  echo "$total"
}

# --- 레그 실행 ------------------------------------------------------------------
leg() { # label cmdline_needle cmd...
  nm=$1; needle=$2; shift 2
  "$@" >"$W/$nm.log" 2>&1 &
  pid=$!
  PIDS="$PIDS $pid"
  # 10만 레코드 존 로드는 엔진마다 걸리는 시간이 다르다. 정답이 나올 때까지 기다린다.
  ok=0
  i=0
  while [ "$i" -lt 40 ]; do
    ans=$(dig +short +timeout=1 +tries=1 @127.0.0.1 -p "$PORT" "$PROBE" A 2>/dev/null | head -1)
    case "$ans" in 192.0.2.*) ok=1; break ;; esac
    i=$((i + 1))
    sleep 0.5
  done
  if [ "$ok" != 1 ]; then
    printf '%s: 정답 확인 실패(%s 가 192.0.2.x 가 아니다) — 이 엔진의 수치는 무효다\n' "$nm" "$PROBE"
    rc=1
    kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
    sleep 1
    return 0
  fi
  if [ "$MIXED" = 1 ] && ! verify_mixed; then
    printf '%s: 혼합 정답 확인 실패(NXDOMAIN/wildcard/ENT/DNAME) — 이 엔진의 수치는 무효다\n' "$nm"
    rc=1
    kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
    sleep 1
    return 0
  fi
  # 메모리는 프로세스 트리 전체의 Pss로 측정한다. 단일 PID VmRSS를 읽으면 fork하는
  # 엔진에서 8배 가까이 낮게 나온다(procmem.sh 주석 참조).
  mem=$(engine_memory "$needle")
  procs=${mem%% *}
  pss=$(printf '%s' "$mem" | awk '{print $2}')
  dump_memory_map "$nm" "$needle"
  cpu_before=$(engine_cpu "$needle")
  out=$(taskset -c 3 dnsperf -s 127.0.0.1 -p "$PORT" -d "$Q" -c 20 -q 40 -T 1 -l 6 2>/dev/null)
  cpu_after=$(engine_cpu "$needle")
  q=$(printf '%s\n' "$out" | awk '/Queries per second/{print $4}')
  l=$(printf '%s\n' "$out" | awk '/Average Latency/{print $4}')
  lost=$(printf '%s\n' "$out" | awk 'tolower($0) ~ /queries lost/{print $3}')
  done_n=$(printf '%s\n' "$out" | awk 'tolower($0) ~ /queries completed/{gsub(",", "", $3); print $3}')
  pss2=$(engine_pss_kib "$needle")
  # 해석당 CPU. QPS는 이 호스트에서 레그 드리프트가 5~20%라 몇 %의 마진을 가릴 수
  # 없지만 이 값은 창 열화에 둔감하다. 라운드 안의 비율로만 읽을 것.
  cpu_us=$(awk -v b="$cpu_before" -v a="$cpu_after" -v t="$TICKS" -v n="${done_n:-0}" \
    'BEGIN { if (n <= 0 || t <= 0) { print 0; exit } printf "%.4f", (a - b) * 1000000.0 / (t * n) }')
  if [ -z "$q" ] || [ "${lost:-1}" != 0 ]; then
    printf '%s: WARN 불완전한 측정(qps=%s lost=%s)\n' "$nm" "$q" "$lost"
    rc=1
  else
    printf '%s %s %s\n' "$ENGINE" "$q" "$cpu_us" >>"$RESULTS"
  fi
  printf '%-10s qps=%s avg_latency_s=%s lost=%s procs=%s pss_kib=%s->%s cpu_us_per_query=%s\n' \
    "$nm" "${q:-0}" "${l:-?}" "${lost:-?}" "$procs" "$pss" "$pss2" "$cpu_us"
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  sleep 1
}

onetdns() {
  ENGINE=onetdns
  leg "$1" onetdns-auth.toml taskset -c 2 "$BIN" --config "$W/onetdns-auth.toml" \
    --no-web --no-supervisor
}

ab_onetdns() {
  ENGINE=baseline
  leg "$1" onetdns-auth.toml taskset -c 2 "$AB_BIN" --config "$W/onetdns-auth.toml" \
    --no-web --no-supervisor
}

bind_leg() { ENGINE=bind; leg "$1" named.conf taskset -c 2 named -c "$W/named.conf" -f -g; }
nsd_leg()  { ENGINE=nsd;  leg "$1" nsd.conf   taskset -c 2 nsd -c "$W/nsd.conf" -d; }
knot_leg() { ENGINE=knot; leg "$1" knot.conf  taskset -c 2 knotd -c "$W/knot.conf"; }

# 라운드마다 순서를 뒤집어 순서 편향을 통제하고, **경쟁 엔진에도 레그를 여럿 준다.**
# 한 엔진에 레그가 하나뿐이면 그 값이 창의 어느 지점을 잡았는지 알 수 없어
# 배율을 인용할 수 없다.
round=1
while [ "$round" -le "$ROUNDS" ]; do
  if [ -n "$AB_BIN" ]; then
    if [ $((round % 2)) -eq 1 ]; then
      onetdns "primary$round"; ab_onetdns "baseline$round"
    else
      ab_onetdns "baseline$round"; onetdns "primary$round"
    fi
  elif [ $((round % 2)) -eq 1 ]; then
    onetdns "O${round}a"; bind_leg "bind$round"; nsd_leg "nsd$round"; knot_leg "knot$round"
    onetdns "O${round}b"
  else
    onetdns "O${round}a"; knot_leg "knot$round"; nsd_leg "nsd$round"; bind_leg "bind$round"
    onetdns "O${round}b"
  fi
  round=$((round + 1))
done

# 엔진마다 따로 드리프트를 판정한다. 경합은 해석당 CPU를 **올리므로** 잡음이 끼면
# 경쟁 엔진이 실제보다 나쁘게 보인다 — OnetDNS에 유리한 방향의 오염이라 더더욱
# 전 엔진에 같은 게이트를 걸어야 한다.
awk '
  { n[$1]++; q[$1, n[$1]] = $2 + 0; c[$1, n[$1]] = $3 + 0 }
  END {
    for (engine in n) {
      cnt = n[engine]
      if (cnt < 2) {
        printf "%-9s legs=%d  ← 레그가 부족해 드리프트 판정 불가(AUTHORITY_ROUNDS를 올릴 것)\n", engine, cnt
        continue
      }
      qlo = qhi = q[engine, 1]; qsum = 0
      clo = chi = c[engine, 1]; csum = 0
      for (i = 1; i <= cnt; i++) {
        if (q[engine, i] < qlo) qlo = q[engine, i]
        if (q[engine, i] > qhi) qhi = q[engine, i]
        qsum += q[engine, i]
        if (c[engine, i] < clo) clo = c[engine, i]
        if (c[engine, i] > chi) chi = c[engine, i]
        csum += c[engine, i]
      }
      qdrift = qsum > 0 ? (qhi - qlo) * cnt * 100 / qsum : 100
      cdrift = csum > 0 ? (chi - clo) * cnt * 100 / csum : 100
      printf "%-9s legs=%d qps=%.0f~%.0f drift=%.3f%%%s  cpu_us=%.4f~%.4f cpu_drift=%.3f%%%s\n",
        engine, cnt, qlo, qhi, qdrift, (qdrift > 5.0 ? "(초과)" : ""),
        clo, chi, cdrift, (cdrift > 5.0 ? "(초과)" : "")
    }
  }
' "$RESULTS" | sort

echo "5% 게이트를 넘은 엔진의 절대값·배율은 이 창 밖으로 인용하지 말 것."
echo "artifacts=$W"
exit "$rc"
