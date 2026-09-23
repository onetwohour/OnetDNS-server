#!/bin/sh
# 콜드-미스 반복 해석 지연. 질의 파일 1회 통과(-n 1)로 응답 캐시 미스와
# 질의마다 새로운 최종 leaf 위임 조회를 강제한다.
# usage: unshare -rn sh -c 'ip link set lo up; sh run-miss-latency.sh BENCHDIR BIN MODE WORKERS CLIENTS ROUNDS'
# MODE=qm이면 경쟁 엔진도 QNAME 최소화 ON(OnetDNS는 상시 활성이라 동조건).
set -eu
H_ARG=${1:?benchdir}
BIN=${2:?onetdns binary}
MODE=${3:-off}
WORKERS=${4:-1}
CLIENTS=${5:-1}
ROUNDS=${6:-3}
case "$MODE" in
  off|qm) ;;
  *) echo "mode must be 'off' or 'qm'" >&2; exit 2 ;;
esac
if ! [ "$WORKERS" -ge 0 ] 2>/dev/null; then
  echo "WORKERS must be a non-negative integer (0=automatic)" >&2
  exit 2
fi
for value in "$CLIENTS" "$ROUNDS"; do
  if ! [ "$value" -ge 1 ] 2>/dev/null; then
    echo "CLIENTS and ROUNDS must be positive integers" >&2
    exit 2
  fi
done
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
H=$(CDPATH= cd -- "$H_ARG" && pwd -P)
case "$BIN" in
  /*) ;;
  *) echo "onetdns binary must be an absolute path" >&2; exit 2 ;;
esac
WORK="$H/run-miss-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir "$WORK"
PDNS_SOCKET_DIR=$(mktemp -d /tmp/onetdns-pdns-socket-XXXXXX)
QUERIES="$H/queries-recurse.txt"
if ! awk '
  NF < 2 { print "malformed query line " NR > "/dev/stderr"; bad=1; next }
  {
    parent=$1
    sub(/\.$/, "", parent)
    sub(/^[^.]+\./, "", parent)
    if (++seen[parent] > 1 && !duplicate) {
      print "cold-miss dataset reuses delegated zone " parent > "/dev/stderr"
      duplicate=1
    }
  }
  END {
    if (NR == 0) print "query file is empty" > "/dev/stderr"
    exit bad || duplicate || NR == 0
  }
' "$QUERIES"; then
  echo "regenerate with: generate-delegation.sh OUTDIR ZONES 1" >&2
  exit 2
fi
cat >"$WORK/root.hints" <<EOF
.                        3600000      NS    ns.root.
ns.root.                 3600000      A     127.0.1.1
EOF
sed "s|ROOTHINTS|$WORK/root.hints|g" "$SRC/pdns-recursor.conf" >"$WORK/recursor.conf"
sed -e "s|ROOTHINTS|$WORK/root.hints|g" -e "s|BENCHDIR|$WORK|g" "$SRC/named-recurse.conf" >"$WORK/named-recurse.conf"
sed "s|ROOTHINTS|$WORK/root.hints|g" "$SRC/unbound-recurse.conf" >"$WORK/unbound-recurse.conf"
# 캐시 용량은 **경쟁 엔진과 대칭이어야 한다.** Unbound는 msg 64m + rrset 64m,
# PDNS-R은 1,000,000 항목, BIND는 128m으로 이 workload의 고유 이름을 전부 담는데
# `onetdns-recurse.toml`은 hot-cache 벤치와 공유하느라 20,000 항목이다. 그대로 두면
# OnetDNS만 계속 퇴거하며 실행되는 셈이고, RSS 비가 엔진 특성이 아니라 설정 차이가 된다
# (15만 질의 실측: 20,000 항목 19,368 KiB 대 400,000 항목 48,820 KiB).
CACHE_SIZE=${MISS_CACHE_SIZE:-$(awk 'END { print int(NR * 1.2) + 1000 }' "$QUERIES")}
sed -e "s/^workers = .*/workers = $WORKERS/" \
    -e "s/^cache_size = .*/cache_size = $CACHE_SIZE/" \
    "$SRC/onetdns-recurse.toml" >"$WORK/onetdns-recurse.toml"
# A/B 실험용: 추가 설정 줄을 환경으로 주입한다.
if [ -n "${ONETDNS_EXTRA_CONF:-}" ]; then
  printf '%s\n' "$ONETDNS_EXTRA_CONF" >>"$WORK/onetdns-recurse.toml"
fi
if [ "$MODE" = "qm" ]; then
  sed -i "s|qname-minimisation: no|qname-minimisation: yes|" "$WORK/unbound-recurse.conf"
  sed -i "s|qname-minimization=no|qname-minimization=yes|" "$WORK/recursor.conf"
  sed -i "s|qname-minimization off|qname-minimization relaxed|" "$WORK/named-recurse.conf"
fi

RESOLVER_PID=
ROOT_PID=
TLD_PID=
LEAF_PID=
cleanup() {
  for pid in ${RESOLVER_PID:-} ${ROOT_PID:-} ${TLD_PID:-} ${LEAF_PID:-}; do
    kill "$pid" 2>/dev/null || true
  done
  for pid in ${RESOLVER_PID:-} ${ROOT_PID:-} ${TLD_PID:-} ${LEAF_PID:-}; do
    wait "$pid" 2>/dev/null || true
  done
  rm -f "$PDNS_SOCKET_DIR"/*
  rmdir "$PDNS_SOCKET_DIR" 2>/dev/null || true
}
abort() {
  trap - EXIT
  cleanup
  exit 130
}
trap cleanup EXIT
trap abort HUP INT TERM

cd "$H"
taskset -c 0 "$BIN" --config "$H/authority-root.toml" --no-web --no-supervisor >"$WORK/ar.log" 2>&1 &
ROOT_PID=$!
taskset -c 0 "$BIN" --config "$H/authority-tld.toml" --no-web --no-supervisor >"$WORK/at.log" 2>&1 &
TLD_PID=$!
taskset -c 0 "$BIN" --config "$H/authority-leaf.toml" --no-web --no-supervisor >"$WORK/al.log" 2>&1 &
LEAF_PID=$!
sleep 1
for pid in "$ROOT_PID" "$TLD_PID" "$LEAF_PID"; do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "authority process failed during startup; inspect $WORK/*.log" >&2
    exit 1
  fi
done
wait_authority() { # address name type [expected]
  addr=$1 name=$2 type=$3 expected=${4:-}
  tries=0
  while [ "$tries" -lt 120 ]; do
    answer=$(dig +time=1 +tries=1 +short @"$addr" -p 53 "$name" "$type" 2>/dev/null || true)
    if [ -n "$answer" ] && { [ -z "$expected" ] || [ "$answer" = "$expected" ]; }; then
      return 0
    fi
    tries=$((tries+1))
    sleep 1
  done
  echo "authority readiness timed out: @$addr $name $type; inspect $WORK/*.log" >&2
  return 1
}
if ! PREFLIGHT_NAME=$(awk 'NR == 1 { if (toupper($2) != "A") exit 1; print $1 }' "$QUERIES") || \
    [ -z "$PREFLIGHT_NAME" ]; then
  echo "first query must be an A query" >&2
  exit 2
fi
PREFLIGHT_FQDN=${PREFLIGHT_NAME%.}.
wait_authority 127.0.1.1 . SOA
wait_authority 127.0.2.1 test. SOA
wait_authority 127.0.3.1 "$PREFLIGHT_FQDN" A 192.0.2.1

QUERY_COUNT=$(wc -l <"$QUERIES")
CLK_TCK=$(getconf CLK_TCK)
: >"$WORK/results.txt"
: >"$WORK/retries.txt"

process_snapshot() {
  awk '
    /^VmRSS:/ { rss=$2 }
    /^Threads:/ { threads=$2 }
    END {
      if (rss == "" || threads == "") exit 1
      printf "%s %s", rss, threads
    }
  ' "/proc/$1/status"
}

# /proc/PID/stat의 utime+stime. 프로세스 이름에는 공백과 괄호가 들어갈 수 있으므로
# (NSD가 실제로 "nsd: main" 꼴이다) 마지막 ") "까지 잘라낸 뒤에 곳을 센다. 자르지
# 않으면 comm에 공백이 있는 엔진에서 엉뚱한 필드를 CPU로 읽는다.
process_ticks() {
  stat=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
  [ -n "$stat" ] || return 1
  printf '%s' "${stat##*") "}" | awk '{ print $12 + $13 }'
}

authority_ticks() {
  root_ticks=$(process_ticks "$ROOT_PID") || return 1
  tld_ticks=$(process_ticks "$TLD_PID") || return 1
  leaf_ticks=$(process_ticks "$LEAF_PID") || return 1
  echo $((root_ticks+tld_ticks+leaf_ticks))
}

stop_resolver() {
  if [ -n "${RESOLVER_PID:-}" ]; then
    kill "$RESOLVER_PID" 2>/dev/null || true
    wait "$RESOLVER_PID" 2>/dev/null || true
    RESOLVER_PID=
  fi
}

missrun() {
  nm=$1 round=$2; shift 2
  RETRYABLE=0
  tag="$nm-r$round-a${ATTEMPT:-1}"
  # 먼저 실제 정답을 확인한다. 이 질의가 재귀 캐시를 데우므로 검증 프로세스는
  # 반드시 종료하고, 측정은 새 프로세스로 시작한다.
  "$@" >"$WORK/$tag-preflight.log" 2>&1 &
  RESOLVER_PID=$!
  sleep 3
  if ! kill -0 "$RESOLVER_PID" 2>/dev/null; then
    echo "$tag resolver failed during preflight startup; inspect $WORK/$tag-preflight.log" >&2
    return 1
  fi
  response=$(dig +time=2 +tries=1 @127.0.0.1 -p 5300 "$PREFLIGHT_FQDN" A 2>/dev/null || true)
  answer=$(printf '%s\n' "$response" | awk -v name="$PREFLIGHT_FQDN" \
    'tolower($1)==tolower(name) && $4=="A" {print $5; exit}')
  if [ "$answer" != "192.0.2.1" ] || ! printf '%s\n' "$response" | grep -q 'status: NOERROR'; then
    echo "$tag resolver returned an invalid preflight answer; inspect $WORK/$tag-preflight.log" >&2
    return 1
  fi
  stop_resolver

  "$@" >"$WORK/$tag.log" 2>&1 &
  RESOLVER_PID=$!
  sleep 3
  if ! kill -0 "$RESOLVER_PID" 2>/dev/null; then
    echo "$tag resolver failed during measured startup; inspect $WORK/$tag.log" >&2
    return 1
  fi
  if ! resource_start=$(process_snapshot "$RESOLVER_PID"); then
    echo "$tag cannot read resolver resource usage" >&2
    return 1
  fi
  if ! auth_ticks_start=$(authority_ticks); then
    echo "$tag cannot read authority CPU usage" >&2
    return 1
  fi
  if ! resolver_ticks_start=$(process_ticks "$RESOLVER_PID"); then
    echo "$tag cannot read resolver CPU usage" >&2
    return 1
  fi
  if ! out=$(taskset -c 1 dnsperf -s 127.0.0.1 -p 5300 -d "$QUERIES" -n 1 -q 20 -c "$CLIENTS" -T 1 2>/dev/null); then
    echo "$tag dnsperf failed" >&2
    return 1
  fi
  if ! resolver_ticks_end=$(process_ticks "$RESOLVER_PID"); then
    echo "$tag cannot read resolver CPU usage after load" >&2
    return 1
  fi
  if ! auth_ticks_end=$(authority_ticks); then
    echo "$tag cannot read authority CPU usage after load" >&2
    return 1
  fi
  if ! resource_end=$(process_snapshot "$RESOLVER_PID"); then
    echo "$tag resolver exited before resource sampling" >&2
    return 1
  fi
  printf '%s\n' "$out" >"$WORK/$tag.dnsperf.txt"
  if ! line=$(printf '%s\n' "$out" | awk '
      /Queries per second/ { q=$4 }
      /Average Latency \(s\)/ { l=$4 }
      /Run time \(s\)/ { runtime=$4 }
      tolower($0) ~ /queries completed/ { completed=$3 }
      tolower($0) ~ /queries lost/ { lost=$3 }
      /Response codes:/ {
        for (i=3; i<NF; i++) if ($i == "NOERROR") noerror=$(i+1)
      }
      END {
        if (q == "" || l == "" || runtime == "" || completed == "" || lost == "" || noerror == "") exit 1
        printf "%s %.4f %s %s %s %s", q, l*1000, completed, lost, noerror, runtime
      }'); then
    echo "$tag dnsperf result is incomplete" >&2
    return 1
  fi
  q=${line%% *}
  rest=${line#* }
  latency=${rest%% *}
  rest=${rest#* }
  completed=${rest%% *}
  rest=${rest#* }
  lost=${rest%% *}
  rest=${rest#* }
  noerror=${rest%% *}
  runtime=${rest#* }
  if [ "$completed" != "$QUERY_COUNT" ] || [ "$lost" != "0" ] || \
      [ "$noerror" != "$QUERY_COUNT" ]; then
    echo "$tag invalid completion: completed=$completed/$QUERY_COUNT lost=$lost NOERROR=$noerror/$QUERY_COUNT" >&2
    return 1
  fi
  if ! awk -v q="$q" -v latency="$latency" \
      'BEGIN { exit !(q > 0 && latency >= 0 && latency < 60000) }'; then
    echo "$tag invalid timing: qps=$q avg_latency_ms=$latency" >&2
    RETRYABLE=1
    return 1
  fi
  rss_start=${resource_start%% *}
  threads_start=${resource_start#* }
  rss_end=${resource_end%% *}
  threads_end=${resource_end#* }
  rss_kib=$rss_start
  [ "$rss_end" -gt "$rss_kib" ] && rss_kib=$rss_end
  threads=$threads_start
  [ "$threads_end" -gt "$threads" ] && threads=$threads_end
  auth_ticks_delta=$((auth_ticks_end-auth_ticks_start))
  auth_cpu_pct=$(awk -v ticks="$auth_ticks_delta" -v hz="$CLK_TCK" -v runtime="$runtime" \
    'BEGIN { if (runtime <= 0 || hz <= 0) exit 1; printf "%.1f", ticks*100/(hz*runtime) }')
  if ! awk -v cpu="$auth_cpu_pct" 'BEGIN { exit !(cpu < 80) }'; then
    echo "$tag authority CPU is saturated: $auth_cpu_pct%" >&2
    return 1
  fi
  # 해석당 CPU. QPS는 이 하네스에서 드리프트가 커 경쟁 엔진이 게이트를 자주 넘지만,
  # 이 값은 창 열화에 훨씬 둔감해 같은 라운드 안의 비교를 가능하게 한다.
  resolver_ticks_delta=$((resolver_ticks_end-resolver_ticks_start))
  cpu_us_per_resolution=$(awk -v ticks="$resolver_ticks_delta" -v hz="$CLK_TCK" \
    -v done_count="$completed" \
    'BEGIN { if (hz <= 0 || done_count <= 0) exit 1; printf "%.4f", ticks*1000000/(hz*done_count) }')
  printf '%s[%s]: answer=%s qps=%s avg_latency_ms=%s completed=%s lost=%s noerror=%s rss_kib=%s threads=%s auth_cpu_pct=%s cpu_us_per_resolution=%s\n' \
    "$nm" "$round" "$answer" "$q" "$latency" "$completed" "$lost" "$noerror" "$rss_kib" "$threads" "$auth_cpu_pct" "$cpu_us_per_resolution"
  printf '%s %s %s %s %s %s %s %s\n' \
    "$nm" "$round" "$q" "$latency" "$rss_kib" "$threads" "$auth_cpu_pct" \
    "$cpu_us_per_resolution" >>"$WORK/results.txt"
  stop_resolver
  sleep 1
}

run_with_timing_retry() {
  retry_nm=$1 retry_round=$2; shift 2
  ATTEMPT=1
  while ! missrun "$retry_nm" "$retry_round" "$@"; do
    stop_resolver
    if [ "$RETRYABLE" != "1" ] || [ "$ATTEMPT" -ge 3 ]; then
      return 1
    fi
    printf '%s %s %s timing\n' "$retry_nm" "$retry_round" "$ATTEMPT" >>"$WORK/retries.txt"
    ATTEMPT=$((ATTEMPT+1))
    echo "$retry_nm[$retry_round]: retrying timing anomaly (attempt $ATTEMPT/3)" >&2
    sleep 1
  done
}

# 엔진 하나가 회차를 망쳐도 나머지 엔진은 계속 측정한다. 예전에는 실패가 스크립트를 전부
# 끝내서, 이미 깨끗하게 끝난 다른 엔진의 자료까지 함께 버려졌다 — 4엔진 15만 질의 실행이
# 10분 넘게 걸리므로 그 비용이 크다. 실패한 엔진은 기록해 두었다가 요약에서 무효로 찍고
# 종료 코드로 알린다.
attempt_engine() { # name round cmd...
  if run_with_timing_retry "$@"; then
    return 0
  fi
  printf '%s\n' "$1" >>"$WORK/failed.txt"
  echo "$1[$2]: 이 회차는 무효다 — 나머지 엔진은 계속 측정한다" >&2
  stop_resolver
  return 0
}

: >"$WORK/failed.txt"
round=1
while [ "$round" -le "$ROUNDS" ]; do
  if [ $((round % 2)) -eq 1 ]; then
    attempt_engine OnetDNS "$round" taskset -c 2 "$BIN" --config "$WORK/onetdns-recurse.toml" --no-web --no-supervisor
    attempt_engine Unbound  "$round" taskset -c 2 unbound -d -c "$WORK/unbound-recurse.conf"
    attempt_engine PDNS-R   "$round" taskset -c 2 pdns_recursor --config-dir="$WORK" --socket-dir="$PDNS_SOCKET_DIR"
    attempt_engine BIND9    "$round" taskset -c 2 named -g -c "$WORK/named-recurse.conf"
  else
    attempt_engine BIND9    "$round" taskset -c 2 named -g -c "$WORK/named-recurse.conf"
    attempt_engine PDNS-R   "$round" taskset -c 2 pdns_recursor --config-dir="$WORK" --socket-dir="$PDNS_SOCKET_DIR"
    attempt_engine Unbound  "$round" taskset -c 2 unbound -d -c "$WORK/unbound-recurse.conf"
    attempt_engine OnetDNS "$round" taskset -c 2 "$BIN" --config "$WORK/onetdns-recurse.toml" --no-web --no-supervisor
  fi
  round=$((round+1))
done

rc=0
for engine in OnetDNS Unbound PDNS-R BIND9; do
  # 유효 회차가 하나도 없는 엔진이 있을 수 있다(전 회차 무효). awk가 실패로 끝나므로
  # 대입에서 set -e에 걸리지 않게 받아 낸다.
  summary=$(awk -v engine="$engine" '
    $1 == engine {
      value[++n]=$3
      rss[n]=$5
      cpu[n]=$8
      if ($6 > max_threads) max_threads=$6
      if ($7 > max_auth_cpu) max_auth_cpu=$7
    }
    END {
      if (n == 0) exit 1
      for (i=1; i<=n; i++) for (j=i+1; j<=n; j++) if (value[j] < value[i]) {
        t=value[i]; value[i]=value[j]; value[j]=t
      }
      for (i=1; i<=n; i++) for (j=i+1; j<=n; j++) if (rss[j] < rss[i]) {
        t=rss[i]; rss[i]=rss[j]; rss[j]=t
      }
      for (i=1; i<=n; i++) for (j=i+1; j<=n; j++) if (cpu[j] < cpu[i]) {
        t=cpu[i]; cpu[i]=cpu[j]; cpu[j]=t
      }
      median = n % 2 ? value[(n+1)/2] : (value[n/2]+value[n/2+1])/2
      median_rss = n % 2 ? rss[(n+1)/2] : (rss[n/2]+rss[n/2+1])/2
      median_cpu = n % 2 ? cpu[(n+1)/2] : (cpu[n/2]+cpu[n/2+1])/2
      drift = median > 0 ? (value[n]-value[1])*100/median : 100
      cpu_drift = median_cpu > 0 ? (cpu[n]-cpu[1])*100/median_cpu : 100
      printf "median_qps=%.3f min_qps=%.3f max_qps=%.3f drift_pct=%.3f median_rss_kib=%.0f max_threads=%.0f max_auth_cpu_pct=%.1f median_cpu_us=%.4f cpu_drift_pct=%.3f", \
        median, value[1], value[n], drift, median_rss, max_threads, max_auth_cpu, median_cpu, cpu_drift
    }
  ' "$WORK/results.txt") || summary=""
  retries=$(awk -v engine="$engine" '$1 == engine { n++ } END { print n+0 }' "$WORK/retries.txt")
  failed=$(awk -v engine="$engine" '$1 == engine { n++ } END { print n+0 }' "$WORK/failed.txt")
  if [ -z "$summary" ]; then
    echo "$engine summary: 유효 회차 없음 invalid_rounds=$failed"
    rc=1
    continue
  fi
  echo "$engine summary: $summary timing_retries=$retries invalid_rounds=$failed"
  if [ "$failed" != 0 ]; then
    echo "$engine: WARN 무효 회차가 $failed 개다 — 이 엔진의 수치는 쓰지 마라" >&2
    rc=1
  fi
  drift=$(printf '%s\n' "$summary" | awk -F'drift_pct=' '{ split($2, field, " "); print field[1] }')
  if ! awk -v drift="$drift" 'BEGIN { exit !(drift <= 5.0) }'; then
    echo "$engine: WARN round drift exceeds 5%; measurement is invalid" >&2
    rc=1
  fi
done
echo "artifacts=$WORK"
echo done
exit "$rc"
