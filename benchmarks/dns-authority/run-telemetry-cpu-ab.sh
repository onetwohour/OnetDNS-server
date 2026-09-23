#!/bin/sh
# 기본 텔레메트리의 종단 CPU 비용을 같은 OnetDNS 바이너리 안에서 교대 측정한다.
#
# usage: sh run-telemetry-cpu-ab.sh WORKDIR ONETDNS_BIN [OWNERS=100000]
#   TELEMETRY_ROUNDS=N       교대 라운드 수(기본 12)
#   TELEMETRY_SECONDS=N      dnsperf 레그 길이(기본 6초)
#   TELEMETRY_DNS_PORT=N     DNS 포트(기본 15454)
#   TELEMETRY_CONTROL_PORT=N 컨트롤 플레인 포트(기본 18553)
#
# off는 --no-web, on은 인증된 루프백 컨트롤 플레인과 통계 수집을 켠다. 그 밖의
# 권한 존·worker·CPU affinity·부하는 같다. 판정 축은 프로세스 전체
# utime+stime / 완료 질의이며, QPS와 payload 마이크로벤치는 보조 지표다.
set -eu

if [ "$#" -lt 2 ]; then
  echo "usage: sh run-telemetry-cpu-ab.sh WORKDIR ONETDNS_BIN [OWNERS=100000]" >&2
  exit 2
fi
W=$1
BIN=$2
OWNERS=${3:-100000}
ROUNDS=${TELEMETRY_ROUNDS:-12}
DURATION=${TELEMETRY_SECONDS:-6}
DNS_PORT=${TELEMETRY_DNS_PORT:-15454}
CONTROL_PORT=${TELEMETRY_CONTROL_PORT:-18553}
SERVER_CPU=${TELEMETRY_SERVER_CPU:-2}
CLIENT_CPU=${TELEMETRY_CLIENT_CPU:-3}
TOKEN=onetdns-telemetry-bench-token-0001
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
TICKS=$(getconf CLK_TCK)
RESULTS="$W/telemetry-cpu-legs.txt"
RATIOS="$W/telemetry-cpu-ratios.txt"
PID=""
rc=0

for tool in awk curl dig dnsperf getconf sort taskset; do
  command -v "$tool" >/dev/null 2>&1 || {
    printf '필수 도구가 없습니다: %s\n' "$tool" >&2
    exit 2
  }
done
[ "$ROUNDS" -ge 2 ] 2>/dev/null || { echo "TELEMETRY_ROUNDS는 2 이상이어야 합니다" >&2; exit 2; }
[ "$DURATION" -ge 1 ] 2>/dev/null || { echo "TELEMETRY_SECONDS는 1 이상이어야 합니다" >&2; exit 2; }
[ "$OWNERS" -ge 1 ] 2>/dev/null || { echo "OWNERS는 1 이상이어야 합니다" >&2; exit 2; }
[ -x "$BIN" ] || { printf '실행할 수 없는 바이너리입니다: %s\n' "$BIN" >&2; exit 2; }

mkdir -p "$W"
: >"$RESULTS"
: >"$RATIOS"

cleanup() {
  if [ -n "$PID" ]; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
    PID=""
  fi
}
trap cleanup EXIT
trap 'trap - EXIT; cleanup; exit 130' HUP INT TERM

sh "$SRC/generate-zone.sh" "$W" "$OWNERS" >/dev/null
Q="$W/queries-auth.txt"
PROBE=$(awk 'NR == 1 { print $1; exit }' "$Q")

cat >"$W/onetdns-telemetry-off.toml" <<EOF
mode = "personal"
backend = "forward"
listen = ["127.0.0.1:$DNS_PORT"]
workers = 1
do_udp = true
do_tcp = false
cache_enabled = false
querylog = false
zones = [
  { origin = "bench.test", file = "$W/db.bench.test" },
]
EOF

cat >"$W/onetdns-telemetry-on.toml" <<EOF
mode = "personal"
backend = "forward"
listen = ["127.0.0.1:$DNS_PORT"]
workers = 1
do_udp = true
do_tcp = false
cache_enabled = false
querylog = false
control_listen = "127.0.0.1:$CONTROL_PORT"
control_token = "$TOKEN"
zones = [
  { origin = "bench.test", file = "$W/db.bench.test" },
]
EOF

proc_cpu() {
  stat=$(cat "/proc/$1/stat" 2>/dev/null || echo "")
  [ -n "$stat" ] || { echo 0; return; }
  printf '%s' "${stat##*") "}" | awk '{ print $12 + $13 }'
}

read_metrics() {
  curl -fsS --max-time 2 -H "Authorization: Bearer $TOKEN" \
    "http://127.0.0.1:$CONTROL_PORT/metrics" >"$1"
}

metric_value() {
  awk -v metric="$2" '$1 == metric { print $2; found = 1 } END { if (!found) exit 1 }' "$1"
}

wait_ready() {
  mode=$1
  i=0
  while [ "$i" -lt 60 ]; do
    if kill -0 "$PID" 2>/dev/null; then
      ans=$(dig +short +timeout=1 +tries=1 @127.0.0.1 -p "$DNS_PORT" "$PROBE" A 2>/dev/null | head -1)
      case "$ans" in
        192.0.2.*)
          if [ "$mode" = off ] || read_metrics "$W/readiness.metrics"; then
            return 0
          fi
          ;;
      esac
    fi
    i=$((i + 1))
    sleep 0.25
  done
  return 1
}

stop_server() {
  cleanup
  sleep 0.25
}

leg() {
  mode=$1
  round=$2
  config="$W/onetdns-telemetry-$mode.toml"
  log="$W/$mode-$round.log"
  before="$W/$mode-$round-before.metrics"
  after="$W/$mode-$round-after.metrics"
  perf="$W/$mode-$round.dnsperf.txt"

  if [ "$mode" = off ]; then
    taskset -c "$SERVER_CPU" "$BIN" --config "$config" --no-web --no-supervisor >"$log" 2>&1 &
  else
    taskset -c "$SERVER_CPU" "$BIN" --config "$config" --no-supervisor >"$log" 2>&1 &
  fi
  PID=$!

  if ! wait_ready "$mode"; then
    printf '%s round=%s: 정답 또는 컨트롤 플레인 준비 확인 실패\n' "$mode" "$round" >&2
    sed -n '1,120p' "$log" >&2
    rc=1
    stop_server
    return
  fi

  # 존 페이지와 워커를 같은 조건으로 데운 뒤 기준 계수를 잡는다.
  taskset -c "$CLIENT_CPU" dnsperf -s 127.0.0.1 -p "$DNS_PORT" -d "$Q" \
    -c 20 -q 40 -T 1 -l 1 >/dev/null 2>&1 || true
  sleep 0.05

  query_before=0
  stat_before=0
  log_before=0
  if [ "$mode" = on ]; then
    read_metrics "$before"
    query_before=$(metric_value "$before" onetdns_queries_total)
    stat_before=$(metric_value "$before" onetdns_dropped_stat_events_total)
    log_before=$(metric_value "$before" onetdns_dropped_log_events_total)
  fi

  cpu_before=$(proc_cpu "$PID")
  taskset -c "$CLIENT_CPU" dnsperf -s 127.0.0.1 -p "$DNS_PORT" -d "$Q" \
    -c 20 -q 40 -T 1 -l "$DURATION" >"$perf" 2>&1 || true
  # collector의 최대 idle 주기(20ms)보다 길게 양쪽 모두 기다려 마지막 슬롯 비용도 센다.
  sleep 0.05
  cpu_after=$(proc_cpu "$PID")

  qps=$(awk '/Queries per second/ { print $4 }' "$perf")
  lost=$(awk 'tolower($0) ~ /queries lost/ { gsub(",", "", $3); print $3 }' "$perf")
  completed=$(awk 'tolower($0) ~ /queries completed/ { gsub(",", "", $3); print $3 }' "$perf")
  cpu_us=$(awk -v b="$cpu_before" -v a="$cpu_after" -v t="$TICKS" -v n="${completed:-0}" '
    BEGIN {
      if (n <= 0 || t <= 0 || a < b) { print 0; exit }
      printf "%.4f", (a - b) * 1000000.0 / (t * n)
    }
  ')

  valid=1
  if [ -z "$qps" ] || [ "${lost:-1}" != 0 ] || [ "${completed:-0}" -le 0 ] || [ "$cpu_us" = 0 ]; then
    valid=0
    printf '%s round=%s: 불완전한 결과(qps=%s lost=%s completed=%s cpu=%s)\n' \
      "$mode" "$round" "${qps:-}" "${lost:-}" "${completed:-}" "$cpu_us" >&2
  fi

  query_delta=0
  stat_delta=0
  log_delta=0
  if [ "$mode" = on ]; then
    if read_metrics "$after"; then
      query_after=$(metric_value "$after" onetdns_queries_total)
      stat_after=$(metric_value "$after" onetdns_dropped_stat_events_total)
      log_after=$(metric_value "$after" onetdns_dropped_log_events_total)
      query_delta=$((query_after - query_before))
      stat_delta=$((stat_after - stat_before))
      log_delta=$((log_after - log_before))
      if [ "$query_delta" -ne "${completed:-0}" ] || [ "$stat_delta" -ne 0 ] || [ "$log_delta" -ne 0 ]; then
        valid=0
        printf 'on round=%s: 카운터 불일치(completed=%s query_delta=%s stat_drop=%s log_drop=%s)\n' \
          "$round" "${completed:-0}" "$query_delta" "$stat_delta" "$log_delta" >&2
      fi
    else
      valid=0
      printf 'on round=%s: 측정 뒤 metrics 조회 실패\n' "$round" >&2
    fi
  fi

  if grep -E 'stats\.slot_full|querylog\.queue_full|panic' "$log" >/dev/null 2>&1; then
    valid=0
    printf '%s round=%s: 서버 로그에 drop 또는 panic이 있습니다\n' "$mode" "$round" >&2
  fi

  if [ "$valid" = 1 ]; then
    printf '%s %s %s %s %s %s %s\n' \
      "$mode" "$round" "$qps" "$cpu_us" "$completed" "$query_delta" "$stat_delta" >>"$RESULTS"
  else
    rc=1
  fi
  printf '%-3s round=%02d qps=%s cpu_us_per_query=%s completed=%s query_delta=%s stat_drop=%s\n' \
    "$mode" "$round" "${qps:-0}" "$cpu_us" "${completed:-0}" "$query_delta" "$stat_delta"
  stop_server
}

round=1
while [ "$round" -le "$ROUNDS" ]; do
  if [ $((round % 2)) -eq 1 ]; then
    leg off "$round"
    leg on "$round"
  else
    leg on "$round"
    leg off "$round"
  fi
  round=$((round + 1))
done

awk '
  $1 == "off" { off[$2] = $4 + 0 }
  $1 == "on"  { on[$2] = $4 + 0 }
  END {
    for (round in off)
      if (round in on && off[round] > 0)
        printf "%s %.6f\n", round, on[round] / off[round]
  }
' "$RESULTS" | sort -k2,2n >"$RATIOS"

awk -v expected="$ROUNDS" '
  {
    mode = $1
    n[mode]++
    value = $4 + 0
    if (n[mode] == 1 || value < lo[mode]) lo[mode] = value
    if (n[mode] == 1 || value > hi[mode]) hi[mode] = value
    sum[mode] += value
  }
  END {
    for (mode in n) {
      mean = sum[mode] / n[mode]
      drift = mean > 0 ? (hi[mode] - lo[mode]) * 100 / mean : 100
      printf "%-3s legs=%d cpu_us=%.4f~%.4f mean=%.4f drift=%.3f%%%s\n",
        mode, n[mode], lo[mode], hi[mode], mean, drift,
        (n[mode] != expected || drift > 5.0 ? "(무효)" : "")
    }
  }
' "$RESULTS" | sort

awk -v expected="$ROUNDS" '
  { n++; value[n] = $2 + 0; sum += $2 }
  END {
    if (!n) { print "paired ratios: 없음"; exit }
    median = n % 2 ? value[(n + 1) / 2] : (value[n / 2] + value[n / 2 + 1]) / 2
    printf "paired on/off cpu ratio: rounds=%d median=%.4f mean=%.4f overhead_median=%.2f%%%s\n",
      n, median, sum / n, (median - 1) * 100, (n != expected ? "(무효)" : "")
  }
' "$RATIOS"

if [ "$(wc -l <"$RESULTS")" -ne $((ROUNDS * 2)) ]; then
  printf '유효한 레그가 부족합니다: %s/%s\n' "$(wc -l <"$RESULTS")" $((ROUNDS * 2)) >&2
  rc=1
fi

for mode in off on; do
  drift=$(awk -v wanted="$mode" '
    $1 == wanted {
      n++
      value = $4 + 0
      if (n == 1 || value < lo) lo = value
      if (n == 1 || value > hi) hi = value
      sum += value
    }
    END {
      mean = n ? sum / n : 0
      drift = mean > 0 ? (hi - lo) * 100 / mean : 100
      printf "%.6f", drift
    }
  ' "$RESULTS")
  if ! awk -v drift="$drift" 'BEGIN { exit !(drift <= 5.0) }'; then
    printf '%s CPU 드리프트 %s%%가 5%% 게이트를 넘었습니다\n' "$mode" "$drift" >&2
    rc=1
  fi
done

echo "5% 드리프트·완료 질의 일치·유실 0·stat/log drop 0을 모두 통과한 실행만 인용할 것."
echo "artifacts=$W"
exit "$rc"
