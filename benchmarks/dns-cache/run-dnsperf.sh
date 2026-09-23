#!/bin/sh
set -eu

port=${1:?"usage: run-dnsperf.sh PORT [QUERY_FILE] [SECONDS] [RUNS]"}
queries=${2:-/home/ubuntu/onetdns-bench/queries.txt}
seconds=${3:-10}
runs=${4:-5}
server=${DNSPERF_SERVER:-127.0.0.1}
# 부하 생성기를 묶을 CPU. taskset 목록 문법을 그대로 받는다("1" 또는 "1,3,5,7").
cpu=${DNSPERF_CPU:-1}
# 부하 생성기 용량. **기본값은 종전 그대로다** — 공표된 수치와 비교 가능해야 한다.
#
# 단일 소켓·단일 스레드는 이 호스트에서 약 54만 QPS가 천장이라, 그보다 빠른 서버를
# 측정하면 서버가 아니라 생성기를 재게 된다. 서버의 진짜 천장을 보려면 세 값을 올리고
# DNSPERF_CPU에 코어를 더 줘서 **QPS가 더 이상 오르지 않을 때까지** 확인해야 한다.
clients=${DNSPERF_CLIENTS:-1}
threads=${DNSPERF_THREADS:-1}
outstanding=${DNSPERF_OUTSTANDING:-100}
# 질의에 OPT를 붙일지. dnsperf 기본은 평문이지만 실제로 이 서버에 오는 질의 —
# dig·systemd-resolved·브라우저·상위 재귀 리졸버 — 은 거의 전부 EDNS를 붙인다.
# 평문만 측정하면 EDNS 경로에만 있는 결함이 수치에 나타나지 않는다.
edns=""
if [ "${DNSPERF_EDNS:-0}" = "1" ]; then
  edns="-e"
fi

results=$(mktemp)
sorted="${results}.sorted"
trap 'rm -f "$results" "$sorted"' EXIT HUP INT TERM

# 측정 전 정답 확인. 해석·차단에 실패해도 dnsperf는 QPS를 보고하고 오히려 SERVFAIL이
# 더 빠르므로, 이 확인이 없으면 무효 수치가 조용히 나온다. 기대값은 workload마다
# 다르니 환경으로 받는다 — 차단 workload는 EXPECT_RCODE=NXDOMAIN EXPECT_ANSWER=0.
expect_rcode=${EXPECT_RCODE:-NOERROR}
expect_answer=${EXPECT_ANSWER:-1}
probe_name=$(awk 'NR==1{print $1}' "$queries")
probe_type=$(awk 'NR==1{print ($2 == "" ? "A" : $2)}' "$queries")
probe_edns="+noedns"
if [ "${DNSPERF_EDNS:-0}" = "1" ]; then
  probe_edns="+edns=0"
fi
probe=$(dig $probe_edns +time=3 +tries=1 "@$server" -p "$port" "$probe_name" "$probe_type" 2>/dev/null || true)
if ! printf '%s\n' "$probe" | grep -q "status: $expect_rcode"; then
    printf '정답 확인 실패: %s %s 가 %s가 아니다 — 이 엔진의 수치는 무효다\n' \
        "$probe_name" "$probe_type" "$expect_rcode" >&2
    exit 1
fi
if [ "$expect_answer" = 1 ] && ! printf '%s\n' "$probe" | grep -q '^;; ANSWER SECTION'; then
    printf '정답 확인 실패: %s 에 답 레코드가 없다 — 이 엔진의 수치는 무효다\n' \
        "$probe_name" >&2
    exit 1
fi

taskset -c "$cpu" dnsperf $edns \
    -s "$server" -p "$port" -d "$queries" \
    -q "$outstanding" -c "$clients" -T "$threads" -l 2 \
    >/dev/null

i=1
while [ "$i" -le "$runs" ]; do
    output=$(taskset -c "$cpu" dnsperf $edns \
        -s "$server" -p "$port" -d "$queries" \
        -q "$outstanding" -c "$clients" -T "$threads" -l "$seconds")
    printf '%s\n' "$output"
    printf '%s\n' "$output" | awk '
        /Queries per second:/ { qps = $4 }
        /Average Latency \(s\):/ { latency = $4 }
        /Queries lost:/ { lost = $3 }
        END {
            if (qps == "" || latency == "") exit 1
            printf "%.6f %.9f %d\n", qps, latency, (lost == "" ? 0 : lost)
        }
    ' >>"$results"
    i=$((i + 1))
done

sort -n -k1,1 "$results" >"$sorted"
median_qps=$(awk '
    { value[NR] = $1 }
    END {
        if (NR % 2) print value[(NR + 1) / 2]
        else print (value[NR / 2] + value[NR / 2 + 1]) / 2
    }
' "$sorted")
sort -n -k2,2 "$results" >"$sorted"
median_latency_ms=$(awk '
    { value[NR] = $2 * 1000 }
    END {
        if (NR % 2) print value[(NR + 1) / 2]
        else print (value[NR / 2] + value[NR / 2 + 1]) / 2
    }
' "$sorted")

max_lost=$(awk '{ if ($3 > m) m = $3 } END { print m + 0 }' "$results")

printf 'median_qps=%s median_latency_ms=%s max_lost=%s\n' \
    "$median_qps" "$median_latency_ms" "$max_lost"
if [ "$max_lost" -gt 0 ]; then
    printf '유실이 있는 회차가 있다(최대 %s) — 처리량 비교에 쓰기 전에 원인을 확인하라\n' \
        "$max_lost" >&2
fi
