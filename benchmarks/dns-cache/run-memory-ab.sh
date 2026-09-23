#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: run-memory-ab.sh BASELINE_BIN CANDIDATE_BIN" >&2
    exit 2
fi

baseline=$1
candidate=$2
bench_dir=${BENCH_DIR:-/home/ubuntu/onetdns-bench}
target_config=${TARGET_CONFIG:-$bench_dir/onetdns-cache.toml}
auth_cpu=${AUTH_CPU:-0}
load_cpu=${LOAD_CPU:-1}
target_cpu=${TARGET_CPU:-2}
hot_seconds=${HOT_SECONDS:-5}
authority_log=$(mktemp)
target_log=
authority_pid=
target_pid=

cleanup() {
    if [ -n "$target_pid" ] && kill -0 "$target_pid" 2>/dev/null; then
        kill "$target_pid"
        wait "$target_pid" 2>/dev/null || true
    fi
    if [ -n "$authority_pid" ] && kill -0 "$authority_pid" 2>/dev/null; then
        kill "$authority_pid"
        wait "$authority_pid" 2>/dev/null || true
    fi
    [ -z "$target_log" ] || rm -f "$target_log"
    rm -f "$authority_log"
    [ -z "${authority_bin:-}" ] || rm -f "$authority_bin"
}
trap cleanup EXIT HUP INT TERM

wait_port() {
    pid=$1
    port=$2
    attempt=0
    while [ "$attempt" -lt 100 ]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "process $pid exited before UDP/$port became ready" >&2
            return 1
        fi
        if ss -H -lun | awk '{print $4}' | grep -Eq ":${port}$"; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 0.05
    done
    echo "UDP/$port did not become ready" >&2
    return 1
}

snapshot() {
    label=$1
    round=$2
    phase=$3
    pid=$4
    rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status")
    anon=$(awk '/^RssAnon:/ {print $2}' "/proc/$pid/status")
    file=$(awk '/^RssFile:/ {print $2}' "/proc/$pid/status")
    data=$(awk '/^VmData:/ {print $2}' "/proc/$pid/status")
    private=$(awk '/^Private_Clean:|^Private_Dirty:/ {sum += $2} END {print sum + 0}' "/proc/$pid/smaps_rollup")
    pss=$(awk '/^Pss:/ {print $2}' "/proc/$pid/smaps_rollup")
    printf 'MEM\t%s\t%s\t%s\trss_kib=%s\tanon_kib=%s\tfile_kib=%s\tdata_kib=%s\tprivate_kib=%s\tpss_kib=%s\n' \
        "$label" "$round" "$phase" "$rss" "$anon" "$file" "$data" "$private" "$pss"
}

run_one() {
    label=$1
    round=$2
    binary=$3
    target_log=$(mktemp)
    taskset -c "$target_cpu" "$binary" \
        --config "$target_config" --no-web --no-supervisor \
        >"$target_log" 2>&1 &
    target_pid=$!
    if ! wait_port "$target_pid" 15353; then
        tail -n 40 "$target_log" >&2
        return 1
    fi
    sleep 0.5
    snapshot "$label" "$round" startup "$target_pid"

    warm=$(taskset -c "$load_cpu" dnsperf -s 127.0.0.1 -p 15353 \
        -d "$bench_dir/queries.txt" -q 100 -c 1 -T 1 -t 2 -n 1 2>&1)
    sent=$(printf '%s\n' "$warm" | awk '/Queries sent:/ {print $3}')
    lost=$(printf '%s\n' "$warm" | awk '/Queries lost:/ {print $3}')
    warm_qps=$(printf '%s\n' "$warm" | awk '/Queries per second:/ {print $4}')
    if [ "$sent" != 10000 ] || [ "$lost" != 0 ]; then
        printf '%s\n' "$warm" >&2
        return 1
    fi
    printf 'WARM\t%s\t%s\tqps=%s\tlost=%s\n' "$label" "$round" "$warm_qps" "$lost"
    sleep 0.5
    snapshot "$label" "$round" warm10k "$target_pid"

    hot=$(taskset -c "$load_cpu" dnsperf -s 127.0.0.1 -p 15353 \
        -d "$bench_dir/queries.txt" -q 100 -c 1 -T 1 -t 2 -l "$hot_seconds" 2>&1)
    qps=$(printf '%s\n' "$hot" | awk '/Queries per second:/ {print $4}')
    lost=$(printf '%s\n' "$hot" | awk '/Queries lost:/ {print $3}')
    printf 'HOT\t%s\t%s\tqps=%s\tlost=%s\n' "$label" "$round" "$qps" "$lost"
    snapshot "$label" "$round" posthot "$target_pid"

    kill "$target_pid"
    wait "$target_pid" 2>/dev/null || true
    target_pid=
    rm -f "$target_log"
    target_log=
    sleep 0.3
}

# 권한 서버를 두 후보 중 하나로 시작하면 그 쪽만 텍스트 페이지를 공유해 Pss가 낮게 나온다.
# 같은 파일을 매핑한 프로세스끼리 Pss를 나눠 갖기 때문이다. 실측에서 그 차이가 2.2 MiB로
# 재려는 차이보다 컸다. 별도 사본으로 시작해 어느 쪽도 공유하지 않게 한다.
authority_bin=$(mktemp)
cp "$candidate" "$authority_bin"
chmod +x "$authority_bin"
taskset -c "$auth_cpu" "$authority_bin" \
    --config "$bench_dir/onetdns-authority.toml" --no-web --no-supervisor \
    >"$authority_log" 2>&1 &
authority_pid=$!
if ! wait_port "$authority_pid" 15400; then
    tail -n 40 "$authority_log" >&2
    exit 1
fi

run_one baseline 1 "$baseline"
run_one candidate 1 "$candidate"
run_one candidate 2 "$candidate"
run_one baseline 2 "$baseline"
run_one baseline 3 "$baseline"
run_one candidate 3 "$candidate"
