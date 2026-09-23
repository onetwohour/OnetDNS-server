#!/bin/sh
# 콜드-미스 workload 중 리졸버의 사용자공간 CPU 프로파일(perf, 자기 프로세스라
# paranoid=2에서 동작). 디버그 심볼 포함 빌드를 쓸 것.
# usage: unshare -rn sh -c 'ip link set lo up; sh run-profile.sh BENCHDIR BIN OUTDIR'
set -eu
H=${1:?benchdir}
BIN=${2:?debug-symbol binary}
OUT=${3:?perf output dir}
WORK="$H/run"
mkdir -p "$WORK" "$OUT"
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
cp "$SRC/onetdns-recurse.toml" "$WORK/onetdns-recurse.toml"

# 자기가 시작한 PID만 회수한다. 이름으로 pkill하면 호스트에서 돌던 남의 onetdns까지 죽는다
# — 권한 계층과 측정 대상이 같은 이름이라 특히 구분되지 않는다.
PIDS=""
cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null || true; done
  for p in $PIDS; do wait "$p" 2>/dev/null || true; done
}
trap cleanup EXIT
trap 'trap - EXIT; cleanup; exit 130' HUP INT TERM

for role in root tld leaf; do
  taskset -c 0 "$BIN" --config "$H/authority-$role.toml" --no-web --no-supervisor \
    >"$WORK/a$role.log" 2>&1 &
  PIDS="$PIDS $!"
done
sleep 3

perf record -o "$OUT/perf.data" -F 999 -g --call-graph dwarf,16384 -- \
  taskset -c 2 "$BIN" --config "$WORK/onetdns-recurse.toml" --no-web --no-supervisor >"$WORK/t.log" 2>&1 &
PERFPID=$!
PIDS="$PIDS $PERFPID"
sleep 4
taskset -c 1 dnsperf -s 127.0.0.1 -p 5300 -d "$H/queries-recurse.txt" -n 2 -q 20 -c 1 -T 1 2>/dev/null | awk '/Queries per second/{print "qps:", $4}'
# perf가 표본을 다 쓰도록 INT로 끊는다.
kill -INT "$PERFPID" 2>/dev/null || true
wait "$PERFPID" 2>/dev/null || true
sleep 1
perf report -i "$OUT/perf.data" --stdio --no-children --percent-limit 1 2>/dev/null | head -50
echo profile_done
