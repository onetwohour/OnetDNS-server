#!/bin/sh
# 계측 바이너리(coldprof)로 콜드-미스 구간별 시간을 수집한다(임시 측정용).
# usage: unshare -rn sh -c 'ip link set lo up; sh run-coldprof.sh BENCHDIR AUTH_BIN PROF_BIN'
set -eu
H=${1:?benchdir}
AUTH=${2:?authority binary}
BIN=${3:?instrumented binary}
WORK="$H/run"
mkdir -p "$WORK"
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
cp "$SRC/onetdns-recurse.toml" "$WORK/onetdns-recurse.toml"

# 자기가 시작한 PID만 회수한다. 이름으로 pkill하면 호스트에서 돌던 남의 프로세스까지 죽인다.
PIDS=""
cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null || true; done
  for p in $PIDS; do wait "$p" 2>/dev/null || true; done
}
trap cleanup EXIT
trap 'trap - EXIT; cleanup; exit 130' HUP INT TERM

for role in root tld leaf; do
  taskset -c 0 "$AUTH" --config "$H/authority-$role.toml" --no-web --no-supervisor \
    >"$WORK/a$role.log" 2>&1 &
  PIDS="$PIDS $!"
done
sleep 3
taskset -c 2 "$BIN" --config "$WORK/onetdns-recurse.toml" --no-web --no-supervisor >"$WORK/prof.log" 2>&1 &
P=$!
PIDS="$PIDS $P"
sleep 3
taskset -c 1 dnsperf -s 127.0.0.1 -p 5300 -d "$H/queries-recurse.txt" -n 5 -q 20 -c 1 -T 1 2>/dev/null \
  | awk '/Queries per second/{print "qps:", $4}'
kill "$P" 2>/dev/null || true
wait "$P" 2>/dev/null || true
sleep 1
grep coldprof "$WORK/prof.log" | tail -4 || echo "no coldprof output"
echo done
