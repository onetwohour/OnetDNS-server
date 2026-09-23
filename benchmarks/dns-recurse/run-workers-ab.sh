#!/bin/sh
# 동일 1코어(CPU 2) 예산에서 workers=1 vs workers=32(블로킹 대기 중첩) 콜드-미스
# 비교 + 같은 창의 Unbound 기준점. 스레드 수는 구현 세부이고 자원 예산(1코어)은
# 동일하다 — Unbound의 이벤트 루프 다중화와 같은 조건.
# usage: unshare -rn sh -c 'ip link set lo up; sh run-workers-ab.sh BENCHDIR AUTH_BIN TEST_BIN'
#
# 회차 분산이 크다. 엔진마다 새로 시작하고 3초 뒤 단일 패스를 재는데, 콜드-미스
# workload라 워밍 패스를 넣을 수 없어(넣으면 미스가 아니게 된다) 시작 직후 상태가
# 회차마다 다르게 섞인다. 2026-07-27 실측에서 브래킷 1회는 w1 드리프트 2.86%·w32
# 43.6%, 2회는 w1 8.73%·w32 2.91%로 **어느 구성도 한 번은 5% 게이트를 넘었다**.
# 따라서 브래킷 하나의 드리프트로 유효성을 판정하지 말고, 최소 2회를 돌려 구성별
# 범위가 겹치는지로 결론을 내라.
set -eu
H=${1:?benchdir}
AUTH=${2:?authority binary}
BIN=${3:?test binary}
WORK="$H/run"
mkdir -p "$WORK"
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
cp "$SRC/onetdns-recurse.toml" "$WORK/onetdns-recurse.toml"
sed 's/^workers = 1/workers = 32/' "$WORK/onetdns-recurse.toml" > "$WORK/onetdns-recurse-w32.toml"
# Unbound 설정도 실체화한다. 빠뜨리면 unbound가 기본 설정으로 떠서 가짜 test. 계층
# 대신 실제 루트를 찾다가 전 질의가 타임아웃하고, 그 QPS가 기준점으로 인용된다.
cp "$SRC/root.hints" "$WORK/root.hints"
sed "s|ROOTHINTS|$WORK/root.hints|" "$SRC/unbound-recurse.conf" > "$WORK/unbound-recurse.conf"
PROBE=$(awk 'NR==1{print $1}' "$H/queries-recurse.txt")
rc=0

# 자기가 시작한 PID만 회수한다. 이름으로 pkill하면 호스트에서 돌던 남의 unbound·
# onetdns까지 죽인다.
PIDS=""
cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null || true; done
  for p in $PIDS; do wait "$p" 2>/dev/null || true; done
}
trap cleanup EXIT
trap 'trap - EXIT; cleanup; exit 130' HUP INT TERM

taskset -c 0 "$AUTH" --config "$H/authority-root.toml" --no-web --no-supervisor >"$WORK/ar.log" 2>&1 &
PIDS="$PIDS $!"
taskset -c 0 "$AUTH" --config "$H/authority-tld.toml" --no-web --no-supervisor >"$WORK/at.log" 2>&1 &
PIDS="$PIDS $!"
taskset -c 0 "$AUTH" --config "$H/authority-leaf.toml" --no-web --no-supervisor >"$WORK/al.log" 2>&1 &
PIDS="$PIDS $!"
sleep 3

run_one() { # name cmd...
  nm=$1; shift
  "$@" >"$WORK/t-$nm.log" 2>&1 &
  P=$!
  sleep 3
  # 해석에 실패해도 dnsperf는 QPS를 보고한다(전 질의 타임아웃이 곧 "빠른" 수치가
  # 되기도 한다). 측정 전에 한 이름을 직접 물어 정답을 확인하고, 아니면 이 엔진의
  # 수치는 내지 않는다. 워밍되는 이름은 데이터셋의 1개뿐이다.
  probe=$(dig +time=3 +tries=1 @127.0.0.1 -p 5300 "$PROBE" A 2>/dev/null || true)
  if ! printf '%s\n' "$probe" | grep -q "status: NOERROR" ||
     ! printf '%s\n' "$probe" | grep -q "^$PROBE"; then
    printf '%s: FAIL (정답 확인 실패 — 이 엔진은 해석하지 못하고 있다)\n' "$nm"
    rc=1
    kill "$P" 2>/dev/null || true
    sleep 1
    return 0
  fi
  out=$(taskset -c 1 dnsperf -s 127.0.0.1 -p 5300 -d "$H/queries-recurse.txt" -n 1 -q 40 -c 20 -T 1 2>/dev/null)
  q=$(printf '%s\n' "$out" | awk '/Queries per second/{print $4}')
  l=$(printf '%s\n' "$out" | awk '/Average Latency/{print $4}')
  # "Queries lost:" 줄은 값이 세 번째 곳이다. 네 번째를 읽으면 언제나 비어 나와
  # 유실 검사가 전부 무력해진다.
  lost=$(printf '%s\n' "$out" | awk 'tolower($0) ~ /queries lost/{print $3}')
  if [ -z "$q" ] || [ "${lost:-1}" != 0 ]; then
    printf '%s: WARN 유실이 있거나 결과가 불완전하다(qps=%s lost=%s) — 이 수치는 무효다\n' \
      "$nm" "${q:-?}" "${lost:-?}"
    rc=1
  fi
  printf '%s: qps=%s avg_latency_s=%s lost=%s\n' "$nm" "$q" "$l" "${lost:-?}"
  kill "$P" 2>/dev/null || true
  wait "$P" 2>/dev/null || true
  sleep 1
}

run_one w1_a   taskset -c 2 "$BIN" --config "$WORK/onetdns-recurse.toml" --no-web --no-supervisor
run_one w32_a  taskset -c 2 "$BIN" --config "$WORK/onetdns-recurse-w32.toml" --no-web --no-supervisor
run_one unbound taskset -c 2 unbound -d -c "$WORK/unbound-recurse.conf"
run_one w32_b  taskset -c 2 "$BIN" --config "$WORK/onetdns-recurse-w32.toml" --no-web --no-supervisor
run_one w1_b   taskset -c 2 "$BIN" --config "$WORK/onetdns-recurse.toml" --no-web --no-supervisor
if [ "$rc" != 0 ]; then
  echo "일부 엔진이 정답 확인에 실패했다 — 이 창의 비교는 무효다"
fi
echo done
exit "$rc"
