#!/bin/sh
# 퇴거가 지배하는 캐시 workload. `run-engines-interleave.sh`는 20,000 용량에 고유 이름
# 10,000개라 워밍 뒤 퇴거가 한 번도 일어나지 않는다 — 캐시 삽입·퇴거 경로를 바꾼 변경은
# 그 하네스에서 아무 신호도 내지 않는다. 여기서는 용량을 고유 이름 수의 1/5로 낮춰
# 모든 질의가 미스+퇴거를 유발하게 한다(자원이 모자란 배포의 실제 조건).
#
# usage: sh run-evict-interleave.sh BENCHDIR BIN_A [BIN_B]
#   BIN_B를 주면 A-B-A-B로 번갈아 재 같은 창에서 두 바이너리를 비교한다.
#
# netns로 감싸지 말 것 — 이유는 run-engines-interleave.sh 주석 참조.
set -eu
H=${1:?benchdir}
A=${2:?binary a}
B=${3:-}
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
CACHE=${EVICT_CACHE_SIZE:-2000}
PIDS=""
rc=0
cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null || true; done
  for p in $PIDS; do wait "$p" 2>/dev/null || true; done
}
trap cleanup EXIT
trap 'trap - EXIT; cleanup; exit 130' HUP INT TERM

sed "s|/home/ubuntu/onetdns-bench|$H|g" "$SRC/onetdns-authority.toml" > "$H/evict-auth.toml"
# 이 workload는 업스트림 전달이 지배하므로 **워커 자동값(WORKERS=0)으로 측정한다**.
# 공유하는 `onetdns-cache.toml`은 hot-cache·RSS 벤치의 최소 자원 프로필이라
# `workers = 1`로 고정돼 있는데, 그 값이면 UDP 워커가 하나뿐이라 reuseport 소켓
# 묶기(CPU 수만큼 열고 워커가 나눠 읽기)와 전달 백엔드 CPU×4 자동값이 **둘 다
# 발동하지 않는다**. 실측: workers=1은 26.3~26.5k(dnsmasq 31.0~31.4k에 패배),
# 자동값은 75.2~75.4k(2.41~2.43배 우세). 고정하고 싶으면 WORKERS를 준다.
WORKERS=${WORKERS:-0}
if [ "${NO_CACHE:-0}" = 1 ]; then
  sed "s|/home/ubuntu/onetdns-bench|$H|g" "$SRC/onetdns-cache.toml" \
    | sed "s/^cache_enabled = .*/cache_enabled = false/" \
    | sed "s/^workers = .*/workers = $WORKERS/" > "$H/evict-cache.toml"
  sed "s/^cache-size=.*/cache-size=0/" "$H/dnsmasq.conf" > "$H/evict-dnsmasq.conf"
else
  sed "s|/home/ubuntu/onetdns-bench|$H|g" "$SRC/onetdns-cache.toml" \
    | sed "s/^cache_size = .*/cache_size = $CACHE/" \
    | sed "s/^workers = .*/workers = $WORKERS/" > "$H/evict-cache.toml"
  sed "s/^cache-size=.*/cache-size=$CACHE/" "$H/dnsmasq.conf" > "$H/evict-dnsmasq.conf"
fi

# 권한 서버는 A 바이너리 하나로 고정한다 — 업스트림이 레그마다 바뀌면 비교가 오염된다.
taskset -c 0 "$A" --config "$H/evict-auth.toml" --no-web --no-supervisor \
  >"$H/evict-auth.log" 2>&1 &
PIDS="$PIDS $!"
sleep 3

leg() { # label port cmd...
  lbl=$1; port=$2; shift 2
  "$@" >"$H/evict-$lbl.log" 2>&1 &
  P=$!
  sleep 4
  if result=$(DNSPERF_CPU=1 sh "$SRC/run-dnsperf.sh" "$port" "$H/queries.txt" 10 5 2>&1); then
    rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$P/status")
    printf '%s: %s rss_kib=%s\n' "$lbl" "$(printf '%s\n' "$result" | tail -1)" "$rss"
  else
    printf '%s: %s\n' "$lbl" "$(printf '%s\n' "$result" | tail -1)"
    rc=1
  fi
  # 회수하고 나서 다음 레그로 간다. kill은 비동기라 내려가는 엔진이 다음 레그와
  # 같은 코어에서 겹치면 그 수치가 오염된다.
  kill "$P" 2>/dev/null || true
  wait "$P" 2>/dev/null || true
  sleep 1
}

onetdns() { # label binary
  leg "$1" 15353 taskset -c 2 "$2" --config "$H/evict-cache.toml" --no-web --no-supervisor
}

dnsmasq_leg() {
  leg "$1" 15356 taskset -c 2 dnsmasq -k --log-facility=- --pid-file="$H/dnsmasq.pid" \
    --user="$(id -un)" --group="$(id -gn)" -C "$H/evict-dnsmasq.conf"
}

onetdns A1 "$A"
[ -n "$B" ] && onetdns B1 "$B"
dnsmasq_leg dnsmasq1
onetdns A2 "$A"
[ -n "$B" ] && onetdns B2 "$B"
dnsmasq_leg dnsmasq2
onetdns A3 "$A"
[ -n "$B" ] && onetdns B3 "$B"

if [ "$rc" != 0 ]; then
  echo "정답 확인에 실패한 엔진이 있다 — 그 엔진을 포함한 비교는 무효다"
fi
echo done
exit "$rc"
