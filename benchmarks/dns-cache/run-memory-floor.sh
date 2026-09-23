#!/bin/sh
# 최소 자원 바닥 찾기: 엔진이 여전히 **정답을 주는** 가장 작은 주소공간 한도를
# 계단식으로 찾는다. 처리량 벤치는 자원이 넉넉한 조건만 재므로, 열악한 환경에서
# 무엇이 먼저 죽는지는 알 수 없다.
#
# usage: sh run-memory-floor.sh BENCHDIR ONETDNS_BIN
#
# 주의: `ulimit -v`는 RSS가 아니라 **주소공간**을 제한한다. Go 런타임처럼 큰 VA를
# 예약하는 엔진은 실제 사용 메모리보다 훨씬 큰 한도를 요구하므로, 이 값은
# "필요 메모리"가 아니라 "이 한도 아래로는 못 내려간다"는 하한이다. 실제 RSS는
# run-rss-interleave.sh에서 따로 측정한다.
#
# 바닥은 "한 번 답한다"가 아니라 **캐시를 채우는 부하를 견디고도 답한다**로 정의한다.
# 시작·초기 응답은 되는데 캐시를 채우다 할당 실패로 죽는 구간이 실재한다 — 이 프로젝트도
# lazy 할당 도입 직후 16,384 KiB에서 그렇게 죽었고(유실 6.85%), LruMap이 못 늘릴 때
# 밀어내기로 퇴화하도록 고친 뒤 같은 한도에서 404,253질의·유실 0으로 살아남는다.
#
# 2026-07-27 실측(지속 부하 검증 포함, 전 엔진 정답 확인 통과·유실 0):
#   OnetDNS 16,384 KiB(RSS 7,392)  dnsmasq 16,384 KiB(RSS 6,944)
#   Unbound 32,768 KiB(RSS 18,816)
# 처음 쟀을 때 OnetDNS 바닥은 32,768 KiB로 dnsmasq의 2배였다. 원인은 `LruMap::new(cap)`이
# `HashMap::with_capacity(cap)`와 `Vec::with_capacity(cap)`를 시작 시 즉시 잡는 것이었고
# (VmSize 24,052 KiB 중 익명 매핑 하나가 11,440 KiB, VmRSS는 5,600 KiB뿐), 초기 예약을
# 1,024 엔트리로 제한해 16,384 KiB로 내렸다. 다만 그것만으로는 실패 시점이 시작에서
# 부하 중으로 옮겨갈 뿐이라, 못 늘릴 때 밀어내기로 퇴화하는 수정이 함께 필요했다.
set -eu
H=${1:?benchdir}
BIN=${2:?onetdns binary}
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
LADDER=${LADDER:-"1048576 524288 262144 131072 98304 65536 49152 32768 24576 16384 12288 8192"}
SUSTAIN_SECONDS=${SUSTAIN_SECONDS:-10}
PIDS=""
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
trap 'trap - EXIT; cleanup; exit 130' HUP INT TERM

sed "s|/home/ubuntu/onetdns-bench|$H|g" "$SRC/onetdns-authority.toml" > "$H/floor-auth.toml"
sed "s|/home/ubuntu/onetdns-bench|$H|g" "$SRC/onetdns-cache.toml" > "$H/floor-cache.toml"
sed "s|/home/ubuntu/onetdns-bench|$H|g" "$SRC/unbound.conf" > "$H/floor-unbound.conf"
PROBE=$(awk 'NR==1{print $1}' "$H/queries.txt")

taskset -c 0 "$BIN" --config "$H/floor-auth.toml" --no-web --no-supervisor \
  >"$H/floor-auth.log" 2>&1 &
PIDS="$PIDS $!"
sleep 3

# 한도 kib에서 엔진이 뜨고, 캐시를 채우는 부하를 견디고, 그 뒤에도 정답을 주면 0.
# "한 번 답한다"만 보면 안 된다 — 시작·초기 응답은 되는데 캐시를 채우다 할당 실패로
# 죽는 구간이 실재한다(이 프로젝트에서 실제로 관측·수정했다).
try_at() { # kib port cmd...
  kib=$1; port=$2; shift 2
  ( ulimit -v "$kib" 2>/dev/null || exit 1; exec "$@" ) >"$H/floor-try.log" 2>&1 &
  P=$!
  sleep 4
  ok=1
  resp=$(dig +time=2 +tries=1 @127.0.0.1 -p "$port" "$PROBE" A 2>/dev/null || true)
  printf '%s\n' "$resp" | grep -q "status: NOERROR" || ok=0
  printf '%s\n' "$resp" | grep -q '^;; ANSWER SECTION' || ok=0
  if [ "$ok" = 1 ]; then
    taskset -c 1 dnsperf -s 127.0.0.1 -p "$port" -d "$H/queries.txt" \
      -q 100 -c 1 -T 1 -l "$SUSTAIN_SECONDS" >"$H/floor-load.txt" 2>&1 || true
    lost=$(awk '/Queries lost/{print $3}' "$H/floor-load.txt")
    [ "${lost:-1}" = 0 ] || ok=0
    kill -0 "$P" 2>/dev/null || ok=0
    after=$(dig +time=2 +tries=1 @127.0.0.1 -p "$port" "$PROBE" A 2>/dev/null || true)
    printf '%s\n' "$after" | grep -q "status: NOERROR" || ok=0
  fi
  rss=$(ps -o rss= -p "$P" 2>/dev/null | tr -d ' ')
  kill "$P" 2>/dev/null || true
  wait "$P" 2>/dev/null || true
  sleep 1
  [ "$ok" = 1 ] && { echo "${rss:-?}"; return 0; }
  return 1
}

floor() { # label port cmd...
  lbl=$1; port=$2; shift 2
  best=""
  bestrss=""
  for kib in $LADDER; do
    if rss=$(try_at "$kib" "$port" "$@"); then
      best=$kib
      bestrss=$rss
    else
      break
    fi
  done
  if [ -n "$best" ]; then
    printf '%s: sustained_floor_kib=%s rss_at_floor_kib=%s\n' "$lbl" "$best" "$bestrss"
  else
    printf '%s: 사다리 최상단에서도 정답을 주지 못했다\n' "$lbl"
  fi
}

floor onetdns 15353 taskset -c 2 "$BIN" --config "$H/floor-cache.toml" --no-web --no-supervisor
floor unbound 15354 taskset -c 2 unbound -d -c "$H/floor-unbound.conf"
floor dnsmasq 15356 taskset -c 2 dnsmasq -k --log-facility=- --pid-file="$H/dnsmasq.pid" \
  --user="$(id -un)" --group="$(id -gn)" -C "$H/dnsmasq.conf"
echo done
