#!/bin/sh
# 핫캐시 다엔진 인터리브. 경쟁 엔진 사이사이에 OnetDNS 레그를 넣어 호스트 드리프트를
# 같은 창에서 함께 잡는다. 측정은 정답 확인이 들어간 run-dnsperf.sh가 수행하므로
# 잘못 뜬 엔진은 수치를 내지 않고 실패한다.
#
# usage: sh run-engines-interleave.sh BENCHDIR ONETDNS_BIN
#   BENCHDIR: queries.txt·dnsmasq.conf·Corefile·AdGuardHome/·coredns 가 있는 디렉터리
#
# **netns로 감싸지 말 것.** 재귀 하네스와 달리 이 벤치는 전부 높은 포트를 쓰므로
# 격리가 필요 없고, 비특권 user namespace 안에서는 dnsmasq가 setgroups 거부로 시작
# 자체에 실패한다("failed to change group-id"). 게다가 dnsmasq는 기본적으로 syslog에
# 기록해 그 실패가 로그에 남지 않으므로, 진단할 때는 `--log-facility=-`를 붙여라.
set -eu
H=${1:?benchdir}
BIN=${2:?onetdns binary}
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
PIDS=""
rc=0
cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null || true; done
  for p in $PIDS; do wait "$p" 2>/dev/null || true; done
}
trap cleanup EXIT
trap 'trap - EXIT; cleanup; exit 130' HUP INT TERM

sed "s|/home/ubuntu/onetdns-bench|$H|g" "$SRC/onetdns-authority.toml" > "$H/interleave-auth.toml"
sed "s|/home/ubuntu/onetdns-bench|$H|g" "$SRC/onetdns-cache.toml" > "$H/interleave-cache.toml"

taskset -c 0 "$BIN" --config "$H/interleave-auth.toml" --no-web --no-supervisor \
  >"$H/interleave-auth.log" 2>&1 &
PIDS="$PIDS $!"
sleep 3

leg() { # label port cmd...
  lbl=$1; port=$2; shift 2
  "$@" >"$H/interleave-$lbl.log" 2>&1 &
  P=$!
  sleep 4
  printf '%s: ' "$lbl"
  if ! DNSPERF_CPU=1 sh "$SRC/run-dnsperf.sh" "$port" "$H/queries.txt" 10 5 2>&1 | tail -1; then
    rc=1
  fi
  # 다음 레그를 시작하기 전에 반드시 회수한다. kill은 비동기라 회수하지 않으면
  # 내려가는 엔진이 다음 레그와 같은 코어에서 겹쳐 그 수치를 오염시킨다.
  kill "$P" 2>/dev/null || true
  wait "$P" 2>/dev/null || true
  sleep 1
}

onetdns() {
  leg "$1" 15353 taskset -c 2 "$BIN" --config "$H/interleave-cache.toml" --no-web --no-supervisor
}

onetdns O1
# dnsmasq는 자기 uid/gid로 고정해야 권한 강등 실패로 죽지 않는다.
leg dnsmasq 15356 taskset -c 2 dnsmasq -k --log-facility=- --pid-file="$H/dnsmasq.pid" \
  --user="$(id -un)" --group="$(id -gn)" -C "$H/dnsmasq.conf"
onetdns O2
leg coredns 15358 env GOMAXPROCS=1 taskset -c 2 "$H/coredns" -conf "$H/Corefile"
onetdns O3
leg adguard 15355 env GOMAXPROCS=1 taskset -c 2 "$H/AdGuardHome/AdGuardHome" \
  -c "$H/AdGuardHome.yaml" -w "$H/adguard-work" --no-check-update
onetdns O4

if [ "$rc" != 0 ]; then
  echo "정답 확인에 실패한 엔진이 있다 — 그 엔진을 포함한 비교는 무효다"
fi
echo done
exit "$rc"
