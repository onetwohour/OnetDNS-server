#!/bin/sh
# 엔진별 startup RSS와 같은 질의 집합으로 데운 뒤의 RSS를 같은 창에서 측정한다.
# RSS는 CPU 경합에 둔감해 처리량보다 호스트 상태에 덜 흔들리지만, 잘못 뜬 엔진은
# 캐시가 비어 있어 RSS만 작게 나오므로 워밍 전에 정답을 확인한다.
#
# usage: sh run-rss-interleave.sh BENCHDIR ONETDNS_BIN
#
# netns로 감싸지 말 것 — 이유는 run-engines-interleave.sh 주석 참조.
set -eu
H=${1:?benchdir}
BIN=${2:?onetdns binary}
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$SRC/../lib/procmem.sh"
WARM=${WARM_SECONDS:-10}
PIDS=""
rc=0
cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null || true; done
  for p in $PIDS; do wait "$p" 2>/dev/null || true; done
}
trap cleanup EXIT
trap 'trap - EXIT; cleanup; exit 130' HUP INT TERM

sed "s|/home/ubuntu/onetdns-bench|$H|g" "$SRC/onetdns-authority.toml" > "$H/rss-auth.toml"
sed "s|/home/ubuntu/onetdns-bench|$H|g" "$SRC/onetdns-cache.toml" > "$H/rss-cache.toml"
sed "s|/home/ubuntu/onetdns-bench|$H|g" "$SRC/unbound.conf" > "$H/rss-unbound.conf"
PROBE=$(awk 'NR==1{print $1}' "$H/queries.txt")

# 권한 서버를 OnetDNS 바이너리 그대로 시작하면 **OnetDNS 목표만** 텍스트 페이지를 공유해
# Pss가 낮게 나온다. 경쟁 엔진은 공유할 상대가 없으므로 이 비교는 OnetDNS에 유리하게
# 기운다. 실측에서 그 치우침이 2.2 MiB로, 엔진 사이 차이보다 큰 축도 있었다.
# 별도 사본으로 시작해 아무도 공유하지 않게 한다.
AUTH_BIN="$H/rss-auth-bin"
cp "$BIN" "$AUTH_BIN"
chmod +x "$AUTH_BIN"
taskset -c 0 "$AUTH_BIN" --config "$H/rss-auth.toml" --no-web --no-supervisor \
  >"$H/rss-auth.log" 2>&1 &
PIDS="$PIDS $!"
sleep 3

# 프로세스 트리 전체를 측정한다. 자식을 fork하는 엔진은 하네스가 붙잡은 PID 하나만
# 보면 크게 낮게 나온다(권한 축에서 NSD가 실제로 8배 낮게 잡혔다). procs가 1보다
# 크면 단일 PID 수치는 무의미하다.
leg() { # label port cmdline_needle cmd...
  lbl=$1; port=$2; needle=$3; shift 3
  "$@" >"$H/rss-$lbl.log" 2>&1 &
  P=$!
  sleep 4
  probe=$(dig +time=3 +tries=1 @127.0.0.1 -p "$port" "$PROBE" A 2>/dev/null || true)
  if ! printf '%s\n' "$probe" | grep -q "status: NOERROR" ||
     ! printf '%s\n' "$probe" | grep -q '^;; ANSWER SECTION'; then
    printf '%s: 정답 확인 실패 — RSS를 내지 않는다\n' "$lbl"
    rc=1
    kill "$P" 2>/dev/null || true
    wait "$P" 2>/dev/null || true
    sleep 1
    return 0
  fi
  start=$(engine_memory "$needle")
  taskset -c 1 dnsperf -s 127.0.0.1 -p "$port" -d "$H/queries.txt" \
    -q 100 -c 1 -T 1 -l "$WARM" >/dev/null 2>&1 || true
  warm=$(engine_memory "$needle")
  printf '%s: procs=%s startup_pss_kib=%s startup_rss_kib=%s warmed_pss_kib=%s warmed_rss_kib=%s\n' \
    "$lbl" "${start%% *}" \
    "$(printf '%s' "$start" | awk '{print $2}')" "$(printf '%s' "$start" | awk '{print $3}')" \
    "$(printf '%s' "$warm" | awk '{print $2}')" "$(printf '%s' "$warm" | awk '{print $3}')"
  kill "$P" 2>/dev/null || true
  wait "$P" 2>/dev/null || true
  sleep 1
}

onetdns() {
  leg "$1" 15353 rss-cache.toml taskset -c 2 "$BIN" --config "$H/rss-cache.toml" \
    --no-web --no-supervisor
}

onetdns O1
leg unbound 15354 rss-unbound.conf taskset -c 2 unbound -d -c "$H/rss-unbound.conf"
onetdns O2
leg dnsmasq 15356 dnsmasq.conf taskset -c 2 dnsmasq -k --log-facility=- \
  --pid-file="$H/dnsmasq.pid" --user="$(id -un)" --group="$(id -gn)" -C "$H/dnsmasq.conf"
onetdns O3
leg coredns 15358 Corefile env GOMAXPROCS=1 taskset -c 2 "$H/coredns" -conf "$H/Corefile"
onetdns O4
leg adguard 15355 AdGuardHome.yaml env GOMAXPROCS=1 taskset -c 2 \
  "$H/AdGuardHome/AdGuardHome" -c "$H/AdGuardHome.yaml" -w "$H/adguard-work" --no-check-update
onetdns O5

if [ "$rc" != 0 ]; then
  echo "정답 확인에 실패한 엔진이 있다 — 그 엔진의 RSS는 비교에 쓰지 마라"
fi
echo done
exit "$rc"
