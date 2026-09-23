#!/bin/sh
# 10만 규칙 차단 판정 처리량을 OnetDNS와 AdGuard Home 사이에서 인터리브로 측정한다.
#
# **업스트림(권한 서버)을 일부러 시작하지 않는다.** 규칙이 실제로 로드되지 않았다면
# 질의가 업스트림으로 나가 SERVFAIL/타임아웃이 되므로, run-dnsperf.sh의 정답 확인이 곧
# 실차단 증명이 된다. 반대로 규칙이 로드됐으면 로컬에서 즉답한다. NXDOMAIN만으로
# 판정하면 업스트림의 정당한 NXDOMAIN과 구분되지 않는다는 함정을 이 구성이 없앤다.
#
# usage: sh run-filter-interleave.sh WORKDIR ONETDNS_BIN AGH_BIN AGH_YAML
set -eu
W=${1:?workdir}
BIN=${2:?onetdns binary}
AGH=${3:?AdGuardHome binary}
AGYAML=${4:?AdGuardHome yaml}
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
PERF="$SRC/../dns-cache/run-dnsperf.sh"
rc=0

mkdir -p "$W"
if [ ! -s "$W/blocklist.txt" ]; then
  awk 'BEGIN{for(i=0;i<100000;i++) printf "||b%06d.example^\n", i}' > "$W/blocklist.txt"
fi
if [ ! -s "$W/blocked-queries.txt" ]; then
  awk 'BEGIN{srand(7); for(i=0;i<20000;i++) printf "b%06d.example A\n", int(rand()*100000)}' \
    > "$W/blocked-queries.txt"
fi
sed -e "s|^blocklists = .*|blocklists = [\"$W/blocklist.txt\"]|" \
    "$SRC/onetdns-filter.toml" > "$W/onetdns-filter.toml"

leg() { # label port expect_rcode expect_answer cmd...
  lbl=$1; port=$2; erc=$3; ean=$4; shift 4
  "$@" >"$W/filter-$lbl.log" 2>&1 &
  P=$!
  sleep 5
  # 10만 규칙을 실제로 물고 있는 상태의 RSS. 규칙 미로드면 아래 정답 확인에 걸린다.
  loaded=$(ps -o rss= -p "$P" 2>/dev/null | tr -d ' ')
  printf '%s: rules_loaded_rss_kib=%s ' "$lbl" "${loaded:-?}"
  if ! EXPECT_RCODE="$erc" EXPECT_ANSWER="$ean" DNSPERF_CPU=1 \
       sh "$PERF" "$port" "$W/blocked-queries.txt" 10 5 2>&1 | tail -1; then
    rc=1
  fi
  after=$(ps -o rss= -p "$P" 2>/dev/null | tr -d ' ')
  printf '  %s: after_load_rss_kib=%s\n' "$lbl" "${after:-?}"
  # 회수하고 나서 다음 레그로 간다. kill은 비동기라 내려가는 엔진이 다음 레그와
  # 같은 코어에서 겹치면 그 수치가 오염된다.
  kill "$P" 2>/dev/null || true
  wait "$P" 2>/dev/null || true
  sleep 1
}

onetdns() {
  leg "$1" 15357 NXDOMAIN 0 taskset -c 2 "$BIN" --config "$W/onetdns-filter.toml" \
    --no-web --no-supervisor
}

onetdns O1
# AGH의 기본 차단 응답은 0.0.0.0이라 NOERROR + 답 레코드다.
leg adguard 15355 NOERROR 1 env GOMAXPROCS=1 taskset -c 2 "$AGH" -c "$AGYAML" \
  -w "$W/agwork" --no-check-update
onetdns O2

if [ "$rc" != 0 ]; then
  echo "정답 확인에 실패한 엔진이 있다 — 규칙이 로드되지 않았거나 차단이 동작하지 않는다"
fi
echo done
exit "$rc"
