#!/bin/sh
# DNSSEC 검증 처리량 비교(O-U-O 또는 B-C-U-C-B). 서명된 3계층에 대해 검증 리졸버가 매 해석마다
# 서명 검증을 수행한다. 미스 단일 패스(-n 1)로 검증 CPU를 포함해 측정.
# 자산: generate-delegation.sh를 DNSSEC 모드로 먼저 생성해야 한다.
# usage: unshare -rn sh -c 'ip link set lo up; sh run-dnssec-bench.sh DNSSEC_DIR ONETDNS_BIN [BASELINE_BIN]'
set -eu
D=${1:?dnssec benchdir(=generate-delegation DNSSEC 출력)}
BIN=${2:?onetdns binary}
BASELINE_BIN=${3:-}
# 출하 기본값(0=재귀 자동, CPU당 UDP 5)으로 측정한다. 스레드 대등 조건을 보려면 1을 준다.
WORKERS=${4:-0}
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
WORK="$D/run-dnssec-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir "$WORK"

RESOLVER_PID=
ROOT_PID=
TLD_PID=
LEAF_PID=
cleanup() {
  for pid in ${RESOLVER_PID:-} ${ROOT_PID:-} ${TLD_PID:-} ${LEAF_PID:-}; do
    kill "$pid" 2>/dev/null || true
  done
  for pid in ${RESOLVER_PID:-} ${ROOT_PID:-} ${TLD_PID:-} ${LEAF_PID:-}; do
    wait "$pid" 2>/dev/null || true
  done
}
abort() {
  trap - EXIT
  cleanup
  exit 130
}
trap cleanup EXIT
trap abort HUP INT TERM

# 권한 3계층(서명됨) 시작
taskset -c 0 "$BIN" --config "$D/authority-root.toml" --no-web --no-supervisor >"$WORK/ar.log" 2>&1 &
ROOT_PID=$!
taskset -c 0 "$BIN" --config "$D/authority-tld.toml" --no-web --no-supervisor >"$WORK/at.log" 2>&1 &
TLD_PID=$!
taskset -c 0 "$BIN" --config "$D/authority-leaf.toml" --no-web --no-supervisor >"$WORK/al.log" 2>&1 &
LEAF_PID=$!
sleep 1
for pid in "$ROOT_PID" "$TLD_PID" "$LEAF_PID"; do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "authority process failed during startup; inspect $WORK/*.log" >&2
    exit 1
  fi
done
wait_authority() { # address name type [expected]
  addr=$1 name=$2 type=$3 expected=${4:-}
  tries=0
  while [ "$tries" -lt 60 ]; do
    answer=$(dig +time=1 +tries=1 +short @"$addr" -p 53 "$name" "$type" 2>/dev/null || true)
    if [ -n "$answer" ] && { [ -z "$expected" ] || [ "$answer" = "$expected" ]; }; then
      return 0
    fi
    tries=$((tries+1))
    sleep 1
  done
  echo "authority readiness timed out: @$addr $name $type; inspect $WORK/*.log" >&2
  return 1
}
wait_authority 127.0.1.1 . SOA
wait_authority 127.0.2.1 test. SOA
wait_authority 127.0.3.1 a00.z0007.test. A 192.0.2.1

# OnetDNS 검증 리졸버 설정
sed -e "s/^dnssec = .*/dnssec = true/" -e "s/^workers = .*/workers = $WORKERS/" \
  "$SRC/onetdns-recurse.toml" > "$WORK/onetdns-val.toml"
{
  echo "dnssec_anchor_file = \"$D/onetdns-root-anchor.txt\""
  echo "dnssec_rfc5011 = false"
  echo "dnssec_strict = true"
} >> "$WORK/onetdns-val.toml"
# A/B 실험용: 추가 설정 줄을 환경으로 주입한다.
if [ -n "${ONETDNS_EXTRA_CONF:-}" ]; then
  printf '%s\n' "$ONETDNS_EXTRA_CONF" >> "$WORK/onetdns-val.toml"
fi

# Unbound 검증 설정: 루트 DS를 trust-anchor로. root-ds.txt는 "  . 3600 IN DS ..".
# validator 모듈 없이는 trust-anchor를 줘도 Unbound가 검증을 아예 하지 않는다
# (AD 없이 응답) — 검증 대 비검증을 비교하는 무효 측정이 되므로 함께 켠다.
sed -e "s|ROOTHINTS|$WORK/root.hints|g" \
    -e 's|module-config: "iterator"|module-config: "validator iterator"|' \
    -e 's|qname-minimisation: no|qname-minimisation: yes|' \
    "$SRC/unbound-recurse.conf" > "$WORK/unbound-val.conf"
printf '. IN NS ns.root.\nns.root. IN A 127.0.1.1\n' > "$WORK/root.hints"
DSLINE=$(cat "$D/root-ds.txt")
QUERY_COUNT=$(wc -l <"$D/queries-recurse.txt")
{
  echo "server:"
  echo "  trust-anchor: \"$DSLINE\""
} >> "$WORK/unbound-val.conf"

run_one() { # name cmd...
  nm=$1; shift
  "$@" >"$WORK/$nm.log" 2>&1 &
  RESOLVER_PID=$!
  sleep 4
  if ! kill -0 "$RESOLVER_PID" 2>/dev/null; then
    echo "$nm resolver failed during startup; inspect $WORK/$nm.log" >&2
    return 1
  fi
  # 정답+검증(AD 비트) 확인 — +short는 헤더 flags 줄(AD)을 버려 검증 성공을 못 본다.
  # dig는 무응답 시 9로 끝난다. set -e에 걸려 스크립트가 죽으면 정작 아래 WARN이
  # 못 찍히고 뒤 브래킷·정리까지 날아가므로 대입이 항상 성공하게 한다.
  resp=$(dig +dnssec @127.0.0.1 -p 5300 a00.z0007.test A 2>/dev/null || true)
  ans=$(printf '%s\n' "$resp" | awk 'tolower($1)=="a00.z0007.test." && $4=="A"{print $5; exit}')
  ad=no
  if printf '%s\n' "$resp" | grep -E '^;; flags:' | grep -q ' ad[ ;]'; then ad=yes; fi
  if [ "$ans" != "192.0.2.1" ] || [ "$ad" != "yes" ]; then
    printf '%s: WARN 검증 전제 불충족(answer=%s ad=%s) — 이 측정은 검증-on을 보장하지 못함\n' "$nm" "$ans" "$ad"
    rc=1
  fi
  out=$(taskset -c 1 dnsperf -s 127.0.0.1 -p 5300 -d "$D/queries-recurse.txt" -n 1 -q 40 -c 20 -T 1 2>/dev/null)
  printf '%s\n' "$out" >"$WORK/$nm.dnsperf.txt"
  q=$(printf '%s\n' "$out" | awk '/Queries per second/{print $4}')
  l=$(printf '%s\n' "$out" | awk '/Average Latency/{print $4}')
  completed=$(printf '%s\n' "$out" | awk 'tolower($0) ~ /queries completed/{print $3}')
  lost=$(printf '%s\n' "$out" | awk 'tolower($0) ~ /queries lost/{print $3}')
  if [ -z "$q" ] || [ -z "$l" ] || [ "$completed" != "$QUERY_COUNT" ] || [ "$lost" != "0" ]; then
    printf '%s: WARN 불완전한 측정(qps=%s latency=%s completed=%s/%s lost=%s)\n' \
      "$nm" "$q" "$l" "$completed" "$QUERY_COUNT" "$lost"
    rc=1
    q=${q:-0}
  fi
  case "$nm" in
    baseline1) B1=$q ;;
    baseline2) B2=$q ;;
    candidate1) C1=$q ;;
    candidate2) C2=$q ;;
    onetdns_val1) O1=$q ;;
    onetdns_val2) O2=$q ;;
    unbound_val) U=$q ;;
  esac
  printf '%s: answer=%s ad=%s qps=%s avg_latency_s=%s completed=%s lost=%s\n' \
    "$nm" "$ans" "$ad" "$q" "$l" "$completed" "$lost"
  kill "$RESOLVER_PID" 2>/dev/null || true
  wait "$RESOLVER_PID" 2>/dev/null || true
  RESOLVER_PID=
  sleep 1
}

check_bracket() { # label first second
  label=$1 first=$2 second=$3
  drift=$(awk -v a="$first" -v b="$second" 'BEGIN { m=(a+b)/2; if (m<=0) print 100; else printf "%.3f", (a>b?a-b:b-a)*100/m }')
  printf '%s bracket_drift_pct=%s\n' "$label" "$drift"
  if ! awk -v d="$drift" 'BEGIN { exit !(d <= 5.0) }'; then
    printf '%s: WARN 앞뒤 처리량 드리프트가 5%%를 넘어 측정을 무효화합니다\n' "$label"
    rc=1
  fi
}

rc=0
if [ -n "$BASELINE_BIN" ]; then
  B1= B2= C1= C2= U=
  run_one baseline1  taskset -c 2 "$BASELINE_BIN" --config "$WORK/onetdns-val.toml" --no-web --no-supervisor
  run_one candidate1 taskset -c 2 "$BIN" --config "$WORK/onetdns-val.toml" --no-web --no-supervisor
  run_one unbound_val taskset -c 2 unbound -d -c "$WORK/unbound-val.conf"
  run_one candidate2 taskset -c 2 "$BIN" --config "$WORK/onetdns-val.toml" --no-web --no-supervisor
  run_one baseline2  taskset -c 2 "$BASELINE_BIN" --config "$WORK/onetdns-val.toml" --no-web --no-supervisor
  check_bracket baseline "$B1" "$B2"
  check_bracket candidate "$C1" "$C2"
  awk -v b1="$B1" -v b2="$B2" -v c1="$C1" -v c2="$C2" -v u="$U" 'BEGIN {
    b=(b1+b2)/2; c=(c1+c2)/2;
    printf "summary: baseline_qps=%.3f candidate_qps=%.3f delta_pct=%+.3f unbound_qps=%.3f\n", b, c, (c/b-1)*100, u
  }'
else
  O1= O2= U=
  run_one onetdns_val1 taskset -c 2 "$BIN" --config "$WORK/onetdns-val.toml" --no-web --no-supervisor
  run_one unbound_val  taskset -c 2 unbound -d -c "$WORK/unbound-val.conf"
  run_one onetdns_val2 taskset -c 2 "$BIN" --config "$WORK/onetdns-val.toml" --no-web --no-supervisor
  check_bracket onetdns "$O1" "$O2"
fi
# 검증 전제(정답+AD)가 깨진 회차가 있으면 그 측정값은 무효다 — 종료 코드로 알린다.
echo "artifacts=$WORK"
echo done
exit "$rc"
