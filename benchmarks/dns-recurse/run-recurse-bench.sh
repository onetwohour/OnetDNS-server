#!/bin/sh
# 재귀 정상상태 인터리브. 비특권 network namespace 안에서 실행한다.
# usage: unshare -rn sh -c 'ip link set lo up; sh run-recurse-bench.sh BENCHDIR ONETDNS_BIN [RATE=40000]'
# BENCHDIR 예: /home/ubuntu/onetdns-bench/recurse
set -eu
H=${1:?usage: run-recurse-bench.sh BENCHDIR ONETDNS_BIN [RATE]}
BIN=${2:?onetdns binary path}
RATE=${3:-40000}
if ! [ "$RATE" -ge 1 ] 2>/dev/null; then
  echo "RATE must be a positive integer" >&2
  exit 2
fi
Q="$H/queries-recurse.txt"
PROBE=$(awk 'NR==1{print $1}' "$Q")
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
# 생성물·로그는 실행자 소유의 고유 작업 디렉터리에만 쓴다. 기존 측정 자료를
# 삭제하거나 다른 실행과 충돌하지 않는다.
WORK="$H/run-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir "$WORK" || { echo "작업 디렉터리를 만들 수 없습니다: $WORK"; exit 1; }
ROOTHINTS="$WORK/root.hints"

TPID=
RPID=
TLPID=
LPID=
cleanup() {
  for pid in ${TPID:-} ${RPID:-} ${TLPID:-} ${LPID:-}; do
    kill "$pid" 2>/dev/null || true
  done
  for pid in ${TPID:-} ${RPID:-} ${TLPID:-} ${LPID:-}; do
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

# root.hints 준비
cat >"$ROOTHINTS" <<EOF
.                        3600000      NS    ns.root.
ns.root.                 3600000      A     127.0.1.1
EOF

# 엔진별 설정을 WORK로 실체화(경로 치환). PDNS-R은 config-dir의 recursor.conf를 읽는다.
sed "s|ROOTHINTS|$ROOTHINTS|g" "$SRC/pdns-recursor.conf" >"$WORK/recursor.conf"
sed -e "s|ROOTHINTS|$ROOTHINTS|g" -e "s|BENCHDIR|$WORK|g" "$SRC/named-recurse.conf" >"$WORK/named-recurse.conf"
sed "s|ROOTHINTS|$ROOTHINTS|g" "$SRC/unbound-recurse.conf" >"$WORK/unbound-recurse.conf"
cp "$SRC/onetdns-recurse.toml" "$WORK/onetdns-recurse.toml"

# 3계층 권한 서버를 각각 CPU 0에 시작(위임 추적을 실제로 강제).
taskset -c 0 "$BIN" --config "$H/authority-root.toml" --no-web --no-supervisor >"$WORK/recurse-root.log" 2>&1 &
RPID=$!
taskset -c 0 "$BIN" --config "$H/authority-tld.toml" --no-web --no-supervisor >"$WORK/recurse-tld.log" 2>&1 &
TLPID=$!
taskset -c 0 "$BIN" --config "$H/authority-leaf.toml" --no-web --no-supervisor >"$WORK/recurse-leaf.log" 2>&1 &
LPID=$!
sleep 3
for pid in "$RPID" "$TLPID" "$LPID"; do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "권한 서버 시작 실패(포트 53 선점 여부 확인):"
    tail -n 3 "$WORK/recurse-root.log" "$WORK/recurse-tld.log" "$WORK/recurse-leaf.log"; exit 1
  fi
done
auth_cpu() {
  r=$(ps -o %cpu= -p "$RPID" 2>/dev/null | tr -d ' ')
  t=$(ps -o %cpu= -p "$TLPID" 2>/dev/null | tr -d ' ')
  l=$(ps -o %cpu= -p "$LPID" 2>/dev/null | tr -d ' ')
  echo "root=$r tld=$t leaf=$l"
}

measure() { # $1=이름 $2..=대상 시작 커맨드(포트 5300). 회차마다 재시작해 캐시를 비운다.
  name=$1; shift
  echo "[$name]"
  n=1
  while [ "$n" -le 3 ]; do
    "$@" >"$WORK/target.log" 2>&1 &
    TPID=$!
    sleep 3
    if ! kill -0 "$TPID" 2>/dev/null; then
      echo "  시작 실패:"; tail -n 3 "$WORK/target.log"; return 1
    fi
    # 떠 있다고 해석하는 것은 아니다. 해석에 실패해도 dnsperf는 QPS를 보고하므로
    # (SERVFAIL이 오히려 빠르다) 회차마다 한 이름을 직접 물어 정답을 확인한다.
    probe=$(dig +time=3 +tries=1 @127.0.0.1 -p 5300 "$PROBE" A 2>/dev/null || true)
    if ! printf '%s\n' "$probe" | grep -q "status: NOERROR" ||
       ! printf '%s\n' "$probe" | grep -q "^$PROBE"; then
      echo "  정답 확인 실패($PROBE) — 이 엔진의 수치는 무효다" >&2
      kill "$TPID" 2>/dev/null || true
      wait "$TPID" 2>/dev/null || true
      TPID=
      return 1
    fi
    if ! line=$(taskset -c 1 dnsperf -s 127.0.0.1 -p 5300 -d "$Q" -l 8 -Q "$RATE" -q 50 -c 1 -T 1 2>/dev/null \
      | awk '
          /Queries per second/ { q=$4 }
          /Average Latency \(s\)/ { l=$4 }
          END {
            if (q == "" || l == "") exit 1
            printf "%.0f %.4f", q, l*1000
          }'); then
      echo "  dnsperf 결과를 읽지 못했습니다" >&2
      return 1
    fi
    qps=${line%% *}
    latency=${line#* }
    echo "  run$n: qps=$qps latency_ms=$latency auth_cpu=$(auth_cpu)%"
    kill "$TPID" 2>/dev/null || true
    wait "$TPID" 2>/dev/null || true
    TPID=
    sleep 1
    n=$((n+1))
  done
}

measure "OnetDNS(recurse)" taskset -c 2 "$BIN" --config "$WORK/onetdns-recurse.toml" --no-web --no-supervisor
measure "Unbound"          taskset -c 2 unbound -d -c "$WORK/unbound-recurse.conf"
measure "PowerDNS-Recursor" taskset -c 2 pdns_recursor --config-dir="$WORK" --socket-dir="$WORK"
measure "BIND9"            taskset -c 2 named -g -c "$WORK/named-recurse.conf"
measure "OnetDNS(recurse)" taskset -c 2 "$BIN" --config "$WORK/onetdns-recurse.toml" --no-web --no-supervisor

echo "auth_cpu(root/tld/leaf) 중 하나라도 80% 이상인 회차는 권한 서버 포화로 무효(RATE를 낮춰 재측정)."
echo "artifacts=$WORK"
echo done
