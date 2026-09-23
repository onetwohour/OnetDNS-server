#!/bin/sh
# 재귀 정상상태를 QPS가 아니라 해석당 CPU로 판정한다.
#
# 이 호스트에서 정상상태 QPS 드리프트는 두 엔진 모두 23~25%라 8% 마진을 가릴 수 없다.
# 워밍 탓이 아니다 — 엔진을 한 번만 시작하고 잇달아 재도 같은 폭으로 흔들리고, 같은 창에서
# Unbound가 더 크게 흔들린 회차도 있다. 호스트에서 오는 것이다.
#
# 그래서 권한 축에서 쓰던 방법을 그대로 옮긴다. 프로세스 CPU(utime+stime)를 완료 질의 수로
# 나누면 같은 창 드리프트가 1.8% 남짓으로 내려가 마진이 드리프트의 서너 배가 된다.
# 라운드마다 두 엔진의 순서를 뒤집어 순서 편향까지 통제하고, **라운드 안의 비율로만**
# 판정한다 — 창은 시간에 따라 함께 열화하므로 절대값을 라운드 밖으로 인용하지 말 것.
#
# usage: unshare -rn sh -c 'ip link set lo up; sh run-recurse-cpu-interleave.sh BENCHDIR ONETDNS_BIN [ROUNDS] [RATE]'
# BENCHDIR 예: /home/ubuntu/onetdns-bench/recurse
set -eu

H=${1:?usage: run-recurse-cpu-interleave.sh BENCHDIR ONETDNS_BIN [ROUNDS] [RATE]}
BIN=${2:?onetdns binary path}
ROUNDS=${3:-10}
RATE=${4:-1000000}
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
Q="$H/queries-recurse.txt"
PROBE=$(awk 'NR==1{print $1}' "$Q")
WORK="$H/cpu-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir "$WORK" || { echo "작업 디렉터리를 만들 수 없습니다: $WORK" >&2; exit 1; }
ROOTHINTS="$WORK/root.hints"
PIDS=""
cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null || true; done
  for p in $PIDS; do wait "$p" 2>/dev/null || true; done
}
abort() { trap - EXIT; cleanup; exit 130; }
trap cleanup EXIT
trap abort HUP INT TERM

cat >"$ROOTHINTS" <<EOF
.                        3600000      NS    ns.root.
ns.root.                 3600000      A     127.0.1.1
EOF
sed "s|ROOTHINTS|$ROOTHINTS|g" "$SRC/unbound-recurse.conf" >"$WORK/unbound-recurse.conf"
cp "$SRC/onetdns-recurse.toml" "$WORK/onetdns-recurse.toml"

for role in root tld leaf; do
  taskset -c 0 "$BIN" --config "$H/authority-$role.toml" --no-web --no-supervisor \
    >"$WORK/$role.log" 2>&1 &
  PIDS="$PIDS $!"
done
sleep 3
for pid in $PIDS; do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "권한 서버 시작 실패:" >&2
    tail -n 3 "$WORK"/*.log >&2
    exit 1
  fi
done

TICKS=$(getconf CLK_TCK)

# /proc/PID/stat의 utime+stime. 프로세스 이름에 공백·괄호가 들어갈 수 있어
# (NSD가 실제로 "nsd: main" 꼴이다) 마지막 ") "까지 잘라낸 뒤에 곳을 센다.
# cutime/cstime은 더하지 않는다 — 거둬들인 자식의 CPU라 이 축이 재려는 것과 다르고,
# 다른 하네스도 utime+stime으로 통일돼 있다.
proc_cpu() {
  stat=$(cat "/proc/$1/stat" 2>/dev/null || echo "")
  [ -n "$stat" ] || { echo 0; return; }
  printf '%s' "${stat##*") "}" | awk '{print $12 + $13}'
}

# 엔진 하나를 시작해 워밍한 뒤 계측 구간의 CPU와 완료 질의 수를 측정한다.
round() {
  label=$1
  shift
  "$@" >"$WORK/target.log" 2>&1 &
  tpid=$!
  sleep 3
  probe=$(dig +time=3 +tries=1 @127.0.0.1 -p 5300 "$PROBE" A 2>/dev/null || true)
  if ! printf '%s\n' "$probe" | grep -q "status: NOERROR"; then
    echo "  $label: 정답 확인 실패 — 이 회차는 무효다" >&2
    kill "$tpid" 2>/dev/null || true
    wait "$tpid" 2>/dev/null || true
    return 0
  fi
  # 콜드 재귀를 계측 구간 밖으로 밀어낸다. 이 축은 정상상태를 측정하는 것이다.
  taskset -c 1 dnsperf -s 127.0.0.1 -p 5300 -d "$Q" -l 5 -Q "$RATE" -q 50 -c 1 -T 1 \
    >/dev/null 2>&1 || true

  before=$(proc_cpu "$tpid")
  if ! out=$(taskset -c 1 dnsperf -s 127.0.0.1 -p 5300 -d "$Q" -l 8 -Q "$RATE" -q 50 -c 1 -T 1 2>/dev/null \
    | awk '
        /Queries completed/ { gsub(",", "", $3); c=$3 }
        /Queries per second/ { q=$4 }
        END { if (c == "" || q == "") exit 1; printf "%s %.0f", c, q }'); then
    echo "  $label: dnsperf 결과를 읽지 못했습니다" >&2
    kill "$tpid" 2>/dev/null || true
    wait "$tpid" 2>/dev/null || true
    return 0
  fi
  after=$(proc_cpu "$tpid")
  kill "$tpid" 2>/dev/null || true
  wait "$tpid" 2>/dev/null || true
  sleep 1

  echo "$label $before $after $out" | awk -v ticks="$TICKS" '{
    printf "  %-8s cpu_us_per_resolution=%.4f qps=%s completed=%s\n", \
      $1, ($3 - $2) * (1000000.0 / ticks) / $4, $5, $4
  }'
}

n=1
while [ "$n" -le "$ROUNDS" ]; do
  echo "--- round $n ---"
  if [ $((n % 2)) -eq 1 ]; then
    round onetdns taskset -c 2 "$BIN" --config "$WORK/onetdns-recurse.toml" --no-web --no-supervisor
    round unbound taskset -c 2 unbound -d -c "$WORK/unbound-recurse.conf"
  else
    round unbound taskset -c 2 unbound -d -c "$WORK/unbound-recurse.conf"
    round onetdns taskset -c 2 "$BIN" --config "$WORK/onetdns-recurse.toml" --no-web --no-supervisor
  fi
  n=$((n + 1))
done
echo "artifacts=$WORK"
echo done
