#!/bin/sh
# DNSSEC 검증 workload의 CPU를 엔진별로 분해한다. 처리량만 보면 "누가 빠른가"만
# 알 수 있고 "왜"를 알 수 없다 — 코어를 못 채운 것인지(유휴) 일이 비싼 것인지
# (해석당 CPU) 구분해야 고칠 곳이 정해진다.
#
# usage: unshare -rn sh -c 'ip link set lo up; sh run-dnssec-cpu-decompose.sh DNSSEC_DIR BIN [WORKERS]'
#   WORKERS: OnetDNS 워커 수(0=출하 자동, 1=스레드 대등). 기본 1.
#
# 두 엔진 모두 CPU 2에 고정하고, 부하 전후의 /proc/<pid>/stat utime+stime 차이로
# 실제 소비 CPU를 재며, 검증이 실제로 일어났는지 AD 비트로 확인한다.
set -eu
D=${1:?dnssec benchdir}
BIN=${2:?onetdns binary}
WORKERS=${3:-1}
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
PIDS=""
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
trap 'trap - EXIT; cleanup; exit 130' HUP INT TERM

for cfg in authority-root authority-tld authority-leaf; do
  taskset -c 0 "$BIN" --config "$D/$cfg.toml" --no-web --no-supervisor >"$D/cpu-$cfg.log" 2>&1 &
  PIDS="$PIDS $!"
done
sleep 4

{
  echo '. IN NS ns.root.'
  echo 'ns.root. IN A 127.0.1.1'
} > "$D/cpu-root.hints"
sed -e "s|ROOTHINTS|$D/cpu-root.hints|g" \
    -e 's|module-config: "iterator"|module-config: "validator iterator"|' \
    -e 's|qname-minimisation: no|qname-minimisation: yes|' \
    "$SRC/unbound-recurse.conf" > "$D/cpu-unbound.conf"
{
  echo "server:"
  echo "  trust-anchor: \"$(cat "$D/root-ds.txt")\""
} >> "$D/cpu-unbound.conf"

sed -e "s/^dnssec = .*/dnssec = true/" -e "s/^workers = .*/workers = $WORKERS/" \
  "$SRC/onetdns-recurse.toml" > "$D/cpu-onetdns.toml"
{
  echo "dnssec_anchor_file = \"$D/onetdns-root-anchor.txt\""
  echo "dnssec_rfc5011 = true"
  echo "dnssec_strict = true"
} >> "$D/cpu-onetdns.toml"
# A/B용 추가 설정 줄.
if [ -n "${ONETDNS_EXTRA_CONF:-}" ]; then
  printf '%s\n' "$ONETDNS_EXTRA_CONF" >> "$D/cpu-onetdns.toml"
fi

# /proc/PID/stat의 utime+stime. 프로세스 이름에 공백·괄호가 들어갈 수 있어
# (NSD가 실제로 "nsd: main" 꼴이다) 마지막 ") "까지 잘라낸 뒤에 곳을 센다.
proc_cpu() {
  stat=$(cat "/proc/$1/stat" 2>/dev/null || echo "")
  [ -n "$stat" ] || { echo 0; return; }
  printf '%s' "${stat##*") "}" | awk '{print $12 + $13}'
}

decompose() { # label cmd...
  lbl=$1; shift
  "$@" >"$D/cpu-$lbl.log" 2>&1 &
  P=$!
  sleep 6
  resp=$(dig +dnssec @127.0.0.1 -p 5300 a00.z0007.test A 2>/dev/null || true)
  if ! printf '%s\n' "$resp" | grep -q "status: NOERROR" ||
     ! printf '%s\n' "$resp" | grep -E '^;; flags:' | grep -q ' ad[ ;]'; then
    printf '%s: 검증 확인 실패(NOERROR+AD 아님) — 이 수치는 무효다\n' "$lbl"
    kill "$P" 2>/dev/null || true
    wait "$P" 2>/dev/null || true
    sleep 1
    return 0
  fi
  before=$(proc_cpu "$P")
  start=$(date +%s%N)
  taskset -c 1 dnsperf -s 127.0.0.1 -p 5300 -d "$D/queries-recurse.txt" -n 1 -q 40 -c 20 -T 1 \
    >"$D/cpu-$lbl.perf" 2>&1 || true
  end=$(date +%s%N)
  after=$(proc_cpu "$P")
  # 해석당 CPU는 소비 CPU를 **완료 질의 수**로 직접 나눈다. 벽시계로 나누면
  # stat 읽기와 타임스탬프 사이의 틈이 그대로 오차가 되어 CPU%가 100%를 넘기도 한다.
  awk -v b="$before" -v a="$after" -v s="$start" -v e="$end" -v hz="$(getconf CLK_TCK)" \
      -v lbl="$lbl" -v f="$D/cpu-$lbl.perf" '
    BEGIN {
      while ((getline line < f) > 0) {
        if (line ~ /Queries per second/) { split(line, t, ":"); q = t[2] + 0 }
        if (line ~ /Queries completed/)  { split(line, c, ":"); done = c[2] + 0 }
        if (line ~ /Queries lost/)       { split(line, u, ":"); lost = u[2] + 0 }
      }
      cpu = (a - b) / hz
      wall = (e - s) / 1000000000
      printf "%s: qps=%.0f us_per_resolution=%.1f cpu_pct_approx=%.1f completed=%d lost=%d\n",
        lbl, q, (done > 0 ? cpu/done*1000000 : 0), cpu/wall*100, done, lost
    }'
  kill "$P" 2>/dev/null || true
  wait "$P" 2>/dev/null || true
  sleep 1
}

decompose "onetdns_w$WORKERS" taskset -c 2 "$BIN" --config "$D/cpu-onetdns.toml" \
  --no-web --no-supervisor
decompose unbound taskset -c 2 unbound -d -c "$D/cpu-unbound.conf"
echo done
