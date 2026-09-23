#!/bin/sh
# 서명된 3계층에 대해 검증 리졸버가 정답+AD, 오염엔 SERVFAIL을 내는지 확인.
# usage: unshare -rn sh -c 'ip link set lo up; sh run-dnssec-smoke.sh BENCHDIR BIN'
set -eu
D=${1:?dnssec benchdir}
BIN=${2:?binary}
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
PIDS=""
rc=0
cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null || true; done
  for p in $PIDS; do wait "$p" 2>/dev/null || true; done
}
trap cleanup EXIT
trap 'trap - EXIT; cleanup; exit 130' HUP INT TERM
track() { PIDS="$PIDS $1"; }
taskset -c 0 "$BIN" --config "$D/authority-root.toml" --no-web --no-supervisor >"$D/ar.log" 2>&1 &
track $!
taskset -c 0 "$BIN" --config "$D/authority-tld.toml" --no-web --no-supervisor >"$D/at.log" 2>&1 &
track $!
taskset -c 0 "$BIN" --config "$D/authority-leaf.toml" --no-web --no-supervisor >"$D/al.log" 2>&1 &
track $!
sleep 4
sed -e "s/^dnssec = .*/dnssec = true/" "$SRC/onetdns-recurse.toml" > "$D/resolver.toml"
{
  echo "dnssec_anchor_file = \"$D/onetdns-root-anchor.txt\""
  echo "dnssec_rfc5011 = true"
  echo "dnssec_strict = true"
} >> "$D/resolver.toml"
# A/B 실험용: 추가 설정 줄을 환경으로 주입한다.
if [ -n "${ONETDNS_EXTRA_CONF:-}" ]; then
  printf '%s\n' "$ONETDNS_EXTRA_CONF" >> "$D/resolver.toml"
fi
taskset -c 2 "$BIN" --config "$D/resolver.toml" --no-web --no-supervisor >"$D/r.log" 2>&1 &
track $!
sleep 8
echo "== 서명된 이름 검증(AD 기대) =="
# 출력만 찍고 끝내면 SERVFAIL이어도 성공 종료라 스모크가 아무것도 보장하지 못한다.
# NOERROR + AD 비트 + 정답 RDATA를 모두 단정한다(+short는 flags를 버려 AD를 못 본다).
resp=$(dig +dnssec @127.0.0.1 -p 5300 a00.z0007.test A 2>/dev/null || true)
printf '%s
' "$resp" | grep -E "flags:|status:|192.0.2" || true
printf '%s
' "$resp" | grep -q "status: NOERROR" || { echo "SMOKE: FAIL (NOERROR 아님)"; rc=1; }
printf '%s
' "$resp" | grep -E '^;; flags:' | grep -q ' ad[ ;]' || { echo "SMOKE: FAIL (AD 없음 — 검증되지 않음)"; rc=1; }
printf '%s
' "$resp" | grep -q "192.0.2.1" || { echo "SMOKE: FAIL (정답 RDATA 없음)"; rc=1; }
if [ "$rc" = 0 ]; then echo "SMOKE: PASS (NOERROR + AD + 정답)"; fi
grep -iE "rfc5011|bogus|validation" "$D/r.log" | tail -3 || true
echo done
exit "$rc"
