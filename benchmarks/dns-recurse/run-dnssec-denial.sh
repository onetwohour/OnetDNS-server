#!/bin/sh
# DNSSEC 보안 점검(부재 증명): 서명된 존의 존재하지 않는 이름에 대해
# (1) 검증 리졸버가 인증된 NXDOMAIN(AD 비트)을 반환하는지,
# (2) 부인 증명(NSEC/NSEC3)이 제거된 위조 부인을 bogus로 거부하는지 확인.
# usage: unshare -rn sh -c 'ip link set lo up; sh run-dnssec-denial.sh DNSSEC_DIR BIN'
set -eu
D=${1:?dnssec benchdir}
BIN=${2:?binary}
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
WORK="$D/run"
mkdir -p "$WORK"

PIDS=""
rc=0
# 이 스크립트가 시작한 프로세스만 종료한다(pkill은 같은 이름의 남의 프로세스까지 죽인다).
stop_tracked() {
  for p in $PIDS; do kill "$p" 2>/dev/null || true; done
  for p in $PIDS; do wait "$p" 2>/dev/null || true; done
  PIDS=""
}
trap stop_tracked EXIT
trap 'trap - EXIT; stop_tracked; exit 130' HUP INT TERM
track() { PIDS="$PIDS $1"; }
sleep 1

taskset -c 0 "$BIN" --config "$D/authority-root.toml" --no-web --no-supervisor >"$WORK/ar.log" 2>&1 &
track $!
taskset -c 0 "$BIN" --config "$D/authority-tld.toml" --no-web --no-supervisor >"$WORK/at.log" 2>&1 &
track $!
taskset -c 0 "$BIN" --config "$D/authority-leaf.toml" --no-web --no-supervisor >"$WORK/al.log" 2>&1 &
track $!
sleep 4

# 권한 서버가 부재 증명(NSEC/NSEC3)을 직접 내는지 먼저 확인
echo "== leaf 직접: 없는 이름의 부인 증명 유형 =="
denial=$(dig +norec +dnssec @127.0.3.1 nope.z0007.test A | awk '/IN[[:space:]]+(NSEC|NSEC3)/{print $4}' | sort -u | tr '\n' ' ')
echo "denial_records=[$denial]"

sed -e "s/^dnssec = .*/dnssec = true/" "$SRC/onetdns-recurse.toml" > "$WORK/val.toml"
{
  echo "dnssec_anchor_file = \"$D/onetdns-root-anchor.txt\""
  echo "dnssec_rfc5011 = true"
  echo "dnssec_strict = true"
} >> "$WORK/val.toml"
# A/B 실험용: 추가 설정 줄을 환경으로 주입한다.
if [ -n "${ONETDNS_EXTRA_CONF:-}" ]; then
  printf '%s
' "$ONETDNS_EXTRA_CONF" >> "$WORK/val.toml"
fi
taskset -c 2 "$BIN" --config "$WORK/val.toml" --no-web --no-supervisor >"$WORK/r.log" 2>&1 &
track $!
sleep 8

echo "== 검증 리졸버: 없는 이름 → 인증된 NXDOMAIN(AD) 기대 =="
hdr=$(dig +dnssec @127.0.0.1 -p 5300 nope.z0007.test A | grep -E "flags:|status:")
echo "$hdr"
if echo "$hdr" | grep -q "status: NXDOMAIN" && echo "$hdr" | grep -q " ad;"; then
  echo "DENIAL_RESULT: PASS (인증된 부재 증명 — AD NXDOMAIN)"
elif echo "$hdr" | grep -q "status: NXDOMAIN"; then
  echo "DENIAL_RESULT: PARTIAL (NXDOMAIN이나 AD 없음 — 부인 미검증)"
  rc=1
else
  echo "DENIAL_RESULT: CHECK ($hdr)"
  rc=1
fi
# 1단계 서버를 반드시 내린 뒤 2단계를 시작한다. 남겨 두면 SO_REUSEPORT로 같은 포트를
# 나눠 가져 서명된 1단계가 답할 수 있고, 그러면 이 검사가 통과한 것처럼 보인다.
stop_tracked
sleep 1

# 음성: 부모 DS가 있는데 자식이 미서명 → 부인 증명을 인증 못 함 → bogus 기대.
# (서명 없는 NXDOMAIN을 수용하면 공격자가 실재 이름을 없는 것처럼 숨길 수 있다.)
cp "$D/authority-leaf.toml" "$WORK/leaf-unsigned.toml"
sed -i 's/, dnssec_sign = true[^}]*}/ }/g' "$WORK/leaf-unsigned.toml"
taskset -c 0 "$BIN" --config "$D/authority-root.toml" --no-web --no-supervisor >"$WORK/ar2.log" 2>&1 &
track $!
taskset -c 0 "$BIN" --config "$D/authority-tld.toml" --no-web --no-supervisor >"$WORK/at2.log" 2>&1 &
track $!
taskset -c 0 "$BIN" --config "$WORK/leaf-unsigned.toml" --no-web --no-supervisor >"$WORK/al2.log" 2>&1 &
track $!
sleep 4
taskset -c 2 "$BIN" --config "$WORK/val.toml" --no-web --no-supervisor >"$WORK/r2.log" 2>&1 &
track $!
sleep 8
echo "== 미서명 자식의 NXDOMAIN → bogus(SERVFAIL) 기대 =="
st=$(dig +dnssec @127.0.0.1 -p 5300 nope.z0007.test A | awk -F'status: ' '/status:/{split($2,a,","); print a[1]}')
echo "status=$st"
if [ "$st" = "SERVFAIL" ]; then
  echo "FORGED_DENIAL_RESULT: PASS (미인증 부인 거부 — NSEC 다운그레이드 차단)"
else
  echo "FORGED_DENIAL_RESULT: FAIL (미인증 NXDOMAIN 수용! status=$st — 심각)"
  rc=1
fi
echo done
exit "$rc"
