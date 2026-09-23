#!/bin/sh
# DNSSEC 보안 점검: 검증 리졸버가 (1) 정상 서명은 AD로 수용, (2) 서명이
# 깨진 존은 SERVFAIL(bogus)로 거부하는지 확인. 후자가 통과의 핵심 —
# 검증이 실제로 위조를 막는지 증명한다.
# usage: unshare -rn sh -c 'ip link set lo up; sh run-dnssec-bogus.sh DNSSEC_DIR BIN'
set -eu
D=${1:?dnssec benchdir}
BIN=${2:?binary}
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
WORK="$D/run"
mkdir -p "$WORK"

PIDS=""
rc=0
cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null || true; done
  for p in $PIDS; do wait "$p" 2>/dev/null || true; done
}
trap cleanup EXIT
trap 'trap - EXIT; cleanup; exit 130' HUP INT TERM
track() { PIDS="$PIDS $1"; }

# 정상 leaf 존을 복제해 서명 대상 A 레코드의 주소를 서명 후 조작할 수는 없으니,
# 대신 "서명 없이 dnssec_sign을 끈 leaf"를 만들어 부모(test)엔 DS가 남아 있게 한다.
# → 자식이 서명을 제시하지 못하므로 검증 리졸버는 bogus로 거부해야 한다.
cp "$D/authority-leaf.toml" "$WORK/leaf-unsigned.toml"
sed -i 's/, dnssec_sign = true[^}]*}/ }/g' "$WORK/leaf-unsigned.toml"

taskset -c 0 "$BIN" --config "$D/authority-root.toml" --no-web --no-supervisor >"$WORK/ar.log" 2>&1 &
track $!
taskset -c 0 "$BIN" --config "$D/authority-tld.toml" --no-web --no-supervisor >"$WORK/at.log" 2>&1 &
track $!
taskset -c 0 "$BIN" --config "$WORK/leaf-unsigned.toml" --no-web --no-supervisor >"$WORK/al.log" 2>&1 &
track $!
sleep 4

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

echo "== 부모(test)에 DS가 있으나 자식(z0007)이 서명 미제시 → bogus 기대 =="
status=$(dig +dnssec @127.0.0.1 -p 5300 a00.z0007.test A | awk -F'status: ' '/status:/{split($2,a,","); print a[1]}')
echo "status=$status"
if [ "$status" = "SERVFAIL" ]; then
  echo "RESULT: PASS (검증이 위조/미서명 자식을 거부)"
else
  rc=1
  echo "RESULT: FAIL (검증 우회! status=$status — 심각)"
fi
echo done
exit "$rc"
