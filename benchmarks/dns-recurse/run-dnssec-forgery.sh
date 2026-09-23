#!/bin/sh
# DNSSEC 보안 점검(강화): 자식 존이 정상적으로 서명돼 있으나 부모 DS가 가리키는
# 키와 다른 키로 서명된 경우(키 치환 위조) 검증 리졸버가 bogus로 거부하는지 확인.
# leaf를 sub 키가 아닌 root 키로 서명 → test.의 DS(sub-ksk)와 불일치 → 거부 기대.
# usage: unshare -rn sh -c 'ip link set lo up; sh run-dnssec-forgery.sh DNSSEC_DIR BIN KEYDIR'
set -eu
D=${1:?dnssec benchdir}
BIN=${2:?binary}
KEYDIR=${3:?keydir(root-zsk/root-ksk 필요)}
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

# leaf를 root 키로 재서명하도록 설정 치환(부모 test.의 DS는 sub-ksk 그대로).
sed -e "s#$KEYDIR/sub-zsk.pem#$KEYDIR/root-zsk.pem#g" \
    -e "s#$KEYDIR/sub-ksk.pem#$KEYDIR/root-ksk.pem#g" \
    "$D/authority-leaf.toml" > "$WORK/leaf-wrongkey.toml"

taskset -c 0 "$BIN" --config "$D/authority-root.toml" --no-web --no-supervisor >"$WORK/ar.log" 2>&1 &
track $!
taskset -c 0 "$BIN" --config "$D/authority-tld.toml" --no-web --no-supervisor >"$WORK/at.log" 2>&1 &
track $!
taskset -c 0 "$BIN" --config "$WORK/leaf-wrongkey.toml" --no-web --no-supervisor >"$WORK/al.log" 2>&1 &
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

echo "== leaf가 부모 DS와 다른 키로 서명(키 치환 위조) → bogus 기대 =="
status=$(dig +dnssec @127.0.0.1 -p 5300 a00.z0007.test A | awk -F'status: ' '/status:/{split($2,a,","); print a[1]}')
echo "status=$status"
if [ "$status" = "SERVFAIL" ]; then
  echo "RESULT: PASS (DS/DNSKEY 바인딩 강제 — 키 치환 위조 거부)"
else
  echo "RESULT: FAIL (위조 수용! status=$status — 심각)"
  rc=1
fi
echo done
exit "$rc"
