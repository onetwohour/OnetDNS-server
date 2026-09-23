#!/bin/sh
# 가짜 루트 위임 계층과 질의 파일을 생성한다.
# 인자: 출력 디렉터리 [존 수=2000] [존당 이름 수=10] [KEYDIR] [FIXTURES_BIN]
# KEYDIR·FIXTURES_BIN을 주면 DNSSEC 모드: 전 계층 서명(dnssec_sign) + 부모
# 존에 자식 DS 주입 + 루트 앵커 파일(onetdns-root-anchor.txt) 생성.
# KEYDIR에는 root-zsk/root-ksk/sub-zsk/sub-ksk .pem(P-256 PKCS#8)이 필요하다.
# 없으면 openssl로 만든다. FIXTURES_BIN은 examples/dnssec_bench_fixtures 빌드다.
set -eu
OUT=${1:?usage: generate-delegation.sh OUTDIR [ZONES] [NAMES_PER_ZONE] [KEYDIR] [FIXTURES_BIN]}
ZONES=${2:-2000}
NAMES_PER_ZONE=${3:-10}
KEYDIR=${4:-}
FIXTURES=${5:-}
DNSSEC=0
if [ -n "$KEYDIR" ] && [ -n "$FIXTURES" ]; then
  DNSSEC=1
  mkdir -p "$KEYDIR"
  for k in root-zsk root-ksk sub-zsk sub-ksk; do
    [ -f "$KEYDIR/$k.pem" ] && continue
    command -v openssl >/dev/null 2>&1 || {
      echo "missing $KEYDIR/$k.pem and openssl is not installed" >&2
      exit 2
    }
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256       -out "$KEYDIR/$k.pem" 2>/dev/null || {
      echo "failed to generate $KEYDIR/$k.pem" >&2
      exit 2
    }
  done
fi
if ! [ "$ZONES" -ge 1 ] 2>/dev/null; then
  echo "ZONES must be a positive integer" >&2
  exit 2
fi
if ! [ "$NAMES_PER_ZONE" -ge 1 ] 2>/dev/null || [ "$NAMES_PER_ZONE" -gt 254 ]; then
  echo "NAMES_PER_ZONE must be an integer in 1..254" >&2
  exit 2
fi
mkdir -p "$OUT/zones"

# 루트: test. 위임 + 글루 (+DNSSEC 모드: test. DS)
cat >"$OUT/zones/root.zone" <<EOF
\$TTL 3600
. IN SOA ns.root. host.root. 1 3600 900 604800 3600
. IN NS ns.root.
ns.root. IN A 127.0.1.1
test. IN NS ns.test.
ns.test. IN A 127.0.2.1
EOF
if [ "$DNSSEC" = 1 ]; then
  "$FIXTURES" ds "$KEYDIR/sub-zsk.pem" "$KEYDIR/sub-ksk.pem" test. >>"$OUT/zones/root.zone"
  "$FIXTURES" anchor "$KEYDIR/root-zsk.pem" "$KEYDIR/root-ksk.pem" . >"$OUT/onetdns-root-anchor.txt"
  "$FIXTURES" ds "$KEYDIR/root-zsk.pem" "$KEYDIR/root-ksk.pem" . >"$OUT/root-ds.txt"
fi

# TLD: 존 위임 + 공용 리프 NS 글루
{
  printf '$TTL 3600\n'
  printf 'test. IN SOA ns.test. host.test. 1 3600 900 604800 3600\n'
  printf 'test. IN NS ns.test.\n'
  printf 'ns.test. IN A 127.0.2.1\n'
  awk -v zones="$ZONES" 'BEGIN {
    for (i=0; i<zones; i++) printf "z%04d.test. IN NS ns-leaf.test.\n", i
  }'
  printf 'ns-leaf.test. IN A 127.0.3.1\n'
  if [ "$DNSSEC" = 1 ]; then
    awk -v zones="$ZONES" 'BEGIN {
      for (i=0; i<zones; i++) printf "z%04d.test.\n", i
    }' | "$FIXTURES" ds "$KEYDIR/sub-zsk.pem" "$KEYDIR/sub-ksk.pem" -
  fi
} >"$OUT/zones/test.zone"

# 위임 추적을 실제로 강제하려면 각 계층이 자기 존만 아는 별도 프로세스여야 한다.
# 한 서버가 모든 존을 가지면 root 주소로 깊은 이름을 물어도 위임 없이 즉답한다.
COMMON='mode = "personal"\nbackend = "forward"\nworkers = 1\ndo_udp = true\ndo_tcp = false\ncache_enabled = false\nquerylog = false\nlog_level = "warn"\n'
SIGNROOT=""
SIGNSUB=""
if [ "$DNSSEC" = 1 ]; then
  SIGNROOT=", dnssec_sign = true, dnssec_key = \"$KEYDIR/root-zsk.pem\", dnssec_ksk = \"$KEYDIR/root-ksk.pem\""
  SIGNSUB=", dnssec_sign = true, dnssec_key = \"$KEYDIR/sub-zsk.pem\", dnssec_ksk = \"$KEYDIR/sub-ksk.pem\""
fi

# root 계층: root.zone만 서빙(test. 위임)
{
  printf '%b' "$COMMON"
  printf 'listen = ["127.0.1.1:53"]\n'
  printf 'zones = [ { origin = ".", file = "%s/zones/root.zone"%s } ]\n' "$OUT" "$SIGNROOT"
} >"$OUT/authority-root.toml"

# TLD 계층: test.zone만 서빙(zNNNN.test. 위임)
{
  printf '%b' "$COMMON"
  printf 'listen = ["127.0.2.1:53"]\n'
  printf 'zones = [ { origin = "test", file = "%s/zones/test.zone"%s } ]\n' "$OUT" "$SIGNSUB"
} >"$OUT/authority-tld.toml"

# leaf 계층: DNSSEC은 자식 존별 서명 파일, 순수 콜드 측정은 하나의 test.
# 권한 존에서 실제 A 응답을 제공한다. TLD의 자식 위임은 어느 쪽도 동일하다.
LEAF="$OUT/authority-leaf.toml"
{
  printf '%b' "$COMMON"
  printf 'listen = ["127.0.3.1:53"]\n'
} >"$LEAF"
if [ "$DNSSEC" = 1 ]; then
  printf 'zones = [\n' >>"$LEAF"
else
  cat >"$OUT/zones/leaf.test.zone" <<EOF
\$TTL 3600
test. IN SOA ns-leaf.test. host.test. 1 3600 900 604800 3600
test. IN NS ns-leaf.test.
ns-leaf.test. IN A 127.0.3.1
EOF
  printf 'zones = [ { origin = "test", file = "%s/zones/leaf.test.zone" } ]\n' "$OUT" >>"$LEAF"
fi
: >"$OUT/queries-recurse.txt"
if [ "$DNSSEC" = 1 ]; then
  i=0
  while [ "$i" -lt "$ZONES" ]; do
    z=$(printf 'z%04d' "$i")
    leaf_file="$OUT/zones/$z.test.zone"
    {
      printf '$TTL 3600\n'
      printf '%s.test. IN SOA ns-leaf.test. host.%s.test. 1 3600 900 604800 3600\n' "$z" "$z"
      printf '%s.test. IN NS ns-leaf.test.\n' "$z"
      j=0
      while [ "$j" -lt "$NAMES_PER_ZONE" ]; do
        printf 'a%02d.%s.test. IN A 192.0.2.%d\n' "$j" "$z" $((j+1))
        j=$((j+1))
      done
    } >"$leaf_file"
    printf '  { origin = "%s.test", file = "%s/zones/%s.test.zone"%s },\n' "$z" "$OUT" "$z" "$SIGNSUB" >>"$LEAF"
    j=0
    while [ "$j" -lt "$NAMES_PER_ZONE" ]; do
      printf 'a%02d.%s.test. A\n' "$j" "$z" >>"$OUT/queries-recurse.txt"
      j=$((j+1))
    done
    i=$((i+1))
  done
  printf ']\n' >>"$LEAF"
else
  awk -v zones="$ZONES" -v names="$NAMES_PER_ZONE" 'BEGIN {
    for (i=0; i<zones; i++) for (j=0; j<names; j++)
      printf "a%02d.z%04d.test. IN A 192.0.2.%d\n", j, i, j+1
  }' >>"$OUT/zones/leaf.test.zone"
  awk -v zones="$ZONES" -v names="$NAMES_PER_ZONE" 'BEGIN {
    for (i=0; i<zones; i++) for (j=0; j<names; j++)
      printf "a%02d.z%04d.test. A\n", j, i
  }' >"$OUT/queries-recurse.txt"
fi
echo "generated: $ZONES leaf zones x $NAMES_PER_ZONE names, $(wc -l <"$OUT/queries-recurse.txt") queries (root/tld/leaf 3계층 분리)"
