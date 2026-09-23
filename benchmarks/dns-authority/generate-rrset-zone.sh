#!/bin/sh
# 이름 하나에 A 레코드가 여러 개 붙은 존을 만든다.
#
# usage: sh generate-rrset-zone.sh WORKDIR [OWNERS=100000] [RECORDS_PER_OWNER=16]
#
# 기본 존은 이름당 A 하나라 응답이 54바이트에서 끝난다. 실제 배포에서 흔한 것은
# CDN A 무리·MX·NS처럼 이름 하나에 RRset이 여럿 달린 형태이고, 그때는 이름 조회보다
# **RRset 순회와 응답 인코딩**이 비용을 지배한다. 이 축을 따로 재려는 것이다.
set -eu
W=${1:?usage: generate-rrset-zone.sh WORKDIR [OWNERS] [RECORDS_PER_OWNER]}
OWNERS=${2:-100000}
RECORDS=${3:-16}
if ! [ "$OWNERS" -ge 1 ] 2>/dev/null; then
  echo "OWNERS must be a positive integer" >&2
  exit 2
fi
# 254를 넘으면 마지막 옥텟이 겹쳐 RRset 안에 같은 레코드가 생긴다. 중복 RRSet은
# 엔진마다 다루는 방식이 달라 비교가 오염된다.
if ! [ "$RECORDS" -ge 1 ] 2>/dev/null || [ "$RECORDS" -gt 254 ]; then
  echo "RECORDS_PER_OWNER must be between 1 and 254" >&2
  exit 2
fi
mkdir -p "$W"

if [ -s "$W/db.rrset.bench.test" ] && [ -s "$W/queries-auth-rrset.txt" ]; then
  echo "존과 질의 목록이 이미 있습니다: $W"
  exit 0
fi

{
  echo '$TTL 3600'
  echo '@ IN SOA ns1.bench.test. hostmaster.bench.test. 1 3600 600 86400 300'
  echo '@ IN NS ns1.bench.test.'
  echo 'ns1 IN A 127.0.0.1'
  # 대역을 192.0.2.0/24로 고정한다. 하네스의 정답 확인이 192.0.2.x를 기대하는데,
  # RRset 안의 순서는 엔진마다 다르므로 일부만 그 대역이면 확인이 순서에 좌우된다.
  awk -v n="$OWNERS" -v r="$RECORDS" 'BEGIN {
    for (i = 0; i < n; i++) {
      for (j = 0; j < r; j++) {
        printf "h%06d IN A 192.0.2.%d\n", i, ((i + j) % 254) + 1
      }
    }
  }'
} > "$W/db.rrset.bench.test"

awk -v n="$OWNERS" 'BEGIN {
  for (i = 0; i < n; i++) printf "h%06d.bench.test. A\n", i
}' > "$W/queries-auth-rrset.txt"

printf 'zone=%s owners=%s records_per_owner=%s queries=%s\n' \
  "$W/db.rrset.bench.test" "$OWNERS" "$RECORDS" "$(wc -l < "$W/queries-auth-rrset.txt")"
