#!/bin/sh
# 권한 서버 벤치용 존 파일과 질의 목록을 만든다.
#
# usage: sh generate-zone.sh WORKDIR [OWNERS=100000]
#
# 존은 A 레코드 위주로 만든다 — 권한 서빙의 핵심 경로(이름 조회 → RRset 반환 →
# 응답 인코딩)를 재려는 것이지 RDATA 종류별 파싱을 재려는 것이 아니다. 질의 목록은
# 존 안의 이름만 담아 전부 NOERROR가 나오게 하고, 정답 확인은 첫 이름으로 한다.
set -eu
W=${1:?workdir}
OWNERS=${2:-100000}
mkdir -p "$W"

if [ -s "$W/db.bench.test" ] && [ -s "$W/queries-auth.txt" ]; then
  echo "존과 질의 목록이 이미 있습니다: $W"
  exit 0
fi

{
  echo '$TTL 3600'
  echo '@ IN SOA ns1.bench.test. hostmaster.bench.test. 1 3600 600 86400 300'
  echo '@ IN NS ns1.bench.test.'
  echo 'ns1 IN A 127.0.0.1'
  awk -v n="$OWNERS" 'BEGIN{
    for (i = 0; i < n; i++) printf "h%06d IN A 192.0.2.%d\n", i, (i % 254) + 1
  }'
} > "$W/db.bench.test"

awk -v n="$OWNERS" 'BEGIN{
  for (i = 0; i < n; i++) printf "h%06d.bench.test. A\n", i
}' > "$W/queries-auth.txt"

printf 'zone=%s owners=%s queries=%s\n' \
  "$W/db.bench.test" "$OWNERS" "$(wc -l < "$W/queries-auth.txt")"
