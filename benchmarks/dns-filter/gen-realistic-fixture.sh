#!/bin/sh
# 실제 차단 목록의 구조를 모델링한 픽스처를 만든다. `run-filter-interleave.sh`는
# 워크디렉터리에 파일이 이미 있으면 그대로 쓰므로, 그 앞에 이 스크립트를 돌리면
# 붕괴 픽스처 대신 이 픽스처로 같은 하네스를 돌릴 수 있다.
#
# **왜 필요한가**: 기본 픽스처(`||b000000.example^`)는 공통 접미사만 다른 이름이라
# automaton이 붕괴한다 — 10만 규칙에서 상태가 수십 개로 줄어 메모리 비교가 무의미해진다.
# 실제 목록은 등록 도메인이 다양하되 서브도메인 라벨(ads/track/analytics...)이 반복되고
# 한 도메인 아래 여러 항목이 붙는다. 아래 생성기는 그 구조를 모델링한 것이지 실제
# 목록이 아니다 — 진짜 목록을 구할 수 있으면 그것으로 교체하는 편이 언제나 낫다.
#
# usage: sh gen-realistic-fixture.sh WORKDIR [RULES=100000] [QUERIES=20000]
set -eu
W=${1:?workdir}
RULES=${2:-100000}
QUERIES=${3:-20000}
mkdir -p "$W"

# 중복이 생기므로 넉넉히 추출해 정렬·중복 제거한 뒤 정확히 RULES개로 자른다.
awk -v n="$((RULES * 2))" 'BEGIN {
    srand(11);
    split("com net org io ru cn info biz top xyz", tld, " ");
    split("ads ad track tracker analytics stat stats metrics pixel beacon cdn img static log event collect sync rtb bid px t a", sub_, " ");
    ndom = int(n / 8) + 1;
    for (d = 0; d < ndom; d++) {
        len = 5 + int(rand() * 9); lab = "";
        for (j = 0; j < len; j++) lab = lab sprintf("%c", 97 + int(rand() * 26));
        dom[d] = lab "." tld[1 + int(rand() * 10)];
    }
    for (i = 0; i < n; i++) {
        d = int(rand() * ndom); r = rand();
        if (r < 0.25) name = dom[d];
        else if (r < 0.85) name = sub_[1 + int(rand() * 22)] "." dom[d];
        else name = sub_[1 + int(rand() * 22)] "." sub_[1 + int(rand() * 22)] "." dom[d];
        print name;
    }
}' | sort -u | head -n "$RULES" > "$W/names.txt"

have=$(wc -l < "$W/names.txt")
if [ "$have" -lt "$RULES" ]; then
    echo "고유 이름이 $have 개뿐이다 — 생성 배수를 늘려라" >&2
    exit 1
fi

awk '{ printf "||%s^\n", $0 }' "$W/names.txt" > "$W/blocklist.txt"
# 질의는 반드시 차단 목록 안의 이름이어야 한다 — 하네스의 정답 확인이 곧 실차단 증명이다.
awk -v q="$QUERIES" 'BEGIN { srand(13) } { all[NR] = $0 } END {
    for (i = 0; i < q; i++) printf "%s A\n", all[1 + int(rand() * NR)];
}' "$W/names.txt" > "$W/blocked-queries.txt"
rm -f "$W/names.txt"

echo "rules=$(wc -l < "$W/blocklist.txt") queries=$(wc -l < "$W/blocked-queries.txt")"
