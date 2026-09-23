#!/bin/bash
# BIND의 단일 스레드 서명 CPU를 측정한다. onetdns 순차판과 직접 비교할 수 있는 축이다.
set -e
D="$HOME/cmp-bind"
W="$HOME/signcmp"
export LD_LIBRARY_PATH="$D/root/usr/lib/x86_64-linux-gnu:$D/root/usr/lib/x86_64-linux-gnu/bind9"
SZ="$D/root/usr/bin/dnssec-signzone"
CZ="$D/root/usr/bin/named-compilezone"
cd "$W"
KEY=$(basename "$(find . -maxdepth 1 -name 'Kbench.test.*.key' | head -1)" .key)
echo "key=$KEY  zone=$(wc -l < zone.txt)줄"

echo "--- BIND signzone -n 1 (단일 스레드) ---"
for i in 1 2 3; do
  /usr/bin/time -f "round$i user=%U sys=%S wall=%e" \
    "$SZ" -o bench.test -N keep -P -z -n 1 -f s1.zone zone.txt "$KEY" > /dev/null
done

echo "--- BIND compilezone (파싱+쓰기, 단일) ---"
for i in 1 2; do
  /usr/bin/time -f "round$i user=%U sys=%S wall=%e" \
    "$CZ" -o c1.zone bench.test zone.txt > /dev/null
done

echo "--- 서명 수 확인 ---"
printf 'RRSIG: '; grep -cP '\tRRSIG\t' s1.zone
printf 'NSEC:  '; grep -cP '\tNSEC\t' s1.zone
