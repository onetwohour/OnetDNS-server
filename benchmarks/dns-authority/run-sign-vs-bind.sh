#!/bin/bash
# BIND 9의 서명 비용을 재고, 파싱+쓰기 몫을 named-compilezone으로 분리한다.
set -e
D="$HOME/cmp-bind"
W="$HOME/signcmp"
export LD_LIBRARY_PATH="$D/root/usr/lib/x86_64-linux-gnu:$D/root/usr/lib/x86_64-linux-gnu/bind9"
SZ="$D/root/usr/bin/dnssec-signzone"
KG="$D/root/usr/bin/dnssec-keygen"
CZ="$D/root/usr/bin/named-compilezone"
OWNERS=${1:-100000}

rm -rf "$W"
mkdir -p "$W"
cd "$W"

{
  echo '$TTL 300'
  echo 'bench.test. 300 IN SOA ns.bench.test. hostmaster.bench.test. 1 300 60 3600 60'
  echo 'bench.test. 300 IN NS ns.bench.test.'
  echo 'ns.bench.test. 300 IN A 192.0.2.53'
  awk -v n="$OWNERS" 'BEGIN{for(i=0;i<n;i++){printf "host%d.bench.test. 60 IN A 192.0.2.%d\n", i, (i%250)+1}}'
} > zone.txt

"$KG" -a ECDSAP256SHA256 -f KSK -q bench.test > /dev/null 2>&1
KEY=$(basename "$(find . -maxdepth 1 -name 'Kbench.test.*.key' | head -1)" .key)
grep -v '^;' "$KEY.key" >> zone.txt
CPUS=$(nproc)

echo "존: $(wc -l < zone.txt)줄, 키: $KEY, 스레드: $CPUS"
echo "BIND: $("$SZ" -V 2>&1 | head -1)"
echo

run3() {
  local label="$1"; shift
  for i in 1 2 3; do
    local S E
    S=$(date +%s%N)
    "$@" > /dev/null 2>&1
    E=$(date +%s%N)
    printf '%s round%d: %d ms\n' "$label" "$i" $(( (E - S) / 1000000 ))
  done
}

if [ -x "$CZ" ]; then
  run3 "compilezone(파싱+쓰기)" "$CZ" -o compiled.zone bench.test zone.txt
else
  echo "named-compilezone 없음"
fi
echo
run3 "signzone(전체)" "$SZ" -o bench.test -N keep -P -z -n "$CPUS" -f signed.zone zone.txt "$KEY"
echo
echo "--- CPU 시간 (user+sys) ---"
/usr/bin/time -f "compilezone  user=%U sys=%S wall=%e" "$CZ" -o compiled.zone bench.test zone.txt > /dev/null 2>>cpu.txt || true
/usr/bin/time -f "signzone     user=%U sys=%S wall=%e" "$SZ" -o bench.test -N keep -P -z -n "$CPUS" -f signed.zone zone.txt "$KEY" > /dev/null 2>>cpu.txt || true
cat cpu.txt
echo
echo "--- 출력 크기 ---"
echo "compiled.zone: $(stat -c %s compiled.zone 2>/dev/null || echo 0) bytes"
echo "signed.zone:   $(stat -c %s signed.zone) bytes"
echo "signed RRSIG:  $(awk '{for(i=1;i<=NF;i++) if($i=="RRSIG" && $(i-1)=="IN"){c++;break}} END{print c+0}' signed.zone)"
echo "signed NSEC:   $(awk '{for(i=1;i<=NF;i++) if($i=="NSEC" && $(i-1)=="IN"){c++;break}} END{print c+0}' signed.zone)"
