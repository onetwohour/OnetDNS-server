#!/bin/bash
# root 없이 BIND 유틸을 홈 아래에 푼다. 시스템 경로는 건드리지 않는다.
set -e
D="$HOME/cmp-bind"
if [ -x "$D/root/usr/bin/dnssec-signzone" ]; then
  echo "이미 있음: $D"
else
  rm -rf "$D"
  mkdir -p "$D"
  cd "$D"
  apt-get download bind9-utils bind9-dnsutils bind9-libs libuv1t64 libjson-c5 libmaxminddb0 > /dev/null 2>&1
  mkdir -p root
  for f in *.deb; do dpkg -x "$f" root; done
fi
export LD_LIBRARY_PATH="$D/root/usr/lib/x86_64-linux-gnu:$D/root/usr/lib/x86_64-linux-gnu/bind9"
echo "--- 실행 확인 ---"
"$D/root/usr/bin/dnssec-signzone" -h 2>&1 | head -2
"$D/root/usr/bin/dnssec-keygen" -h 2>&1 | head -2
echo "--- 버전 ---"
"$D/root/usr/bin/dnssec-signzone" -V 2>&1 | head -2 || true
