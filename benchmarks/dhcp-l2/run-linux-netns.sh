#!/usr/bin/env bash
# Isolated DHCPv4 initial-unicast and interface-bound broadcast proof. Run as root; only disposable
# netns/veth state is changed.
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "run-linux-netns.sh must run as root" >&2
  exit 2
fi
if [[ $# -ne 1 ]]; then
  echo "usage: $0 /absolute/path/to/OnetDNS" >&2
  exit 2
fi

binary=$(readlink -f -- "$1")
if [[ ! -x "$binary" ]]; then
  echo "OnetDNS binary is not executable: $binary" >&2
  exit 2
fi

suffix="$$"
server_ns="onetdns-dhcp-s-$suffix"
client_ns="onetdns-dhcp-c-$suffix"
server_if="odhs$((suffix % 100000))"
client_if="odhc$((suffix % 100000))"
work=$(mktemp -d)
server_pid=""

cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  ip netns delete "$client_ns" 2>/dev/null || true
  ip netns delete "$server_ns" 2>/dev/null || true
  rm -f -- "$work/onetdns.toml" "$work/server.log"
  rmdir -- "$work" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

ip netns add "$server_ns"
ip netns add "$client_ns"
ip link add "$server_if" type veth peer name "$client_if"
ip link set "$server_if" netns "$server_ns"
ip link set "$client_if" netns "$client_ns"
ip -n "$server_ns" link set lo up
ip -n "$client_ns" link set lo up
ip -n "$server_ns" address add 192.0.2.1/24 dev "$server_if"
ip -n "$server_ns" link set "$server_if" up
ip -n "$client_ns" link set "$client_if" up

cat >"$work/onetdns.toml" <<EOF
mode = "personal"
backend = "forward"
listen = ["192.0.2.1:5353"]
upstream_urls = ["udp://192.0.2.254:53"]
workers = 1
do_udp = true
do_tcp = false
dnssec = false
cache_enabled = false
querylog = false
dhcp_enable = true
dhcp_server_ip = "192.0.2.1"
dhcp_range_start = "192.0.2.100"
dhcp_range_end = "192.0.2.110"
dhcp_subnet_mask = "255.255.255.0"
dhcp_router = "192.0.2.1"
dhcp_dns = ["192.0.2.1"]
dhcp_lease_secs = 3600
EOF

ip netns exec "$server_ns" "$binary" --config "$work/onetdns.toml" \
  --no-web --no-supervisor >"$work/server.log" 2>&1 &
server_pid=$!

ready=0
for _ in $(seq 1 50); do
  if ! kill -0 "$server_pid" 2>/dev/null; then
    break
  fi
  if ip netns exec "$server_ns" ss -H -lun | grep -qE '(^|:)67[[:space:]]'; then
    ready=1
    break
  fi
  sleep 0.05
done
if [[ $ready -ne 1 ]]; then
  cat "$work/server.log" >&2
  echo "DHCP server did not bind UDP 67" >&2
  exit 1
fi

for mode in unicast broadcast; do
ip netns exec "$client_ns" python3 - "$client_if" "$mode" <<'PY'
import socket
import struct
import sys
import time

iface, mode = sys.argv[1], sys.argv[2]
with open(f"/sys/class/net/{iface}/address", "rt", encoding="ascii") as handle:
    client_mac = bytes.fromhex(handle.read().strip().replace(":", ""))

xid = 0x4f4e4554 if mode == "unicast" else 0x4f4e4555
request = bytearray(240)
request[0:4] = bytes((1, 1, 6, 0))
request[4:8] = xid.to_bytes(4, "big")
if mode == "broadcast":
    request[10:12] = (0x8000).to_bytes(2, "big")
request[28:34] = client_mac
request[236:240] = bytes((99, 130, 83, 99))
request += bytes((53, 1, 1, 255))

sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
sniffer.bind((iface, 0))
sniffer.settimeout(3.0)
sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sender.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sender.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode() + b"\0")
sender.bind(("0.0.0.0", 68))
sender.sendto(request, ("255.255.255.255", 67))

def checksum(data):
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

deadline = time.monotonic() + 3.0
while time.monotonic() < deadline:
    frame = sniffer.recv(65535)
    if len(frame) < 42 or frame[12:14] != b"\x08\x00":
        continue
    ihl = (frame[14] & 0x0f) * 4
    if ihl < 20 or len(frame) < 14 + ihl + 8:
        continue
    udp_at = 14 + ihl
    source_port, target_port, udp_len, udp_sum = struct.unpack("!HHHH", frame[udp_at:udp_at + 8])
    if (source_port, target_port) != (67, 68):
        continue
    payload = frame[udp_at + 8:udp_at + udp_len]
    if len(payload) < 240 or int.from_bytes(payload[4:8], "big") != xid:
        continue
    want_mac = client_mac if mode == "unicast" else bytes([0xff] * 6)
    want_ip = "192.0.2.100" if mode == "unicast" else "255.255.255.255"
    if frame[:6] != want_mac:
        raise SystemExit(f"{mode}: wrong Ethernet destination: {frame[:6].hex(':')}")
    if frame[30:34] != socket.inet_aton(want_ip):
        raise SystemExit(f"{mode}: wrong IP destination: {socket.inet_ntoa(frame[30:34])}")
    if payload[16:20] != socket.inet_aton("192.0.2.100"):
        raise SystemExit(f"wrong DHCP yiaddr: {socket.inet_ntoa(payload[16:20])}")
    if checksum(frame[14:14 + ihl]) != 0:
        raise SystemExit("invalid IPv4 header checksum")
    # Only the unicast frame is built by OnetDNS. The kernel sends the broadcast, and veth
    # checksum offload leaves its UDP checksum unfinished in the captured frame.
    pseudo = frame[26:34] + bytes((0, 17)) + udp_len.to_bytes(2, "big")
    if mode == "unicast" and (
        udp_sum == 0 or checksum(pseudo + frame[udp_at:udp_at + udp_len]) != 0
    ):
        raise SystemExit("invalid UDP checksum")
    options = payload[240:]
    if bytes((53, 1, 2)) not in options:
        raise SystemExit("response is not DHCPOFFER")
    print(
        f"dhcp-l2 netns {mode} OK: "
        f"ethernet_dst={want_mac.hex(':')} ip_dst={want_ip} udp=67->68 xid={xid:08x}"
    )
    break
else:
    raise SystemExit(f"{mode}: timed out waiting for DHCPOFFER")
PY
done

if grep -q 'dhcp4.initial_unicast_fallback' "$work/server.log"; then
  cat "$work/server.log" >&2
  echo "server used broadcast fallback instead of direct L2 delivery" >&2
  exit 1
fi
# The server namespace has no default route, so a broadcast that is not bound to the interface
# holding dhcp_server_ip fails with ENETUNREACH instead of reaching the client.
if grep -q 'dhcp4.send_failed' "$work/server.log"; then
  cat "$work/server.log" >&2
  echo "server failed to send a DHCP reply" >&2
  exit 1
fi
