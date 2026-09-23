# DHCPv4 initial L2 unicast proof

This harness starts OnetDNS and an addressless DHCP client in two disposable Linux network
namespaces joined by one veth pair. The client sends DHCPDISCOVER with `ciaddr=0`, `giaddr=0`, and
the broadcast bit clear. Its AF_PACKET receiver requires the DHCPOFFER to use the client's exact
`chaddr` as the Ethernet destination and `yiaddr` as the IPv4 destination. It also verifies the
IPv4 and UDP checksums, ports, transaction ID, offered address, message type, and absence of the
broadcast-fallback event.

A second DHCPDISCOVER sets the broadcast bit. The server namespace has no default route, so the
DHCPOFFER reaches the client only if the server sends the limited broadcast out of the interface
that holds `dhcp_server_ip`. The receiver requires an Ethernet and IPv4 broadcast destination, and
the run fails if the server logs `dhcp4.send_failed`.

The script requires root only for the isolated namespaces, veth, UDP 67, and AF_PACKET sockets.
It does not alter an existing interface, route, neighbor table, or OnetDNS service.

```sh
sudo ./run-linux-netns.sh /absolute/path/to/OnetDNS
```
