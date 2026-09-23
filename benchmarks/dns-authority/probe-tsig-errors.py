#!/usr/bin/env python3
"""Independently verify RFC 8945 TSIG success and error responses over TCP."""

import base64
import hashlib
import hmac
import socket
import struct
import sys
import time


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def dns_name(value: str) -> bytes:
    wire = bytearray()
    for label in value.rstrip(".").split("."):
        encoded = label.lower().encode("ascii")
        if not encoded or len(encoded) > 63:
            raise ValueError("invalid DNS label")
        wire.append(len(encoded))
        wire.extend(encoded)
    wire.append(0)
    return bytes(wire)


def time48(value: int) -> bytes:
    return value.to_bytes(6, "big")


def make_query(
    message_id: int, zone: str, key_name: str, secret: bytes, signed_time: int
) -> tuple[bytes, bytes]:
    algorithm = "hmac-sha256"
    question = dns_name(zone) + struct.pack("!HH", 6, 1)
    unsigned = struct.pack("!HHHHHH", message_id, 0x0100, 1, 0, 0, 0) + question
    variables = (
        dns_name(key_name)
        + struct.pack("!HI", 255, 0)
        + dns_name(algorithm)
        + time48(signed_time)
        + struct.pack("!HHH", 300, 0, 0)
    )
    mac = hmac.new(secret, unsigned + variables, hashlib.sha256).digest()
    rdata = (
        dns_name(algorithm)
        + time48(signed_time)
        + struct.pack("!HH", 300, len(mac))
        + mac
        + struct.pack("!HHH", message_id, 0, 0)
    )
    tsig = (
        dns_name(key_name)
        + struct.pack("!HHIH", 250, 255, 0, len(rdata))
        + rdata
    )
    query = struct.pack("!HHHHHH", message_id, 0x0100, 1, 0, 0, 1) + question + tsig
    return query, mac


def receive(server: str, port: int, query: bytes) -> bytes:
    with socket.create_connection((server, port), timeout=3) as stream:
        stream.sendall(struct.pack("!H", len(query)) + query)
        length = struct.unpack("!H", receive_exact(stream, 2))[0]
        return receive_exact(stream, length)


def receive_exact(stream: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise RuntimeError("short TCP DNS response")
        data.extend(chunk)
    return bytes(data)


def skip_name(wire: bytes, offset: int) -> int:
    while True:
        length = wire[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length


def read_uncompressed_name(wire: bytes, offset: int) -> tuple[str, int]:
    labels = []
    while True:
        length = wire[offset]
        offset += 1
        if length == 0:
            return ".".join(labels), offset
        if length & 0xC0:
            raise RuntimeError("compressed TSIG variable name")
        labels.append(wire[offset : offset + length].decode("ascii").lower())
        offset += length


def parse_response(wire: bytes) -> dict:
    message_id, flags, questions, answers, authorities, additionals = struct.unpack(
        "!HHHHHH", wire[:12]
    )
    offset = 12
    for _ in range(questions):
        offset = skip_name(wire, offset) + 4
    records = []
    for _ in range(answers + authorities + additionals):
        start = offset
        name_end = skip_name(wire, offset)
        rtype, rclass, ttl, rdlength = struct.unpack(
            "!HHIH", wire[name_end : name_end + 10]
        )
        rdata_start = name_end + 10
        offset = rdata_start + rdlength
        records.append((start, rtype, rclass, ttl, wire[rdata_start:offset]))
    if offset != len(wire) or not records:
        raise RuntimeError("malformed DNS response")
    tsig_offset, rtype, rclass, ttl, rdata = records[-1]
    if (rtype, rclass, ttl) != (250, 255, 0):
        raise RuntimeError("missing final TSIG")

    algorithm, index = read_uncompressed_name(rdata, 0)
    signed_time = int.from_bytes(rdata[index : index + 6], "big")
    index += 6
    fudge, mac_length = struct.unpack("!HH", rdata[index : index + 4])
    index += 4
    mac = rdata[index : index + mac_length]
    index += mac_length
    original_id, error, other_length = struct.unpack("!HHH", rdata[index : index + 6])
    index += 6
    other = rdata[index : index + other_length]
    if index + other_length != len(rdata):
        raise RuntimeError("TSIG RDATA tail")
    return {
        "wire": wire,
        "id": message_id,
        "rcode": flags & 15,
        "additionals": additionals,
        "tsig_offset": tsig_offset,
        "algorithm": algorithm,
        "time": signed_time,
        "fudge": fudge,
        "mac": mac,
        "original_id": original_id,
        "error": error,
        "other": other,
    }


def verify_response(response: dict, key_name: str, secret: bytes, request_mac: bytes) -> None:
    digest = bytearray(response["wire"][: response["tsig_offset"]])
    digest[0:2] = struct.pack("!H", response["original_id"])
    digest[10:12] = struct.pack("!H", response["additionals"] - 1)
    variables = (
        dns_name(key_name)
        + struct.pack("!HI", 255, 0)
        + dns_name(response["algorithm"])
        + time48(response["time"])
        + struct.pack("!HH", response["fudge"], response["error"])
        + struct.pack("!H", len(response["other"]))
        + response["other"]
    )
    expected = hmac.new(
        secret,
        struct.pack("!H", len(request_mac)) + request_mac + bytes(digest) + variables,
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(expected[: len(response["mac"])], response["mac"]):
        raise RuntimeError("response MAC mismatch")


def main() -> None:
    if len(sys.argv) != 6:
        raise SystemExit("usage: probe-tsig-errors.py SERVER PORT ZONE KEY SECRET_BASE64")
    server, port_text, zone, key_name, encoded_secret = sys.argv[1:]
    port = int(port_text)
    secret = base64.b64decode(encoded_secret, validate=True)
    wrong_secret = hashlib.sha256(b"onetdns-independent-wrong-key").digest()
    now = int(time.time())

    valid_query, valid_request_mac = make_query(0x4101, zone, key_name, secret, now)
    valid = parse_response(receive(server, port, valid_query))
    require(
        (valid["rcode"], valid["error"], len(valid["mac"])) == (0, 0, 32),
        "invalid signed success response",
    )
    verify_response(valid, key_name, secret, valid_request_mac)

    badsig_query, _ = make_query(0x4102, zone, key_name, wrong_secret, now)
    badsig = parse_response(receive(server, port, badsig_query))
    require(
        (badsig["rcode"], badsig["error"], len(badsig["mac"]), badsig["other"])
        == (9, 16, 0, b""),
        "invalid BADSIG response",
    )

    unknown_key = "unknown-" + key_name
    badkey_query, _ = make_query(0x4103, zone, unknown_key, secret, now)
    badkey = parse_response(receive(server, port, badkey_query))
    require(
        (badkey["rcode"], badkey["error"], len(badkey["mac"]), badkey["other"])
        == (9, 17, 0, b""),
        "invalid BADKEY response",
    )

    old = now - 301
    badtime_query, badtime_request_mac = make_query(0x4104, zone, key_name, secret, old)
    badtime = parse_response(receive(server, port, badtime_query))
    require(
        (
            badtime["rcode"],
            badtime["error"],
            len(badtime["mac"]),
            badtime["time"],
            badtime["fudge"],
        )
        == (9, 18, 32, old, 300),
        "invalid BADTIME response",
    )
    require(len(badtime["other"]) == 6, "BADTIME server time is not 48-bit")
    server_time = int.from_bytes(badtime["other"], "big")
    skew = abs(int(time.time()) - server_time)
    require(skew <= 2, "BADTIME server time is stale")
    verify_response(badtime, key_name, secret, badtime_request_mac)
    print(
        "tsig_errors=ok "
        f"valid_mac={len(valid['mac'])} "
        f"badsig={badsig['error']}/{len(badsig['mac'])} "
        f"badkey={badkey['error']}/{len(badkey['mac'])} "
        f"badtime={badtime['error']}/{len(badtime['mac'])} "
        f"server_skew={skew}s"
    )


if __name__ == "__main__":
    main()
