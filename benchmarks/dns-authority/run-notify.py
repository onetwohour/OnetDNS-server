#!/usr/bin/env python3
"""Exercise signed NOTIFY retry, ACK, and primary-to-secondary convergence."""

import argparse
import base64
import ctypes
import hashlib
import hmac
import ipaddress
import os
from pathlib import Path
import socket
import struct
import subprocess
import threading
import time


ZONE = "notify.test"
STALLED_ZONES = 8
KEY_NAME = "notify-key"
SECRET_B64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
SECRET = base64.b64decode(SECRET_B64)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def dns_name(value: str) -> bytes:
    out = bytearray()
    for label in value.rstrip(".").split("."):
        encoded = label.lower().encode("ascii")
        require(0 < len(encoded) <= 63, "invalid DNS label")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def skip_name(wire: bytes, offset: int) -> int:
    while True:
        require(offset < len(wire), "truncated DNS name")
        length = wire[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            require(offset + 2 <= len(wire), "truncated DNS pointer")
            return offset + 2
        require(length & 0xC0 == 0 and offset + 1 + length <= len(wire), "bad DNS name")
        offset += 1 + length


def time48(value: int) -> bytes:
    return value.to_bytes(6, "big")


def sign_request(
    message_id: int,
    flags: int,
    questions: int,
    answers: int,
    authorities: int,
    body: bytes,
) -> tuple[bytes, bytes]:
    now = int(time.time())
    unsigned = struct.pack(
        "!HHHHHH", message_id, flags, questions, answers, authorities, 0
    ) + body
    variables = (
        dns_name(KEY_NAME)
        + struct.pack("!HI", 255, 0)
        + dns_name("hmac-sha256")
        + time48(now)
        + struct.pack("!HHH", 300, 0, 0)
    )
    mac = hmac.new(SECRET, unsigned + variables, hashlib.sha256).digest()
    rdata = (
        dns_name("hmac-sha256")
        + time48(now)
        + struct.pack("!HH", 300, len(mac))
        + mac
        + struct.pack("!HHH", message_id, 0, 0)
    )
    tsig = dns_name(KEY_NAME) + struct.pack("!HHIH", 250, 255, 0, len(rdata)) + rdata
    signed = struct.pack(
        "!HHHHHH", message_id, flags, questions, answers, authorities, 1
    ) + body + tsig
    return signed, mac


def read_uncompressed_name(wire: bytes, offset: int) -> tuple[str, int]:
    labels = []
    while True:
        require(offset < len(wire), "truncated TSIG name")
        length = wire[offset]
        offset += 1
        if length == 0:
            return ".".join(labels), offset
        require(length & 0xC0 == 0 and offset + length <= len(wire), "bad TSIG name")
        labels.append(wire[offset : offset + length].decode("ascii").lower())
        offset += length


def verify_tsig_response(wire: bytes, request_mac: bytes, expected_id: int) -> int:
    require(len(wire) >= 12, "short DNS response")
    message_id, flags, questions, answers, authorities, additionals = struct.unpack(
        "!HHHHHH", wire[:12]
    )
    require(message_id == expected_id and flags & 0x8000, "mismatched DNS response")
    offset = 12
    for _ in range(questions):
        offset = skip_name(wire, offset) + 4
    records = []
    for _ in range(answers + authorities + additionals):
        start = offset
        name_end = skip_name(wire, offset)
        require(name_end + 10 <= len(wire), "truncated DNS RR")
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", wire[name_end : name_end + 10])
        rdata_start = name_end + 10
        offset = rdata_start + rdlength
        require(offset <= len(wire), "truncated DNS RDATA")
        records.append((start, rtype, rclass, ttl, wire[rdata_start:offset]))
    require(offset == len(wire) and records, "malformed TSIG response")
    tsig_offset, rtype, rclass, ttl, rdata = records[-1]
    require((rtype, rclass, ttl) == (250, 255, 0), "missing response TSIG")
    algorithm, index = read_uncompressed_name(rdata, 0)
    signed_time = int.from_bytes(rdata[index : index + 6], "big")
    index += 6
    fudge, mac_length = struct.unpack("!HH", rdata[index : index + 4])
    index += 4
    response_mac = rdata[index : index + mac_length]
    index += mac_length
    original_id, error, other_length = struct.unpack("!HHH", rdata[index : index + 6])
    index += 6
    other = rdata[index : index + other_length]
    require(index + other_length == len(rdata), "TSIG RDATA tail")
    digest = bytearray(wire[:tsig_offset])
    digest[:2] = struct.pack("!H", original_id)
    digest[10:12] = struct.pack("!H", additionals - 1)
    variables = (
        dns_name(KEY_NAME)
        + struct.pack("!HI", 255, 0)
        + dns_name(algorithm)
        + time48(signed_time)
        + struct.pack("!HHH", fudge, error, len(other))
        + other
    )
    expected = hmac.new(
        SECRET,
        struct.pack("!H", len(request_mac)) + request_mac + bytes(digest) + variables,
        hashlib.sha256,
    ).digest()
    require(hmac.compare_digest(expected[:mac_length], response_mac), "response TSIG mismatch")
    require(error == 0, f"TSIG response error={error}")
    return flags & 15


def udp_exchange(server: str, port: int, wire: bytes, timeout: float = 1.0) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        client.sendto(wire, (server, port))
        response, source = client.recvfrom(65_535)
        require(source == (server, port), f"response source mismatch: {source}")
        return response


def recv_exact(stream: socket.socket, length: int) -> bytes:
    out = bytearray()
    while len(out) < length:
        part = stream.recv(length - len(out))
        require(part, "TCP stream closed early")
        out.extend(part)
    return bytes(out)


def query(server: str, port: int, name: str, qtype: int, message_id: int) -> bytes:
    question = dns_name(name) + struct.pack("!HH", qtype, 1)
    wire = struct.pack("!HHHHHH", message_id, 0, 1, 0, 0, 0) + question
    response = udp_exchange(server, port, wire)
    received_id, flags = struct.unpack("!HH", response[:4])
    require(received_id == message_id and flags & 0x8000 and flags & 15 == 0, "query failed")
    return response


def answer_records(wire: bytes):
    _, _, questions, answers, _, _ = struct.unpack("!HHHHHH", wire[:12])
    offset = 12
    for _ in range(questions):
        offset = skip_name(wire, offset) + 4
    for _ in range(answers):
        name_end = skip_name(wire, offset)
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", wire[name_end : name_end + 10])
        rdata_offset = name_end + 10
        offset = rdata_offset + rdlength
        yield rtype, rclass, ttl, rdata_offset, rdlength


def query_soa(server: str, port: int, message_id: int, zone: str = ZONE) -> int:
    wire = query(server, port, zone, 6, message_id)
    for rtype, rclass, _, rdata, _ in answer_records(wire):
        if (rtype, rclass) == (6, 1):
            serial_offset = skip_name(wire, skip_name(wire, rdata))
            return struct.unpack("!I", wire[serial_offset : serial_offset + 4])[0]
    raise RuntimeError("SOA answer missing")


def query_a(server: str, port: int, name: str, message_id: int) -> tuple[str, int]:
    wire = query(server, port, name, 1, message_id)
    for rtype, rclass, ttl, rdata, rdlength in answer_records(wire):
        if (rtype, rclass, rdlength) == (1, 1, 4):
            return str(ipaddress.IPv4Address(wire[rdata : rdata + 4])), ttl
    raise RuntimeError("A answer missing")


def update_add(server: str, port: int, owner: str, address: str, message_id: int) -> None:
    zone = dns_name(ZONE) + struct.pack("!HH", 6, 1)
    value = ipaddress.IPv4Address(address).packed
    update = dns_name(owner) + struct.pack("!HHIH", 1, 1, 120, len(value)) + value
    wire, request_mac = sign_request(message_id, 5 << 11, 1, 0, 1, zone + update)
    response = udp_exchange(server, port, wire, 2.0)
    require(verify_tsig_response(response, request_mac, message_id) == 0, "UPDATE refused")


def wait_serial(port: int, expected: int, timeout: float, zone: str = ZONE) -> None:
    deadline = time.monotonic() + timeout
    message_id = 0x6000
    while time.monotonic() < deadline:
        try:
            if query_soa("127.0.0.1", port, message_id, zone) == expected:
                return
        except (OSError, RuntimeError):
            pass
        message_id = (message_id + 1) & 0xFFFF
        time.sleep(0.01)
    raise RuntimeError(f"server on port {port} did not reach {zone} serial {expected}")


def process_usage(process: subprocess.Popen) -> tuple[int | None, float | None]:
    if os.name == "nt":
        class FileTime(ctypes.Structure):
            _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]

            def seconds(self) -> float:
                return ((self.high << 32) | self.low) / 10_000_000

        class Counters(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_uint32),
                ("PageFaultCount", ctypes.c_uint32),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        creation, exit_time, kernel, user = FileTime(), FileTime(), FileTime(), FileTime()
        handle = ctypes.c_void_p(int(process._handle))
        memory_ok = ctypes.windll.psapi.GetProcessMemoryInfo(
            handle, ctypes.byref(counters), counters.cb
        )
        times_ok = ctypes.windll.kernel32.GetProcessTimes(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel),
            ctypes.byref(user),
        )
        return (
            counters.WorkingSetSize // 1024 if memory_ok else None,
            kernel.seconds() + user.seconds() if times_ok else None,
        )
    try:
        status = Path(f"/proc/{process.pid}/status").read_text(encoding="ascii")
        rss = next(int(line.split()[1]) for line in status.splitlines() if line.startswith("VmRSS:"))
        fields = Path(f"/proc/{process.pid}/stat").read_text(encoding="ascii").rsplit(") ", 1)[1].split()
        ticks = os.sysconf("SC_CLK_TCK")
        return rss, (int(fields[11]) + int(fields[12])) / ticks
    except (OSError, StopIteration, ValueError):
        return None, None


def config_path(path: Path) -> str:
    return path.resolve().as_posix()


def stop(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("workdir", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--updates", type=int, default=100)
    parser.add_argument("--primary-port", type=int, default=15460)
    parser.add_argument("--secondary-port", type=int, default=15461)
    parser.add_argument("--stalled-primary-port", type=int, default=15462)
    args = parser.parse_args()
    require(args.updates > 0, "updates must be positive")
    require(args.updates <= 4096, "updates must be <= 4096")
    args.workdir.mkdir(parents=True, exist_ok=True)
    zone_file = args.workdir / "db.notify.test"
    secondary_file = args.workdir / "db.notify.secondary"
    primary_log = args.workdir / "primary.log"
    secondary_log = args.workdir / "secondary.log"
    zone_file.write_text(
        "$ORIGIN notify.test.\n$TTL 300\n"
        "@ IN SOA ns hostmaster 1 15 2 120 60\n"
        "@ IN NS ns\nns IN A 192.0.2.53\n",
        encoding="ascii",
    )
    primary_config = args.workdir / "primary.toml"
    secondary_config = args.workdir / "secondary.toml"
    stalled_entries = ",\n  ".join(
        f'{{ origin = "stalled-{index}.notify.test", primary = "127.0.0.1", primary_port = {args.stalled_primary_port} }}'
        for index in range(STALLED_ZONES)
    )
    primary_config.write_text(
        f'''mode = "personal"
backend = "forward"
listen = ["127.0.0.1:{args.primary_port}"]
workers = 1
do_udp = true
do_tcp = true
cache_enabled = false
querylog = false
xfr_allow = ["127.0.0.1/32"]
xfr_tsig_required = true
update_allow = ["127.0.0.1/32"]
update_tsig_required = true
zones = [{{ origin = "{ZONE}", file = "{config_path(zone_file)}" }}]
notify = [{{ address = "127.0.0.1:{args.secondary_port}", tsig_key = "{KEY_NAME}" }}]

[[tsig_keys]]
name = "{KEY_NAME}"
secret = "{SECRET_B64}"
''',
        encoding="utf-8",
    )
    secondary_config.write_text(
        f'''mode = "personal"
backend = "forward"
listen = ["127.0.0.1:{args.secondary_port}"]
workers = 1
do_udp = true
do_tcp = true
cache_enabled = false
querylog = false
secondary = [
  {stalled_entries},
  {{ origin = "{ZONE}", file = "{config_path(secondary_file)}", primary = "127.0.0.1", primary_port = {args.primary_port}, tsig_key = "{KEY_NAME}" }}
]

[[tsig_keys]]
name = "{KEY_NAME}"
secret = "{SECRET_B64}"
''',
        encoding="utf-8",
    )

    stalled_tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    stalled_tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    stalled_tcp_socket.bind(("127.0.0.1", args.stalled_primary_port))
    stalled_tcp_socket.listen(STALLED_ZONES)
    stalled_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    stalled_socket.bind(("127.0.0.1", args.stalled_primary_port))
    stalled_soa_seen = threading.Event()
    stalled_tcp_seen = threading.Event()
    stalled_stop = threading.Event()
    stalled_times: dict[str, float] = {}

    def delay_stalled_primary() -> None:
        try:
            stalled_socket.settimeout(10)
            requests = []
            while len(requests) < STALLED_ZONES:
                wire, peer = stalled_socket.recvfrom(65_535)
                require(len(wire) >= 12, "short stalled SOA request")
                question_end = skip_name(wire, 12) + 4
                require(question_end <= len(wire), "truncated stalled SOA question")
                requests.append((wire[:2], wire[12:question_end], peer))
            stalled_times["soa"] = time.monotonic()
            stalled_soa_seen.set()
            soa_rdata = (
                dns_name("ns.invalid")
                + dns_name("admin.invalid")
                + struct.pack("!IIIII", 2, 300, 60, 86_400, 60)
            )
            soa_answer = (
                b"\xc0\x0c"
                + struct.pack("!HHIH", 6, 1, 300, len(soa_rdata))
                + soa_rdata
            )
            for message_id, question, peer in requests:
                response = (
                    message_id
                    + struct.pack("!HHHHH", 0x8400, 1, 1, 0, 0)
                    + question
                    + soa_answer
                )
                stalled_socket.sendto(response, peer)
        except OSError:
            pass

    def stall_tcp_xfr() -> None:
        clients = []
        try:
            stalled_tcp_socket.settimeout(10)
            while len(clients) < STALLED_ZONES:
                client, _ = stalled_tcp_socket.accept()
                client.settimeout(2)
                length = struct.unpack("!H", recv_exact(client, 2))[0]
                recv_exact(client, length)
                clients.append(client)
            stalled_times["tcp"] = time.monotonic()
            stalled_tcp_seen.set()
            stalled_stop.wait(timeout=30)
        except OSError:
            pass
        finally:
            for client in clients:
                client.close()

    stalled_thread = threading.Thread(target=delay_stalled_primary, daemon=True)
    stalled_tcp_thread = threading.Thread(target=stall_tcp_xfr, daemon=True)
    stalled_thread.start()
    stalled_tcp_thread.start()
    primary = secondary = None
    with primary_log.open("wb") as primary_output, secondary_log.open("wb") as secondary_output:
        try:
            command = [str(args.binary.resolve()), "--config"]
            primary = subprocess.Popen(
                command + [str(primary_config.resolve()), "--no-web", "--no-supervisor"],
                stdout=primary_output,
                stderr=subprocess.STDOUT,
            )
            wait_serial(args.primary_port, 1, 10)
            time.sleep(1.2)
            secondary_started = time.monotonic()
            secondary = subprocess.Popen(
                command + [str(secondary_config.resolve()), "--no-web", "--no-supervisor"],
                stdout=secondary_output,
                stderr=subprocess.STDOUT,
            )
            wait_serial(args.secondary_port, 1, 10)
            initial_converged = time.monotonic()
            require(
                stalled_soa_seen.wait(timeout=1),
                f"all {STALLED_ZONES} stalled zones were not probed concurrently",
            )
            require(
                stalled_tcp_seen.wait(timeout=1),
                f"all {STALLED_ZONES} stalled TCP XFRs were not admitted concurrently",
            )
            require(
                initial_converged - secondary_started < 1.25,
                "stalled primaries blocked healthy secondary convergence",
            )
            rss_before = tuple(process_usage(process)[0] for process in (primary, secondary))
            cpu_before = tuple(process_usage(process)[1] for process in (primary, secondary))

            started = time.monotonic()
            for index in range(args.updates):
                update_add(
                    "127.0.0.1",
                    args.primary_port,
                    f"load-{index}.{ZONE}",
                    f"198.51.100.{index % 250 + 1}",
                    (0x7000 + index) & 0xFFFF,
                )
            updates_done = time.monotonic()
            final_serial = 1 + args.updates
            require(
                query_soa("127.0.0.1", args.primary_port, 0x7F00) == final_serial,
                "primary serial mismatch",
            )
            wait_serial(args.secondary_port, final_serial, 15)
            converged = time.monotonic()
            address, ttl = query_a(
                "127.0.0.1",
                args.secondary_port,
                f"load-{args.updates - 1}.{ZONE}",
                0x7F01,
            )
            require(address == f"198.51.100.{(args.updates - 1) % 250 + 1}", "A value mismatch")
            require(ttl == 120, "user-configured record TTL changed during replication")
            time.sleep(0.2)
            rss_after = tuple(process_usage(process)[0] for process in (primary, secondary))
            cpu_after = tuple(process_usage(process)[1] for process in (primary, secondary))
        finally:
            stop(secondary)
            stop(primary)
            stalled_stop.set()
            stalled_socket.close()
            stalled_tcp_socket.close()
            stalled_thread.join(timeout=1)
            stalled_tcp_thread.join(timeout=1)

    primary_text = primary_log.read_text(encoding="utf-8", errors="replace")
    secondary_text = secondary_log.read_text(encoding="utf-8", errors="replace")
    sent = sum("event=authority.notify_sent" in line for line in primary_text.splitlines())
    acknowledged = sum(
        "event=authority.notify_acknowledged" in line for line in primary_text.splitlines()
    )
    received = sum(
        "event=authority.notify_received" in line for line in secondary_text.splitlines()
    )
    startup_retry = any(
        "event=authority.notify_sent" in line
        and "serial=1 " in line
        and "transmission=2" in line
        for line in primary_text.splitlines()
    )
    require(startup_retry, "startup NOTIFY was not retried before the secondary started")
    require(acknowledged >= 1 and received >= 1, "signed NOTIFY ACK path not observed")
    update_seconds = updates_done - started
    initial_convergence_ms = (initial_converged - secondary_started) * 1000
    convergence_ms = (converged - updates_done) * 1000
    cpu_delta = None
    if all(value is not None for value in cpu_before + cpu_after):
        cpu_delta = sum(cpu_after) - sum(cpu_before)
    cpu_text = f"{cpu_delta:.4f}" if cpu_delta is not None else "unknown"
    print(
        "notify_live=ok "
        f"serial=1->{1 + args.updates} updates={args.updates} "
        f"updates_per_s={args.updates / update_seconds:.1f} "
        f"multiplexed_soa_primaries={STALLED_ZONES} "
        f"stalled_tcp_primaries={STALLED_ZONES} "
        f"healthy_initial_convergence_ms={initial_convergence_ms:.2f} "
        f"tcp_admission_ms={(stalled_times['tcp'] - secondary_started) * 1000:.2f} "
        f"post_update_convergence_ms={convergence_ms:.2f} record_ttl={ttl} "
        f"startup_retry=yes notify_sent={sent} acked={acknowledged} received={received} "
        f"rss_kib={rss_before[0]}+{rss_before[1]}->{rss_after[0]}+{rss_after[1]} "
        f"cpu_s={cpu_text}"
    )
    print(f"artifacts={args.workdir.resolve()}")


if __name__ == "__main__":
    main()
