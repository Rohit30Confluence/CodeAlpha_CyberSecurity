"""Create one deterministic, offline PCAP for the CodeAlpha Suricata lab.

The file contains a single synthetic TCP SYN from TEST-NET-1 to the configured
lab HOME_NET on port 445. It is written for offline replay only; no packets are
sent and no interface is opened.
"""

from __future__ import annotations

import argparse
import ipaddress
import struct
from pathlib import Path


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def create_pcap(destination: Path) -> None:
    source_ip = ipaddress.IPv4Address("192.0.2.10").packed
    destination_ip = ipaddress.IPv4Address("172.28.0.2").packed
    ethernet = bytes.fromhex("0200000000020200000000010800")
    tcp_without_checksum = struct.pack("!HHLLBBHHH", 49152, 445, 1, 0, 5 << 4, 0x02, 64240, 0, 0)
    pseudo_header = source_ip + destination_ip + struct.pack("!BBH", 0, 6, len(tcp_without_checksum))
    tcp = struct.pack("!HHLLBBHHH", 49152, 445, 1, 0, 5 << 4, 0x02, 64240, checksum(pseudo_header + tcp_without_checksum), 0)
    ip_without_checksum = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, source_ip, destination_ip)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, checksum(ip_without_checksum), source_ip, destination_ip)
    packet = ethernet + ip + tcp
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record_header = struct.pack("<IIII", 1_700_000_000, 0, len(packet), len(packet))
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(global_header + record_header + packet)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate an offline CodeAlpha Suricata lab PCAP")
    parser.add_argument("--output", type=Path, default=Path("suricata/lab-input/codealpha-safe-lab.pcap"))
    args = parser.parse_args()
    create_pcap(args.output)
    print(f"Wrote offline synthetic lab PCAP: {args.output} ({args.output.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
