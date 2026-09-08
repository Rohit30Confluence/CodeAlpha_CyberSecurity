from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class PacketSummary:
    """Privacy-conscious packet metadata: payloads are intentionally omitted."""
    timestamp: str
    source: str
    destination: str
    protocol: str
    length: int
    source_port: int | None = None
    destination_port: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def summarise_packet(packet: Any) -> PacketSummary:
    """Convert a Scapy-like packet into a metadata-only summary.

    Supports a small dictionary representation as well, enabling repeatable tests
    without requiring packet capture permissions or Scapy.
    """
    if isinstance(packet, dict):
        return PacketSummary(
            timestamp=packet.get("timestamp", datetime.now(timezone.utc).isoformat()),
            source=packet.get("source", "unknown"), destination=packet.get("destination", "unknown"),
            protocol=packet.get("protocol", "OTHER"), length=int(packet.get("length", 0)),
            source_port=packet.get("source_port"), destination_port=packet.get("destination_port"),
        )
    try:
        from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    except ImportError as exc:
        raise RuntimeError("Live capture requires the optional 'capture' dependency.") from exc
    if not packet.haslayer(IP):
        return PacketSummary(datetime.now(timezone.utc).isoformat(), "unknown", "unknown", "NON_IP", len(packet))
    ip = packet[IP]
    protocol, sport, dport = "IP", None, None
    if packet.haslayer(TCP):
        protocol, sport, dport = "TCP", int(packet[TCP].sport), int(packet[TCP].dport)
    elif packet.haslayer(UDP):
        protocol, sport, dport = "UDP", int(packet[UDP].sport), int(packet[UDP].dport)
    return PacketSummary(datetime.now(timezone.utc).isoformat(), ip.src, ip.dst, protocol, len(packet), sport, dport)


def capture(interface: str | None = None, count: int = 10, timeout: int = 15) -> list[PacketSummary]:
    """Capture a bounded number of packets on an interface the operator owns."""
    if not 1 <= count <= 1000 or not 1 <= timeout <= 300:
        raise ValueError("count must be 1..1000 and timeout must be 1..300 seconds")
    try:
        from scapy.all import sniff  # type: ignore
    except ImportError as exc:
        raise RuntimeError("Install with: pip install .[capture]") from exc
    return [summarise_packet(packet) for packet in sniff(iface=interface, count=count, timeout=timeout)]
