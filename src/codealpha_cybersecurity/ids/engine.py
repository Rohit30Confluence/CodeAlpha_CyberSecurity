from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterable


@dataclass(frozen=True)
class NetworkEvent:
    timestamp: float
    source: str
    destination: str
    destination_port: int
    protocol: str = "TCP"
    tcp_flags: str = ""


@dataclass(frozen=True)
class Alert:
    rule: str
    severity: str
    source: str
    detail: str
    timestamp: str
    def to_dict(self) -> dict[str, str]: return asdict(self)


class IdsEngine:
    def __init__(self, scan_window_seconds: int = 60, scan_port_threshold: int = 10, sensitive_ports: Iterable[int] = (23, 445, 3389)) -> None:
        self.window = scan_window_seconds
        self.threshold = scan_port_threshold
        self.sensitive_ports = set(sensitive_ports)
        self._ports: dict[str, deque[tuple[float, int]]] = defaultdict(deque)

    def inspect(self, event: NetworkEvent) -> list[Alert]:
        alerts: list[Alert] = []
        now = datetime.fromtimestamp(event.timestamp, timezone.utc).isoformat()
        if event.destination_port in self.sensitive_ports:
            alerts.append(Alert("IDS001", "medium", event.source, f"Connection attempt to monitored port {event.destination_port}", now))
        if event.protocol.upper() == "TCP" and "S" in event.tcp_flags and "A" not in event.tcp_flags:
            entries = self._ports[event.source]
            entries.append((event.timestamp, event.destination_port))
            while entries and entries[0][0] < event.timestamp - self.window: entries.popleft()
            unique_ports = {port for _, port in entries}
            if len(unique_ports) >= self.threshold:
                alerts.append(Alert("IDS002", "high", event.source, f"Possible port scan: {len(unique_ports)} distinct ports in {self.window}s", now))
        return alerts
