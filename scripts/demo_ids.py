"""Offline, deterministic demonstration of the educational Python IDS."""

import json

from codealpha_cybersecurity.ids.engine import IdsEngine, NetworkEvent


def main() -> None:
    engine = IdsEngine(scan_port_threshold=3)
    events = [
        NetworkEvent(1_700_000_000, "192.0.2.10", "192.0.2.20", 445),
        NetworkEvent(1_700_000_001, "192.0.2.11", "192.0.2.20", 80, tcp_flags="S"),
        NetworkEvent(1_700_000_002, "192.0.2.11", "192.0.2.20", 81, tcp_flags="S"),
        NetworkEvent(1_700_000_003, "192.0.2.11", "192.0.2.20", 82, tcp_flags="S"),
    ]
    alerts = [alert.to_dict() for event in events for alert in engine.inspect(event)]
    print(json.dumps(alerts, indent=2))


if __name__ == "__main__":
    main()
