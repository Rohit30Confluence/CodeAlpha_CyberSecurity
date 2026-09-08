from codealpha_cybersecurity.ids.engine import IdsEngine, NetworkEvent


def test_sensitive_port_alert() -> None:
    alerts = IdsEngine().inspect(NetworkEvent(1000, "10.0.0.4", "10.0.0.1", 445))
    assert alerts[0].rule == "IDS001"


def test_port_scan_alert() -> None:
    engine = IdsEngine(scan_port_threshold=3)
    alerts = []
    for port in (80, 81, 82):
        alerts.extend(engine.inspect(NetworkEvent(1000 + port, "10.0.0.4", "10.0.0.1", port, tcp_flags="S")))
    assert any(alert.rule == "IDS002" for alert in alerts)
