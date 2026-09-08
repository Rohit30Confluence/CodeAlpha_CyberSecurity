from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_suricata_lab_assets_reference_local_rules_and_alert_outputs() -> None:
    config = (ROOT / "suricata" / "suricata.yaml").read_text()
    rules = (ROOT / "suricata" / "rules" / "codealpha.rules").read_text()
    compose = (ROOT / "suricata" / "docker-compose.yml").read_text()
    assert "codealpha.rules" in config
    assert "eve.json" in config and "fast.log" in config
    assert "classification-file" in config and "reference-config-file" in config and "threshold-file" in config
    assert (ROOT / "suricata" / "rules" / "classification.config").is_file()
    assert (ROOT / "suricata" / "rules" / "reference.config").is_file()
    assert (ROOT / "suricata" / "rules" / "threshold.config").is_file()
    assert all(f"sid:100000{n}" in rules for n in range(1, 4))
    assert '"-T"' in compose and "cap_drop" in compose
