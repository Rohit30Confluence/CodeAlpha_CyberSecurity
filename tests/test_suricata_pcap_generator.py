import importlib.util
import struct
from pathlib import Path


ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("lab_pcap", ROOT / "scripts" / "generate_suricata_lab_pcap.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_generator_creates_one_offline_ethernet_pcap(tmp_path: Path) -> None:
    output = tmp_path / "lab.pcap"
    MODULE.create_pcap(output)
    data = output.read_bytes()
    magic, major, minor, _, _, _, link_type = struct.unpack("<IHHIIII", data[:24])
    _, _, captured, original = struct.unpack("<IIII", data[24:40])
    assert (magic, major, minor, link_type) == (0xA1B2C3D4, 2, 4, 1)
    assert captured == original == 54
    assert len(data) == 40 + captured
