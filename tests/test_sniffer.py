from codealpha_cybersecurity.network_sniffer.sniffer import summarise_packet


def test_dictionary_packet_is_summarised_without_payload() -> None:
    packet = summarise_packet({"source": "10.0.0.1", "destination": "10.0.0.2", "protocol": "TCP", "length": 60, "source_port": 1234, "destination_port": 443})
    assert packet.source == "10.0.0.1"
    assert packet.destination_port == 443
    assert "payload" not in packet.to_dict()
