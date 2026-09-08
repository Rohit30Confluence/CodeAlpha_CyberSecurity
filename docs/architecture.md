# Architecture

The project uses a dependency-light core so its exercises work offline and in CI. Optional Scapy integration is isolated behind `network_sniffer.capture`; all other components use the Python standard library.

```text
authorised packet source -> metadata summary -> JSON/display
learner answers -> scenario scorer -> explanation + percentage
Python source -> AST visitor -> structured security findings
network events -> educational Python IDS rules + rolling source window -> structured alerts
owned PCAP -> Suricata local rules -> fast.log + eve.json alerts
```

## Security and data handling

- Packet bodies are never retained or serialised by the sniffer.
- Capture is bounded by `count` and `timeout` validation.
- Training runs locally and does not transmit learner answers.
- The reviewer parses source but does not execute it.
- IDS state is in-memory; operators decide whether and where to persist alerts.

## IDS detection logic

`IDS001` triggers on connections to configured monitored ports. `IDS002` counts distinct TCP SYN destination ports for a source during a rolling window. Both settings are configurable through the engine constructor; `config/ids.example.json` is a documented baseline template.

This intentionally small engine illustrates alert logic and testing rather than claiming full intrusion prevention capability.

For the CodeAlpha Suricata requirement, the `suricata/` directory supplies a separate lab-only Suricata configuration, three custom defensive rules, and JSON/text alert outputs. It is intentionally configuration-tested in Docker without attaching to a live interface. See `docs/suricata_lab.md`.
