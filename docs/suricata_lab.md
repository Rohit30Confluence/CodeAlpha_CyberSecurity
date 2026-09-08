# Safe local Suricata lab

## Scope and safety

This lab validates configuration locally. It does not scan, probe, or contact any external system. Use only a PCAP you created or are authorised to analyse. The Compose service drops capabilities and performs configuration validation only; it does not attach to a network interface.

## Prerequisites

- Docker Engine with Compose v2.
- Permission to use Docker locally.

## Validate the configuration

From the repository root:

```bash
mkdir -p suricata/logs
docker compose -f suricata/docker-compose.yml run --rm suricata-config-test
```

Expected result: Suricata reports that the configuration was successfully loaded and exits with status `0`. Exact informational text varies by Suricata image version.

## Offline synthetic-PCAP replay

For a fully reproducible no-network demonstration, generate the repository's synthetic PCAP. It contains one TCP SYN crafted entirely in a file: `192.0.2.10` (TEST-NET-1) to `172.28.0.2:445` (the configured Docker-lab `HOME_NET`). The generator never opens an interface or sends traffic.

```bash
PYTHONPATH=src python scripts/generate_suricata_lab_pcap.py
```

Then replay that local file through the pinned image:

```bash
mkdir -p suricata/lab-input suricata/logs
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v "$PWD/suricata/suricata.yaml:/etc/suricata/suricata.yaml:ro" \
  -v "$PWD/suricata/rules:/etc/suricata/rules:ro" \
  -v "$PWD/suricata/lab-input:/pcap:ro" \
  -v "$PWD/suricata/logs:/var/log/suricata" \
  jasonish/suricata:7.0.8 -c /etc/suricata/suricata.yaml -l /var/log/suricata -r /pcap/codealpha-safe-lab.pcap
```

Expected result: the command reads only the supplied local capture and writes an alert with SID `1000001` to `fast.log` and `eve.json`. Generated PCAPs and logs are ignored by Git; no execution evidence is committed.

You may instead replay an approved capture you created or are authorised to analyse, but never use captures from systems or networks without permission.

## Alert review

```bash
test -f suricata/logs/fast.log && cat suricata/logs/fast.log
test -f suricata/logs/eve.json && grep 'CODEALPHA LAB' suricata/logs/eve.json
```

The `eve.json` fields can be ingested by a SIEM approved by the organisation. Keep raw alerts to the minimum retention period required by policy.
