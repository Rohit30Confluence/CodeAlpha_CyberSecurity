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

## Optional owned-PCAP replay

Do not use captures from systems or networks without permission. Place an approved capture at `suricata/lab-input/owned-traffic.pcap`, then run the pinned image manually:

```bash
mkdir -p suricata/lab-input suricata/logs
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v "$PWD/suricata/suricata.yaml:/etc/suricata/suricata.yaml:ro" \
  -v "$PWD/suricata/rules:/etc/suricata/rules:ro" \
  -v "$PWD/suricata/lab-input:/pcap:ro" \
  -v "$PWD/suricata/logs:/var/log/suricata" \
  oisf/suricata:7.0.8 -c /etc/suricata/suricata.yaml -r /pcap/owned-traffic.pcap
```

Expected result: the command reads only the supplied local capture and writes `fast.log` and `eve.json` if the traffic matches a local rule. No capture is included in this repository, and no execution evidence is claimed.

## Alert review

```bash
test -f suricata/logs/fast.log && cat suricata/logs/fast.log
test -f suricata/logs/eve.json && grep 'CODEALPHA LAB' suricata/logs/eve.json
```

The `eve.json` fields can be ingested by a SIEM approved by the organisation. Keep raw alerts to the minimum retention period required by policy.
