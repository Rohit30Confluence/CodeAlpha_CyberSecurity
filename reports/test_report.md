# Test Report

## Automated test set

The `pytest` suite currently has 11 checks. It covers metadata-only packet summarisation and bounded capture validation; a ten-scenario phishing-training catalogue, category feedback, and scoring; selected static-review findings and remediations; educational IDS alerts for a monitored port plus a simulated SYN scan; and the presence of the Suricata local rules, alert outputs, and capability-restricted configuration test.

Run verification from a clean environment:

```bash
python -m pip install -e '.[dev]'
pytest
```

Expected result: all tests pass. Live packet capture and Suricata PCAP replay are deliberately excluded from automated tests because they require an authorised local environment and Docker/Suricata availability. The Docker validation command is documented separately and must be run by the submitter in their own local lab.
