# Submission evidence template

Complete one entry per item after real execution. Do not replace fields with invented outcomes.

| Task | Suggested evidence | Command / activity | Actual result | Redaction checked | Date | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Network Sniffer | Screenshot of metadata-only output or unit test | `PYTHONPATH=src python -m pytest tests/test_sniffer.py` | _complete after execution_ | _yes/no_ | _date_ | _authorised interface, if live_ |
| Phishing Training | Screenshot of quiz result and category feedback | `codealpha-security phishing-quiz` | _complete after execution_ | _yes/no_ | _date_ | _no learner personal data_ |
| Secure Coding Review | Screenshot of controlled review output | `codealpha-security review path/to/controlled_sample.py` | _complete after execution_ | _yes/no_ | _date_ | _do not execute the sample_ |
| Suricata IDS | Screenshot of successful config validation / redacted local alert | See `docs/suricata_lab.md` | _complete after execution_ | _yes/no_ | _date_ | _owned PCAP only_ |

## Screenshot naming

Use descriptive names such as `task4-suricata-config-check-YYYY-MM-DD.png`. Do not commit screenshots unless you confirm they contain no sensitive data and are required by the submission channel.
