# CodeAlpha Cyber Security Internship Portfolio

This repository delivers all four CodeAlpha Cyber Security internship tasks as a tested, defensive Python project. It is designed for authorised lab, classroom, and self-owned environments only.

| Task | Deliverable | Entry point |
| --- | --- | --- |
| 1. Network Sniffer | Metadata-only packet summariser and bounded opt-in capture | `codealpha-security sniff` |
| 2. Phishing Awareness Training | Interactive scenario quiz with explanations and score | `codealpha-security phishing-quiz` |
| 3. Secure Coding Review | Python AST reviewer for selected high-risk calls | `codealpha-security review path/to/file.py` |
| 4. Network IDS | Reusable signature engine for monitored-port and SYN scan alerts | `codealpha_cybersecurity.ids` |

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
pytest
codealpha-security review path/to/file.py
codealpha-security phishing-quiz
```

Live capture is optional and requires an authorised interface, appropriate system privileges, and Scapy:

```bash
python -m pip install -e '.[capture]'
codealpha-security sniff --interface <authorised-interface> --count 10 --timeout 15
```

The sniffer deliberately emits headers and lengths only—never packet payloads. Do not run it on networks without explicit permission.

## Structure

`src/` holds the implementation, `tests/` automated tests, `config/` IDS tuning, `docs/` task guides, `reports/` evidence, and `submission_materials/` the demo and delivery checklist.

## Verification

Run `pytest` after installation. See [reports/test_report.md](reports/test_report.md) for expected coverage and [docs/architecture.md](docs/architecture.md) for design boundaries.

## Limitations and responsible use

This is educational defensive tooling, not a production SIEM, endpoint agent, or complete secure-code audit. The IDS is signature-based and needs environment-specific baselining; the static reviewer intentionally has a narrow rule set. Follow [docs/responsible_use.md](docs/responsible_use.md).

## License

MIT; see [LICENSE](LICENSE).
