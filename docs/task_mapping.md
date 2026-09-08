# CodeAlpha requirement mapping

This document identifies the deliverable for each required task and how to verify it. All demonstrations must remain within an authorised local lab or owned environment.

| CodeAlpha task | Requirement addressed | Repository evidence | Demonstration |
| --- | --- | --- | --- |
| 1. Network Sniffer | Capture and inspect packet information | `network_sniffer/sniffer.py` summarises source, destination, protocol, ports, and length; it omits payloads | Run the metadata unit test or authorised bounded CLI capture. |
| 2. Phishing Awareness Training | Teach email, fake-site, and social-engineering recognition plus best practice | Ten scenario quiz items cover lookalike domains, QR links, MFA fatigue, impersonation, malicious updates, and safe reporting | Run the interactive quiz; retain only learner-approved aggregate results. |
| 3. Secure Coding Review | Identify common security issues and remediation | AST checks and `reports/secure_coding_review_report.md` identify risky calls and fixes | Run the reviewer against an authorised controlled sample. |
| 4. Network IDS using Suricata | Configure Suricata, rules, alerts, and a safe test setup | `suricata/` contains pinned Docker config, local rules, alert outputs, and lab instructions; Python engine remains an educational companion | Validate Suricata config in Docker, then replay an owned PCAP only if available. |

## Task 2 learner and reporting guidance

The quiz gives an overall score and per-category totals. A learner should review every explanation, especially missed items, then practise this reporting sequence: do not click/reply, preserve the message, report through the approved phishing-report control or help desk, and delete only after the organisation says it is safe. Training administrators should record only the minimum aggregate information needed (completion, aggregate score, training date); do not collect passwords, message contents, or unnecessary personal data.

## Task 4 alert configuration

Suricata writes a concise human-readable `fast.log` and structured `eve.json` to `suricata/logs/`. These should be treated as security records. Review alerts with time, source, destination, signature ID, and local asset context; tune thresholds only after establishing an authorised lab baseline. The bundled three rules are deliberately conservative demonstrations, not a complete detection policy.
