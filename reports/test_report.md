# Test Report

## Automated test set

The `pytest` suite checks metadata-only packet summarisation, a perfect phishing-quiz scoring path, selected static-review findings, and IDS alerts for a monitored port plus a simulated SYN scan.

Run verification from a clean environment:

```bash
python -m pip install -e '.[dev]'
pytest
```

Expected result: all tests pass. Live packet capture is deliberately excluded from automated tests because it requires a real authorised interface and privileges.
