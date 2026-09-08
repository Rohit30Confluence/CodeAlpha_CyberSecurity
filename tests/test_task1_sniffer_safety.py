import pytest

from codealpha_cybersecurity.network_sniffer.sniffer import capture


def test_capture_rejects_unbounded_or_excessive_limits_before_capture() -> None:
    with pytest.raises(ValueError):
        capture(count=0)
    with pytest.raises(ValueError):
        capture(count=1001)
    with pytest.raises(ValueError):
        capture(timeout=301)
