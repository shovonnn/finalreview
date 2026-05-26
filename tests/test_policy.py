from __future__ import annotations

from finalreview.models import Confidence, Severity
from finalreview.policy import is_blocking


def test_policy_blocks_when_threshold_is_met():
    assert is_blocking(
        Severity.HIGH,
        Confidence.HIGH,
        fail_on=Severity.HIGH,
        min_confidence=Confidence.MEDIUM,
    )


def test_policy_does_not_block_below_threshold():
    assert not is_blocking(
        Severity.MEDIUM,
        Confidence.HIGH,
        fail_on=Severity.HIGH,
        min_confidence=Confidence.MEDIUM,
    )
