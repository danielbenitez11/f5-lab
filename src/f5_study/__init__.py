"""Tooling for studying how WAF / anti-bot layers treat a browser (F5 was the first case)."""
from .capture import resource_statuses, save_diagnostic  # noqa: F401
from .chrome_cdp import (  # noqa: F401
    ChromeCdp,
    ChromeCdpError,
    Fingerprint,
    random_fingerprint,
)
from .waf_block import (  # noqa: F401
    DEFAULT_BLOCK_MARKERS,
    FAST_FAIL_STATES,
    classify_block,
    is_block_response,
    is_block_text,
    is_fast_fail_state,
    wait_until_settled,
)

__all__ = [
    "ChromeCdp", "ChromeCdpError", "Fingerprint", "random_fingerprint",
    "DEFAULT_BLOCK_MARKERS", "FAST_FAIL_STATES", "classify_block", "is_block_response",
    "is_block_text", "is_fast_fail_state", "wait_until_settled",
    "resource_statuses", "save_diagnostic",
]
