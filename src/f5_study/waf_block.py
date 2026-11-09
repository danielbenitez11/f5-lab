"""Vendor-neutral block detection, fast failure and classification.

Pure functions: no browser, no network. The point is to decide, from what a
page or a response actually says, whether a WAF turned the visitor away, and to
stop waiting as soon as a challenge reports that it has failed.

This layer detects, classifies and fails fast. It does not defeat a WAF.
"""
import time
from typing import Callable, Iterable, Optional, Tuple

# Generic phrases found on block pages. Lowercase; matching is case-insensitive.
# Callers should pass their own list when a service words its block differently.
DEFAULT_BLOCK_MARKERS = (
    "you have been blocked",
    "unable to access this website",
    "matches an attack",
    "request rejected",
    "access denied",
    "too many requests",
)

# Only these statuses can carry a WAF verdict; the body decides.
BLOCK_STATUSES = (403, 429)

# States a challenge page shows when it has already failed: waiting longer
# only burns the timeout.
FAST_FAIL_STATES = (
    "automation detected",
    "browser check incomplete",
)

BLOCK_ON_LOAD = "BLK-WAF"
BLOCK_ON_REQUESTS = "BLK-RATELIMIT"

REASON_FAST_FAIL = "fast_fail"
REASON_BLOCK = "block"
REASON_READY = "ready"
REASON_TIMEOUT = "timeout"


def _contains(text: Optional[str], needles: Iterable[str]) -> bool:
    if not text:
        return False
    low = text.lower()
    return any(n.lower() in low for n in needles)


def is_block_text(body: Optional[str], markers: Iterable[str] = DEFAULT_BLOCK_MARKERS) -> bool:
    """The body alone says it is a block page (for navigations, where there is no status)."""
    return _contains(body, markers)


def is_block_response(status: Optional[int], body: Optional[str],
                      markers: Iterable[str] = DEFAULT_BLOCK_MARKERS) -> bool:
    """A 403/429 whose body carries a block marker. A bare 429 is not a block:
    it may be an ordinary rate limit."""
    return status in BLOCK_STATUSES and is_block_text(body, markers)


def is_fast_fail_state(text: Optional[str], states: Iterable[str] = FAST_FAIL_STATES) -> bool:
    """The challenge reports it already failed (case-insensitive substring)."""
    return _contains(text, states)


def classify_block(on_load: bool, status: Optional[int] = None) -> str:
    """BLK-WAF for a block when the page loads, BLK-RATELIMIT for a block on
    the requests made afterwards. `status` is accepted for call-site symmetry."""
    return BLOCK_ON_LOAD if on_load else BLOCK_ON_REQUESTS


def wait_until_settled(read_state: Callable[[], Optional[str]], timeout: float, interval: float = 1.0,
                       ready: Optional[Callable[[str], bool]] = None,
                       markers: Iterable[str] = DEFAULT_BLOCK_MARKERS,
                       states: Iterable[str] = FAST_FAIL_STATES,
                       sleep: Callable[[float], None] = time.sleep,
                       clock: Callable[[], float] = time.monotonic) -> Tuple[str, Optional[str]]:
    """Poll `read_state` (title, body text...) and return (reason, last_state).

    reason is "fast_fail" or "block" as soon as one shows up, "ready" when
    `ready(state)` holds, else "timeout". A reader that raises counts as an
    empty read: the wait must not break the attempt.
    """
    markers, states = tuple(markers), tuple(states)
    deadline = clock() + timeout
    state: Optional[str] = None
    while True:
        try:
            state = read_state()
        except Exception:
            state = None
        if is_fast_fail_state(state, states):
            return REASON_FAST_FAIL, state
        if is_block_text(state, markers):
            return REASON_BLOCK, state
        if state is not None and ready is not None and ready(state):
            return REASON_READY, state
        if clock() >= deadline:
            return REASON_TIMEOUT, state
        sleep(interval)
