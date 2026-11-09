"""waf_block: pure block detection, fast-fail states, classification and the wait helper."""
import pytest

from f5_study.waf_block import (
    BLOCK_ON_LOAD, BLOCK_ON_REQUESTS, DEFAULT_BLOCK_MARKERS, FAST_FAIL_STATES,
    classify_block, is_block_response, is_block_text, is_fast_fail_state, wait_until_settled,
)


def test_block_text_matches_case_insensitively():
    assert is_block_text("<h1>You Have Been Blocked</h1>")
    assert not is_block_text("<h1>Welcome</h1>")
    assert not is_block_text("")
    assert not is_block_text(None)


def test_markers_are_configurable():
    assert not is_block_text("denied by policy")
    assert is_block_text("Denied by policy", markers=("denied by policy",))


def test_default_markers_are_lowercase_and_generic():
    assert all(m == m.lower() for m in DEFAULT_BLOCK_MARKERS)
    assert "you have been blocked" in DEFAULT_BLOCK_MARKERS


@pytest.mark.parametrize("status", [403, 429])
def test_block_status_with_marker_is_a_block(status):
    assert is_block_response(status, "Request rejected by policy")


def test_bare_429_is_not_a_block():
    assert not is_block_response(429, "slow down")
    assert not is_block_response(429, "")
    assert not is_block_response(429, None)


@pytest.mark.parametrize("status", [200, 404, 500, None])
def test_marker_with_other_status_is_not_a_block_response(status):
    assert not is_block_response(status, "you have been blocked")


def test_response_markers_are_configurable():
    assert is_block_response(403, "nope", markers=("nope",))


@pytest.mark.parametrize("text", ["Automation detected", "  BROWSER CHECK INCOMPLETE ", "x automation detected y"])
def test_fast_fail_states(text):
    assert is_fast_fail_state(text)


def test_fast_fail_negative_and_custom():
    assert not is_fast_fail_state("Loading")
    assert not is_fast_fail_state(None)
    assert is_fast_fail_state("denied", states=("denied",))
    assert all(s == s.lower() for s in FAST_FAIL_STATES)


def test_classification():
    assert classify_block(True, 200) == "BLK-WAF"
    assert classify_block(True, None) == "BLK-WAF"
    assert classify_block(False, 403) == "BLK-RATELIMIT"
    assert classify_block(False, 429) == "BLK-RATELIMIT"
    assert BLOCK_ON_LOAD == "BLK-WAF" and BLOCK_ON_REQUESTS == "BLK-RATELIMIT"


class _Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def clock(self):
        return self.now

    def sleep(self, s):
        self.sleeps.append(s)
        self.now += s


def _run(states, **kw):
    c = _Clock()
    it = iter(states)
    last = states[-1]
    result = wait_until_settled(lambda: next(it, last), clock=c.clock, sleep=c.sleep, **kw)
    return result, c


def test_wait_returns_early_on_fast_fail_without_exhausting_timeout():
    (reason, state), c = _run(["Loading", "Loading", "Automation detected"], timeout=30, interval=1)
    assert reason == "fast_fail" and state == "Automation detected"
    assert c.now == 2  # did not wait the 30 s


def test_wait_returns_on_block_text():
    (reason, _), c = _run(["", "You have been blocked"], timeout=30, interval=1)
    assert reason == "block" and c.now == 1


def test_wait_returns_when_ready():
    (reason, state), c = _run(["Loading", "Calendar"], timeout=30, interval=1,
                              ready=lambda t: t == "Calendar")
    assert reason == "ready" and state == "Calendar"


def test_wait_times_out():
    (reason, state), c = _run(["Loading"], timeout=5, interval=2)
    assert reason == "timeout" and state == "Loading"
    assert c.now >= 5


def test_failing_reader_counts_as_empty_state():
    c = _Clock()

    def boom():
        raise RuntimeError("page gone")

    reason, state = wait_until_settled(boom, timeout=3, interval=1, clock=c.clock, sleep=c.sleep)
    assert reason == "timeout" and state is None
