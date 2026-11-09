"""diagnose.verdict: the decision table, with no browser involved."""
from f5_study.diagnose import verdict


def test_pass_with_challenge_cookie():
    assert verdict({"ready": True, "rejected": False}, ["TSPD_101", "TS01abc"], None).startswith("PASS ->")


def test_pass_without_challenge_when_api_answers():
    out = verdict({"ready": True, "rejected": False}, ["JSESSIONID"], "200 {}")
    assert out.startswith("PASS WITHOUT CHALLENGE")


def test_no_challenge_but_api_rejected_is_not_a_pass():
    out = verdict({"ready": True, "rejected": False}, [], "200 Request Rejected")
    assert out.startswith("UNRESOLVED")


def test_rejected_page():
    assert verdict({"ready": False, "rejected": True}, ["TS01abc"], None).startswith("REJECTED")


def test_unresolved_page():
    assert verdict({"ready": False, "rejected": False}, [], None).startswith("UNRESOLVED")
