"""chrome_cdp: automation-free Chrome driven over CDP.

No browser and no network: /json, the websocket and the process are doubles.
Checks that the browser launches without automation flags, that the title is
read without touching the page, that CDP commands match their reply by id and
ignore events, and that a failure discards the websocket.
"""
import json
import random
import socket
import sys
import types

import pytest

import f5_study.chrome_cdp as cc
from f5_study.chrome_cdp import ChromeCdp, ChromeCdpError


class _Ws:
    def __init__(self, replies):
        self.replies = list(replies)
        self.sent = []
        self.closed = False

    def settimeout(self, t):
        self.timeout = t

    def send(self, text):
        self.sent.append(json.loads(text))

    def recv(self):
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return json.dumps(r)

    def close(self):
        self.closed = True


def _chrome_with_ws(monkeypatch, ws):
    chrome = ChromeCdp("/tmp/test_profile", log=lambda m: None)
    monkeypatch.setattr(chrome, "_page", lambda: {"type": "page", "title": "x",
                                                  "webSocketDebuggerUrl": "ws://127.0.0.1:1/devtools/page/1"})
    fake = types.ModuleType("websocket")
    fake.create_connection = lambda url, timeout=None, suppress_origin=False: (
        ws if suppress_origin else pytest.fail("without suppress_origin Chrome rejects the websocket"))
    monkeypatch.setitem(sys.modules, "websocket", fake)
    return chrome


class _Proc:
    def __init__(self, alive=True):
        self.pid = 4242
        self.returncode = None if alive else 1

    def poll(self):
        return self.returncode


# -- Binary and display -------------------------------------------------------

def test_preferred_browser_wins(monkeypatch):
    monkeypatch.setattr(cc.shutil, "which", lambda c: f"/usr/bin/{c}" if c == "my-chrome" else None)
    assert cc.find_browser("my-chrome") == "/usr/bin/my-chrome"


def test_no_browser_is_an_error(monkeypatch):
    monkeypatch.setattr(cc.shutil, "which", lambda c: None)
    monkeypatch.setattr(cc.os.path, "isfile", lambda p: False)
    with pytest.raises(ChromeCdpError, match="No Chrome"):
        cc.find_browser()


@pytest.mark.parametrize("display", [None, "", "no-colon", ":x"])
def test_invalid_display_is_not_alive(display):
    assert cc.display_alive(display) is False


def test_remote_display_is_trusted():
    assert cc.display_alive("localhost:10.0") is True


def test_display_alive_probes_the_abstract_socket(monkeypatch):
    probed = []

    class _Socket:
        def __init__(self, *a):
            pass

        def settimeout(self, t):
            pass

        def connect(self, address):
            probed.append(address)
            if not address.startswith("\0"):
                raise FileNotFoundError(address)

        def close(self):
            pass

    monkeypatch.setattr(cc.socket, "socket", _Socket)
    assert cc.display_alive(":1") is True
    assert probed == ["/tmp/.X11-unix/X1", "\0/tmp/.X11-unix/X1"]


def test_without_x_server_a_private_xvfb_is_started(monkeypatch):
    monkeypatch.setattr(cc.sys, "platform", "linux")
    monkeypatch.setenv("DISPLAY", ":10")
    monkeypatch.setattr(cc, "display_alive", lambda d: False)

    class _FakeXvfb:
        def start(self):
            return ":99"

        def stop(self):
            pass

    monkeypatch.setattr(cc, "_Xvfb", _FakeXvfb)
    env = ChromeCdp("/tmp/p", log=lambda m: None)._environment()
    assert env["DISPLAY"] == ":99"
    assert cc.os.environ["DISPLAY"] == ":10"  # the process environment is untouched


# -- Launch -------------------------------------------------------------------

def test_launch_without_automation_flags(monkeypatch):
    launched = []
    monkeypatch.setattr(cc, "find_browser", lambda b: "/snap/bin/chromium")
    monkeypatch.setattr(cc, "_free_port", lambda: 9333)
    monkeypatch.setattr(ChromeCdp, "_environment", lambda self: {})
    monkeypatch.setattr(cc.subprocess, "Popen", lambda args, **kw: launched.append((args, kw)) or _Proc())
    chrome = ChromeCdp("/tmp/profile_x", proxy="127.0.0.1:54321", log=lambda m: None)
    monkeypatch.setattr(chrome, "_page", lambda: {"type": "page"})
    chrome.launch("https://example.com/")

    args, kw = launched[0]
    assert args[0] == "/snap/bin/chromium" and args[-1] == "https://example.com/"
    assert "--remote-debugging-port=9333" in args
    assert "--user-data-dir=/tmp/profile_x" in args
    assert "--proxy-server=http://127.0.0.1:54321" in args
    assert not any("automation" in a.lower() or "headless" in a or "blink-features" in a for a in args)
    assert kw["start_new_session"] is True  # so the whole group can be killed on close


def test_launch_with_fingerprint_sets_flags_and_environment(monkeypatch):
    launched = []
    monkeypatch.setattr(cc, "find_browser", lambda b: "/snap/bin/chromium")
    monkeypatch.setattr(cc, "_free_port", lambda: 9333)
    monkeypatch.setattr(ChromeCdp, "_environment", lambda self: {"PATH": "/usr/bin"})
    monkeypatch.setattr(cc.subprocess, "Popen", lambda args, **kw: launched.append((args, kw)) or _Proc())
    fp = cc.Fingerprint(time_zone="Europe/Rome", language="it-IT", accept_language="it-IT,it",
                        webgl=False, window=(1440, 900))
    chrome = ChromeCdp("/tmp/p", fingerprint=fp, log=lambda m: None)
    monkeypatch.setattr(chrome, "_page", lambda: {"type": "page"})
    chrome.launch("https://x/")
    args, kw = launched[0]
    assert {"--lang=it-IT", "--accept-lang=it-IT,it", "--window-size=1440,900", "--disable-3d-apis"} <= set(args)
    assert sum(a.startswith("--window-size") for a in args) == 1
    assert kw["env"]["TZ"] == "Europe/Rome" and kw["env"]["LANG"] == "it_IT.UTF-8"
    assert kw["env"]["PATH"] == "/usr/bin"


def test_random_fingerprint_comes_from_the_lists():
    rng = random.Random(7)
    seen = {cc.random_fingerprint(rng) for _ in range(50)}
    assert len(seen) > 10  # it really varies
    for f in seen:
        assert f.time_zone in cc.TIME_ZONES and (f.language, f.accept_language) in cc.LANGUAGES
        assert f.window in cc.WINDOWS
        assert ("--disable-3d-apis" in f.flags()) is (not f.webgl)


def test_launch_fails_if_the_browser_dies(monkeypatch):
    monkeypatch.setattr(cc, "find_browser", lambda b: "/usr/bin/chromium")
    monkeypatch.setattr(ChromeCdp, "_environment", lambda self: {})
    monkeypatch.setattr(cc.subprocess, "Popen", lambda args, **kw: _Proc(alive=False))
    chrome = ChromeCdp("/tmp/p", log=lambda m: None)
    monkeypatch.setattr(chrome, "_page", lambda: None)
    with pytest.raises(ChromeCdpError, match="exited on startup"):
        chrome.launch("https://x/")


def test_close_kills_the_group_and_is_idempotent(monkeypatch):
    killed = []
    monkeypatch.setattr(cc, "_kill_group", lambda proc: killed.append(proc.pid))
    chrome = ChromeCdp("/tmp/p", log=lambda m: None)
    chrome.proc = _Proc()
    chrome.close()
    chrome.close()
    assert killed == [4242]


# -- Title and CDP ------------------------------------------------------------

def test_wait_title_returns_the_matching_one(monkeypatch):
    titles = iter([None, "", "example.com", "Example"])
    chrome = ChromeCdp("/tmp/p", log=lambda m: None)
    monkeypatch.setattr(chrome, "title", lambda: next(titles))
    monkeypatch.setattr(cc.time, "sleep", lambda s: None)
    assert chrome.wait_title(lambda t: t == "Example", 30) == "Example"


def test_wait_title_times_out_with_the_last_one(monkeypatch):
    chrome = ChromeCdp("/tmp/p", log=lambda m: None)
    monkeypatch.setattr(chrome, "title", lambda: "example.com")
    assert chrome.wait_title(lambda t: False, 0) == "example.com"


def test_command_matches_by_id_and_ignores_events(monkeypatch):
    ws = _Ws([{"method": "Page.loadEventFired", "params": {}},
              {"id": 1, "result": {"result": {"type": "number", "value": 2}}}])
    chrome = _chrome_with_ws(monkeypatch, ws)
    assert chrome.evaluate("1 + 1") == 2
    sent = ws.sent[0]
    assert sent["method"] == "Runtime.evaluate"
    assert sent["params"] == {"expression": "1 + 1", "awaitPromise": True, "returnByValue": True}


def test_exception_in_the_page_is_an_error(monkeypatch):
    ws = _Ws([{"id": 1, "result": {"result": {}, "exceptionDetails": {
        "exception": {"description": "ReferenceError: x is not defined"}}}}])
    with pytest.raises(ChromeCdpError, match="ReferenceError"):
        _chrome_with_ws(monkeypatch, ws).evaluate("x")


def test_cdp_error_is_an_error(monkeypatch):
    ws = _Ws([{"id": 1, "error": {"code": -32000, "message": "No target"}}])
    with pytest.raises(ChromeCdpError, match="No target"):
        _chrome_with_ws(monkeypatch, ws).command("Network.getAllCookies")


def test_websocket_failure_discards_it(monkeypatch):
    ws = _Ws([socket.timeout("timed out")])
    chrome = _chrome_with_ws(monkeypatch, ws)
    with pytest.raises(ChromeCdpError, match="timed out"):
        chrome.evaluate("1")
    assert ws.closed and chrome._ws is None  # the next command reconnects


def test_cookies_returns_the_list(monkeypatch):
    ws = _Ws([{"id": 1, "result": {"cookies": [{"name": "TSPD_101", "value": "v"}]}}])
    assert _chrome_with_ws(monkeypatch, ws).cookies() == [{"name": "TSPD_101", "value": "v"}]


def test_close_tries_browser_close_before_the_signal(monkeypatch):
    order = []

    class _ExitingProc(_Proc):
        def wait(self, timeout=None):
            order.append("wait")
            self.returncode = 0

    monkeypatch.setattr(ChromeCdp, "_close_via_cdp", lambda self: order.append("cdp"))
    monkeypatch.setattr(cc, "_kill_group", lambda proc: order.append("signal"))
    chrome = ChromeCdp("/tmp/p", log=lambda m: pytest.fail(f"should not warn: {m}"))
    chrome.proc, chrome.port = _ExitingProc(), 9333
    chrome.close()
    assert order == ["cdp", "wait", "signal"]
