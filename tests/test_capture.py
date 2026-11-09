"""capture: diagnostic files and resource statuses that never raise."""
import base64
import os

from f5_study.capture import resource_statuses, save_diagnostic


class _Chrome:
    def __init__(self, png=b"\x89PNG-bytes", html="<html>x</html>", entries=None, fail=()):
        self.png, self._html, self.entries, self.fail = png, html, entries, set(fail)
        self.commands = []
        self.expressions = []

    def command(self, method, params=None, timeout=30.0):
        self.commands.append(method)
        if "command" in self.fail:
            raise RuntimeError("cdp down")
        return {"data": base64.b64encode(self.png).decode()}

    def html(self):
        if "html" in self.fail:
            raise RuntimeError("page gone")
        return self._html

    def evaluate(self, expression, await_promise=True, timeout=30.0):
        self.expressions.append(expression)
        if "evaluate" in self.fail:
            raise RuntimeError("page gone")
        return self.entries


def _log():
    lines = []
    return lines, lines.append


def test_save_diagnostic_writes_png_and_html(tmp_path):
    chrome = _Chrome()
    lines, log = _log()
    base = save_diagnostic(chrome, str(tmp_path), "no_calendar", log=log)
    assert base is not None and os.path.basename(base).startswith("no_calendar_")
    assert open(base + ".png", "rb").read() == b"\x89PNG-bytes"
    assert open(base + ".html", encoding="utf-8").read() == "<html>x</html>"
    assert chrome.commands == ["Page.captureScreenshot"]
    assert lines  # it says what it saved


def test_save_diagnostic_creates_the_directory(tmp_path):
    target = tmp_path / "a" / "b"
    assert save_diagnostic(_Chrome(), str(target), "x") is not None
    assert target.is_dir()


def test_save_diagnostic_keeps_html_when_screenshot_fails(tmp_path):
    lines, log = _log()
    base = save_diagnostic(_Chrome(fail=["command"]), str(tmp_path), "x", log=log)
    assert base is not None
    assert os.path.exists(base + ".html") and not os.path.exists(base + ".png")
    assert any("screenshot" in l for l in lines)


def test_save_diagnostic_never_raises_and_returns_none_when_all_fails(tmp_path):
    lines, log = _log()
    assert save_diagnostic(_Chrome(fail=["command", "html"]), str(tmp_path), "x", log=log) is None
    assert lines


def test_save_diagnostic_survives_unwritable_directory(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("not a dir")
    lines, log = _log()
    assert save_diagnostic(_Chrome(), str(blocker / "sub"), "x", log=log) is None
    assert lines


def test_label_is_sanitised(tmp_path):
    base = save_diagnostic(_Chrome(), str(tmp_path), "../evil name")
    assert os.path.dirname(base) == str(tmp_path)


def test_resource_statuses_filters_by_substring():
    chrome = _Chrome(entries=[{"name": "https://h/api/a", "status": 200},
                              {"name": "https://h/img.png", "status": 200},
                              {"name": "https://h/api/b", "status": 403}])
    assert resource_statuses(chrome, "/api/") == ["https://h/api/a 200", "https://h/api/b 403"]
    assert "responseStatus" in chrome.expressions[0]
    assert "getEntriesByType('resource')" in chrome.expressions[0]


def test_resource_statuses_empty_when_unreadable():
    lines, log = _log()
    assert resource_statuses(_Chrome(fail=["evaluate"]), "x", log=log) == []
    assert lines
    assert resource_statuses(_Chrome(entries=None), "x") == []
    assert resource_statuses(_Chrome(entries="junk"), "x") == []
