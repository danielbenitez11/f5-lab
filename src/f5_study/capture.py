"""Diagnostics that never break the attempt: screenshot + HTML, resource statuses.

Both helpers take a `ChromeCdp`-like object (command(), html(), evaluate()) and
swallow every failure: a diagnostic that raises would hide the real problem
behind its own. Failures are reported through the injected `log` callable.
"""
import base64
import os
import re
import time
from typing import Any, Callable, List, Optional

# responseStatus is 0 for cross-origin resources without Timing-Allow-Origin
# and for failed requests; it is reported as is.
_RESOURCES_JS = (
    "JSON.parse(JSON.stringify(performance.getEntriesByType('resource')"
    ".map(e => ({name: e.name, status: e.responseStatus}))))"
)


def _safe_label(label: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", label).strip("._") or "diagnostic"


def save_diagnostic(chrome: Any, directory: str, label: str,
                    log: Callable[[str], None] = print) -> Optional[str]:
    """Write <label>_<timestamp>.png and .html into `directory`.

    Returns the common path without extension, or None when nothing could be
    saved. A failed screenshot still leaves the HTML (and the other way round).
    """
    try:
        os.makedirs(directory, exist_ok=True)
    except Exception as e:
        log(f"[capture] cannot create {directory}: {type(e).__name__}: {e}")
        return None
    base = os.path.join(directory, f"{_safe_label(label)}_{time.strftime('%Y%m%d_%H%M%S')}")
    saved = []
    try:
        data = chrome.command("Page.captureScreenshot", {"format": "png"}).get("data", "")
        with open(base + ".png", "wb") as f:
            f.write(base64.b64decode(data))
        saved.append(base + ".png")
    except Exception as e:
        log(f"[capture] screenshot failed: {type(e).__name__}: {e}")
    try:
        with open(base + ".html", "w", encoding="utf-8") as f:
            f.write(chrome.html())
        saved.append(base + ".html")
    except Exception as e:
        log(f"[capture] html failed: {type(e).__name__}: {e}")
    if not saved:
        return None
    log(f"[capture] saved {', '.join(os.path.basename(p) for p in saved)}")
    return base


def resource_statuses(chrome: Any, needle: str, log: Callable[[str], None] = print) -> List[str]:
    """["<url> <status>", ...] for the page's resources whose URL contains
    `needle`, read from the Performance API. Empty when unreadable."""
    try:
        entries = chrome.evaluate(_RESOURCES_JS, await_promise=False)
        if not isinstance(entries, list):
            return []
        return [f"{e['name']} {e.get('status')}" for e in entries
                if isinstance(e, dict) and needle in str(e.get("name", ""))]
    except Exception as e:
        log(f"[capture] resource statuses unreadable: {type(e).__name__}: {e}")
        return []
