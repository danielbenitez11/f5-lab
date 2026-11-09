"""One-page diagnostic of an F5 layer with an automation-free Chrome.

Separates the two possible causes of a "Request Rejected":
  - the automation layer (chromedriver, undetected drivers, CDP-mode wrappers), or
  - the binary, the platform or the device fingerprint itself.

It launches the system Chrome like a normal user would (no chromedriver, no
automation flags, no page interaction) with the URL as an argument and, while
the F5 resolves, only reads the tab title through http://127.0.0.1:<port>/json.
Only when the wait is over does it read the browser fingerprint and the cookie
NAMES (never their values) over CDP.

Usage:
    f5-diagnose https://example.com/ --ready-marker "<app-root"
    f5-diagnose https://example.com/ --api-path /api/health --proxy 127.0.0.1:8899
    f5-diagnose https://example.com/ --fingerprint random --wait 60
"""
import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from typing import Any, Dict, Optional

from .chrome_cdp import (ChromeCdp, ChromeCdpError, Fingerprint, find_browser,
                         random_fingerprint)

REJECTED_MARK = "Request Rejected"
CHALLENGE_COOKIE_PREFIX = "TSPD_101"

FINGERPRINT_JS = """
(async () => {
  const h = {
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    webdriver: navigator.webdriver,
    languages: navigator.languages,
    hardwareConcurrency: navigator.hardwareConcurrency,
    deviceMemory: navigator.deviceMemory,
    screen: [screen.width, screen.height, screen.colorDepth],
    timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  };
  if (navigator.userAgentData) {
    h.brands = navigator.userAgentData.brands.map(b => b.brand + " " + b.version);
    try {
      const a = await navigator.userAgentData.getHighEntropyValues(
        ["platform", "platformVersion", "architecture", "bitness"]);
      h.clientHints = {platform: a.platform, platformVersion: a.platformVersion,
                       architecture: a.architecture, bitness: a.bitness};
    } catch (e) { h.clientHints = "error: " + e; }
  }
  try {
    const gl = document.createElement("canvas").getContext("webgl");
    const ext = gl && gl.getExtension("WEBGL_debug_renderer_info");
    h.webgl = gl ? (ext ? [gl.getParameter(ext.UNMASKED_VENDOR_WEBGL),
                           gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)] : "no extension")
                 : "no WebGL";
  } catch (e) { h.webgl = "error: " + e; }
  const html = document.documentElement.outerHTML;
  h.rejected = html.includes(%(rejected)s);
  h.ready = %(marker)s ? html.includes(%(marker)s) : !h.rejected;
  return h;
})()
"""

API_PROBE_JS = """
(async () => {
  try {
    const r = await fetch(%(path)s, {credentials: "include",
      headers: {"Accept": "application/json, text/plain, */*"}});
    const t = await r.text();
    return r.status + " " + (t.includes(%(rejected)s) ? %(rejected)s : t.slice(0, 80));
  } catch (e) { return "exception " + e; }
})()
"""


def verdict(fingerprint: Dict[str, Any], cookie_names: list, api: Optional[str]) -> str:
    """Pure decision table, kept apart from the I/O so it can be tested."""
    challenged = any(n.startswith(CHALLENGE_COOKIE_PREFIX) for n in cookie_names)
    api_ok = api is not None and str(api).startswith("200") and REJECTED_MARK not in str(api)
    if fingerprint.get("ready") and challenged:
        return "PASS -> the F5 accepts this browser and this fingerprint"
    if fingerprint.get("ready") and not fingerprint.get("rejected") and (api is None or api_ok):
        return "PASS WITHOUT CHALLENGE -> the F5 set no challenge cookie and the page is served"
    if fingerprint.get("rejected"):
        return ("REJECTED -> the F5 bans this device fingerprint (or the IP); "
                "retry with --fingerprint random to tell the two apart")
    return "UNRESOLVED -> the page did not settle in time; retry with a longer --wait"


def run(url: str, ready_marker: str, api_path: Optional[str], proxy: Optional[str],
        fingerprint: Optional[Fingerprint], wait: float, browser: Optional[str]) -> int:
    binary = find_browser(browser)
    print(f"[diag] Browser: {binary} | machine {os.uname().machine}")
    if fingerprint:
        print(f"[diag] Fingerprint: {fingerprint.summary()}")
    profile = tempfile.mkdtemp(prefix="f5_diag_", dir=os.path.expanduser("~"))
    try:
        with ChromeCdp(profile, proxy=proxy, browser=browser, fingerprint=fingerprint,
                       log=lambda m: print(m)) as chrome:
            chrome.launch(url)
            start, last = time.time(), None
            while time.time() - start < wait:
                title = chrome.title()
                if title != last:
                    last = title
                    print(f"[diag] {time.time() - start:5.1f}s title={title!r}")
                if title and "Rejected" in title:
                    break
                if title and title not in ("", url, url.split("//", 1)[-1].rstrip("/")):
                    time.sleep(3)  # margin for the F5 to set its cookie
                    break
                time.sleep(2)

            if chrome.title() is None:
                print("VERDICT: NO DATA (DevTools did not answer)")
                return 2
            js = FINGERPRINT_JS % {"rejected": json.dumps(REJECTED_MARK), "marker": json.dumps(ready_marker)}
            fp = chrome.evaluate(js) or {}
            names = sorted(c["name"] for c in chrome.cookies())
            print("[diag] Fingerprint seen by the page:")
            print(json.dumps(fp, indent=2, ensure_ascii=False))
            print(f"[diag] Cookies (names only): {names}")
            api = None
            if api_path:
                api = chrome.evaluate(API_PROBE_JS % {"path": json.dumps(api_path),
                                                      "rejected": json.dumps(REJECTED_MARK)})
                print(f"[diag] API {api_path}: {api}")
            result = verdict(fp, names, api)
            print(f"VERDICT: {result}")
            return 0 if result.startswith("PASS") else 1
    finally:
        shutil.rmtree(profile, ignore_errors=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url")
    ap.add_argument("--ready-marker", default="",
                    help="string present in the real page's HTML (e.g. an app root tag); "
                         "empty = anything that is not a rejection")
    ap.add_argument("--api-path", help="same-origin path to probe with fetch() from inside the page")
    ap.add_argument("--proxy", help="host:port of an HTTP proxy (no credentials)")
    ap.add_argument("--fingerprint", choices=("system", "random"), default="system")
    ap.add_argument("--browser", help="browser binary (default: first one found)")
    ap.add_argument("--wait", type=float, default=45.0, help="seconds for the F5 to resolve")
    args = ap.parse_args(argv)
    fp = random_fingerprint() if args.fingerprint == "random" else None
    try:
        return run(args.url, args.ready_marker, args.api_path, args.proxy, fp, args.wait, args.browser)
    except ChromeCdpError as e:
        print(f"VERDICT: NO DATA ({e})")
        return 2


if __name__ == "__main__":
    sys.exit(main())
