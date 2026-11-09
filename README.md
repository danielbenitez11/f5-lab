# f5-study: WAF study

Field notes and small tools from studying how WAF / anti-bot layers treat a browser,
with an F5 layer as the first case. Reusable in other projects; no site, host or
operator is named. (The package keeps its name, `f5_study`.)

> Educational and defensive-research material. Use it only on systems you own or are
> authorised to test, and respect each service's terms.

Spanish version: [README.es.md](README.es.md).

## What is inside

| Piece | What it is |
|---|---|
| `src/f5_study/chrome_cdp.py` | Chrome launched like a user would (no chromedriver, no automation flags) and driven only through CDP. Title read from `/json` without touching the page; `evaluate()`, `cookies()`; private Xvfb when there is no X server; clean shutdown via `Browser.close` |
| `Fingerprint`, `random_fingerprint()` | Varies time zone, language, WebGL and window size with flags and environment only |
| `src/f5_study/diagnose.py` (`f5-diagnose`) | One-page diagnostic: launches the browser, waits for the challenge, prints the fingerprint the page sees and cookie **names**, and gives a verdict |
| `src/f5_study/waf_block.py` | Vendor-neutral, pure: block detection by body (`is_block_text`, `is_block_response`: 403/429 plus a marker, a bare 429 is not a block), fast-fail challenge states, `BLK-WAF` / `BLK-RATELIMIT` classification, and `wait_until_settled` (returns early with the reason) |
| `src/f5_study/capture.py` | Diagnostics that never raise: `save_diagnostic` (screenshot + HTML) and `resource_statuses` (Performance API) |
| `docs/findings.md` | The study: how the layers behave, what failed, what worked, and why |

## Quick start

```bash
pip install -e ".[test]"
pytest

f5-diagnose https://example.com/ --ready-marker "<app-root" --api-path /api/health
f5-diagnose https://example.com/ --fingerprint random --proxy 127.0.0.1:8899 --wait 60
```

```python
from f5_study import ChromeCdp, random_fingerprint

with ChromeCdp("/home/me/profile", fingerprint=random_fingerprint()) as chrome:
    chrome.launch("https://example.com/")
    chrome.wait_title(lambda t: "Rejected" not in t and t != "", 30)
    data = chrome.evaluate("fetch('/api/health').then(r => r.text())")
```

## Requirements

Python 3.8+, `websocket-client`, and a Chrome/Chromium on the machine. On a Linux
server without a display, `Xvfb` (the library starts its own).

## Summary of the findings

1. Plain HTTP clients, even with browser TLS impersonation, end up rejected.
2. The thing being flagged was the **automation framework's** Chrome, not the binary.
3. The device fingerprint, not the IP, is what gets banned; changing time zone,
   language and WebGL lifted a ban that changing IP did not.
4. Judge a block by the response body, never the status code (rejections are HTTP 200).
5. Across WAFs: blocks can be bound to the session (a persistent profile carries them), a
   429 without rate-limit headers is a verdict on the browser, not a rate limit, a fixed
   user agent that disagrees with Client Hints is a signal, challenges can fail fast,
   geolocate the exit IP through the proxy, and every result is time-scoped.

This toolkit detects, classifies and fails fast; it does not defeat a WAF.

Details and evidence in [docs/findings.md](docs/findings.md).

## License

MIT, see [LICENSE](LICENSE).
