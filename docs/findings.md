# Findings: how WAFs treated a browser (F5 first)

Field notes from observing a production F5 (BIG-IP style) anti-bot layer from the
position of an ordinary consumer of a public website. Everything here was measured
as a visitor of a public service, with a single page load or a handful of same-origin
requests at a time. Sites, hosts, operators and IPs are intentionally left out: the
point is the method and the behaviour of the technology, not any one target.

Educational material. Do not use it against systems you are not authorised to test.

## 1. The layer, as seen from outside

- Cookies named `TS*` appear on first contact; a JS challenge is served from a
  `/TSPD/` path. Once solved, the browser carries `TSPD_101` and `TSPD_101_DID`
  (the latter is a device identifier derived from the browser fingerprint).
- A rejection is an **HTTP 200** with an HTML body titled "Request Rejected" (or a
  connection reset on the TLS/HTTP layer). Status codes do not tell you; the body does.
- The real page can still carry the `/TSPD/` script after passing, so the presence of
  the script is **not** a signal that you are being challenged.
- The layer does not always challenge. On some days the page loaded and the API
  answered with no `TSPD_*` cookie at all. Requiring the cookie produces false
  "blocked" verdicts; require the real page marker plus a working same-origin API call.

## 2. Plain HTTP clients stop working

Same endpoint, same day, after the layer hardened:

| Client | Result |
|---|---|
| HTTP client with a browser TLS impersonation profile (chrome/safari/firefox/edge) | "Request Rejected" |
| System `curl`, `requests` (OpenSSL) | "Request Rejected" |
| HTTP client with no impersonation and plain headers | worked one day, connection reset the next |
| Real Chrome + `fetch()` from inside the page | JSON |

Passing the browser's cookies to an HTTP client did not help either. Swapping HTTP
libraries is a dead end once the layer is tightened; the requests have to come from a
browser that the layer accepts.

## 3. Automation layer vs. the browser itself

A cloud server (ARM64, snap-packaged Chromium) was rejected on every request while the
same site loaded fine from a desktop:

- The same Chromium, launched by hand with the URL as an argument, **passed** in ~10 s,
  with several different IPs, even with a UTC time zone, `en-US`, no WebGL and a user
  agent that did not match the platform.
- What was being flagged was the **automation framework's Chrome** (chromedriver /
  undetected driver / CDP-mode wrapper), not the binary, the platform or the IP.

Conclusion: launch the browser like a user would, read only the tab title from
`http://127.0.0.1:<port>/json` while the challenge resolves (it does not touch the
page), and attach CDP only afterwards. See `f5_study/chrome_cdp.py`.

## 4. The ban is on the device fingerprint, not the IP

After several dozen requests in a day from one machine:

| Test | Result |
|---|---|
| Normal fingerprint, mobile-carrier IP | rejected after the challenge |
| Normal fingerprint, home IP | rejected |
| Same banned IP, different fingerprint (UTC, `en-US`, no WebGL) | **passes**, API 200 |
| Back to the normal fingerprint, same IP | rejected again |

The challenge computes a device identifier from the fingerprint and bans it for
roughly 1-2 hours, from any IP. Rotating IP did not help; changing time zone, language
and WebGL did. Hence `Fingerprint` / `random_fingerprint()`: time zone (`TZ`),
`--lang`, `--accept-lang`, `--disable-3d-apis`, `--window-size`, all set without
touching the page. Plausible European combinations were preferred, because an odd
combination also draws attention.

Not variable with flags: core count, memory and architecture. It is unknown which
fields carry the weight; the three above were enough.

## 5. IP reputation and volume

- Datacentre IPs and residential-proxy pools were rejected outright.
- A rotating mobile-carrier pool worked, but a given IP was banned after roughly
  30-60 requests, and the ban outlived 90 minutes.
- "Burning" an IP in the pool manager did not guarantee a different one on the next
  lease; repeated leases returned the same blocked IP. Ask for a fresh-IP guarantee
  or detect the repeat and release without opening a browser.
- Budget by requests per identity (IP and fingerprint), not by time. Keep the caller's
  frequency low: many fingerprints behind one IP can end in an IP-level ban.

## 6. Practical rules that came out of it

1. Decide "blocked" from the body (rejection marker), never from the status code.
2. A real page marker + a working same-origin API call is the pass criterion, not a
   specific cookie.
3. Do not repeat session-bootstrap calls the site already made in the page: a
   duplicated bootstrap request was the one that got rejected.
4. Close the browser through CDP (`Browser.close`) before signalling it; with a
   confined (snap) Chromium, `killpg` can raise `PermissionError` and leave it alive.
5. A snap Chromium keeps its profile in a private `/tmp`; clean-up from outside the
   sandbox will not reach it.
6. Never log proxy credentials or cookie values; names are enough to diagnose.
7. Treat a failed fetch as a technical failure, never as "no availability".

## 7. Open questions (F5)

- Which fingerprint fields dominate the device identifier.
- Whether the layer will learn to detect an open DevTools port (this approach would
  then fall like the automation frameworks did).
- The real per-identity request threshold; the figures above come from a few runs.

## 8. Beyond one vendor: detecting, classifying and failing fast

The F5 case above has a close relative: other WAFs (for example one of the
Octofence/Karna family) veto a visitor with a different page but the same shape of
problem. The notes below are written as diagnosis, from the same position of an
ordinary visitor. They are what a scraper can *measure*; none of them is a way
through. `f5_study/waf_block.py` and `f5_study/capture.py` implement the detection and
reporting side.

### 8.1 The block can be bound to the session

Some WAFs echo a session identifier in a response header (the id of the session
cookie). When that is so, the verdict lives with the session: a **persistent browser
profile carries the block across attempts**, while a block that was about the IP would
not follow the profile. Use a clean session per attempt as a *measurement control*: if
the same IP passes with a fresh profile and fails with the old one, the block is on the
session, not on the network.

### 8.2 A 429 is not always a rate limit

A real rate limit usually says so: `Retry-After` or the vendor's rate-limit headers. A
429 with none of them, and a body that reads "blocked" or "request rejected", is the
WAF's verdict "this is not a trustworthy browser", a different problem with a different
remedy (slowing down changes nothing). Judge by the **body**; the status alone misleads
in both directions. `is_block_response` therefore needs a 403/429 *and* a block marker;
a bare 429 is not counted as a block. The upstream classification this came from:

| Where it showed up | Class |
|---|---|
| Block page when the page loads | `BLK-WAF` |
| Block on the requests made afterwards (403/429 with block body) | `BLK-RATELIMIT` |

### 8.3 Client Hints must agree with the user agent

A user agent fixed by hand is a claim; the browser's own Client Hints
(`navigator.userAgentData`, `Sec-CH-UA*` headers) and platform fields are a second,
independent statement. If they disagree (a Windows string on a Linux browser, a major
version that differs from the hints), the mismatch is itself a signal. Check coherence
before blaming anything else; the diagnostic that prints what the page sees makes the
disagreement visible.

### 8.4 A challenge can fail fast

Some challenge pages state their failure within a second or two ("Automation
detected", "Browser check incomplete") and then sit there. Waiting the full timeout on
them only burns time and requests. `FAST_FAIL_STATES` and `wait_until_settled` cut the
wait as soon as such a state, or a block text, appears; the result carries the reason
(`fast_fail`, `block`, `ready`, `timeout`) so the caller can classify it.

### 8.5 Geolocate the exit IP through the proxy

A country filter on the exit IP is only meaningful if the lookup goes **through the
proxy**. Looked up from the server, the answer is the server's own country and every
candidate passes silently. Make the geolocation request with the same path the browser
will use, and treat a failed lookup as "unknown", never as "allowed".

### 8.6 Reputation is time-scoped

The reputation of an IP pool flips over days: the same pool rejected on one date and
passed on another. A result is therefore a statement about a date, not about a pool.
Record the date next to every verdict, and re-measure before reusing an old conclusion.

### 8.7 Limits of this layer

It **detects** a block, **classifies** it and **fails fast**; it records evidence
(screenshot, HTML, resource statuses) without ever breaking the attempt. It does not
defeat a WAF, it does not choose identities for you, and its marker lists are generic
starting points: each service words its block differently, so pass your own markers.
