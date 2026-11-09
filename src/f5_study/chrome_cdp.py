"""Chrome launched WITHOUT automation and driven only through CDP (websocket).

Why it exists: an F5 layer that fingerprints the device can reject the Chrome
of a browser-automation framework (chromedriver, undetected drivers, CDP-mode
wrappers) while letting the very same binary through when it is started the way
a user would start it. Here there is no chromedriver and no automation flag:
the browser is launched with the URL as an argument, and while the challenge
resolves only the tab title is read, through http://127.0.0.1:<port>/json,
which does not touch the page. The CDP websocket is opened afterwards, to
evaluate JS (for example a fetch from inside the page).

Display: a real window is used (headless scores as a bot). DISPLAY is used when
a live X server answers on it; otherwise a private Xvfb is started.

Fingerprint (`Fingerprint`, `random_fingerprint`): time zone, language, WebGL
and window size, set with flags and environment, never by touching the page.
A layer that bans the device fingerprint sees a different device with a
different combination: the same IP was rejected with a banned fingerprint and
accepted with another one.

Usage:
    with ChromeCdp(profile_dir, proxy="127.0.0.1:8899") as chrome:
        chrome.launch("https://example.com/")
        chrome.wait_title(lambda t: t == "Example", 30)
        value = chrome.evaluate("(async () => 1 + 1)()")
"""
import json
import os
import random
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

BROWSER_CANDIDATES = ("/snap/bin/chromium", "chromium", "chromium-browser",
                      "google-chrome", "google-chrome-stable")
DEFAULT_WINDOW = (1366, 768)
XVFB_SCREEN = "1920x1080x24"
DEVTOOLS_WAIT_SECONDS = 20  # until the browser opens its DevTools port

# Common European combinations: an unusual fingerprint also draws attention.
TIME_ZONES = ("Europe/Madrid", "Europe/Rome", "Europe/Paris", "Europe/Berlin", "Europe/Lisbon",
              "Europe/London", "Europe/Amsterdam", "Europe/Brussels", "Europe/Vienna", "Europe/Zurich")
LANGUAGES = (("it-IT", "it-IT,it"), ("es-ES", "es-ES,es"), ("en-US", "en-US,en"), ("en-GB", "en-GB,en"),
             ("fr-FR", "fr-FR,fr"), ("de-DE", "de-DE,de"), ("pt-PT", "pt-PT,pt"), ("nl-NL", "nl-NL,nl"))
WINDOWS = ((1366, 768), (1440, 900), (1536, 864), (1600, 900), (1280, 800), (1680, 1050), (1920, 1080))


class ChromeCdpError(RuntimeError):
    """The browser did not start, did not answer, or CDP returned an error."""


@dataclass(frozen=True)
class Fingerprint:
    """What can be varied in the fingerprint without automation."""
    time_zone: str                 # TZ of the browser process
    language: str                  # --lang
    accept_language: str           # --accept-lang (navigator.languages and Accept-Language)
    webgl: bool                    # False = --disable-3d-apis
    window: Tuple[int, int]        # --window-size

    def summary(self) -> str:
        return (f"{self.time_zone}, {self.language}, WebGL {'yes' if self.webgl else 'no'}, "
                f"{self.window[0]}x{self.window[1]}")

    def flags(self) -> List[str]:
        flags = [f"--lang={self.language}", f"--accept-lang={self.accept_language}",
                 f"--window-size={self.window[0]},{self.window[1]}"]
        if not self.webgl:
            flags.append("--disable-3d-apis")
        return flags

    def environment(self) -> Dict[str, str]:
        locale = self.language.replace("-", "_")
        return {"TZ": self.time_zone, "LANG": f"{locale}.UTF-8", "LANGUAGE": locale}


def random_fingerprint(rng: random.Random = random) -> Fingerprint:
    language, accept_language = rng.choice(LANGUAGES)
    return Fingerprint(time_zone=rng.choice(TIME_ZONES), language=language,
                       accept_language=accept_language, webgl=rng.random() < 0.5,
                       window=rng.choice(WINDOWS))


def find_browser(preferred: Optional[str] = None) -> str:
    """Path of the browser: the preferred one or the first installed candidate."""
    for candidate in ([preferred] if preferred else []) + list(BROWSER_CANDIDATES):
        path = shutil.which(candidate) or (candidate if os.path.isfile(candidate) else None)
        if path:
            return path
    raise ChromeCdpError(f"No Chrome/Chromium installed (tried: {', '.join(BROWSER_CANDIDATES)})")


def display_alive(display: Optional[str]) -> bool:
    """An X server is listening on `display`. Both the path socket and the
    abstract one are probed: an Xvfb started in another /tmp namespace is only
    visible through the abstract socket. A remote display (host:N) is trusted."""
    if not display or ":" not in display:
        return False
    host, _, rest = display.rpartition(":")
    if host and host != "unix":
        return True
    number = rest.split(".")[0]
    if not number.isdigit():
        return False
    for address in (f"/tmp/.X11-unix/X{number}", f"\0/tmp/.X11-unix/X{number}"):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect(address)
            return True
        except OSError:
            continue
        finally:
            s.close()
    return False


class _Xvfb:
    """Private Xvfb. -displayfd lets it pick a free number, with no races
    against other processes starting their own."""

    def __init__(self):
        self.proc: Optional[subprocess.Popen] = None
        self.display: Optional[str] = None

    def start(self) -> str:
        if not shutil.which("Xvfb"):
            raise ChromeCdpError("No live X server on DISPLAY and Xvfb is not installed")
        read_fd, write_fd = os.pipe()
        try:
            self.proc = subprocess.Popen(
                ["Xvfb", "-displayfd", str(write_fd), "-screen", "0", XVFB_SCREEN, "-nolisten", "tcp"],
                pass_fds=(write_fd,), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True)
            os.close(write_fd)
            write_fd = None
            with os.fdopen(read_fd, "r") as f:
                read_fd = None
                number = f.readline().strip()
        finally:
            for fd in (read_fd, write_fd):
                if fd is not None:
                    os.close(fd)
        if not number.isdigit():
            self.stop()
            raise ChromeCdpError("Xvfb did not start")
        self.display = f":{number}"
        return self.display

    def stop(self) -> None:
        if self.proc is not None:
            _kill_group(self.proc)
            self.proc = None


def _kill_group(proc: subprocess.Popen, wait: float = 10.0) -> None:
    """SIGTERM to the process group (the browser and its children), SIGKILL if
    it does not leave in time. Idempotent."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError):
            return
        try:
            proc.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ChromeCdp:
    """An automation-free browser: launch, read the title, evaluate JS, close.

    evaluate() and command() take an internal lock, so calls from several
    threads are serialised.
    """

    def __init__(self, profile_dir: str, proxy: Optional[str] = None,
                 browser: Optional[str] = None, log: Callable[[str], None] = print,
                 fingerprint: Optional[Fingerprint] = None):
        self.profile_dir = profile_dir
        self.proxy = proxy
        self.fingerprint = fingerprint
        self.browser = browser
        self.log = log
        self.port: Optional[int] = None
        self.proc: Optional[subprocess.Popen] = None
        self._xvfb: Optional[_Xvfb] = None
        self._ws = None
        self._ws_url: Optional[str] = None
        self._id = 0
        self._lock = threading.Lock()

    # ------------------------------ lifecycle ------------------------------

    def __enter__(self) -> "ChromeCdp":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _environment(self) -> Dict[str, str]:
        env = dict(os.environ)
        if not sys.platform.startswith("linux"):
            return env
        display = os.environ.get("DISPLAY")
        if display_alive(display):
            return env
        self._xvfb = _Xvfb()
        env["DISPLAY"] = self._xvfb.start()
        self.log(f"[chrome_cdp] DISPLAY {display or '(unset)'} has no X server: "
                 f"private Xvfb on {env['DISPLAY']}")
        return env

    def launch(self, url: str) -> None:
        """Start the browser opening `url` and wait for DevTools. Does not touch the page."""
        binary = find_browser(self.browser)
        self.port = _free_port()
        flags = [
            f"--remote-debugging-port={self.port}",
            f"--user-data-dir={self.profile_dir}",
            "--no-first-run",
            "--no-default-browser-check",
        ]
        if self.fingerprint is not None:
            flags += self.fingerprint.flags()
        else:
            flags.append(f"--window-size={DEFAULT_WINDOW[0]},{DEFAULT_WINDOW[1]}")
        if self.proxy:
            flags.append(f"--proxy-server=http://{self.proxy}")
        env = self._environment()
        if self.fingerprint is not None:
            env.update(self.fingerprint.environment())
        self.proc = subprocess.Popen([binary, *flags, url], env=env, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, start_new_session=True)
        deadline = time.monotonic() + DEVTOOLS_WAIT_SECONDS
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise ChromeCdpError(f"{binary} exited on startup (code {self.proc.returncode})")
            if self._page() is not None:
                return
            time.sleep(0.5)
        raise ChromeCdpError(f"{binary} did not open DevTools within {DEVTOOLS_WAIT_SECONDS}s")

    def _close_via_cdp(self) -> None:
        """Browser.close over the browser websocket (not the tab one). It does
        not depend on being able to signal the process: with a snap-confined
        Chromium a killpg may end in PermissionError and leave it alive."""
        import websocket

        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json/version", timeout=3) as r:
                ws_url = json.load(r)["webSocketDebuggerUrl"]
            ws = websocket.create_connection(ws_url, timeout=5, suppress_origin=True)
            try:
                ws.send(json.dumps({"id": 1, "method": "Browser.close"}))
                ws.recv()
            finally:
                ws.close()
        except Exception:
            pass  # already closed or DevTools down: the signal is left

    def close(self) -> None:
        """Close the websocket, the browser (its whole group) and the private Xvfb. Idempotent."""
        if self._ws is not None:
            try:
                self._ws.close()
            except Exception:
                pass
            self._ws = None
        if self.proc is not None:
            if self.port is not None:
                self._close_via_cdp()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            _kill_group(self.proc)
            if self.proc.poll() is None:
                self.log(f"[chrome_cdp] WARNING: browser (PID {self.proc.pid}) still alive after closing")
            self.proc = None
        if self._xvfb is not None:
            self._xvfb.stop()
            self._xvfb = None

    # ------------------------- without touching the page -------------------------

    def _page(self) -> Optional[Dict[str, Any]]:
        """First tab according to /json, or None if DevTools does not answer yet."""
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json", timeout=3) as r:
                tabs = json.load(r)
        except (OSError, ValueError):
            return None
        return next((p for p in tabs if p.get("type") == "page"), None)

    def title(self) -> Optional[str]:
        page = self._page()
        return page.get("title", "") if page else None

    def wait_title(self, condition: Callable[[str], bool], seconds: float,
                   interval: float = 1.0) -> Optional[str]:
        """Poll the title through /json until `condition` holds or time runs
        out. Returns the last title seen (None if DevTools never answered)."""
        deadline = time.monotonic() + seconds
        while True:
            title = self.title()
            if title is not None and condition(title):
                return title
            if time.monotonic() >= deadline:
                return title
            time.sleep(interval)

    # ----------------------------------- CDP -----------------------------------

    def _connect(self) -> None:
        if self._ws is not None:
            return
        import websocket  # websocket-client: only needed once the browser is open

        page = self._page()
        if not page or "webSocketDebuggerUrl" not in page:
            raise ChromeCdpError("DevTools offers no websocket for the tab")
        self._ws_url = page["webSocketDebuggerUrl"]
        # No Origin header: Chrome rejects DevTools websockets whose Origin is
        # not listed in --remote-allow-origins.
        self._ws = websocket.create_connection(self._ws_url, timeout=30, suppress_origin=True)

    def command(self, method: str, params: Optional[Dict[str, Any]] = None,
                timeout: float = 30.0) -> Dict[str, Any]:
        """Send a CDP command and return its `result`. Events are ignored:
        no domain is enabled."""
        with self._lock:
            self._connect()
            self._id += 1
            my_id = self._id
            self._ws.settimeout(timeout)
            try:
                self._ws.send(json.dumps({"id": my_id, "method": method, "params": params or {}}))
                while True:
                    msg = json.loads(self._ws.recv())
                    if msg.get("id") == my_id:
                        break
            except Exception as e:
                # A half-read websocket cannot be reused.
                try:
                    self._ws.close()
                except Exception:
                    pass
                self._ws = None
                raise ChromeCdpError(f"CDP {method} failed: {type(e).__name__}: {e}") from e
        if "error" in msg:
            raise ChromeCdpError(f"CDP {method}: {msg['error']}")
        return msg.get("result", {})

    def evaluate(self, expression: str, await_promise: bool = True, timeout: float = 30.0) -> Any:
        """Evaluate JS in the page and return the value (by value, not by reference)."""
        res = self.command("Runtime.evaluate", {"expression": expression, "awaitPromise": await_promise,
                                                "returnByValue": True}, timeout=timeout)
        if "exceptionDetails" in res:
            detail = res["exceptionDetails"].get("exception", {}).get("description") or res["exceptionDetails"]
            raise ChromeCdpError(f"Exception in the page: {detail}")
        return res.get("result", {}).get("value")

    def html(self) -> str:
        return self.evaluate("document.documentElement.outerHTML", await_promise=False) or ""

    def cookies(self) -> List[Dict[str, Any]]:
        return self.command("Network.getAllCookies").get("cookies", [])
