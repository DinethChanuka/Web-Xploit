#!/usr/bin/env python3
"""
HTTP directory brute-force with intelligent WAF bypass, protocol auto-negotiation,
wildcard 403/404 filtering, and guaranteed non-blocking termination.
"""

import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, CancelledError
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    requests = None


DEFAULT_CONNECT_TIMEOUT = 3.5
DEFAULT_READ_TIMEOUT = 5.0
DEFAULT_TIMEOUT: Tuple[float, float] = (DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT)
DEFAULT_THREADS = 15
DEFAULT_WATCHDOG_SECONDS = 300

# Authentic modern browser headers to bypass Cloudflare / LiteSpeed bot rules & 403s
BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}

INTERESTING_STATUS = {
    200, 201, 202, 204, 206,
    301, 302, 303, 307, 308,
    401, 403, 405, 500,
}


def _normalize_timeout(t: Any) -> Tuple[float, float]:
    if isinstance(t, (int, float)):
        return (float(t), float(t))
    if isinstance(t, tuple) and len(t) == 2:
        return (float(t[0]), float(t[1]))
    return DEFAULT_TIMEOUT


def _make_session(host_header: Optional[str] = None) -> "requests.Session":
    """Session with realistic browser headers and SSL verification disabled."""
    if requests is None:
        raise RuntimeError("requests library is not installed")

    sess = requests.Session()
    sess.headers.update(BROWSER_HEADERS)
    if host_header:
        sess.headers["Host"] = host_header

    _orig_request = sess.request

    def _request_with_timeout(method: str, url: str, **kwargs: Any) -> Any:
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = DEFAULT_TIMEOUT
        return _orig_request(method, url, **kwargs)

    sess.request = _request_with_timeout  # type: ignore[assignment]
    return sess


def load_wordlist(path: str) -> List[str]:
    """Load and normalize entries from a wordlist file."""
    if not os.path.isfile(path):
        # Fallback to repo wordlists
        cand = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists", os.path.basename(path))
        if os.path.isfile(cand):
            path = cand
        else:
            default_cand = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists", "directories.txt")
            if os.path.isfile(default_cand):
                path = default_cand

    words: List[str] = []
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                w = line.strip()
                if not w or w.startswith("#"):
                    continue
                words.append(w)
    return words


def build_url(base: str, path: str) -> str:
    if not base.endswith("/"):
        base += "/"
    return base + path.lstrip("/")


def _extract_title(html: str) -> str:
    """Extract page title from HTML."""
    if not html:
        return ""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if m:
        t = re.sub(r"\s+", " ", m.group(1)).strip()
        return t[:60]
    return ""


def probe_directory(
    session: "requests.Session",
    url: str,
    timeout: Tuple[float, float] = DEFAULT_TIMEOUT,
    stop_event: Optional[threading.Event] = None,
    wildcard_403_len: Optional[int] = None,
    wildcard_403_title: Optional[str] = None,
    wildcard_404_len: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """
    Probe one URL with redirect tracking, 403 false-positive filtering,
    and 403 bypass attempts.
    """
    if stop_event is not None and stop_event.is_set():
        return None

    try:
        r = session.get(url, timeout=timeout, verify=False, allow_redirects=False)
    except requests.exceptions.Timeout:
        return {"url": url, "path": urlparse(url).path, "status": "timeout", "length": 0, "interesting": False}
    except requests.exceptions.ConnectionError:
        return {"url": url, "path": urlparse(url).path, "status": "conn-error", "length": 0, "interesting": False}
    except Exception as e:
        return {"url": url, "path": urlparse(url).path, "status": "error", "length": 0, "interesting": False, "error": str(e)}

    status = r.status_code
    content_len = int(r.headers.get("Content-Length") or len(r.content or b""))
    location = r.headers.get("Location", "")
    content_type = r.headers.get("Content-Type", "").split(";")[0].strip()
    title = ""

    if "text/html" in content_type:
        title = _extract_title(r.text)

    # 1. Check for wildcard 404/403 false positives
    if status == 404:
        return {"url": url, "path": urlparse(url).path, "status": 404, "length": content_len, "interesting": False}

    if status == 403 and wildcard_403_len is not None:
        # If response length is within 35 bytes of generic wildcard 403 or title matches canary 403, drop
        if abs(content_len - wildcard_403_len) < 35 or (wildcard_403_title and title == wildcard_403_title and abs(content_len - wildcard_403_len) < 150):
            return {"url": url, "path": urlparse(url).path, "status": 403, "length": content_len, "interesting": False}

    # 2. Check for same-host trailing slash redirect (e.g. /login -> /login/ -> 200 OK)
    if status in (301, 302, 307, 308) and location:
        dest_url = urljoin(url, location)
        parsed_dest = urlparse(dest_url)
        parsed_orig = urlparse(url)
        # Follow if destination is on the same host
        if parsed_dest.netloc == parsed_orig.netloc or not parsed_dest.netloc:
            try:
                r2 = session.get(dest_url, timeout=timeout, verify=False, allow_redirects=False)
                if r2.status_code in (200, 206, 401, 403):
                    status = r2.status_code
                    content_len = int(r2.headers.get("Content-Length") or len(r2.content or b""))
                    content_type = r2.headers.get("Content-Type", "").split(";")[0].strip()
                    if "text/html" in content_type:
                        title = _extract_title(r2.text)
                    location = f"-> {dest_url}"
            except Exception:
                pass

    # 3. If 403, attempt reverse proxy bypass header
    bypassed = False
    if status == 403:
        for bypass_hdr in ({"X-Forwarded-For": "127.0.0.1"}, {"X-Real-IP": "127.0.0.1"}):
            try:
                r_by = session.get(url, headers=bypass_hdr, timeout=timeout, verify=False, allow_redirects=False)
                if r_by.status_code in (200, 301, 302):
                    status = r_by.status_code
                    content_len = int(r_by.headers.get("Content-Length") or len(r_by.content or b""))
                    title = f"(403 Bypassed via {list(bypass_hdr.keys())[0]}) " + _extract_title(r_by.text)
                    bypassed = True
                    break
            except Exception:
                pass

    interesting = status in INTERESTING_STATUS
    parsed_path = urlparse(url).path or "/"

    return {
        "url": url,
        "path": parsed_path,
        "status": status,
        "length": content_len,
        "content_type": content_type,
        "title": title,
        "redirect": location,
        "bypassed": bypassed,
        "interesting": interesting,
    }


def directory_bruteforce(
    base_url: str,
    wordlist_path: str,
    threads: int = DEFAULT_THREADS,
    timeout: Tuple[float, float] = DEFAULT_TIMEOUT,
    watchdog_seconds: Optional[int] = DEFAULT_WATCHDOG_SECONDS,
    extensions: Optional[List[str]] = None,
    host_header: Optional[str] = None,
    progress_callback: Optional[Callable[[int, int, Dict[str, Any]], None]] = None,
    verbose: bool = True,
) -> List[Dict[str, Any]]:
    """
    Brute-force directories with HTTP->HTTPS auto-upgrade, wildcard 403/404 filtering,
    and guaranteed termination.
    """
    if requests is None:
        raise RuntimeError("requests library is not installed")

    timeout = _normalize_timeout(timeout)

    # 1. Auto-prefix http:// if missing
    if not base_url.startswith(("http://", "https://")):
        base_url = f"http://{base_url}"

    session = _make_session(host_header=host_header)

    # 2. Check root URL for HTTP -> HTTPS upgrade & pre-flight connectivity
    try:
        r_root = session.get(base_url, timeout=timeout, verify=False, allow_redirects=False)
        if r_root.status_code in (301, 302, 307, 308):
            loc = r_root.headers.get("Location", "")
            if loc.startswith("https://") and base_url.startswith("http://"):
                dest_base = loc.rstrip("/")
                print(f"[dirbrute] Detected HTTP -> HTTPS redirect. Upgrading to {dest_base} for true status codes.")
                base_url = dest_base
    except Exception as e_root:
        # If http:// failed, test if https:// works (e.g. port 80 closed, 443 open)
        if base_url.startswith("http://"):
            https_cand = "https://" + base_url[7:]
            try:
                r_https = session.get(https_cand, timeout=timeout, verify=False, allow_redirects=False)
                if r_https.status_code:
                    print(f"[dirbrute] HTTP failed ({e_root}), but HTTPS is active. Upgrading to {https_cand}.")
                    base_url = https_cand
            except Exception:
                pass

    # 3. Check for wildcard 403 / 404 responses (canary test)
    wildcard_403_len = None
    wildcard_403_title = None
    wildcard_404_len = None
    try:
        canary_url = build_url(base_url, "_canary_test_nonexistent_xyz99_")
        r_canary = session.get(canary_url, timeout=timeout, verify=False, allow_redirects=False)
        c_len = int(r_canary.headers.get("Content-Length") or len(r_canary.content or b""))
        if r_canary.status_code == 403:
            wildcard_403_len = c_len
            wildcard_403_title = _extract_title(r_canary.text)
            print(f"[dirbrute] Note: Server returns wildcard 403 on non-existent paths ({c_len}B). Filtering generic 403s.")
        elif r_canary.status_code == 404:
            wildcard_404_len = c_len
    except Exception:
        pass

    # 4. Load Wordlist (ensure >= 1000 entries)
    words = load_wordlist(wordlist_path)
    if not words or len(words) < 50:
        default_wl = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists", "directories.txt")
        words = load_wordlist(default_wl)

    if not words:
        print(f"[dirbrute] Error: Wordlist is empty: {wordlist_path}", file=sys.stderr)
        session.close()
        return []

    if extensions:
        expanded: List[str] = []
        for w in words:
            expanded.append(w)
            for ext in extensions:
                expanded.append(f"{w}.{ext.lstrip('.')}")
        words = expanded

    total = len(words)
    if verbose:
        print(f"[dirbrute] Target      : {base_url}")
        print(f"[dirbrute] Wordlist    : {wordlist_path} ({total} entries)")
        print(f"[dirbrute] Threads     : {threads}")
        print(f"[dirbrute] Timeout     : {timeout}")
        print(f"[dirbrute] Watchdog    : {watchdog_seconds}s")
        if host_header:
            print(f"[dirbrute] Host Header : {host_header}")

    stop_event = threading.Event()
    found: List[Dict[str, Any]] = []
    found_lock = threading.Lock()

    watchdog_timer: Optional[threading.Timer] = None
    if watchdog_seconds and watchdog_seconds > 0:
        def _watchdog() -> None:
            print(f"[dirbrute] [!] Watchdog fired after {watchdog_seconds}s — aborting", file=sys.stderr)
            stop_event.set()

        watchdog_timer = threading.Timer(watchdog_seconds, _watchdog)
        watchdog_timer.daemon = True
        watchdog_timer.start()

    executor = ThreadPoolExecutor(max_workers=threads, thread_name_prefix="dirbrute")
    futures: Dict[Any, str] = {}
    completed_count = 0
    start_time = time.time()

    try:
        for word in words:
            if stop_event.is_set():
                break
            url = build_url(base_url, word)
            fut = executor.submit(
                probe_directory,
                session,
                url,
                timeout,
                stop_event,
                wildcard_403_len,
                wildcard_403_title,
                wildcard_404_len,
            )
            futures[fut] = url

        for fut in as_completed(futures):
            completed_count += 1
            try:
                result = fut.result(timeout=timeout[1] + 2)
            except CancelledError:
                continue
            except Exception as e:
                continue

            if result is None:
                continue

            if result.get("interesting"):
                with found_lock:
                    found.append(result)
                if verbose:
                    st = result["status"]
                    title_info = f" [{result['title']}]" if result.get("title") else ""
                    loc_info = f" -> {result['redirect']}" if result.get("redirect") else ""
                    print(f"[dirbrute] [+] {st:>3} {result['path']} ({result['length']}B){title_info}{loc_info}")

            if progress_callback is not None:
                try:
                    progress_callback(completed_count, total, result)
                except Exception:
                    pass

            if verbose and completed_count % 100 == 0:
                elapsed = time.time() - start_time
                rate = completed_count / elapsed if elapsed > 0 else 0.0
                print(f"[dirbrute] Progress: {completed_count}/{total} ({rate:.1f} req/s) — {len(found)} endpoint(s) found")

    except KeyboardInterrupt:
        print("[dirbrute] [!] Interrupted by user — finishing current tasks...")
        stop_event.set()
        for f in futures:
            f.cancel()
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            executor.shutdown(wait=False)
    finally:
        if watchdog_timer is not None:
            watchdog_timer.cancel()
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            executor.shutdown(wait=False)
        try:
            session.close()
        except Exception:
            pass

    # Sort results: 200s first, then other status codes
    found.sort(key=lambda x: (0 if x["status"] == 200 else (1 if str(x["status"]).startswith("3") else 2), x["path"]))

    elapsed = time.time() - start_time
    if verbose:
        print(f"[dirbrute] Done: {completed_count}/{total} probed in {elapsed:.1f}s — Found {len(found)} active endpoint(s).")

    return found


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python dir_bruteforce.py <base_url> [wordlist]")
        sys.exit(1)
    wl = sys.argv[2] if len(sys.argv) > 2 else "wordlists/directories.txt"
    hits = directory_bruteforce(sys.argv[1], wl)
    for h in hits:
        print(h)
