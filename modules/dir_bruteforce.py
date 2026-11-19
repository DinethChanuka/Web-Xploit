#!/usr/bin/env python3
"""
HTTP directory brute-force with hard guarantees:
  * every request has a timeout  -> never hangs forever
  * thread-pool watchdog         -> aborts after N seconds
  * stop_event cancellation      -> Ctrl+C is immediate
  * graceful KeyboardInterrupt   -> no dangling threads
"""

import sys
import threading
import time
from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed,
    CancelledError,
)
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    requests = None


DEFAULT_CONNECT_TIMEOUT = 5
DEFAULT_READ_TIMEOUT = 10
DEFAULT_TIMEOUT: Tuple[int, int] = (DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT)
DEFAULT_THREADS = 20
DEFAULT_WATCHDOG_SECONDS = 300

USER_AGENT = "Mozilla/5.0 (compatible; Web-Xploit/1.0)"

INTERESTING_STATUS = {
    200, 201, 202, 203, 204, 206,
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
    """Session with baked-in timeout + UA (+ optional Host override)."""
    if requests is None:
        raise RuntimeError("requests library is not installed")

    sess = requests.Session()
    sess.headers.update({"User-Agent": USER_AGENT})
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
    words: List[str] = []
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


def probe_directory(
    session: "requests.Session",
    url: str,
    timeout: Tuple[float, float] = DEFAULT_TIMEOUT,
    stop_event: Optional[threading.Event] = None,
) -> Optional[Dict[str, Any]]:
    """Probe one URL. Returns a dict with status info, or None if cancelled."""
    if stop_event is not None and stop_event.is_set():
        return None
    try:
        r = session.get(url, timeout=timeout, verify=False, allow_redirects=False)
    except requests.exceptions.Timeout:
        return {"url": url, "status": "timeout", "length": 0, "interesting": False}
    except requests.exceptions.ConnectionError as e:
        return {"url": url, "status": "conn-error", "length": 0,
                "interesting": False, "error": str(e)}
    except Exception as e:
        return {"url": url, "status": "error", "length": 0,
                "interesting": False, "error": str(e)}

    length = int(r.headers.get("Content-Length") or len(r.content or b""))
    return {
        "url": url,
        "status": r.status_code,
        "length": length,
        "redirect": r.headers.get("Location", ""),
        "interesting": r.status_code in INTERESTING_STATUS,
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
    Brute-force directories. Returns list of interesting results.
    Guarantees termination even on unresponsive hosts.
    """
    if requests is None:
        raise RuntimeError("requests library is not installed")

    timeout = _normalize_timeout(timeout)
    words = load_wordlist(wordlist_path)
    if not words:
        print(f"[dirbrute] Wordlist is empty: {wordlist_path}", file=sys.stderr)
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
        print(f"[dirbrute] Target    : {base_url}", file=sys.stderr)
        print(f"[dirbrute] Wordlist  : {wordlist_path} ({total} entries)", file=sys.stderr)
        print(f"[dirbrute] Threads   : {threads}", file=sys.stderr)
        print(f"[dirbrute] Timeout   : {timeout}", file=sys.stderr)
        print(f"[dirbrute] Watchdog  : {watchdog_seconds}s", file=sys.stderr)
        if host_header:
            print(f"[dirbrute] Host hdr  : {host_header}", file=sys.stderr)

    session = _make_session(host_header=host_header)
    stop_event = threading.Event()
    found: List[Dict[str, Any]] = []
    found_lock = threading.Lock()

    watchdog_timer: Optional[threading.Timer] = None
    if watchdog_seconds and watchdog_seconds > 0:
        def _watchdog() -> None:
            print(
                f"[dirbrute] [!] Watchdog fired after {watchdog_seconds}s — aborting",
                file=sys.stderr,
            )
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
            fut = executor.submit(probe_directory, session, url, timeout, stop_event)
            futures[fut] = url

        for fut in as_completed(futures):
            completed_count += 1
            try:
                result = fut.result(timeout=timeout[1] + 2)
            except CancelledError:
                continue
            except Exception as e:
                if verbose:
                    print(f"[dirbrute] future error: {e}", file=sys.stderr)
                continue

            if result is None:
                continue

            if result.get("interesting"):
                with found_lock:
                    found.append(result)
                if verbose:
                    print(
                        f"[dirbrute] [+] {result['status']:>3} "
                        f"{result['url']} ({result['length']}B)",
                        file=sys.stderr,
                    )

            if progress_callback is not None:
                try:
                    progress_callback(completed_count, total, result)
                except Exception:
                    pass

            if verbose and completed_count % 50 == 0:
                elapsed = time.time() - start_time
                rate = completed_count / elapsed if elapsed > 0 else 0.0
                print(
                    f"[dirbrute] progress: {completed_count}/{total} "
                    f"({rate:.1f} req/s)",
                    file=sys.stderr,
                )

    except KeyboardInterrupt:
        print("[dirbrute] [!] Interrupted by user — cancelling...", file=sys.stderr)
        stop_event.set()
        for f in futures:
            f.cancel()
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            executor.shutdown(wait=False)
        raise
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

    elapsed = time.time() - start_time
    if verbose:
        print(
            f"[dirbrute] Done: {completed_count}/{total} in {elapsed:.1f}s "
            f"({len(found)} found)",
            file=sys.stderr,
        )
    if stop_event.is_set() and completed_count < total:
        print("[dirbrute] [!] Aborted early (watchdog or Ctrl+C)", file=sys.stderr)

    return found


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python dir_bruteforce.py <base_url> <wordlist>")
        sys.exit(1)
    hits = directory_bruteforce(sys.argv[1], sys.argv[2])
    for h in hits:
        print(h)