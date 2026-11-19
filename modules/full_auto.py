#!/usr/bin/env python3
"""
Full-auto orchestrator.  Every phase runs inside a daemon thread with its own
timeout, so a hung sub-scan can never block the whole run.
"""

import ipaddress
import socket
import sys
import threading
import time
import traceback
from typing import Any, Callable, Dict, List, Optional

from modules.dir_bruteforce import (
    directory_bruteforce,
    DEFAULT_TIMEOUT as DIR_DEFAULT_TIMEOUT,
)
from modules.ftp_detect import detect_ftp_version
from modules.origin_ip import resolve_origin_ips


PHASE_TIMEOUTS: Dict[str, float] = {
    "origin_resolve": 60.0,
    "ftp_version": 30.0,
    "dir_bruteforce": 300.0,
    "http_scan": 300.0,
    "vuln_scan": 180.0,
    "mysql_enum": 120.0,
    "auth_bypass": 120.0,
}


class PhaseTimeoutError(Exception):
    pass


def run_with_timeout(
    func: Callable[..., Any],
    args: tuple = (),
    kwargs: Optional[dict] = None,
    timeout: float = 60.0,
    name: str = "phase",
) -> Any:
    """Run func in a daemon thread; raise PhaseTimeoutError after timeout."""
    kwargs = kwargs or {}
    result_holder: List[Any] = [None]
    exc_holder: List[Optional[BaseException]] = [None]
    done = threading.Event()

    def _target() -> None:
        try:
            result_holder[0] = func(*args, **kwargs)
        except BaseException as e:
            exc_holder[0] = e
        finally:
            done.set()

    t = threading.Thread(target=_target, name=f"{name}-worker", daemon=True)
    t.start()
    if not done.wait(timeout):
        print(
            f"[full_auto] [!] Phase '{name}' exceeded {timeout}s — continuing",
            file=sys.stderr,
        )
        raise PhaseTimeoutError(f"Phase '{name}' timed out after {timeout}s")

    if exc_holder[0] is not None:
        raise exc_holder[0]
    return result_holder[0]


def _phase_wrap(
    name: str,
    fn: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> Dict[str, Any]:
    started = time.time()
    try:
        out = run_with_timeout(
            fn, args, kwargs,
            timeout=PHASE_TIMEOUTS.get(name, 60.0),
            name=name,
        )
        return {
            "phase": name, "ok": True,
            "duration": time.time() - started,
            "result": out, "error": None,
        }
    except PhaseTimeoutError as e:
        return {
            "phase": name, "ok": False,
            "duration": time.time() - started,
            "result": None, "error": str(e), "timed_out": True,
        }
    except Exception as e:
        return {
            "phase": name, "ok": False,
            "duration": time.time() - started,
            "result": None,
            "error": f"{type(e).__name__}: {e}",
            "trace": traceback.format_exc(),
        }


def _detect_target_type(target: str) -> str:
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        return "domain"


def _resolve_target(
    target: str,
    target_type: str,
    verbose: bool = True,
) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "input": target,
        "type": target_type,
        "scan_ips": [],
        "origin_results": [],
        "used_fallback": False,
    }

    if target_type == "ip":
        info["scan_ips"] = [target]
        return info

    try:
        origins = resolve_origin_ips(target, verbose=verbose)
        info["origin_results"] = origins
        verified = [o["ip"] for o in origins if o.get("verified")]
        if verified:
            info["scan_ips"] = verified[:3]
        else:
            info["used_fallback"] = True
    except Exception as e:
        print(f"[full_auto] origin resolve failed: {e}", file=sys.stderr)
        info["used_fallback"] = True

    if not info["scan_ips"]:
        try:
            ips = sorted({ai[4][0] for ai in socket.getaddrinfo(target, None)})
            info["scan_ips"] = ips[:3]
        except Exception:
            pass

    return info


def full_auto(
    target: str,
    target_type: Optional[str] = None,
    wordlist_path: str = "wordlists/common.txt",
    ftp_port: int = 21,
    verbose: bool = True,
) -> Dict[str, Any]:
    """Run all applicable attacks in order with per-phase timeouts."""
    if target_type is None:
        target_type = _detect_target_type(target)

    report: Dict[str, Any] = {
        "target": target,
        "target_type": target_type,
        "phases": [],
        "start_time": time.time(),
    }

    # ---------- Phase 1: resolve target ----------
    print(f"\n[full_auto] ==== Resolving target: {target} ({target_type}) ====",
          file=sys.stderr)
    try:
        resolved = run_with_timeout(
            _resolve_target, (target, target_type, verbose),
            timeout=PHASE_TIMEOUTS["origin_resolve"], name="origin_resolve",
        )
    except Exception as e:
        print(f"[full_auto] resolution failed: {e}", file=sys.stderr)
        resolved = {
            "input": target, "type": target_type,
            "scan_ips": [target], "origin_results": [],
            "used_fallback": True,
        }
    report["resolved"] = resolved
    print(f"[full_auto] Scan IPs: {resolved['scan_ips']}", file=sys.stderr)

    scan_ip = resolved["scan_ips"][0] if resolved["scan_ips"] else target
    host_header = target if target_type == "domain" else None

    # ---------- Phase 2: FTP version ----------
    print(f"\n[full_auto] ==== FTP version ({scan_ip}:{ftp_port}) ====",
          file=sys.stderr)
    ftp_phase = _phase_wrap("ftp_version", detect_ftp_version, scan_ip, ftp_port)
    report["phases"].append(ftp_phase)
    if ftp_phase["ok"]:
        r = ftp_phase["result"]
        print(f"[full_auto] FTP: product={r['product']} version={r['version']}",
              file=sys.stderr)
    else:
        print(f"[full_auto] FTP error: {ftp_phase['error']}", file=sys.stderr)

    # ---------- Phase 3: directory brute-force ----------
    base_url = f"http://{scan_ip}"
    print(f"\n[full_auto] ==== Directory brute ({base_url}) ====", file=sys.stderr)
    dir_phase = _phase_wrap(
        "dir_bruteforce",
        directory_bruteforce,
        base_url,
        wordlist_path,
        threads=20,
        timeout=DIR_DEFAULT_TIMEOUT,
        watchdog_seconds=240,
        host_header=host_header,
        verbose=verbose,
    )
    report["phases"].append(dir_phase)
    if dir_phase["ok"]:
        hits = dir_phase["result"] or []
        print(f"[full_auto] Directory hits: {len(hits)}", file=sys.stderr)
    else:
        print(f"[full_auto] Directory brute error: {dir_phase['error']}",
              file=sys.stderr)

    # ---------- Phase 4: optional HTTP scanner ----------
    try:
        from modules import http_scanner  # type: ignore
        http_phase = _phase_wrap("http_scan", http_scanner.scan, scan_ip)
        report["phases"].append(http_phase)
    except ImportError:
        print("[full_auto] http_scanner module not found — skipping",
              file=sys.stderr)

    # ---------- Summary ----------
    report["end_time"] = time.time()
    report["duration"] = report["end_time"] - report["start_time"]

    print("\n[full_auto] ==== Summary ====", file=sys.stderr)
    for ph in report["phases"]:
        if ph["ok"]:
            status = "OK"
        elif ph.get("timed_out"):
            status = "TIMEOUT"
        else:
            status = "FAIL"
        print(f"  {ph['phase']:<18} {status:<8} {ph['duration']:.1f}s",
              file=sys.stderr)
    print(f"[full_auto] Total: {report['duration']:.1f}s", file=sys.stderr)

    return report


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python full_auto.py <target> [wordlist] [ip|domain]")
        sys.exit(1)
    tgt = sys.argv[1]
    wl = sys.argv[2] if len(sys.argv) > 2 else "wordlists/common.txt"
    tt = sys.argv[3] if len(sys.argv) > 3 else None
    full_auto(tgt, target_type=tt, wordlist_path=wl)