"""
Server Directory Mapping Module
Performs deep directory and file enumeration to map the web server's site structure.
Uses multithreaded probing with hard per-request timeouts, protocol auto-negotiation,
realistic browser headers, and wildcard false-positive filtering.
Outputs a structured site directory map and saves it to downloads/<host>/.
"""
import concurrent.futures
import http.client
import json
import os
import re
import ssl
import sys
import threading
import time
from urllib.parse import urlparse

from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from Design.colors_cli import console, escape
from modules.target import TargetInfo
from modules.attack_config import AttackConfig
from modules.downloads import host_dir, ensure_dir, save_text


BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "close",
    "Upgrade-Insecure-Requests": "1",
}


def _make_conn(host: str, port: int, tls: bool, timeout: float = 3.5):
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    return http.client.HTTPConnection(host, port, timeout=timeout)


def _extract_title(html: str) -> str:
    if not html:
        return ""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()[:50]
    return ""


def _probe_single(host: str, port: int, tls: bool, path: str, timeout: float = 3.5) -> dict | None:
    """Send a single GET request with realistic browser headers and strict timeout."""
    conn = None
    try:
        conn = _make_conn(host, port, tls, timeout=timeout)
        headers = dict(BROWSER_HEADERS)
        headers["Host"] = host
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        data = resp.read(8192)
        status = resp.status
        content_type = resp.getheader("Content-Type", "").split(";")[0].strip()
        location = resp.getheader("Location", "")
        length = len(data)
        cl = resp.getheader("Content-Length")
        if cl and cl.isdigit():
            length = int(cl)

        title = ""
        if "text/html" in content_type:
            try:
                title = _extract_title(data.decode("utf-8", "ignore"))
            except Exception:
                pass

        # Follow trailing-slash redirect on same host
        if status in (301, 302, 307, 308) and location:
            if location.endswith(f"{path}/") or (location.startswith("/") and location == f"{path}/"):
                try:
                    conn2 = _make_conn(host, port, tls, timeout=timeout)
                    dest_path = f"{path}/"
                    conn2.request("GET", dest_path, headers=headers)
                    resp2 = conn2.getresponse()
                    if resp2.status in (200, 206, 401, 403):
                        data2 = resp2.read(8192)
                        status = resp2.status
                        length = len(data2)
                        cl2 = resp2.getheader("Content-Length")
                        if cl2 and cl2.isdigit():
                            length = int(cl2)
                        title = _extract_title(data2.decode("utf-8", "ignore"))
                        location = f"-> {dest_path}"
                    conn2.close()
                except Exception:
                    pass

        return {
            "path": path,
            "status": status,
            "length": length,
            "content_type": content_type,
            "location": location,
            "title": title,
        }
    except Exception:
        return None
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def run(target: TargetInfo, config: AttackConfig) -> None:
    tls = target.service.lower() == "https" or target.port in (443, 8443)
    base_path = (config.http_path or "/").rstrip("/")

    # Detect HTTP -> HTTPS redirect on port 80
    if not tls and target.port == 80:
        root_probe = _probe_single(target.host, target.port, False, "/", timeout=3.5)
        if root_probe and root_probe.get("status") in (301, 302, 307, 308):
            loc = root_probe.get("location", "")
            if loc.startswith("https://"):
                console.print(f"  [cyan]ℹ Detected HTTP -> HTTPS upgrade on port 80. Probing HTTPS 443 for true status codes.[/cyan]")
                tls = True
                target.port = 443
                target.service = "https"

    console.print(
        f"\n[bold primary]━━━ SERVER DIRECTORY MAPPING ━━━[/bold primary]\n"
        f"  [muted]Target    :[/muted] [primary]{target.service.upper()} {target.host}:{target.port}[/primary]\n"
        f"  [muted]Base Path :[/muted] [text]{base_path or '/'}[/text]\n"
        f"  [muted]Threads   :[/muted] [text]15 worker threads with 3.5s watchdog[/text]\n"
    )

    # 1. Prepare wordlist (ensure minimum 1000 entries)
    words = []
    if config.password_file and os.path.isfile(config.password_file):
        try:
            with open(config.password_file, "r", encoding="utf-8", errors="ignore") as fh:
                words = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
        except Exception:
            pass

    if not words or len(words) < 50:
        wl_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "wordlists")
        for cand in ("directories.txt", "directories_large.txt"):
            p = os.path.join(wl_dir, cand)
            if os.path.isfile(p):
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                        words = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
                        if words:
                            break
                except Exception:
                    pass

    # Canary test for wildcard 403 / 404
    wildcard_403_len = None
    canary = _probe_single(target.host, target.port, tls, "/_canary_not_found_test_99_", timeout=3.5)
    if canary and canary["status"] == 403:
        wildcard_403_len = canary["length"]
        console.print(f"  [yellow]⚠ Note: Server returns generic 403 on non-existent paths ({wildcard_403_len}B). Filtering false positives.[/yellow]")

    # Normalize paths
    paths_to_test = []
    seen = set()
    for w in words:
        clean = w.strip()
        if not clean:
            continue
        full = f"{base_path}/{clean.lstrip('/')}"
        if full not in seen:
            seen.add(full)
            paths_to_test.append(full)

    console.print(f"  [muted]Total paths to map:[/muted] [text]{len(paths_to_test)}[/text]\n")

    discovered: list[dict] = []
    completed = 0
    total = len(paths_to_test)
    stop_event = threading.Event()

    def _worker(path: str):
        if stop_event.is_set():
            return None
        return _probe_single(target.host, target.port, tls, path, timeout=3.5)

    console.print("[dim]Starting directory mapping probe... (Press Ctrl+C to stop and generate report)[/dim]\n")

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            future_to_path = {executor.submit(_worker, p): p for p in paths_to_test}
            for future in concurrent.futures.as_completed(future_to_path):
                completed += 1
                try:
                    res = future.result()
                    if res:
                        st = res["status"]
                        # Drop 404s and wildcard 403s
                        if st == 404:
                            continue
                        if st == 403 and wildcard_403_len is not None and abs(res["length"] - wildcard_403_len) < 5:
                            continue

                        # Filter interesting statuses
                        if st in (200, 201, 204, 206, 301, 302, 307, 308, 401, 403, 500):
                            discovered.append(res)
                            loc_info = f" → {res['location']}" if res.get("location") else ""
                            title_info = f" [{res['title']}]" if res.get("title") else ""
                            if st in (200, 206):
                                st_str = f"[bold success]{st}[/bold success]"
                            elif st in (301, 302, 307, 308):
                                st_str = f"[bold cyan]{st}[/bold cyan]"
                            elif st in (401, 403):
                                st_str = f"[bold yellow]{st}[/bold yellow]"
                            else:
                                st_str = f"[bold red]{st}[/bold red]"
                            console.print(
                                f"  [{completed}/{total}] {st_str} "
                                f"[text]{res['path']}[/text] "
                                f"[muted]({res['length']}b){loc_info}{title_info}[/muted]"
                            )
                except Exception:
                    pass
    except KeyboardInterrupt:
        stop_event.set()
        console.print("\n[warning]  Mapping paused by user. Generating report for discovered paths...[/warning]\n")

    # Sort results: 200s first, then redirects, then others
    discovered.sort(key=lambda x: (0 if x["status"] == 200 else (1 if str(x["status"]).startswith("3") else 2), x["path"]))

    # Render results table
    table = Table(title=f"Site Directory Map — {target.host}:{target.port}", show_lines=True)
    table.add_column("Status", style="bold", width=8)
    table.add_column("Path", style="text", width=34)
    table.add_column("Size", style="muted", width=10)
    table.add_column("Details & Title", style="primary")

    for item in discovered:
        st = item["status"]
        if st in (200, 206):
            s_color = "green"
        elif st in (301, 302, 307, 308):
            s_color = "cyan"
        elif st in (401, 403):
            s_color = "yellow"
        else:
            s_color = "red"

        details = item.get("title") or item.get("location") or item.get("content_type", "")[:40]
        table.add_row(
            f"[{s_color}]{st}[/{s_color}]",
            item["path"],
            f"{item['length']} B",
            details,
        )

    console.print()
    if discovered:
        console.print(table)
        console.print(f"\n[bold success]✓ Directory mapping complete: {len(discovered)} active endpoint(s) mapped.[/bold success]")
    else:
        console.print(f"  [muted]No accessible endpoints discovered out of {completed} probed paths.[/muted]")

    # Save to disk
    out_dir = ensure_dir(host_dir(target.host))
    report_file = os.path.join(out_dir, f"site_directory_map_{target.port}.txt")
    json_file = os.path.join(out_dir, f"site_directory_map_{target.port}.json")

    try:
        with open(report_file, "w", encoding="utf-8") as fh:
            fh.write(f"SITE DIRECTORY MAP — {target.host}:{target.port} ({time.strftime('%Y-%m-%d %H:%M:%S')})\n")
            fh.write("=" * 70 + "\n\n")
            for item in discovered:
                loc = f" -> {item['location']}" if item.get("location") else ""
                t_str = f" [{item['title']}]" if item.get("title") else ""
                fh.write(f"[{item['status']}] {item['path']} ({item['length']} bytes){loc}{t_str}\n")
        console.print(f"  [muted]Text map saved to:[/muted] [text]{report_file}[/text]")

        with open(json_file, "w", encoding="utf-8") as fh:
            json.dump(discovered, fh, indent=2)
        console.print(f"  [muted]JSON map saved to:[/muted] [text]{json_file}[/text]\n")
    except Exception as e:
        console.print(f"  [warning]Could not save map files: {e}[/warning]")
