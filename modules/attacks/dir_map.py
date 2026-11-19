"""
Server Directory Mapping Module
Performs deep directory and file enumeration to map the web server's site structure.
Uses multithreaded probing with hard per-request timeouts so it never hangs.
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


DEFAULT_DIR_WORDS = [
    # Top administrative panels
    "admin", "admin/", "admin/login", "admin/login.php", "admin/index.php",
    "administrator", "administrator/", "adminpanel", "cpanel", "controlpanel",
    "login", "login.php", "signin", "auth", "user/login", "wp-login.php",
    "wp-admin/", "phpmyadmin/", "pma/", "adminer.php", "manager/html",
    # Backups, dumps & archives
    "backup", "backup/", "backups/", "backup.zip", "backup.tar.gz", "backup.sql",
    "db.sql", "db_backup.sql", "dump.sql", "database.sql", "site.zip", "www.zip",
    "web.zip", "old/", "temp/", "tmp/", "export.sql",
    # Configs & credentials
    ".env", ".env.local", ".env.production", ".env.bak", ".git/HEAD", ".git/config",
    ".svn/entries", ".htaccess", ".htpasswd", "web.config", "config.php",
    "config.inc.php", "wp-config.php", "wp-config.php.bak", "configuration.php",
    "settings.py", "database.yml", "secrets.json", "credentials.json",
    # Sensitive information & logs
    "info.php", "phpinfo.php", "test.php", "error.log", "access.log", "debug.log",
    "server-status", "server-info", "actuator", "actuator/env", "actuator/health",
    # APIs & Web Services
    "api", "api/", "api/v1/", "api/v2/", "api/v3/", "api/docs", "swagger",
    "swagger/", "swagger.json", "swagger-ui/", "openapi.json", "graphql", "graphiql",
    # Public & asset directories
    "robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt",
    "uploads/", "upload/", "files/", "images/", "img/", "static/", "assets/",
    "css/", "js/", "media/", "download/", "downloads/", "includes/",
    # Application & source files
    "app/", "core/", "src/", "vendor/", "node_modules/", "portal/", "dashboard/",
    "register", "signup", "forgot-password", "profile", "account", "search",
    "index.php", "index.html", "home", "default.aspx", "main",
]


def _make_conn(host: str, port: int, tls: bool, timeout: float = 3.5):
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    return http.client.HTTPConnection(host, port, timeout=timeout)


def _probe_single(host: str, port: int, tls: bool, path: str, timeout: float = 3.5) -> dict | None:
    """Send a single GET request with a strict timeout. Never hangs."""
    conn = None
    try:
        conn = _make_conn(host, port, tls, timeout=timeout)
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/DirectoryMapper)",
            "Accept": "*/*",
            "Connection": "close",
        }
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        data = resp.read(8192)  # Read up to 8KB
        status = resp.status
        content_type = resp.getheader("Content-Type", "")
        location = resp.getheader("Location", "")
        length = len(data)
        cl = resp.getheader("Content-Length")
        if cl and cl.isdigit():
            length = int(cl)
        return {
            "path": path,
            "status": status,
            "length": length,
            "content_type": content_type,
            "location": location,
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
    tls = target.service.lower() == "https"
    base_path = (config.http_path or "/").rstrip("/")
    console.print(
        f"\n[bold primary]━━━ SERVER DIRECTORY MAPPING ━━━[/bold primary]\n"
        f"  [muted]Target    :[/muted] [primary]{target.service.upper()} {target.host}:{target.port}[/primary]\n"
        f"  [muted]Base Path :[/muted] [text]{base_path or '/'}[/text]\n"
        f"  [muted]Threads   :[/muted] [text]15 worker threads with 3.5s watchdog[/text]\n"
    )

    # 1. Prepare wordlist
    words = list(DEFAULT_DIR_WORDS)
    wordlist_file = getattr(config, "password_file", None)
    if wordlist_file and os.path.isfile(wordlist_file):
        try:
            with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as fh:
                custom = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
                if custom:
                    words = custom
                    console.print(f"  [muted]Loaded wordlist:[/muted] [text]{wordlist_file}[/text] ({len(words)} entries)")
        except Exception as e:
            console.print(f"  [warning]Could not read custom wordlist: {e}[/warning]")

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

    console.print("[dim]Starting directory mapping probe... (Press Ctrl+C to stop and show findings)[/dim]\n")

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            future_to_path = {executor.submit(_worker, p): p for p in paths_to_test}
            for future in concurrent.futures.as_completed(future_to_path):
                completed += 1
                try:
                    res = future.result()
                    if res:
                        st = res["status"]
                        # Filter interesting statuses
                        if st in (200, 201, 204, 206, 301, 302, 307, 308, 401, 403, 500):
                            discovered.append(res)
                            loc_info = f" → {res['location']}" if res.get("location") else ""
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
                                f"[muted]({res['length']}b){loc_info}[/muted]"
                            )
                except Exception:
                    pass
    except KeyboardInterrupt:
        stop_event.set()
        console.print("\n[warning]  Mapping paused by user. Generating report for discovered paths...[/warning]\n")

    # Sort results
    discovered.sort(key=lambda x: (0 if x["status"] == 200 else 1, x["path"]))

    # Render results table
    table = Table(title=f"Site Directory Map — {target.host}:{target.port}", show_lines=True)
    table.add_column("Status", style="bold", width=8)
    table.add_column("Path", style="text", width=38)
    table.add_column("Size", style="muted", width=10)
    table.add_column("Details", style="primary")

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

        details = item.get("location") or item.get("content_type", "")[:40]
        table.add_row(
            f"[{s_color}]{st}[/{s_color}]",
            item["path"],
            f"{item['length']} B",
            details,
        )

    console.print()
    if discovered:
        console.print(table)
        console.print(f"\n[bold success]✓ Directory mapping complete: {len(discovered)} endpoints discovered.[/bold success]")
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
                fh.write(f"[{item['status']}] {item['path']} ({item['length']} bytes){loc}\n")
        console.print(f"  [muted]Text map saved to:[/muted] [text]{report_file}[/text]")

        with open(json_file, "w", encoding="utf-8") as fh:
            json.dump(discovered, fh, indent=2)
        console.print(f"  [muted]JSON map saved to:[/muted] [text]{json_file}[/text]\n")
    except Exception as e:
        console.print(f"  [warning]Could not save map files: {e}[/warning]")
