"""
SSL/TLS Weakness Scan — protocols, ciphers, certificate.
"""
import socket
import ssl
from datetime import datetime, timezone

from Design.colors_cli import console
from modules.target import TargetInfo
from modules.attack_config import AttackConfig


WEAK_PROTOCOLS = [
    ("TLSv1",   ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
]


def _test_protocol(host, port, version):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                return True
    except Exception:
        return False


def run(target: TargetInfo, config: AttackConfig) -> None:
    console.print(
        f"\n[bold primary][ SSL/TLS SCAN ][/bold primary]\n"
        f"  [muted]Target :[/muted] [primary]{target.host}:{target.port}[/primary]\n"
    )

    findings = []

    # 1. Supported protocols
    console.print("\n[bold secondary]▸ Protocol Support[/bold secondary]")
    for name, ver in WEAK_PROTOCOLS:
        if _test_protocol(target.host, target.port, ver):
            console.print(f"  [bold warning]⚠ {name} SUPPORTED (deprecated)[/bold warning]")
            findings.append(f"{name} deprecated protocol")

    # 2. Certificate info
    console.print("\n[bold secondary]▸ Certificate[/bold secondary]")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target.host, target.port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=target.host) as s:
                cert = s.getpeercert()
                if cert:
                    subj = dict(x[0] for x in cert.get("subject", ()))
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    not_after = cert.get("notAfter", "")
                    console.print(f"  [muted]Subject:[/muted] [text]{subj.get('commonName', '?')}[/text]")
                    console.print(f"  [muted]Issuer :[/muted] [text]{issuer.get('organizationName', '?')}[/text]")
                    if not_after:
                        try:
                            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            exp = exp.replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            days = (exp - now).days
                            if days < 0:
                                console.print(f"  [bold error]⚠ Certificate EXPIRED ({abs(days)} days ago)[/bold error]")
                                findings.append("expired certificate")
                            elif days < 30:
                                console.print(f"  [bold warning]⚠ Expires in {days} days[/bold warning]")
                                findings.append(f"certificate expires in {days} days")
                            else:
                                console.print(f"  [success]✓ Valid for {days} days[/success]")
                        except Exception:
                            pass
    except Exception as e:
        console.print(f"  [warning]Cert fetch failed: {e}[/warning]")

    # 3. Cipher info
    console.print("\n[bold secondary]▸ Cipher[/bold secondary]")
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target.host, target.port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=target.host) as s:
                cipher = s.cipher()
                proto  = s.version()
                console.print(f"  [muted]Negotiated:[/muted] [text]{proto} / {cipher[0]}[/text]")
                if "RC4" in cipher[0] or "DES" in cipher[0] or "MD5" in cipher[0]:
                    console.print("  [bold warning]⚠ Weak cipher suite[/bold warning]")
                    findings.append(f"weak cipher {cipher[0]}")
    except Exception as e:
        console.print(f"  [warning]Cipher fetch failed: {e}[/warning]")

    if config.log_file:
        try:
            with open(config.log_file, "a", encoding="utf-8") as fh:
                for f in findings:
                    fh.write(f"[SSL] {target.host}:{target.port} {f}\n")
        except OSError:
            pass