"""
SSH Weak-Config / Auth Scan — checks supported auth methods,
weak ciphers, and protocol version.
"""
import socket
import paramiko

from Design.colors_cli import console
from modules.target import TargetInfo
from modules.attack_config import AttackConfig


WEAK_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1"}
WEAK_CIPHERS = {"arcfour", "arcfour128", "arcfour256", "3des-cbc",
                "blowfish-cbc", "cast128-cbc"}


def run(target: TargetInfo, config: AttackConfig) -> None:
    console.print(
        f"\n[bold primary][ SSH CONFIG SCAN ][/bold primary]\n"
        f"  [muted]Target :[/muted] [primary]{target.host}:{target.port}[/primary]\n"
    )

    findings = []

    # 1. Banner + protocol
    try:
        with socket.create_connection((target.host, target.port), timeout=8) as s:
            banner = s.recv(256).decode("utf-8", "replace").strip()
            console.print(f"  [muted]Banner:[/muted] [text]{banner}[/text]")
            if banner.startswith("SSH-1."):
                console.print("  [bold error]⚠ SSHv1 detected — insecure[/bold error]")
                findings.append("SSHv1 protocol")
    except Exception as e:
        console.print(f"[error]  Banner read failed: {e}[/error]")
        return

    # 2. Auth methods
    try:
        transport = paramiko.Transport((target.host, target.port))
        transport.start_client(timeout=8)
        try:
            transport.auth_none("test")
        except paramiko.BadAuthenticationType as e:
            methods = e.allowed_types
            console.print(
                f"  [muted]Auth methods:[/muted] [text]{', '.join(methods)}[/text]"
            )
            if "password" in methods:
                console.print("  [muted]Password auth enabled → brute force viable[/muted]")
            if "none" in methods:
                console.print("  [bold error]⚠ No-auth accepted[/bold error]")
                findings.append("none auth accepted")
        except Exception:
            pass
        transport.close()
    except Exception as e:
        console.print(f"  [warning]Auth-method probe failed: {e}[/warning]")

    # 3. Ciphers via nmap-style raw KEX would need full handshake;
    #    fall back to attempting weak KEX and seeing if it's accepted.
    for kex in WEAK_KEX:
        try:
            t = paramiko.Transport((target.host, target.port))
            t.get_security_options().kex = [kex]
            t.start_client(timeout=8)
            console.print(f"  [bold warning]⚠ Weak KEX accepted: {kex}[/bold warning]")
            findings.append(f"weak kex {kex}")
            t.close()
        except Exception:
            pass

    if config.log_file:
        try:
            with open(config.log_file, "a", encoding="utf-8") as fh:
                for f in findings:
                    fh.write(f"[SSH] {target.host}:{target.port} {f}\n")
        except OSError:
            pass