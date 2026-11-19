"""
SMTP User Enumeration via VRFY / EXPN / RCPT TO.
Reads responses to determine valid vs invalid users.
"""
import smtplib
import socket

from Design.colors_cli import console
from modules.target import TargetInfo
from modules.attack_config import AttackConfig, load_wordlist


def _connect(host, port, timeout=8):
    if port == 465:
        s = smtplib.SMTP_SSL(host, port, timeout=timeout)
    else:
        s = smtplib.SMTP(host, port, timeout=timeout)
        try: s.starttls()
        except Exception: pass
    return s


def run(target: TargetInfo, config: AttackConfig) -> None:
    console.print(
        f"\n[bold primary][ SMTP USER ENUMERATION ][/bold primary]\n"
        f"  [muted]Target :[/muted] [primary]{target.host}:{target.port}[/primary]\n"
    )

    users = load_wordlist(config.username_file) if config.username_file else []

    # Common fallback list
    if not users:
        users = ["root", "admin", "postmaster", "webmaster", "abuse",
                 "test", "info", "support", "mail", "user"]

    try:
        s = _connect(target.host, target.port)
        s.ehlo(config.smtp_helo)
    except Exception as e:
        console.print(f"[error]  Connect failed: {e}[/error]")
        return

    found = []
    for u in users:
        # VRFY
        try:
            code, msg = s.verify(u)
            if code in (250, 251, 252):
                console.print(f"  [success]✓ VRFY {u}: {msg.decode(errors='replace')[:80]}[/success]")
                found.append(u)
                continue
        except Exception:
            pass

        # EXPN
        try:
            code, msg, _ = s.expn(u)
            if code == 250:
                console.print(f"  [success]✓ EXPN {u}: {msg.decode(errors='replace')[:80]}[/success]")
                found.append(u)
                continue
        except Exception:
            pass

        # RCPT TO
        try:
            code, msg = s.rcpt(f"<{u}@test.local>")
            if code in (250, 251):
                console.print(f"  [success]✓ RCPT {u}: valid[/success]")
                found.append(u)
        except Exception:
            pass

    try: s.quit()
    except Exception: pass

    console.print(f"\n[primary]Found {len(found)} valid user(s):[/primary] {', '.join(found) or '(none)'}")
    if config.log_file and found:
        try:
            with open(config.log_file, "a", encoding="utf-8") as fh:
                for u in found:
                    fh.write(f"[SMTP-USER] {target.host}:{target.port} user={u}\n")
        except OSError:
            pass