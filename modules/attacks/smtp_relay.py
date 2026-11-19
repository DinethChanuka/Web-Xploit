"""
SMTP Open Relay Vulnerability Scanner
Tests whether the target mail transfer agent allows relaying messages to external domains.
"""
from datetime import datetime
import smtplib
import socket

from rich.panel import Panel
from rich.table import Table

from Design.colors_cli import console
from modules.target import TargetInfo
from modules.attack_config import AttackConfig


TEST_RELAY_PAIRS = [
    ("test@target.local", "recipient@example.com"),
    ("admin@mail.com", "security-test@gmail.com"),
    ("scanner@relaytest.org", "testuser@relaytest.org"),
    ("", "relay-check@test.com"),
]


def run(target: TargetInfo, config: AttackConfig) -> None:
    console.print(
        f"\n[bold primary][ SMTP OPEN RELAY TEST ][/bold primary]\n"
        f"  [muted]Target :[/muted] [primary]{target.host}:{target.port}[/primary]\n"
    )

    results = []
    is_vulnerable = False

    try:
        if target.port == 465:
            server = smtplib.SMTP_SSL(target.host, target.port, timeout=8)
        else:
            server = smtplib.SMTP(target.host, target.port, timeout=8)
            try:
                server.starttls()
            except Exception:
                pass

        server.ehlo_or_helo_if_needed()

        for sender, recipient in TEST_RELAY_PAIRS:
            try:
                mail_code, _ = server.mail(sender)
                rcpt_code, rcpt_msg = server.rcpt(recipient)

                # Reset state for next probe
                try:
                    server.rset()
                except Exception:
                    pass

                # If recipient accepted (250 OK or 251), server is open relay!
                if rcpt_code in (250, 251):
                    is_vulnerable = True
                    results.append((sender, recipient, f"[bold red]ACCEPTED ({rcpt_code})[/bold red]", "VULNERABLE (Open Relay)"))
                elif rcpt_code in (550, 554, 553, 501, 571):
                    results.append((sender, recipient, f"[green]REJECTED ({rcpt_code})[/green]", "Relay Denied"))
                else:
                    results.append((sender, recipient, f"[yellow]RESPONSE ({rcpt_code})[/yellow]", rcpt_msg.decode('utf-8', 'replace')[:30]))

            except Exception as e:
                results.append((sender, recipient, "[muted]ERROR[/muted]", str(e)[:30]))

        try:
            server.quit()
        except Exception:
            pass

    except Exception as e:
        console.print(f"[error]  Connection or handshake failed: {e}[/error]\n")
        return

    table = Table(title=f"SMTP Relay Test Results: {target.host}:{target.port}")
    table.add_column("Mail From", style="text")
    table.add_column("Rcpt To", style="text")
    table.add_column("Status", style="bold")
    table.add_column("Assessment", style="primary")

    for s, r, st, asm in results:
        table.add_row(s or "<empty>", r, st, asm)

    console.print(table)

    if is_vulnerable:
        console.print(
            "\n[bold red]⚠ CRITICAL: Target server is an OPEN RELAY! "
            "It accepts arbitrary external mail forwarding.[/bold red]\n"
        )
    else:
        console.print(
            "\n[success]✓ Secure: Target server denies open relay attempts.[/success]\n"
        )

    if config.log_file:
        try:
            with open(config.log_file, "a", encoding="utf-8") as fh:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                fh.write(f"\n--- [{ts}] SMTP RELAY TEST: {target.host}:{target.port} ---\n")
                fh.write(f"Vulnerable: {is_vulnerable}\n")
                for s, r, st, asm in results:
                    fh.write(f"FROM: {s} -> TO: {r} [{asm}]\n")
            console.print(f"  [muted]Saved findings to:[/muted] [primary]{config.log_file}[/primary]")
        except OSError as e:
            console.print(f"  [warning]Could not write log: {e}[/warning]")
