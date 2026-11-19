import os
import signal

from Design.colors_cli import console
from Design.header import render_header
from Design.prompts import ask_input, GoBack
from Design.menus import render_menu
from modules.port_scanner import scan_target, render_scan_summary, SERVICE_PORTS
from modules.attack_menu import run_attack_menu, run_attack_menu_all, AttackType
from modules.attack_config import run_attack_config
from modules.downloads import init_downloads
from modules.attacks import (
    bruteforce, dictionary, wordlist,
    config_enum, mysql_exploit, vuln_scan,
    cred_sniffer, ftp_anon, ftp_bounce,
    http_bruteforce, http_scanner, exploit_upload, ssl_scan,
    smtp_enum, smtp_bruteforce, smtp_relay,
    ssh_bruteforce, ssh_scanner, auto_pwn, full_auto,
)
from modules.attacks.mysql_advanced import (
    run_mysql_udf, run_mysql_auth_bypass, run_mysql_backdoor,
)
from modules.attacks.ftp_exploits import (
    run_ftp_proftpd_modcopy, run_ftp_vsftpd_backdoor, run_ftp_webshell,
)
from modules.attacks.web_exploits import (
    run_web_shell_upload, run_web_ssti, run_web_ssrf, run_web_xxe,
    run_web_deser, run_web_open_redirect, run_web_host_header,
    run_web_smuggling, run_web_cache_poison, run_web_csrf,
)
from modules.attacks.web_auth import (
    run_web_auth_bypass, run_web_jwt_attack,
    run_web_php_type_juggling, run_web_nosql_injection,
)
from modules.attacks.web_recon import (
    run_web_wp_scanner, run_web_api_scan,
    run_web_secrets_scan, run_web_graphql,
)
from modules.attacks.sqli_extract import run_web_sqli_extract
from modules.attacks.lfi_rce import run_web_lfi_rce
from modules.attacks.ssh_exploits import run_ssh_key_backdoor, run_ssh_user_enum
from modules.attacks.smtp_exploits import run_smtp_spoof_chain, run_smtp_header_injection
from modules.attacks.advanced_services import (
    run_redis_scan, run_redis_rce, run_mongo_enum, run_postgres_scan,
    run_mssql_scan, run_docker_escape, run_kube_secrets, run_elastic_dump,
    run_memcached_dump, run_vnc_scan, run_ldap_enum, run_telnet_brute,
)


DISPATCH = {
    # ── Base attacks ────────────────────────────────────────────────────────
    AttackType.BRUTEFORCE:      bruteforce.run,
    AttackType.DICTIONARY:      dictionary.run,
    AttackType.WORDLIST:        wordlist.run,
    AttackType.CONFIG_ENUM:     config_enum.run,
    AttackType.MYSQL_EXPLOIT:   mysql_exploit.run,
    AttackType.VULN_SCAN:       vuln_scan.run,
    AttackType.CRED_SNIFFER:    cred_sniffer.run,
    AttackType.FTP_ANON:        ftp_anon.run,
    AttackType.FTP_BOUNCE:      ftp_bounce.run,
    AttackType.HTTP_BRUTEFORCE: http_bruteforce.run,
    AttackType.HTTP_SCANNER:    http_scanner.run,
    AttackType.EXPLOIT_UPLOAD:  exploit_upload.run,
    AttackType.SSL_SCAN:        ssl_scan.run,
    AttackType.SMTP_ENUM:       smtp_enum.run,
    AttackType.SMTP_BRUTEFORCE: smtp_bruteforce.run,
    AttackType.SMTP_RELAY:      smtp_relay.run,
    AttackType.SSH_BRUTEFORCE:  ssh_bruteforce.run,
    AttackType.SSH_SCANNER:     ssh_scanner.run,
    AttackType.AUTO_PWN:        auto_pwn.run,
    AttackType.FULL_AUTO:       full_auto.run,

    # ── Advanced MySQL ───────────────────────────────────────────────────────
    AttackType.MYSQL_UDF:          run_mysql_udf,
    AttackType.MYSQL_AUTH_BYPASS:  run_mysql_auth_bypass,
    AttackType.MYSQL_BACKDOOR:     run_mysql_backdoor,

    # ── Advanced FTP ─────────────────────────────────────────────────────────
    AttackType.FTP_PROFTPD_MODCOPY:  run_ftp_proftpd_modcopy,
    AttackType.FTP_VSFTPD_BACKDOOR:  run_ftp_vsftpd_backdoor,
    AttackType.FTP_WEBSHELL:         run_ftp_webshell,

    # ── Advanced Web (exploits) ───────────────────────────────────────────────
    AttackType.WEB_SHELL_UPLOAD:     run_web_shell_upload,
    AttackType.WEB_SSTI:             run_web_ssti,
    AttackType.WEB_SSRF:             run_web_ssrf,
    AttackType.WEB_XXE:              run_web_xxe,
    AttackType.WEB_DESER:            run_web_deser,
    AttackType.WEB_OPEN_REDIRECT:    run_web_open_redirect,
    AttackType.WEB_HOST_HEADER:      run_web_host_header,
    AttackType.WEB_SMUGGLING:        run_web_smuggling,
    AttackType.WEB_CACHE_POISON:     run_web_cache_poison,
    AttackType.WEB_CSRF:             run_web_csrf,

    # ── Advanced Web (auth) ───────────────────────────────────────────────────
    AttackType.WEB_AUTH_BYPASS:      run_web_auth_bypass,
    AttackType.WEB_JWT_ATTACK:       run_web_jwt_attack,
    AttackType.WEB_PHP_TYPE_JUGGLING: run_web_php_type_juggling,
    AttackType.WEB_NOSQL_INJECTION:  run_web_nosql_injection,

    # ── Advanced Web (recon) ──────────────────────────────────────────────────
    AttackType.WEB_WP_SCANNER:       run_web_wp_scanner,
    AttackType.WEB_API_SCAN:         run_web_api_scan,
    AttackType.WEB_SECRETS_SCAN:     run_web_secrets_scan,
    AttackType.WEB_GRAPHQL:          run_web_graphql,
    AttackType.WEB_SQLI_EXTRACT:     run_web_sqli_extract,
    AttackType.WEB_LFI_RCE:          run_web_lfi_rce,

    # ── Advanced SSH ──────────────────────────────────────────────────────────
    AttackType.SSH_KEY_BACKDOOR:     run_ssh_key_backdoor,
    AttackType.SSH_USER_ENUM:        run_ssh_user_enum,

    # ── Advanced SMTP ─────────────────────────────────────────────────────────
    AttackType.SMTP_SPOOF_CHAIN:     run_smtp_spoof_chain,
    AttackType.SMTP_HEADER_INJECTION: run_smtp_header_injection,

    # ── New services ──────────────────────────────────────────────────────────
    AttackType.REDIS_SCAN:      run_redis_scan,
    AttackType.REDIS_RCE:       run_redis_rce,
    AttackType.MONGO_ENUM:      run_mongo_enum,
    AttackType.POSTGRES_SCAN:   run_postgres_scan,
    AttackType.MSSQL_SCAN:      run_mssql_scan,
    AttackType.DOCKER_ESCAPE:   run_docker_escape,
    AttackType.KUBE_SECRETS:    run_kube_secrets,
    AttackType.ELASTIC_DUMP:    run_elastic_dump,
    AttackType.MEMCACHED_DUMP:  run_memcached_dump,
    AttackType.VNC_SCAN:        run_vnc_scan,
    AttackType.LDAP_ENUM:       run_ldap_enum,
    AttackType.TELNET_BRUTE:    run_telnet_brute,
}


def _sigint_handler(sig, frame):
    raise KeyboardInterrupt


def setup_signals():
    try:
        signal.signal(signal.SIGINT, _sigint_handler)
    except Exception:
        pass


def _choose_scan_services() -> list[str]:
    console.print("\n[bold primary][ SERVICES TO SCAN ][/bold primary]\n")
    for svc, ports in SERVICE_PORTS.items():
        console.print(
            f"  [primary]{svc:<6}[/primary]  [muted]ports:[/muted] "
            f"[text]{', '.join(map(str, ports))}[/text]"
        )
    console.print()
    raw = ask_input("Services (comma-separated, blank = all)", "", allow_back=True)
    if not raw.strip():
        return list(SERVICE_PORTS.keys())
    chosen = [s.strip().lower() for s in raw.split(",") if s.strip()]
    valid = [s for s in chosen if s in SERVICE_PORTS]
    return valid or list(SERVICE_PORTS.keys())


def main():
    setup_signals()
    os.system("cls" if os.name == "nt" else "clear")
    downloads = init_downloads()

    while True:
        try:
            render_header()
            console.print(
                f"[muted]Downloads directory:[/muted] [text]{downloads}[/text]\n"
            )
            host = ask_input(
                "Target IP / hostname ('q' to exit)", "localhost", allow_back=False
            ).strip()
            if not host or host.lower() in ("q", "quit", "exit"):
                console.print("\n[muted]Exiting. Goodbye![/muted]\n")
                break

            targets = None
            while True:
                try:
                    services = _choose_scan_services()
                    targets = scan_target(host, services)
                    render_scan_summary(host, targets)
                    break
                except GoBack:
                    break

            if not targets:
                continue

            while True:
                try:
                    if len(targets) == 1:
                        target, atk = run_attack_menu(targets)
                        plan = [(target, atk)]
                    else:
                        mode = render_menu(
                            "EXECUTION MODE",
                            [
                                "Single target + single attack",
                                "One attack type across all compatible targets",
                            ],
                            allow_back=True,
                        )
                        if mode == 0:
                            target, atk = run_attack_menu(targets)
                            plan = [(target, atk)]
                        else:
                            compatible, atk = run_attack_menu_all(targets)
                            plan = [(t, atk) for t in compatible]

                    by_attack: dict[AttackType, list] = {}
                    for t, atk in plan:
                        by_attack.setdefault(atk, []).append(t)

                    for atk, group in by_attack.items():
                        config = run_attack_config(atk)
                        for t in group:
                            console.print(
                                f"\n[bold primary]━━━ {atk.value.upper()} → "
                                f"{t.service.upper()} {t.host}:{t.port} ━━━[/bold primary]\n"
                            )
                            try:
                                DISPATCH[atk](t, config)
                            except KeyboardInterrupt:
                                console.print(
                                    "\n[warning]  Attack stopped by user (Ctrl+C).[/warning]\n"
                                )
                            except (RuntimeError, ValueError) as e:
                                console.print(f"[error]  Error: {e}[/error]")

                    try:
                        next_action = render_menu(
                            "NEXT ACTION",
                            [
                                "Run another attack on current target",
                                "Scan another target / change host",
                                "Exit",
                            ],
                            allow_back=False,
                        )
                        if next_action == 0:
                            continue
                        elif next_action == 1:
                            break
                        else:
                            console.print("\n[muted]Exiting. Goodbye![/muted]\n")
                            return
                    except (GoBack, KeyboardInterrupt):
                        break

                except GoBack:
                    break
                except KeyboardInterrupt:
                    console.print("\n[warning]  Cancelled by user (Ctrl+C).[/warning]\n")
                    break

        except KeyboardInterrupt:
            console.print("\n\n[warning]  Exiting on Ctrl+C. Goodbye![/warning]\n")
            break
        except (RuntimeError, ValueError) as error:
            console.print(f"\n[error]ERROR: {error}[/error]")


if __name__ == "__main__":
    main()