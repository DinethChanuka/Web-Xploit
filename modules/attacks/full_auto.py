"""
FULL AUTO — runs EVERY non-brute advanced attack, bottom→top.
Crash-proof: exceptions are escaped before being printed.
"""
from Design.colors_cli import console, escape
from modules.target import TargetInfo
from modules.attack_config import AttackConfig, CredentialMode
from modules.attack_registry import get_attacks, ATTACK_LABELS
from modules.attack_menu import AttackType
from modules.attacks.common import harvest_creds_from_log
from modules.downloads import host_dir, ensure_dir


# Brief explanation shown before each attack fires
_ATTACK_BRIEF: dict[AttackType, str] = {
    AttackType.VULN_SCAN:            "Maps the detected service version to known CVEs.",
    AttackType.MYSQL_EXPLOIT:        "Attempts OUTFILE/LOAD_FILE file-read and write.",
    AttackType.MYSQL_BACKDOOR:       "Creates a hidden admin user + event-scheduler beacon.",
    AttackType.MYSQL_UDF:            "Uploads lib_mysqludf_sys.so to get RCE via sys_eval().",
    AttackType.MYSQL_AUTH_BYPASS:    "Tests empty-password accounts + CVE-2012-2122 bypass.",
    AttackType.CONFIG_ENUM:          "Dumps MySQL users, grants, global variables.",
    AttackType.FTP_ANON:             "Attempts anonymous login and downloads all readable files.",
    AttackType.FTP_BOUNCE:           "Uses PORT command to pivot a port-scan through the FTP server.",
    AttackType.FTP_WEBSHELL:         "Logs in anonymously, writes a PHP shell to a web-writable dir.",
    AttackType.FTP_VSFTPD_BACKDOOR:  "Triggers CVE-2011-2523 smiley-face backdoor → shell on :6200.",
    AttackType.FTP_PROFTPD_MODCOPY:  "Uses SITE CPFR/CPTO (CVE-2015-3306) to copy files into webroot.",
    AttackType.HTTP_SCANNER:         "Dir-brute + SQLi/XSS/LFI/CMDi param scan with WAF bypass variants.",
    AttackType.WEB_LFI_RCE:          "Detects LFI params, reads /etc/passwd, then chains log-poisoning → RCE.",
    AttackType.WEB_SQLI_EXTRACT:     "UNION-based SQLi to extract version/user/db + table dump.",
    AttackType.WEB_GRAPHQL:          "Sends introspection query to discover the full GraphQL schema.",
    AttackType.WEB_SECRETS_SCAN:     "Scans JS files and .env endpoints for hardcoded secrets/keys.",
    AttackType.WEB_API_SCAN:         "Probes 30+ common REST/API paths for exposed endpoints.",
    AttackType.WEB_WP_SCANNER:       "Detects WordPress version, plugins, themes, users via REST API.",
    AttackType.WEB_NOSQL_INJECTION:  "Sends MongoDB operator payloads ($ne, $gt, $regex) to bypass auth.",
    AttackType.WEB_PHP_TYPE_JUGGLING:"Sends magic-hash values to exploit PHP loose comparisons (==).",
    AttackType.WEB_JWT_ATTACK:       "Extracts JWTs from responses, tries none-alg and common secrets.",
    AttackType.WEB_CSRF:             "Checks whether forms lack CSRF tokens.",
    AttackType.WEB_CACHE_POISON:     "Injects X-Forwarded-Host and checks if the value is cached.",
    AttackType.WEB_SMUGGLING:        "Sends CL.TE and TE.CL probes to detect HTTP request smuggling.",
    AttackType.WEB_HOST_HEADER:      "Sends a spoofed Host header and checks if it's reflected.",
    AttackType.WEB_OPEN_REDIRECT:    "Tests 17 redirect params for open-redirect to example.com.",
    AttackType.WEB_DESER:            "Checks response body/cookies for Java/PHP/Python serialized objects.",
    AttackType.WEB_XXE:              "Posts XML with an external entity to read /etc/passwd.",
    AttackType.WEB_SSRF:             "Tests URL params to reach AWS/GCP/Azure metadata and localhost.",
    AttackType.WEB_SSTI:             "Injects template syntax (Jinja2/Twig/Freemarker) to detect SSTI/RCE.",
    AttackType.WEB_AUTH_BYPASS:      "Tries 40+ header/path variants to bypass 401/403 protected paths.",
    AttackType.WEB_SHELL_UPLOAD:     "Uploads PHP/JSP shells with bypassed content-type and extension.",
    AttackType.SSL_SCAN:             "Checks TLS protocol support, certificate, and negotiated cipher.",
    AttackType.SMTP_ENUM:            "Enumerates valid usernames via VRFY, EXPN, and RCPT TO.",
    AttackType.SMTP_RELAY:           "Tests whether the server relays mail for external domains.",
    AttackType.SMTP_SPOOF_CHAIN:     "Sends CEO→HR spoofed mail over an open relay.",
    AttackType.SMTP_HEADER_INJECTION:"Injects CRLF sequences into RCPT to add hidden Bcc headers.",
    AttackType.SSH_SCANNER:          "Reads server banner and tests which auth methods are enabled.",
    AttackType.SSH_USER_ENUM:        "Uses CVE-2018-15473 timing to enumerate valid SSH usernames.",

    # ---- New services ----
    AttackType.REDIS_SCAN:     "Connects to Redis (no-auth check), runs INFO ALL + SCAN to dump all keys.",
    AttackType.REDIS_RCE:      "Abuses Redis CONFIG SET to write SSH keys or cron jobs (unauthenticated RCE).",
    AttackType.MONGO_ENUM:     "Connects to MongoDB wire-protocol, lists databases/collections without credentials.",
    AttackType.POSTGRES_SCAN:  "Sends StartupMessage to PostgreSQL, checks for passwordless/no-auth access.",
    AttackType.MSSQL_SCAN:     "Sends TDS pre-login packet to SQL Server, parses version bytes from response.",
    AttackType.DOCKER_ESCAPE:  "Hits unauthenticated Docker API (:2375), lists containers/images and dumps /etc/shadow path.",
    AttackType.KUBE_SECRETS:   "Queries Kubernetes API server anonymously for /api/v1/secrets, pods, namespaces.",
    AttackType.ELASTIC_DUMP:   "Enumerates Elasticsearch indices (_cat/indices) and dumps sample documents.",
    AttackType.MEMCACHED_DUMP: "Dumps Memcached stats + slab contents without authentication.",
    AttackType.VNC_SCAN:       "Checks VNC RFB banner for version and whether authentication is required.",
    AttackType.LDAP_ENUM:      "Anonymous LDAP bind + base search to enumerate users and groups.",
    AttackType.TELNET_BRUTE:   "Tries 19 common credentials over raw Telnet socket.",
}


# Attacks excluded from FULL_AUTO
_SKIP = {
    AttackType.FULL_AUTO,
    AttackType.CRED_SNIFFER,       # blocks on sniff()
    AttackType.EXPLOIT_UPLOAD,     # waits for user
    # NO brute-force attacks (user requested)
    AttackType.BRUTEFORCE,
    AttackType.DICTIONARY,
    AttackType.WORDLIST,
    AttackType.HTTP_BRUTEFORCE,
    AttackType.SMTP_BRUTEFORCE,
    AttackType.SSH_BRUTEFORCE,
    AttackType.AUTO_PWN,           # includes brute
    # Interactive-only
    AttackType.SSH_KEY_BACKDOOR,   # needs valid creds, prompts
}


def _auto_log(target: TargetInfo) -> str:
    logs = ensure_dir(f"{host_dir(target.host)}/logs")
    return f"{logs}/full_auto_{target.service}_{target.port}.log"


def _auto_config(atk, target, base, creds, log):
    common = dict(attack_type=atk, log_file=log, delay=0.0)
    u, p = creds[0] if creds else ("root", "")

    # MySQL
    if atk in (AttackType.MYSQL_EXPLOIT, AttackType.MYSQL_UDF,
               AttackType.MYSQL_BACKDOOR, AttackType.CONFIG_ENUM):
        return AttackConfig(**common, username_mode=CredentialMode.FIXED,
                            username_value=u, password_mode=CredentialMode.FIXED,
                            password_value=p)
    if atk == AttackType.MYSQL_AUTH_BYPASS:
        return AttackConfig(**common)

    # FTP
    if atk in (AttackType.FTP_PROFTPD_MODCOPY, AttackType.FTP_VSFTPD_BACKDOOR,
               AttackType.FTP_WEBSHELL, AttackType.FTP_ANON):
        return AttackConfig(**common, http_use_tls=False)
    if atk == AttackType.FTP_BOUNCE:
        return AttackConfig(**common, ftp_bounce_host=target.host)

    # HTTP/HTTPS
    tls = target.service == "https"
    if atk in (AttackType.WEB_SHELL_UPLOAD, AttackType.WEB_SSTI,
               AttackType.WEB_SSRF, AttackType.WEB_XXE, AttackType.WEB_DESER,
               AttackType.WEB_OPEN_REDIRECT, AttackType.WEB_HOST_HEADER,
               AttackType.WEB_SMUGGLING, AttackType.WEB_CACHE_POISON,
               AttackType.WEB_CSRF, AttackType.WEB_AUTH_BYPASS,
               AttackType.WEB_JWT_ATTACK, AttackType.WEB_PHP_TYPE_JUGGLING,
               AttackType.WEB_NOSQL_INJECTION, AttackType.WEB_WP_SCANNER,
               AttackType.WEB_API_SCAN, AttackType.WEB_SECRETS_SCAN,
               AttackType.WEB_GRAPHQL, AttackType.WEB_SQLI_EXTRACT,
               AttackType.WEB_LFI_RCE, AttackType.HTTP_SCANNER,
               AttackType.SSL_SCAN):
        return AttackConfig(**common, http_use_tls=tls, http_path="/")

    # SMTP
    if atk in (AttackType.SMTP_ENUM, AttackType.SMTP_RELAY,
               AttackType.SMTP_SPOOF_CHAIN, AttackType.SMTP_HEADER_INJECTION):
        return AttackConfig(**common)

    # SSH
    if atk in (AttackType.SSH_SCANNER, AttackType.SSH_USER_ENUM):
        return AttackConfig(**common)

    # Fallback
    if atk == AttackType.VULN_SCAN:
        return AttackConfig(**common)
    return AttackConfig(**common)


def run(target: TargetInfo, config: AttackConfig) -> None:
    from main import DISPATCH

    log = config.log_file or _auto_log(target)
    ensure_dir(host_dir(target.host))

    ordered = [a for a in reversed(get_attacks(target.service)) if a not in _SKIP]

    console.print(
        f"\n[bold primary]━━━ FULL AUTO — {target.service.upper()} "
        f"{target.host}:{target.port} ━━━[/bold primary]\n"
        f"  [muted]Runs {len(ordered)} non-brute advanced attacks bottom→top:[/muted]\n"
    )
    for i, a in enumerate(ordered, 1):
        console.print(f"  [primary]{i:>2}.[/primary] [text]{ATTACK_LABELS[a]}[/text]")
    console.print(f"\n  [muted]Log :[/muted] [text]{log}[/text]\n")

    creds: list[tuple[str, str]] = []

    for i, atk in enumerate(ordered, 1):
        label = ATTACK_LABELS[atk]
        brief = _ATTACK_BRIEF.get(atk, "")

        console.print(
            f"\n[bold secondary]━━ [{i}/{len(ordered)}] {label} ━━[/bold secondary]"
        )
        if brief:
            console.print(f"  [dim italic]⟶ {brief}[/dim italic]\n")
        else:
            console.print()

        # Safety: skip if the attack wasn't wired into DISPATCH
        if atk not in DISPATCH:
            console.print(
                f"  [warning]  ⚠ No handler registered for {atk.value} — skipping[/warning]"
            )
            continue

        cfg = _auto_config(atk, target, config, creds, log)
        try:
            # Run attack with a 90s watchdog timeout so a hung network socket never stalls Full Auto
            import threading
            err_box = []

            def _runner():
                try:
                    DISPATCH[atk](target, cfg)
                except BaseException as e:
                    err_box.append(e)

            th = threading.Thread(target=_runner, daemon=True)
            th.start()
            th.join(timeout=90.0)
            if th.is_alive():
                console.print(f"  [bold warning]⚠ Attack '{label}' reached 90s timeout — advancing to next attack[/bold warning]")
            elif err_box:
                exc = err_box[0]
                if isinstance(exc, KeyboardInterrupt):
                    console.print("[warning]  Ctrl+C — skipping to next attack[/warning]")
                else:
                    console.print(f"[warning]  Error: {escape(str(exc))}[/warning]")
        except KeyboardInterrupt:
            console.print("[warning]  Ctrl+C — skipping to next attack[/warning]")
        except (RuntimeError, ValueError) as exc:
            console.print(f"[warning]  Skipped: {escape(str(exc))}[/warning]")
        except Exception as exc:
            console.print(f"[warning]  Error: {escape(str(exc))}[/warning]")

        # Refresh creds from log after each attack
        creds = harvest_creds_from_log(log)

    console.print("\n[bold success]━━ FULL AUTO COMPLETE ━━[/bold success]")
    if creds:
        console.print("[muted]Credentials harvested:[/muted]")
        for u, p in creds:
            console.print(f"  [success]{escape(u)}:{escape(p)}[/success]")
    console.print(
        f"\n[muted]All output:[/muted] [text]{host_dir(target.host)}[/text]"
    )