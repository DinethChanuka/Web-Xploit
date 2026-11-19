import enum
import os
from dataclasses import dataclass, field

from Design.colors_cli import console
from Design.prompts import ask_input
from Design.menus import render_menu
from modules.attack_menu import AttackType
from modules.downloads import init_downloads, host_dir


class CredentialMode(enum.Enum):
    FIXED            = "fixed"
    RANDOM_FROM_LIST = "random_from_list"


@dataclass
class AttackConfig:
    attack_type: AttackType

    username_mode:  CredentialMode = CredentialMode.FIXED
    username_value: str            = ""
    username_file:  str | None     = None

    password_mode:  CredentialMode = CredentialMode.FIXED
    password_value: str            = ""
    password_file:  str | None     = None

    charset:        str            = "abcdefghijklmnopqrstuvwxyz0123456789"
    max_length:     int            = 6
    random_order:   bool           = False

    delay:          float          = 0.0
    log_file:       str | None     = None
    download_dir:   str | None     = None

    interface:      str | None     = None
    payload_type:   str            = "php"
    bind_port:      int            = 0

    http_path:      str            = "/"
    http_method:    str            = "POST"
    http_username_field: str       = "username"
    http_password_field: str       = "password"
    http_use_tls:   bool           = False
    http_params:    str            = "q,id,search,page"
    http_scan_types: list          = field(default_factory=lambda: [
        "dirbust", "sqli", "xss", "lfi", "cmdi",
    ])

    smtp_helo:      str            = "test.local"
    smtp_from:      str            = "test@test.local"
    smtp_rcpt:      str            = "test@test.local"

    ftp_bounce_host: str           = ""

    auto_default_users: list = field(default_factory=lambda: [
        "root", "admin", "mysql", "test", "user",
        "ftp", "anonymous", "guest", "postmaster", "administrator",
    ])
    auto_default_passes: list = field(default_factory=lambda: [
        "", "root", "admin", "password", "mysql", "test",
        "123456", "toor", "letmein", "qwerty", "ftp", "guest",
        "12345", "P@ssw0rd", "admin123", "root123",
    ])


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_USERS_PATH     = os.path.join(PROJECT_ROOT, "wordlists", "usernames.txt")
DEFAULT_PASSWORDS_PATH = os.path.join(PROJECT_ROOT, "wordlists", "passwords.txt")
DEFAULT_USER_PASS_PATH = os.path.join(PROJECT_ROOT, "wordlists", "user_pass.txt")
DEFAULT_CHARSET        = "abcdefghijklmnopqrstuvwxyz0123456789"
def _cfg_web_generic(attack_type):
    """Generic web config: scheme / path / params / payload type."""
    console.print(f"\n[bold primary][ {attack_type.value.upper()} CONFIG ][/bold primary]\n")
    tls = render_menu("SCHEME", ["Plain HTTP", "HTTPS"]) == 1
    path = ask_input("Path", "/")
    params = ask_input("Params (comma-separated)", "q,id,url,file,next")
    log = ask_input("Save findings to file (blank = skip)", "")
    return AttackConfig(
        attack_type=attack_type, http_use_tls=tls, http_path=path,
        http_params=params, log_file=log or None,
    )


def _cfg_web_shell_upload():
    console.print("\n[bold primary][ WEB SHELL UPLOAD CONFIG ][/bold primary]\n")
    tls = render_menu("SCHEME", ["Plain HTTP", "HTTPS"]) == 1
    path = ask_input("Upload endpoint", "/upload.php")
    field = ask_input("File field name", "file")
    lang = ask_input("Payload lang (php/jsp/asp/aspx)", "php")
    _, log = _ask_runtime_options()
    return AttackConfig(
        attack_type=AttackType.WEB_SHELL_UPLOAD,
        http_use_tls=tls, http_path=path,
        http_username_field=field, payload_type=lang,
        log_file=log,
    )


def _cfg_mysql_creds(attack_type):
    console.print(f"\n[bold primary][ {attack_type.value.upper()} ][/bold primary]\n")
    u = ask_input("MySQL username", "root")
    p = ask_input("MySQL password", "")
    log = ask_input("Save to file (blank = skip)", "")
    return AttackConfig(
        attack_type=attack_type,
        username_mode=CredentialMode.FIXED, username_value=u,
        password_mode=CredentialMode.FIXED, password_value=p,
        log_file=log or None,
    )


def _cfg_ssh_key_backdoor():
    console.print("\n[bold primary][ SSH KEY BACKDOOR ][/bold primary]\n")
    u = ask_input("SSH username", "root")
    p = ask_input("SSH password", "")
    return AttackConfig(
        attack_type=AttackType.SSH_KEY_BACKDOOR,
        username_mode=CredentialMode.FIXED, username_value=u,
        password_mode=CredentialMode.FIXED, password_value=p,
    )


def _cfg_ssh_user_enum():
    path = ask_input("\nUsernames wordlist", DEFAULT_USERS_PATH)
    log = ask_input("Save to file (blank = skip)", "")
    return AttackConfig(
        attack_type=AttackType.SSH_USER_ENUM,
        username_file=path, log_file=log or None,
    )


def _cfg_simple(attack_type):
    log = ask_input("\nSave to file (blank = skip)", "")
    return AttackConfig(attack_type=attack_type, log_file=log or None)


def load_wordlist(path: str) -> list[str]:
    resolved = path
    if not os.path.isabs(resolved) and not os.path.exists(resolved):
        alt = os.path.join(PROJECT_ROOT, resolved)
        if os.path.exists(alt):
            resolved = alt
    if not os.path.isfile(resolved):
        raise RuntimeError(f"Wordlist file not found: {path}")
    entries = []
    with open(resolved, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            s = line.strip()
            if s and not s.startswith("#"):
                entries.append(s)
    if not entries:
        raise RuntimeError(f"Wordlist is empty: {path}")
    return entries


def _ask_wordlist_path(label: str, default: str = "") -> str:
    while True:
        path = ask_input(label, default=default)
        if not path:
            console.print("[warning]Path cannot be empty.[/warning]")
            continue
        resolved = path
        if not os.path.isabs(resolved) and not os.path.exists(resolved):
            alt = os.path.join(PROJECT_ROOT, resolved)
            if os.path.exists(alt):
                resolved = alt
        if not os.path.isfile(resolved):
            console.print(f"[error]File not found: {path}[/error]")
            continue
        try:
            load_wordlist(resolved)
        except RuntimeError as e:
            console.print(f"[error]{e}[/error]")
            continue
        return resolved


def _ask_credential_mode(role: str):
    idx = render_menu(f"{role.upper()} MODE", [f"Fixed {role}", "Random from list"])
    if idx == 0:
        default_val = "root" if role.lower() == "username" else ""
        return CredentialMode.FIXED, ask_input(f"Enter {role}", default_val), None
    default_file = ("wordlists/usernames.txt"
                    if role.lower() == "username" else "wordlists/passwords.txt")
    path = _ask_wordlist_path(f"{role.capitalize()} wordlist file path", default_file)
    return CredentialMode.RANDOM_FROM_LIST, "", path


def _ask_runtime_options():
    d = ask_input("Delay (seconds, 0 = none)", "0")
    try:
        delay = float(d)
    except ValueError:
        delay = 0.0
    log = ask_input("Save results to file (blank = auto)", "")
    return delay, (log or None)


# ------------ config flows ----------------

def _cfg_bruteforce():
    console.print("\n[bold primary][ BRUTE FORCE CONFIG ][/bold primary]\n")
    user = ask_input("Fixed username")
    charset = ask_input("Password charset", DEFAULT_CHARSET)
    m = ask_input("Max length", "6")
    while not m.isdigit() or int(m) < 1:
        console.print("[warning]Must be positive integer.[/warning]")
        m = ask_input("Max length", "6")
    delay, log = _ask_runtime_options()
    return AttackConfig(
        attack_type=AttackType.BRUTEFORCE,
        username_mode=CredentialMode.FIXED, username_value=user,
        charset=charset, max_length=int(m), delay=delay, log_file=log,
    )


def _cfg_dictionary():
    console.print("\n[bold primary][ DICTIONARY CONFIG ][/bold primary]\n")
    um, uv, uf = _ask_credential_mode("username")
    pm, pv, pf = _ask_credential_mode("password")
    mx = ask_input("Max attempts (0 = unlimited)", "1000")
    n = int(mx) if mx.isdigit() else 1000
    delay, log = _ask_runtime_options()
    return AttackConfig(
        attack_type=AttackType.DICTIONARY,
        username_mode=um, username_value=uv, username_file=uf,
        password_mode=pm, password_value=pv, password_file=pf,
        max_length=n, delay=delay, log_file=log,
    )


def _cfg_wordlist():
    console.print("\n[bold primary][ WORDLIST CONFIG ][/bold primary]\n")
    path = _ask_wordlist_path("Combined wordlist (user:pass)", "wordlists/user_pass.txt")
    order = render_menu("ENTRY ORDER", ["Sequential", "Random"])
    delay, log = _ask_runtime_options()
    return AttackConfig(
        attack_type=AttackType.WORDLIST,
        username_file=path, random_order=(order == 1),
        delay=delay, log_file=log,
    )


def _cfg_config_enum():
    console.print("\n[bold primary][ MYSQL CONFIG ENUM ][/bold primary]\n")
    u = ask_input("MySQL username", "root")
    p = ask_input("MySQL password", "")
    log = ask_input("Save to file (blank = skip)", "")
    return AttackConfig(
        attack_type=AttackType.CONFIG_ENUM,
        username_mode=CredentialMode.FIXED, username_value=u,
        password_mode=CredentialMode.FIXED, password_value=p,
        log_file=log or None,
    )


def _cfg_mysql_exploit():
    console.print("\n[bold primary][ MYSQL EXPLOIT CONFIG ][/bold primary]\n")
    u = ask_input("MySQL username", "root")
    p = ask_input("MySQL password", "")
    log = ask_input("Save to file (blank = skip)", "")
    return AttackConfig(
        attack_type=AttackType.MYSQL_EXPLOIT,
        username_mode=CredentialMode.FIXED, username_value=u,
        password_mode=CredentialMode.FIXED, password_value=p,
        log_file=log or None,
    )


def _cfg_vuln_scan():
    log = ask_input("\nSave findings to file (blank = skip)", "")
    return AttackConfig(attack_type=AttackType.VULN_SCAN, log_file=log or None)


def _cfg_cred_sniffer():
    console.print("\n[bold primary][ CRED SNIFFER CONFIG ][/bold primary]\n")
    iface = ask_input("Interface (blank = auto)", "")
    _, log = _ask_runtime_options()
    return AttackConfig(
        attack_type=AttackType.CRED_SNIFFER,
        interface=iface or None, log_file=log,
    )


def _cfg_ftp_anon():
    _, log = _ask_runtime_options()
    return AttackConfig(attack_type=AttackType.FTP_ANON, log_file=log)


def _cfg_ftp_bounce():
    console.print("\n[bold primary][ FTP BOUNCE CONFIG ][/bold primary]\n")
    target_host = ask_input("Host to bounce-scan (blank = target host)", "")
    log = ask_input("Save to file (blank = skip)", "")
    return AttackConfig(
        attack_type=AttackType.FTP_BOUNCE,
        ftp_bounce_host=target_host, log_file=log or None,
    )


def _cfg_http_bruteforce():
    console.print("\n[bold primary][ HTTP BRUTE CONFIG ][/bold primary]\n")
    tls = render_menu("SCHEME", ["Plain HTTP", "HTTPS"]) == 1
    path = ask_input("Login path", "/login.php")
    method = ask_input("Method (POST/GET)", "POST").upper()
    uf = ask_input("Username field name", "username")
    pf = ask_input("Password field name", "password")
    um, uv, ufl = _ask_credential_mode("username")
    pm, pv, pfl = _ask_credential_mode("password")
    delay, log = _ask_runtime_options()
    return AttackConfig(
        attack_type=AttackType.HTTP_BRUTEFORCE,
        http_use_tls=tls, http_path=path, http_method=method,
        http_username_field=uf, http_password_field=pf,
        username_mode=um, username_value=uv, username_file=ufl,
        password_mode=pm, password_value=pv, password_file=pfl,
        delay=delay, log_file=log,
    )


def _cfg_dir_map():
    console.print("\n[bold primary][ SERVER DIRECTORY MAPPING CONFIG ][/bold primary]\n")
    tls = render_menu("SCHEME", ["Plain HTTP", "HTTPS"]) == 1
    path = ask_input("Base path to map", "/")
    wordlist = ask_input("Custom wordlist path (blank = default high-priority list)", "")
    log = ask_input("Save findings to file (blank = skip)", "")
    return AttackConfig(
        attack_type=AttackType.DIR_MAP,
        http_use_tls=tls,
        http_path=path,
        password_file=wordlist or None,
        log_file=log or None,
    )


def _cfg_http_scanner():
    console.print("\n[bold primary][ HTTP SCANNER CONFIG ][/bold primary]\n")
    tls = render_menu("SCHEME", ["Plain HTTP", "HTTPS"]) == 1
    path = ask_input("Base path", "/")
    params = ask_input("Test params (comma-separated)", "q,id,search,page")
    console.print("[muted]Modules: dirbust, sqli, xss, lfi, cmdi[/muted]")
    mods = ask_input("Modules (blank = all)", "dirbust,sqli,xss,lfi,cmdi")
    mod_list = [m.strip().lower() for m in mods.split(",") if m.strip()]
    log = ask_input("Save to file (blank = skip)", "")
    return AttackConfig(
        attack_type=AttackType.HTTP_SCANNER,
        http_use_tls=tls, http_path=path, http_params=params,
        http_scan_types=mod_list, log_file=log or None,
    )


def _cfg_exploit_upload():
    console.print("\n[bold primary][ EXPLOIT UPLOAD CONFIG ][/bold primary]\n")
    pt = ask_input("Payload (php/jsp/asp/aspx)", "php")
    _, log = _ask_runtime_options()
    return AttackConfig(
        attack_type=AttackType.EXPLOIT_UPLOAD,
        payload_type=pt.lower() or "php", log_file=log,
    )


def _cfg_ssl_scan():
    log = ask_input("\nSave findings to file (blank = skip)", "")
    return AttackConfig(attack_type=AttackType.SSL_SCAN, log_file=log or None)


def _cfg_smtp_enum():
    console.print("\n[bold primary][ SMTP ENUM CONFIG ][/bold primary]\n")
    path = ask_input("Usernames wordlist", DEFAULT_USERS_PATH)
    log = ask_input("Save to file (blank = skip)", "")
    return AttackConfig(
        attack_type=AttackType.SMTP_ENUM,
        username_file=path, log_file=log or None,
    )


def _cfg_smtp_bruteforce():
    console.print("\n[bold primary][ SMTP BRUTE CONFIG ][/bold primary]\n")
    um, uv, uf = _ask_credential_mode("username")
    pm, pv, pf = _ask_credential_mode("password")
    delay, log = _ask_runtime_options()
    return AttackConfig(
        attack_type=AttackType.SMTP_BRUTEFORCE,
        username_mode=um, username_value=uv, username_file=uf,
        password_mode=pm, password_value=pv, password_file=pf,
        delay=delay, log_file=log,
    )


def _cfg_smtp_relay():
    _, log = _ask_runtime_options()
    return AttackConfig(attack_type=AttackType.SMTP_RELAY, log_file=log)


def _cfg_ssh_bruteforce():
    console.print("\n[bold primary][ SSH BRUTE CONFIG ][/bold primary]\n")
    um, uv, uf = _ask_credential_mode("username")
    pm, pv, pf = _ask_credential_mode("password")
    delay, log = _ask_runtime_options()
    return AttackConfig(
        attack_type=AttackType.SSH_BRUTEFORCE,
        username_mode=um, username_value=uv, username_file=uf,
        password_mode=pm, password_value=pv, password_file=pf,
        delay=delay, log_file=log,
    )


def _cfg_ssh_scanner():
    log = ask_input("\nSave findings to file (blank = skip)", "")
    return AttackConfig(attack_type=AttackType.SSH_SCANNER, log_file=log or None)


def _cfg_auto_pwn():
    console.print("\n[bold primary][ AUTO-PWN CONFIG ][/bold primary]\n")
    console.print(
        "[muted]Chain: vuln scan → default creds → dictionary → config enum[/muted]\n"
    )
    delay, log = _ask_runtime_options()
    return AttackConfig(
        attack_type=AttackType.AUTO_PWN,
        delay=delay, log_file=log,
        username_file=DEFAULT_USERS_PATH, password_file=DEFAULT_PASSWORDS_PATH,
        max_length=300,
    )


def _cfg_full_auto():
    console.print("\n[bold primary][ FULL AUTO CONFIG ][/bold primary]\n")
    console.print(
        "[muted]Runs every applicable attack bottom→top for this service.[/muted]\n"
        "[muted]All downloads saved to:[/muted] "
        f"[text]{init_downloads()}[/text]\n"
    )
    delay_str = ask_input("Delay between attempts (0 = none)", "0")
    try:
        delay = float(delay_str)
    except ValueError:
        delay = 0.0
    return AttackConfig(
        attack_type=AttackType.FULL_AUTO,
        delay=delay,
        log_file=None,       # auto-generated per target
        download_dir=init_downloads(),
    )


_DISPATCH = {
    AttackType.BRUTEFORCE:      _cfg_bruteforce,
    AttackType.DICTIONARY:      _cfg_dictionary,
    AttackType.WORDLIST:        _cfg_wordlist,
    AttackType.CONFIG_ENUM:     _cfg_config_enum,
    AttackType.MYSQL_EXPLOIT:   _cfg_mysql_exploit,
    AttackType.VULN_SCAN:       _cfg_vuln_scan,
    AttackType.CRED_SNIFFER:    _cfg_cred_sniffer,
    AttackType.FTP_ANON:        _cfg_ftp_anon,
    AttackType.FTP_BOUNCE:      _cfg_ftp_bounce,
    AttackType.HTTP_BRUTEFORCE: _cfg_http_bruteforce,
    AttackType.HTTP_SCANNER:    _cfg_http_scanner,
    AttackType.EXPLOIT_UPLOAD:  _cfg_exploit_upload,
    AttackType.SSL_SCAN:        _cfg_ssl_scan,
    AttackType.SMTP_ENUM:       _cfg_smtp_enum,
    AttackType.SMTP_BRUTEFORCE: _cfg_smtp_bruteforce,
    AttackType.SMTP_RELAY:      _cfg_smtp_relay,
    AttackType.SSH_BRUTEFORCE:  _cfg_ssh_bruteforce,
    AttackType.SSH_SCANNER:     _cfg_ssh_scanner,
    AttackType.AUTO_PWN:        _cfg_auto_pwn,
    AttackType.FULL_AUTO:       _cfg_full_auto,
    AttackType.DIR_MAP:         _cfg_dir_map,
}
_DISPATCH.update({
    AttackType.WEB_SHELL_UPLOAD:      _cfg_web_shell_upload,
    AttackType.WEB_SSTI:              lambda: _cfg_web_generic(AttackType.WEB_SSTI),
    AttackType.WEB_SSRF:              lambda: _cfg_web_generic(AttackType.WEB_SSRF),
    AttackType.WEB_XXE:               lambda: _cfg_web_generic(AttackType.WEB_XXE),
    AttackType.WEB_DESER:             lambda: _cfg_web_generic(AttackType.WEB_DESER),
    AttackType.WEB_OPEN_REDIRECT:     lambda: _cfg_web_generic(AttackType.WEB_OPEN_REDIRECT),
    AttackType.WEB_HOST_HEADER:       lambda: _cfg_web_generic(AttackType.WEB_HOST_HEADER),
    AttackType.WEB_SMUGGLING:         lambda: _cfg_web_generic(AttackType.WEB_SMUGGLING),
    AttackType.WEB_CACHE_POISON:      lambda: _cfg_web_generic(AttackType.WEB_CACHE_POISON),
    AttackType.WEB_CSRF:              lambda: _cfg_web_generic(AttackType.WEB_CSRF),
    AttackType.WEB_AUTH_BYPASS:       lambda: _cfg_web_generic(AttackType.WEB_AUTH_BYPASS),
    AttackType.WEB_JWT_ATTACK:        lambda: _cfg_web_generic(AttackType.WEB_JWT_ATTACK),
    AttackType.WEB_PHP_TYPE_JUGGLING: lambda: _cfg_web_generic(AttackType.WEB_PHP_TYPE_JUGGLING),
    AttackType.WEB_NOSQL_INJECTION:   lambda: _cfg_web_generic(AttackType.WEB_NOSQL_INJECTION),
    AttackType.WEB_WP_SCANNER:        lambda: _cfg_web_generic(AttackType.WEB_WP_SCANNER),
    AttackType.WEB_API_SCAN:          lambda: _cfg_web_generic(AttackType.WEB_API_SCAN),
    AttackType.WEB_SECRETS_SCAN:      lambda: _cfg_web_generic(AttackType.WEB_SECRETS_SCAN),
    AttackType.WEB_GRAPHQL:           lambda: _cfg_web_generic(AttackType.WEB_GRAPHQL),
    AttackType.WEB_SQLI_EXTRACT:      lambda: _cfg_web_generic(AttackType.WEB_SQLI_EXTRACT),
    AttackType.WEB_LFI_RCE:           lambda: _cfg_web_generic(AttackType.WEB_LFI_RCE),
    AttackType.MYSQL_UDF:             lambda: _cfg_mysql_creds(AttackType.MYSQL_UDF),
    AttackType.MYSQL_AUTH_BYPASS:     lambda: _cfg_simple(AttackType.MYSQL_AUTH_BYPASS),
    AttackType.MYSQL_BACKDOOR:        lambda: _cfg_mysql_creds(AttackType.MYSQL_BACKDOOR),
    AttackType.FTP_PROFTPD_MODCOPY:   lambda: _cfg_simple(AttackType.FTP_PROFTPD_MODCOPY),
    AttackType.FTP_VSFTPD_BACKDOOR:   lambda: _cfg_simple(AttackType.FTP_VSFTPD_BACKDOOR),
    AttackType.FTP_WEBSHELL:          lambda: _cfg_simple(AttackType.FTP_WEBSHELL),
    AttackType.SSH_KEY_BACKDOOR:      _cfg_ssh_key_backdoor,
    AttackType.SSH_USER_ENUM:         _cfg_ssh_user_enum,
    AttackType.SMTP_SPOOF_CHAIN:      lambda: _cfg_simple(AttackType.SMTP_SPOOF_CHAIN),
    AttackType.SMTP_HEADER_INJECTION: lambda: _cfg_simple(AttackType.SMTP_HEADER_INJECTION),
})

def _cfg_service_simple(attack_type: AttackType) -> AttackConfig:
    """Minimal config for new single-socket service attacks."""
    return AttackConfig(attack_type=attack_type, log_file=None)

_DISPATCH.update({
    AttackType.REDIS_SCAN:      lambda: _cfg_service_simple(AttackType.REDIS_SCAN),
    AttackType.REDIS_RCE:       lambda: _cfg_service_simple(AttackType.REDIS_RCE),
    AttackType.MONGO_ENUM:      lambda: _cfg_service_simple(AttackType.MONGO_ENUM),
    AttackType.POSTGRES_SCAN:   lambda: _cfg_service_simple(AttackType.POSTGRES_SCAN),
    AttackType.MSSQL_SCAN:      lambda: _cfg_service_simple(AttackType.MSSQL_SCAN),
    AttackType.DOCKER_ESCAPE:   lambda: _cfg_service_simple(AttackType.DOCKER_ESCAPE),
    AttackType.KUBE_SECRETS:    lambda: _cfg_service_simple(AttackType.KUBE_SECRETS),
    AttackType.ELASTIC_DUMP:    lambda: _cfg_service_simple(AttackType.ELASTIC_DUMP),
    AttackType.MEMCACHED_DUMP:  lambda: _cfg_service_simple(AttackType.MEMCACHED_DUMP),
    AttackType.VNC_SCAN:        lambda: _cfg_service_simple(AttackType.VNC_SCAN),
    AttackType.LDAP_ENUM:       lambda: _cfg_service_simple(AttackType.LDAP_ENUM),
    AttackType.TELNET_BRUTE:    lambda: _cfg_service_simple(AttackType.TELNET_BRUTE),
})

def run_attack_config(attack_type: AttackType) -> AttackConfig:
    handler = _DISPATCH.get(attack_type)
    if not handler:
        raise ValueError(f"No config flow for {attack_type}")
    return handler()