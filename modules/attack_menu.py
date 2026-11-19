import enum

from Design.menus import render_menu
from modules.target import TargetInfo


class AttackType(enum.Enum):
    # existing
    BRUTEFORCE      = "bruteforce"
    DICTIONARY      = "dictionary"
    WORDLIST        = "wordlist"
    CONFIG_ENUM     = "config_enum"
    MYSQL_EXPLOIT   = "mysql_exploit"
    VULN_SCAN       = "vuln_scan"
    CRED_SNIFFER    = "cred_sniffer"
    FTP_ANON        = "ftp_anon"
    FTP_BOUNCE      = "ftp_bounce"
    HTTP_BRUTEFORCE = "http_bruteforce"
    HTTP_SCANNER    = "http_scanner"
    EXPLOIT_UPLOAD  = "exploit_upload"
    SSL_SCAN        = "ssl_scan"
    SMTP_ENUM       = "smtp_enum"
    SMTP_BRUTEFORCE = "smtp_bruteforce"
    SMTP_RELAY      = "smtp_relay"
    SSH_BRUTEFORCE  = "ssh_bruteforce"
    SSH_SCANNER     = "ssh_scanner"
    AUTO_PWN        = "auto_pwn"
    FULL_AUTO       = "full_auto"
    DIR_MAP         = "dir_map"

    # ---- 30 new advanced attacks ----
    WEB_SHELL_UPLOAD       = "web_shell_upload"
    WEB_SSTI               = "web_ssti"
    WEB_SSRF               = "web_ssrf"
    WEB_XXE                = "web_xxe"
    WEB_DESER              = "web_deser"
    WEB_OPEN_REDIRECT      = "web_open_redirect"
    WEB_HOST_HEADER        = "web_host_header"
    WEB_SMUGGLING          = "web_smuggling"
    WEB_CACHE_POISON       = "web_cache_poison"
    WEB_CSRF               = "web_csrf"
    WEB_AUTH_BYPASS        = "web_auth_bypass"
    WEB_JWT_ATTACK         = "web_jwt_attack"
    WEB_PHP_TYPE_JUGGLING  = "web_php_type_juggling"
    WEB_NOSQL_INJECTION    = "web_nosql_injection"
    WEB_WP_SCANNER         = "web_wp_scanner"
    WEB_API_SCAN           = "web_api_scan"
    WEB_SECRETS_SCAN       = "web_secrets_scan"
    WEB_GRAPHQL            = "web_graphql"
    WEB_SQLI_EXTRACT       = "web_sqli_extract"
    WEB_LFI_RCE            = "web_lfi_rce"
    MYSQL_UDF              = "mysql_udf"
    MYSQL_AUTH_BYPASS      = "mysql_auth_bypass"
    MYSQL_BACKDOOR         = "mysql_backdoor"
    FTP_PROFTPD_MODCOPY    = "ftp_proftpd_modcopy"
    FTP_VSFTPD_BACKDOOR    = "ftp_vsftpd_backdoor"
    FTP_WEBSHELL           = "ftp_webshell"
    SSH_KEY_BACKDOOR       = "ssh_key_backdoor"
    SSH_USER_ENUM          = "ssh_user_enum"
    SMTP_SPOOF_CHAIN       = "smtp_spoof_chain"
    SMTP_HEADER_INJECTION  = "smtp_header_injection"

    # ---- New service attacks (12) ----
    REDIS_SCAN      = "redis_scan"
    REDIS_RCE       = "redis_rce"
    MONGO_ENUM      = "mongo_enum"
    POSTGRES_SCAN   = "postgres_scan"
    MSSQL_SCAN      = "mssql_scan"
    DOCKER_ESCAPE   = "docker_escape"
    KUBE_SECRETS    = "kube_secrets"
    ELASTIC_DUMP    = "elastic_dump"
    MEMCACHED_DUMP  = "memcached_dump"
    VNC_SCAN        = "vnc_scan"
    LDAP_ENUM       = "ldap_enum"
    TELNET_BRUTE    = "telnet_brute"


def _attack_sort_key(atk: AttackType) -> int:
    """Ensure top order: 1) FULL_AUTO, 2) VULN_SCAN, 3) DIR_MAP, followed by others."""
    if atk == AttackType.FULL_AUTO:
        return 0
    if atk == AttackType.VULN_SCAN:
        return 1
    if atk == AttackType.DIR_MAP:
        return 2
    return 3


def run_attack_menu(targets: list[TargetInfo]) -> tuple[TargetInfo, "AttackType"]:
    from modules.attack_registry import get_attacks, ATTACK_LABELS
    entries: list[tuple[TargetInfo, AttackType]] = []
    for t in targets:
        for atk in get_attacks(t.service):
            entries.append((t, atk))
    if not entries:
        raise RuntimeError("No applicable attacks for detected services.")
    # Prioritize: 1. FULL_AUTO, 2. VULN_SCAN, 3. DIR_MAP
    entries.sort(key=lambda item: _attack_sort_key(item[1]))
    options = [f"[{t.service.upper()}:{t.port}]  {ATTACK_LABELS[atk]}" for t, atk in entries]
    idx = render_menu("SELECT ATTACK", options)
    return entries[idx]


def run_attack_menu_all(targets: list[TargetInfo]) -> tuple[list[TargetInfo], "AttackType"]:
    from modules.attack_registry import get_attacks, ATTACK_LABELS
    all_types: list[AttackType] = []
    for t in targets:
        for a in get_attacks(t.service):
            if a not in all_types:
                all_types.append(a)
    if not all_types:
        raise RuntimeError("No applicable attacks.")
    # Prioritize: 1. FULL_AUTO, 2. VULN_SCAN, 3. DIR_MAP
    all_types.sort(key=_attack_sort_key)
    labels = [ATTACK_LABELS[a] for a in all_types]
    idx = render_menu("SELECT ATTACK (runs on all compatible targets)", labels)
    chosen = all_types[idx]
    compatible = [t for t in targets if chosen in get_attacks(t.service)]
    return compatible, chosen