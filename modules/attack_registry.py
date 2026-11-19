"""
Attack Registry
===============
Maps each detected service to the attacks that apply to it, and provides
human-readable labels for every AttackType. This is the single source of
truth the menu system uses to decide which attacks to display for a target.

Services supported:  mysql, ftp, http, https, smtp, ssh
Attacks total:       50 (20 base + 30 advanced)
"""

from modules.attack_menu import AttackType


# ============================================================================
# Shared web-attack bundle — reused by both HTTP and HTTPS entries
# ============================================================================
WEB_COMMON: list[AttackType] = [
    AttackType.WEB_AUTH_BYPASS,
    AttackType.WEB_SSTI,
    AttackType.WEB_SSRF,
    AttackType.WEB_XXE,
    AttackType.WEB_DESER,
    AttackType.WEB_OPEN_REDIRECT,
    AttackType.WEB_HOST_HEADER,
    AttackType.WEB_SMUGGLING,
    AttackType.WEB_CACHE_POISON,
    AttackType.WEB_CSRF,
    AttackType.WEB_JWT_ATTACK,
    AttackType.WEB_PHP_TYPE_JUGGLING,
    AttackType.WEB_NOSQL_INJECTION,
    AttackType.WEB_WP_SCANNER,
    AttackType.WEB_API_SCAN,
    AttackType.WEB_SECRETS_SCAN,
    AttackType.WEB_GRAPHQL,
    AttackType.WEB_SQLI_EXTRACT,
    AttackType.WEB_LFI_RCE,
]


# ============================================================================
# SERVICE → ATTACKS
# Order matters: FULL_AUTO is placed first so it appears at the top of attack
# menus. When FULL_AUTO runs, it iterates non-brute attacks bottom→top.
# ============================================================================
SERVICE_ATTACKS: dict[str, list[AttackType]] = {

    # ------------------------------------------------------------------ MySQL
    "mysql": [
        AttackType.FULL_AUTO,
        AttackType.BRUTEFORCE,
        AttackType.DICTIONARY,
        AttackType.WORDLIST,
        AttackType.CONFIG_ENUM,
        AttackType.MYSQL_EXPLOIT,
        AttackType.MYSQL_AUTH_BYPASS,
        AttackType.MYSQL_UDF,
        AttackType.MYSQL_BACKDOOR,
        AttackType.VULN_SCAN,
        AttackType.CRED_SNIFFER,
        AttackType.AUTO_PWN,
    ],

    # -------------------------------------------------------------------- FTP
    "ftp": [
        AttackType.FULL_AUTO,
        AttackType.BRUTEFORCE,
        AttackType.DICTIONARY,
        AttackType.WORDLIST,
        AttackType.FTP_ANON,
        AttackType.FTP_BOUNCE,
        AttackType.FTP_PROFTPD_MODCOPY,
        AttackType.FTP_VSFTPD_BACKDOOR,
        AttackType.FTP_WEBSHELL,
        AttackType.VULN_SCAN,
        AttackType.CRED_SNIFFER,
        AttackType.AUTO_PWN,
    ],

    # ------------------------------------------------------------------- HTTP
    "http": [
        AttackType.FULL_AUTO,
        AttackType.HTTP_BRUTEFORCE,
        AttackType.HTTP_SCANNER,
        AttackType.WEB_SHELL_UPLOAD,
        AttackType.EXPLOIT_UPLOAD,
        *WEB_COMMON,
        AttackType.VULN_SCAN,
        AttackType.CRED_SNIFFER,
        AttackType.AUTO_PWN,
    ],

    # ------------------------------------------------------------------ HTTPS
    "https": [
        AttackType.FULL_AUTO,
        AttackType.HTTP_BRUTEFORCE,
        AttackType.SSL_SCAN,
        AttackType.WEB_SHELL_UPLOAD,
        AttackType.EXPLOIT_UPLOAD,
        *WEB_COMMON,
        AttackType.CRED_SNIFFER,
        AttackType.AUTO_PWN,
    ],

    # ------------------------------------------------------------------- SMTP
    "smtp": [
        AttackType.FULL_AUTO,
        AttackType.SMTP_ENUM,
        AttackType.SMTP_BRUTEFORCE,
        AttackType.SMTP_RELAY,
        AttackType.SMTP_SPOOF_CHAIN,
        AttackType.SMTP_HEADER_INJECTION,
        AttackType.VULN_SCAN,
        AttackType.AUTO_PWN,
    ],

    # -------------------------------------------------------------------- SSH
    "ssh": [
        AttackType.FULL_AUTO,
        AttackType.SSH_BRUTEFORCE,
        AttackType.SSH_SCANNER,
        AttackType.SSH_USER_ENUM,
        AttackType.SSH_KEY_BACKDOOR,
        AttackType.VULN_SCAN,
        AttackType.AUTO_PWN,
    ],

    # ------------------------------------------------------------------ Redis
    "redis": [
        AttackType.FULL_AUTO,
        AttackType.REDIS_SCAN,
        AttackType.REDIS_RCE,
        AttackType.VULN_SCAN,
    ],

    # --------------------------------------------------------------- MongoDB
    "mongodb": [
        AttackType.FULL_AUTO,
        AttackType.MONGO_ENUM,
        AttackType.VULN_SCAN,
    ],

    # ------------------------------------------------------------ PostgreSQL
    "postgres": [
        AttackType.FULL_AUTO,
        AttackType.POSTGRES_SCAN,
        AttackType.VULN_SCAN,
    ],

    # ----------------------------------------------------------------- MSSQL
    "mssql": [
        AttackType.FULL_AUTO,
        AttackType.MSSQL_SCAN,
        AttackType.VULN_SCAN,
    ],

    # ------------------------------------------------------- Elasticsearch
    "elasticsearch": [
        AttackType.FULL_AUTO,
        AttackType.ELASTIC_DUMP,
        AttackType.VULN_SCAN,
    ],

    # ------------------------------------------------------------ Memcached
    "memcached": [
        AttackType.FULL_AUTO,
        AttackType.MEMCACHED_DUMP,
        AttackType.VULN_SCAN,
    ],

    # -------------------------------------------------------------------VNC
    "vnc": [
        AttackType.FULL_AUTO,
        AttackType.VNC_SCAN,
        AttackType.VULN_SCAN,
    ],

    # ---------------------------------------------------------------- Telnet
    "telnet": [
        AttackType.FULL_AUTO,
        AttackType.TELNET_BRUTE,
        AttackType.VULN_SCAN,
    ],

    # ------------------------------------------------------------------ LDAP
    "ldap": [
        AttackType.FULL_AUTO,
        AttackType.LDAP_ENUM,
        AttackType.VULN_SCAN,
    ],

    # ---------------------------------------------------------------- Docker
    "docker": [
        AttackType.FULL_AUTO,
        AttackType.DOCKER_ESCAPE,
        AttackType.VULN_SCAN,
    ],

    # ------------------------------------------------------------- Kubernetes
    "kubernetes": [
        AttackType.FULL_AUTO,
        AttackType.KUBE_SECRETS,
        AttackType.VULN_SCAN,
    ],
}


# ============================================================================
# ATTACK → HUMAN-READABLE LABEL
# Every AttackType in the enum must have an entry (used by the menu system).
# ============================================================================
ATTACK_LABELS: dict[AttackType, str] = {

    # ---------------- Base attacks (20) ----------------
    AttackType.BRUTEFORCE:      "Brute Force (fixed user + charset exhaustion)",
    AttackType.DICTIONARY:      "Dictionary Attack (random from user/pass lists)",
    AttackType.WORDLIST:        "Wordlist Attack (combined user:pass file)",
    AttackType.CONFIG_ENUM:     "MySQL Config Enumeration (users/grants/vars)",
    AttackType.MYSQL_EXPLOIT:   "MySQL Exploit (OUTFILE / LOAD_FILE)",
    AttackType.VULN_SCAN:       "Vulnerability Scan (version → CVE mapping)",
    AttackType.CRED_SNIFFER:    "Credential Sniffer (passive packet capture)",
    AttackType.FTP_ANON:        "FTP Anonymous Login + Download",
    AttackType.FTP_BOUNCE:      "FTP Bounce Port Scan (pivot)",
    AttackType.HTTP_BRUTEFORCE: "HTTP Brute Force (form / basic auth)",
    AttackType.HTTP_SCANNER:    "HTTP Scanner (dirbust + SQLi/XSS/LFI/cmdi)",
    AttackType.EXPLOIT_UPLOAD:  "Exploit Upload via Cloudflare Tunnel",
    AttackType.SSL_SCAN:        "SSL/TLS Weakness Scan",
    AttackType.SMTP_ENUM:       "SMTP User Enumeration (VRFY/EXPN/RCPT)",
    AttackType.SMTP_BRUTEFORCE: "SMTP Brute Force (AUTH LOGIN/PLAIN)",
    AttackType.SMTP_RELAY:      "SMTP Open Relay Test",
    AttackType.SSH_BRUTEFORCE:  "SSH Brute Force (paramiko)",
    AttackType.SSH_SCANNER:     "SSH Weak-Config / Auth Method Scan",
    AttackType.AUTO_PWN:        "AUTO PWN (scan → defaults → dictionary → enum)",
    AttackType.FULL_AUTO:       "★ FULL AUTO (run every applicable attack, no brute)",

    # ---------------- Advanced web attacks (20) ----------------
    AttackType.WEB_SHELL_UPLOAD:      "Web Shell Upload (multipart bypass + polyglot)",
    AttackType.WEB_SSTI:              "SSTI (Jinja2 / Twig / Freemarker → RCE)",
    AttackType.WEB_SSRF:              "SSRF (AWS / GCP / Azure metadata + localhost)",
    AttackType.WEB_XXE:               "XXE Injection (file read via DOCTYPE)",
    AttackType.WEB_DESER:             "Deserialization Detector (Java/PHP/Python)",
    AttackType.WEB_OPEN_REDIRECT:     "Open Redirect (17 redirect params)",
    AttackType.WEB_HOST_HEADER:       "Host Header Injection",
    AttackType.WEB_SMUGGLING:         "HTTP Request Smuggling (CL.TE / TE.CL)",
    AttackType.WEB_CACHE_POISON:      "Web Cache Poisoning",
    AttackType.WEB_CSRF:              "CSRF Token Absence Check",
    AttackType.WEB_AUTH_BYPASS:       "Auth Bypass (40+ header / path tricks)",
    AttackType.WEB_JWT_ATTACK:        "JWT Attack (none-alg + weak-secret crack)",
    AttackType.WEB_PHP_TYPE_JUGGLING: "PHP Type Juggling (magic hash bypass)",
    AttackType.WEB_NOSQL_INJECTION:   "NoSQL Injection (Mongo operator injection)",
    AttackType.WEB_WP_SCANNER:        "WordPress Scanner (version/plugins/users)",
    AttackType.WEB_API_SCAN:          "API Endpoint Discovery + Auth Probe",
    AttackType.WEB_SECRETS_SCAN:      "Exposed Secrets Scanner (JS / .env)",
    AttackType.WEB_GRAPHQL:           "GraphQL Introspection + Schema Dump",
    AttackType.WEB_SQLI_EXTRACT:      "SQLi Data Extraction (UNION + DB dump)",
    AttackType.WEB_LFI_RCE:           "LFI → RCE (log poisoning / php://filter)",

    # ---------------- Advanced MySQL (3) ----------------
    AttackType.MYSQL_UDF:             "MySQL UDF Privilege Escalation (sys_eval)",
    AttackType.MYSQL_AUTH_BYPASS:     "MySQL Auth Bypass (CVE-2012-2122 / empty pwd)",
    AttackType.MYSQL_BACKDOOR:        "MySQL Backdoor (hidden user + event scheduler)",

    # ---------------- Advanced FTP (3) ----------------
    AttackType.FTP_PROFTPD_MODCOPY:   "ProFTPD mod_copy CVE-2015-3306 (RCE via web dir)",
    AttackType.FTP_VSFTPD_BACKDOOR:   "vsftpd 2.3.4 Backdoor CVE-2011-2523 (port 6200)",
    AttackType.FTP_WEBSHELL:          "FTP → Web Shell Drop (writable dirs)",

    # ---------------- Advanced SSH (2) ----------------
    AttackType.SSH_KEY_BACKDOOR:      "SSH Key Backdoor (authorized_keys persistence)",
    AttackType.SSH_USER_ENUM:         "SSH User Enumeration (CVE-2018-15473 timing)",

    # ---------------- Advanced SMTP (2) ----------------
    AttackType.SMTP_SPOOF_CHAIN:      "SMTP Spoof Chain (From-CEO / From-IT / etc.)",
    AttackType.SMTP_HEADER_INJECTION: "SMTP Header Injection (CRLF Bcc / Reply-To)",

    # ---------------- New services (12) ----------------
    AttackType.REDIS_SCAN:     "Redis Scan (INFO dump + all keys + no-auth check)",
    AttackType.REDIS_RCE:      "Redis RCE (CONFIG SET → SSH key / cron write)",
    AttackType.MONGO_ENUM:     "MongoDB Enum (listDatabases + collections, no-auth)",
    AttackType.POSTGRES_SCAN:  "PostgreSQL Scan (passwordless login + pg_tables dump)",
    AttackType.MSSQL_SCAN:     "MSSQL Scan (banner + TDS pre-login probe)",
    AttackType.DOCKER_ESCAPE:  "Docker API Escape (:2375 unauthenticated container list)",
    AttackType.KUBE_SECRETS:   "Kubernetes Secrets Dump (anon API /api/v1/secrets)",
    AttackType.ELASTIC_DUMP:   "Elasticsearch Dump (_cat/indices + sample docs)",
    AttackType.MEMCACHED_DUMP: "Memcached Dump (stats + slab contents)",
    AttackType.VNC_SCAN:       "VNC Scan (banner + auth check, v3.3=noauth)",
    AttackType.LDAP_ENUM:      "LDAP Enum (anon bind + base search for users/groups)",
    AttackType.TELNET_BRUTE:   "Telnet Brute (common root/admin/guest credentials)",
}


# ============================================================================
# PUBLIC API
# ============================================================================
def get_attacks(service: str) -> list[AttackType]:
    """
    Return the list of attacks applicable to a service name.
    Service is case-insensitive.
    """
    return SERVICE_ATTACKS.get(service.lower(), [])


def get_label(attack_type: AttackType) -> str:
    """Return the human label for an AttackType (falls back to its value)."""
    return ATTACK_LABELS.get(attack_type, attack_type.value)


def all_attack_types() -> list[AttackType]:
    """Every AttackType across every service, in registry order, deduplicated."""
    seen: list[AttackType] = []
    for svc_attacks in SERVICE_ATTACKS.values():
        for atk in svc_attacks:
            if atk not in seen:
                seen.append(atk)
    return seen


def attacks_for_targets(targets: list) -> list[tuple]:
    """
    Given a list of TargetInfo objects, return (target, attack) pairs
    in the order they should appear in the menu.
    """
    pairs: list[tuple] = []
    for t in targets:
        for atk in get_attacks(t.service):
            pairs.append((t, atk))
    pairs.sort(key=lambda item: 0 if item[1] == AttackType.FULL_AUTO else 1)
    return pairs


def compatible_targets(targets: list, attack_type: AttackType) -> list:
    """Return only the targets that support this attack type."""
    return [t for t in targets if attack_type in get_attacks(t.service)]