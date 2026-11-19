"""
MySQL Configuration Enumeration
Gathers server variables, privileges, user accounts, and security settings.
"""
from datetime import datetime
import pymysql

from rich.panel import Panel
from rich.table import Table

from Design.colors_cli import console
from modules.target import TargetInfo
from modules.attack_config import AttackConfig


SENSITIVE_VARS = [
    "version",
    "version_compile_os",
    "datadir",
    "basedir",
    "plugin_dir",
    "secure_file_priv",
    "general_log",
    "general_log_file",
    "slow_query_log",
    "log_error",
    "bind_address",
    "port",
    "skip_networking",
    "have_ssl",
    "local_infile",
    "validate_password_policy",
]


def run(target: TargetInfo, config: AttackConfig) -> None:
    console.print(
        f"\n[bold primary][ MYSQL CONFIG ENUMERATION ][/bold primary]\n"
        f"  [muted]Target :[/muted] [primary]{target.host}:{target.port}[/primary]\n"
    )

    user = config.username_value or "root"
    password = config.password_value or ""

    try:
        conn = pymysql.connect(
            host=target.host,
            port=target.port,
            user=user,
            password=password,
            connect_timeout=6,
        )
    except Exception as e:
        console.print(f"[error]  Connection failed: {e}[/error]")
        return

    cur = conn.cursor()
    findings: list[tuple[str, str]] = []

    # 1. Basic Identity
    try:
        cur.execute("SELECT USER(), CURRENT_USER(), DATABASE(), VERSION()")
        u_actual, u_current, db_current, ver = cur.fetchone()
        findings.append(("Connected User", str(u_actual)))
        findings.append(("Effective User", str(u_current)))
        findings.append(("Current Database", str(db_current or "None")))
        findings.append(("Server Version", str(ver)))
    except Exception as e:
        findings.append(("Identity Error", str(e)))

    # 2. Key Security Variables
    vars_dict = {}
    for var_name in SENSITIVE_VARS:
        try:
            cur.execute(f"SHOW VARIABLES LIKE '{var_name}'")
            row = cur.fetchone()
            if row:
                vars_dict[row[0]] = row[1]
        except Exception:
            pass

    # 3. Assess secure_file_priv
    sfp = vars_dict.get("secure_file_priv")
    if sfp == "" or sfp is None:
        findings.append(("secure_file_priv", "[bold red]DISABLED (Arbitrary file read/write allowed!)[/bold red]"))
    elif sfp == "NULL":
        findings.append(("secure_file_priv", "NULL (File read/write disabled)"))
    else:
        findings.append(("secure_file_priv", f"Restricted to: {sfp}"))

    for k, v in vars_dict.items():
        if k != "secure_file_priv":
            findings.append((k, str(v)))

    # 4. Enumerate accessible databases
    databases = []
    try:
        cur.execute("SHOW DATABASES")
        databases = [r[0] for r in cur.fetchall()]
        findings.append(("Accessible Databases", ", ".join(databases)))
    except Exception as e:
        findings.append(("Databases Error", str(e)))

    # 5. Enumerate Users (if privileged)
    user_accounts = []
    try:
        cur.execute("SELECT User, Host, plugin FROM mysql.user")
        for u, h, p in cur.fetchall():
            user_accounts.append(f"{u}@{h} ({p})")
        findings.append(("User Accounts", "\n".join(user_accounts)))
    except Exception:
        findings.append(("mysql.user Table", "Access Denied (requires SUPER/GRANT)"))

    # 6. Current User Grants
    grants = []
    try:
        cur.execute("SHOW GRANTS")
        grants = [r[0] for r in cur.fetchall()]
        findings.append(("User Grants", "\n".join(grants)))
    except Exception:
        pass

    conn.close()

    # Render table
    table = Table(title=f"MySQL Configuration: {target.host}:{target.port}")
    table.add_column("Property", style="primary", width=26)
    table.add_column("Value", style="text")

    for k, v in findings:
        table.add_row(k, v)

    console.print(table)

    if config.log_file:
        try:
            with open(config.log_file, "a", encoding="utf-8") as fh:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                fh.write(f"\n--- [{ts}] MYSQL ENUM: {target.host}:{target.port} ---\n")
                for k, v in findings:
                    fh.write(f"{k}: {v}\n")
            console.print(f"  [muted]Saved config report to:[/muted] [primary]{config.log_file}[/primary]")
        except OSError as e:
            console.print(f"  [warning]Could not write log: {e}[/warning]")
