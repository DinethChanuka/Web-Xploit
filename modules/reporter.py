"""
Report generator — creates full HTML + text reports with devil ASCII art header.
Called at the end of every attack to save a complete record.
"""
import datetime
import os
from modules.downloads import ensure_dir, host_dir

TOOL_NAME = "web-Xploit"
TOOL_VERSION = "2.0.0"

DEVIL_ASCII = r"""
  ██╗    ██╗███████╗██████╗       ██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗
  ██║    ██║██╔════╝██╔══██╗      ╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
  ██║ █╗ ██║█████╗  ██████╔╝       ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║   
  ██║███╗██║██╔══╝  ██╔══██╗       ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║   
  ╚███╔███╔╝███████╗██████╔╝      ██╔╝ ██╗██║     ███████╗╚██████╔╝██║   ██║   
   ╚══╝╚══╝ ╚══════╝╚═════╝       ╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝  

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⠐⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠢⡉⠁⢠⠐⠒⢀⡀⠀⠀⠀⠀⠀⠂⠀⠀⠈⠀⠀⠀⠀⠀⢀⡀⠒⢂⠄⠈⢉⠔⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠔⠂⠐⠃⠠⠖⠈⡁⢄⠔⠨⠀⠀⡀⡄⢠⣢⣿⣿⣔⣤⢀⠀⠀⠀⠧⠐⠀⣈⡁⠢⠃⠘⠁⠐⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠆⠀⠀⠀⠀⠀⠀⠑⠥⠁⢉⠠⡢⠁⠀⠰⣬⢻⣿⣿⡟⣡⠆⠀⠀⢂⢄⡁⠓⠴⠊⠀⠀⠀⠀⠀⠀⠰⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠅⠃⢀⢄⠂⠀⢸⣿⠏⠻⣿⡀⠂⠰⢠⡀⠘⠪⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢠⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠈⠀⠀⡰⣹⣾⣿⡇⢸⣿⡻⣏⢂⠀⠈⠐⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⡄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⡔⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢗⣄⢈⠔⣽⣿⠟⡁⢈⠿⣾⢭⢦⠁⣠⣚⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢢⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⠆⠀⠀⠀⠀⠀⢄⠀⠀⠀⠀⠀⠄⠀⠀⠮⣵⡻⣟⡃⣚⡣⠘⣓⢘⣻⢲⣯⠵⠀⢀⠤⠀⠀⠀⠀⢀⡠⠀⠀⠀⠀⠀⠐⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣈⠄⢀⠀⠀⠀⠀⠈⠙⢦⣠⡄⠀⠀⠐⡄⠀⠒⣳⣜⢧⣙⠇⠰⢃⡼⣣⢋⠦⢀⡠⠂⠀⠀⠤⣀⡴⠋⠁⠀⠀⠀⠀⡀⢠⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⡄⢀⠀⠀⠀⠀⠀⠠⠀⠈⠉⠄⠀⠴⡻⣯⢷⣌⠻⣷⢿⠃⠘⡏⣴⡗⣡⡖⣼⡻⡂⠀⠠⠋⠀⠀⠀⠀⠀⠀⠀⠀⡀⠠⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⡀⡔⢰⠀⠀⠀⠀⠀⠀⠁⠀⠀⢀⠀⠀⠀⠈⠑⠙⢳⡝⢫⠇⠸⡝⢣⣾⠋⠈⠁⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⡆⢨⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠵⠀⣂⠀⠀⠀⠀⣀⡀⠀⠐⠀⠀⢅⠀⠀⠀⠀⠈⠁⢊⣠⣤⡑⠈⠁⠀⠂⠀⠀⡠⠀⠀⠂⠀⢀⢀⠀⠀⠀⠀⡐⠀⠮⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠐⡑⠀⡂⠠⠀⠃⠐⢪⠁⢀⠀⠀⠈⠲⣄⢀⠠⠀⢰⢺⣽⣯⡝⠀⠀⠀⠀⣠⠆⠁⠀⠀⡠⠈⡱⠂⠋⠀⠄⠐⠁⠚⢀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠠⠀⠁⠀⠀⠀⠀⠡⠤⠂⠀⠀⠀⠁⢊⡳⡊⢠⢹⢽⣏⡝⡤⢳⢜⠑⠉⠀⠀⠀⠠⠠⠈⠀⠀⠀⠀⠈⠀⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⢾⠶⣽⢷⣿⣇⠰⣷⠀⠀⠀⠀⠀⠀⠈⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢃⠁⠈⠀⢻⡀⠹⣿⣷⠏⠀⡟⠀⠀⢀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠠⢀⠀⠧⠻⣦⠀⢀⣴⢟⠜⢀⡀⠎⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠎⠀⠁⠀⣀⡀⢀⡀⠀⠈⠀⠡⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⡀⢐⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⠀⠔⢼⢪⡱⠙⠢⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⡐⢄⠀⠀⠀⠀⡜⡄⠓⠠⠀⠁⠀⠀⠠⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠁⠂⠀⠀⠀⠀⢢⠀⠀⠠⠂⠈⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠌⠀⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠢⢄⡀⠀⠘⢁⠀⠀⡀⠂⠀⠠⠀⠀⠀⠀⠀⠀⠀⠀⠄⠈⠠⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠂⠀⠀⠐⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠁⢀⡉⠐⠂⢊⠀⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠂⠁⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠄⡂⠀⠅⠀⠒⠀⠀⠨⠁⢒⠀⠄⠀⠀⠀⠀⠀⠀⠠⠐⠀⠀⠀⠀⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢁⠀⠄⠀⠀⡀⠀⡈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⠐⠈⠌⠁⠁⠂⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
       ☠  W E B - X P L O I T  ☠  v2.0  |  ADVANCED PENTESTING FRAMEWORK
"""

DEVIL_TEXT_HEADER = f"""
{'='*80}
{DEVIL_ASCII}
{'='*80}
  TOOL    : {TOOL_NAME} v{TOOL_VERSION}
  PURPOSE : Advanced Web & Network Penetration Testing Framework
  WARNING : For authorized security testing only
{'='*80}
"""


def _timestamp() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _report_path(host: str, attack_name: str) -> str:
    base = ensure_dir(f"{host_dir(host)}/reports")
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(base, f"{attack_name}_{ts}.txt")


def save_attack_report(
    host: str,
    attack_name: str,
    target_info: str,
    findings: list[str],
    requests_made: int = 0,
    duration: float = 0.0,
    raw_log: str = "",
) -> str:
    """
    Save a full text report for an attack run.
    Returns the report file path.
    """
    path = _report_path(host, attack_name)
    ts = _timestamp()

    lines = [DEVIL_TEXT_HEADER]
    lines.append(f"\n  ATTACK REPORT\n  {'─'*40}")
    lines.append(f"  Attack    : {attack_name}")
    lines.append(f"  Target    : {target_info}")
    lines.append(f"  Timestamp : {ts}")
    lines.append(f"  Requests  : {requests_made}")
    lines.append(f"  Duration  : {duration:.1f}s" if duration else "  Duration  : -")
    lines.append(f"\n  FINDINGS ({len(findings)} total)\n  {'─'*40}")

    if findings:
        for f in findings:
            lines.append(f"  [+] {f}")
    else:
        lines.append("  [-] No findings — target appears hardened for this attack vector")

    if raw_log:
        lines.append(f"\n  FULL LOG\n  {'─'*40}")
        lines.append(raw_log)

    lines.append(f"\n{'='*80}")
    lines.append(f"  END OF REPORT — {ts}")
    lines.append(f"{'='*80}\n")

    content = "\n".join(lines)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)

    return path


def save_vuln_report(host: str, service: str, port: int, vulns: list[dict]) -> str:
    """
    Save a vulnerability scan report (CVEs + misconfigs).
    Returns report path.
    """
    attack_name = f"vuln_scan_{service}_{port}"
    findings = []
    for v in vulns:
        sev = v.get("severity", "?")
        name = v.get("name", v.get("identifier", "?"))
        desc = v.get("description", "")
        findings.append(f"[{sev}] {name} — {desc[:100]}")
    return save_attack_report(
        host=host,
        attack_name=attack_name,
        target_info=f"{service.upper()} {host}:{port}",
        findings=findings,
    )
