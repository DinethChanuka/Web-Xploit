import re
import shutil
import socket
import struct
from dataclasses import dataclass, field

import pymysql
import pymysql.err

from rich.panel import Panel
from rich.text import Text
from rich.box import DOUBLE

from Design.colors_cli import console
from Design.prompts import ask_input


MYSQL_PORTS   = [3306, 3307, 33060, 33061]
FTP_PORTS     = [21, 2121, 990]
SCAN_TIMEOUT  = 2.0    # responsive timeout per port
PROBE_TIMEOUT = 5.0    # seconds for handshake / service probe
TCP_TIMEOUT   = 2.0    # seconds for raw TCP ping


@dataclass
class TargetInfo:
    host: str
    port: int
    version: str
    service: str = "mysql"   # "mysql", "ftp", or "hybrid"
    extra: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Handshake & Protocol Parsers
# ---------------------------------------------------------------------------

def parse_mysql_handshake(data: bytes) -> dict:
    """
    Parse the MySQL Initial Handshake Packet (Protocol::HandshakeV10 / V9).
    The server sends this packet immediately upon TCP connection before any auth.
    Extracts version, thread ID, default auth plugin, and SSL capability.
    """
    info = {
        "version": "Unknown",
        "raw_version": "Unknown",
        "protocol": None,
        "thread_id": None,
        "auth_plugin": None,
        "ssl_supported": False,
        "status_flags": None,
    }
    if len(data) < 5:
        return info

    proto = data[4]
    info["protocol"] = proto

    # Error packet from server (e.g., Host is blocked or too many connections)
    if proto == 0xFF and len(data) >= 7:
        errno = data[5] | (data[6] << 8)
        msg = data[7:].decode("utf-8", errors="replace")
        info["error"] = f"MySQL Error {errno}: {msg}"
        return info

    if proto not in (9, 10):
        return info

    idx = data.find(b"\x00", 5)
    if idx == -1:
        return info

    raw_version = data[5:idx].decode("utf-8", errors="replace")
    version = raw_version
    # MariaDB often prepends 5.5.5- for replication compatibility
    if version.startswith("5.5.5-"):
        version = version[6:]

    info["raw_version"] = raw_version
    info["version"] = version

    pos = idx + 1
    # 4 bytes thread id (connection id)
    if len(data) >= pos + 4:
        info["thread_id"] = struct.unpack("<I", data[pos:pos+4])[0]
        pos += 4

    # 8 bytes auth_plugin_data_part_1
    pos += 8
    # 1 byte filler / filter (0x00)
    pos += 1

    # Capability flags (lower 2 bytes)
    if len(data) >= pos + 2:
        caps_low = struct.unpack("<H", data[pos:pos+2])[0]
        pos += 2
        # 1 byte character set / collation
        if len(data) >= pos + 1:
            info["charset_id"] = data[pos]
            pos += 1
        # 2 bytes status flags
        if len(data) >= pos + 2:
            info["status_flags"] = struct.unpack("<H", data[pos:pos+2])[0]
            pos += 2
        # 2 bytes capability flags (upper 2 bytes)
        if len(data) >= pos + 2:
            caps_high = struct.unpack("<H", data[pos:pos+2])[0]
            pos += 2
            caps = caps_low | (caps_high << 16)
            CLIENT_SSL = 0x00000800
            info["ssl_supported"] = bool(caps & CLIENT_SSL)

            tail = data[pos:]
            for plugin in [
                b"mysql_native_password",
                b"caching_sha2_password",
                b"sha256_password",
                b"mysql_clear_password",
            ]:
                if plugin in tail:
                    info["auth_plugin"] = plugin.decode("ascii")
                    break

    return info


def read_mysql_banner(host: str, port: int, timeout: float = PROBE_TIMEOUT) -> dict | None:
    """
    Connect to host:port via raw socket and receive the MySQL greeting packet.
    Returns parsed dictionary if valid MySQL handshake, or None.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(1024)
            if data and len(data) >= 5:
                parsed = parse_mysql_handshake(data)
                if parsed.get("version") and parsed["version"] != "Unknown":
                    return parsed
    except Exception:
        pass
    return None


def tcp_ping(host: str, port: int) -> bool:
    """Raw TCP connect check to see if port is listening."""
    try:
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT):
            return True
    except Exception:
        return False


def scan_mysql_port(host: str) -> tuple[int | None, dict | None]:
    """
    Try MYSQL_PORTS in order. Return (open_port, banner_dict or None).
    """
    console.print(
        f"\n[muted]Scanning common MySQL ports on[/muted] "
        f"[primary]{host}[/primary] "
        f"[muted](timeout {SCAN_TIMEOUT:.0f}s/port)…[/muted]"
    )
    for port in MYSQL_PORTS:
        try:
            with socket.create_connection((host, port), timeout=SCAN_TIMEOUT) as sock:
                sock.settimeout(SCAN_TIMEOUT)
                data = b""
                try:
                    data = sock.recv(1024)
                except Exception:
                    pass

                banner = parse_mysql_handshake(data) if data else None
                ver = banner.get("version") if banner else None
                if ver and ver != "Unknown":
                    console.print(f"  [success]✓ Port {port} is open — MySQL/MariaDB {ver}[/success]")
                else:
                    console.print(f"  [success]✓ Port {port} is open[/success]")
                return port, banner
        except (OSError, ConnectionRefusedError, TimeoutError):
            console.print(f"  [muted]  Port {port} — no response[/muted]")
    return None, None


def probe_mysql(host: str, port: int, initial_banner: dict | None = None) -> dict:
    """
    Probe the MySQL service to extract the exact server version and details.
    Uses initial socket banner first (guaranteed exact version directly from
    MySQL handshake greeting packet without authentication failure).
    Falls back to PyMySQL connect only if raw banner could not be read.
    """
    info = initial_banner or read_mysql_banner(host, port, timeout=PROBE_TIMEOUT) or {}
    if info.get("version") and info["version"] != "Unknown":
        info["reachable"] = True
        return info

    # Fallback to PyMySQL connect
    try:
        conn = pymysql.connect(
            host=host,
            port=port,
            user="",
            password="",
            connect_timeout=int(PROBE_TIMEOUT),
        )
        info["version"] = conn.get_server_info()
        conn.close()
        info["reachable"] = True
        return info

    except pymysql.err.OperationalError as exc:
        errno = exc.args[0]
        msg   = str(exc)

        # 1045 = Access denied, 1130 = Host not allowed
        # Both prove MySQL is running and communicating
        if errno in (1045, 1130):
            info["reachable"] = True
            info["auth_notice"] = msg
            m = re.search(r"(\d+\.\d+\.\d+[\w\.\-]*)", msg)
            if m:
                info["version"] = m.group(1)
            return info

        if errno in (2003, 2005, 2013):
            raise RuntimeError(
                f"Cannot reach MySQL at {host}:{port}\n"
                f"  Reason : {msg}\n"
                f"  Likely : firewall blocking port {port}, or MySQL not "
                f"bound to 0.0.0.0"
            )

        info["reachable"] = True
        return info

    except Exception as exc:
        raise RuntimeError(f"Cannot reach MySQL at {host}:{port}  ({exc})")


# ---------------------------------------------------------------------------
# FTP Scanning & Probing
# ---------------------------------------------------------------------------

def scan_ftp_port(host: str) -> tuple[int | None, str | None]:
    """
    Try FTP_PORTS in order. Return (open_port, banner_string or None).
    FTP servers send a 220 greeting banner immediately on connect.
    """
    console.print(
        f"\n[muted]Scanning common FTP ports on[/muted] "
        f"[primary]{host}[/primary] "
        f"[muted](timeout {SCAN_TIMEOUT:.0f}s/port)…[/muted]"
    )
    for port in FTP_PORTS:
        try:
            with socket.create_connection((host, port), timeout=SCAN_TIMEOUT) as sock:
                sock.settimeout(SCAN_TIMEOUT)
                data = b""
                try:
                    data = sock.recv(1024)
                except Exception:
                    pass

                banner = data.decode("utf-8", errors="replace").strip() if data else ""
                if banner:
                    console.print(f"  [success]✓ Port {port} is open — {banner[:60]}[/success]")
                else:
                    console.print(f"  [success]✓ Port {port} is open[/success]")
                return port, banner
        except (OSError, ConnectionRefusedError, TimeoutError):
            console.print(f"  [muted]  Port {port} — no response[/muted]")
    return None, None


def probe_ftp(host: str, port: int) -> dict:
    """
    Connect to FTP port and read the 220 greeting banner.
    Returns dict with version info.
    Raises RuntimeError if unreachable.
    """
    import ftplib
    info: dict = {}
    try:
        try:
            from modules.ftp_detect import detect_ftp_version
            f_res = detect_ftp_version(host, port, timeout=int(PROBE_TIMEOUT))
            if f_res.get("raw_ok") or (f_res.get("banner") and f_res.get("version") != "Unknown"):
                info["banner"] = f_res.get("banner", "")
                info["reachable"] = True
                info["version"] = f_res.get("version", "Unknown")
                info["software"] = f_res.get("product", "Unknown")
                # Test anonymous login
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(host, port, timeout=int(PROBE_TIMEOUT))
                    ftp.login("anonymous", "test@test.com")
                    info["anonymous_login"] = True
                    try:
                        ftp.quit()
                    except Exception:
                        ftp.close()
                except Exception:
                    info["anonymous_login"] = False
                return info
        except Exception:
            pass

        with socket.create_connection((host, port), timeout=PROBE_TIMEOUT) as sock:
            sock.settimeout(PROBE_TIMEOUT)
            data = sock.recv(1024)
            banner = data.decode("utf-8", errors="replace").strip() if data else ""
            info["banner"] = banner
            info["reachable"] = True

            # Extract version from banner like "220 (vsFTPd 3.0.5)" or "220 ProFTPD 1.3.8"
            m = re.search(r"(\d+\.\d+[\.\d]*)", banner)
            if m:
                info["version"] = m.group(1)
            else:
                info["version"] = "Unknown"

            # Try to identify the FTP server software
            banner_lower = banner.lower()
            if "vsftpd" in banner_lower:
                info["software"] = "vsFTPd"
            elif "proftpd" in banner_lower:
                info["software"] = "ProFTPD"
            elif "pure-ftpd" in banner_lower:
                info["software"] = "Pure-FTPd"
            elif "filezilla" in banner_lower:
                info["software"] = "FileZilla Server"
            elif "microsoft" in banner_lower or "iis" in banner_lower:
                info["software"] = "Microsoft IIS FTP"
            elif "wu-ftpd" in banner_lower:
                info["software"] = "WU-FTPD"
            else:
                info["software"] = "Unknown"

            # Check if anonymous login is allowed
            try:
                ftp = ftplib.FTP()
                ftp.connect(host, port, timeout=int(PROBE_TIMEOUT))
                ftp.login("anonymous", "test@test.com")
                info["anonymous_login"] = True
                try:
                    ftp.quit()
                except Exception:
                    ftp.close()
            except Exception:
                info["anonymous_login"] = False

            return info

    except Exception as exc:
        raise RuntimeError(f"Cannot reach FTP at {host}:{port}  ({exc})")


def _render_ftp_panel(info: TargetInfo) -> None:
    """Render server info panel for FTP targets."""
    terminal_width = shutil.get_terminal_size(fallback=(80, 24)).columns
    width = min(terminal_width, 100)

    content = Text(justify="left")
    content.append("  HOST        : ", style="muted")
    content.append(f"{info.host}\n", style="success")
    content.append("  PORT        : ", style="muted")
    content.append(f"{info.port}\n", style="primary")
    content.append("  SERVICE     : ", style="muted")
    content.append("FTP\n", style="primary")

    software = info.extra.get("software", "Unknown")
    content.append("  SOFTWARE    : ", style="muted")
    content.append(f"{software}\n", style="text")

    content.append("  VERSION     : ", style="muted")
    ver = info.version
    content.append(
        f"{ver}\n",
        style="bold success" if ver != "Unknown" else "warning",
    )

    banner = info.extra.get("banner", "")
    if banner:
        content.append("  BANNER      : ", style="muted")
        content.append(f"{banner[:70]}\n", style="text")

    anon = info.extra.get("anonymous_login")
    if anon is not None:
        content.append("  ANON LOGIN  : ", style="muted")
        if anon:
            content.append("ALLOWED ⚠\n", style="bold warning")
        else:
            content.append("DENIED\n", style="text")

    content.append("  STATUS      : ", style="muted")
    content.append("REACHABLE ✓", style="bold success")

    console.print(
        Panel(
            content,
            title="[bold primary]TARGET INFO & FTP RECON[/bold primary]",
            border_style="success",
            box=DOUBLE,
            padding=(1, 2),
            width=width,
        ),
        justify="center",
    )


def _render_target_panel(info: TargetInfo) -> None:
    terminal_width = shutil.get_terminal_size(fallback=(80, 24)).columns
    width = min(terminal_width, 100)

    content = Text(justify="left")
    content.append("  HOST        : ", style="muted")
    content.append(f"{info.host}\n", style="success")
    content.append("  PORT        : ", style="muted")
    content.append(f"{info.port}\n", style="primary")

    ver_display = info.version
    if "mariadb" in ver_display.lower():
        ver_text = ver_display
    elif ver_display != "Unknown":
        ver_text = f"MySQL {ver_display}" if not ver_display.lower().startswith("mysql") else ver_display
    else:
        ver_text = "Unknown"

    content.append("  VERSION     : ", style="muted")
    content.append(f"{ver_text}\n", style="bold success" if ver_display != "Unknown" else "warning")

    auth_plugin = info.extra.get("auth_plugin")
    if auth_plugin:
        content.append("  AUTH METHOD : ", style="muted")
        content.append(f"{auth_plugin}\n", style="text")

    thread_id = info.extra.get("thread_id")
    if thread_id is not None:
        content.append("  THREAD ID   : ", style="muted")
        content.append(f"{thread_id}\n", style="text")

    ssl = info.extra.get("ssl_supported")
    if ssl is not None:
        content.append("  SSL SUPPORT : ", style="muted")
        ssl_str = "YES" if ssl else "NO"
        content.append(f"{ssl_str}\n", style="text")

    content.append("  STATUS      : ", style="muted")
    content.append("REACHABLE ✓", style="bold success")

    console.print(
        Panel(
            content,
            title="[bold primary]TARGET INFO & SERVER RECON[/bold primary]",
            border_style="success",
            box=DOUBLE,
            padding=(1, 2),
            width=width,
        ),
        justify="center",
    )


def _render_skip_panel(host: str, port: int) -> None:
    """Panel shown when user skips the probe."""
    terminal_width = shutil.get_terminal_size(fallback=(80, 24)).columns
    width = min(terminal_width, 100)

    content = Text(justify="left")
    content.append("  HOST    : ", style="muted")
    content.append(f"{host}\n", style="success")
    content.append("  PORT    : ", style="muted")
    content.append(f"{port}\n", style="primary")
    content.append("  VERSION : ", style="muted")
    content.append("Unknown (probe skipped)\n", style="warning")
    content.append("  STATUS  : ", style="muted")
    content.append("ASSUMED REACHABLE", style="bold warning")

    console.print(
        Panel(
            content,
            title="[bold primary]TARGET INFO[/bold primary]",
            border_style="warning",
            box=DOUBLE,
            padding=(1, 2),
            width=width,
        ),
        justify="center",
    )


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def _run_mysql_setup(host: str, port_str: str) -> TargetInfo | None:
    """MySQL-specific target setup. Returns TargetInfo or None to retry."""
    banner = None
    if port_str == "":
        port, banner = scan_mysql_port(host)
        if port is None:
            console.print(
                f"\n[error]No open MySQL port found on {host}.[/error]\n"
                f"[muted]  → Make sure the server allows external "
                f"connections and MySQL is bound to 0.0.0.0[/muted]\n"
            )
            return None
    else:
        port = int(port_str)
        console.print(
            f"\n[muted]Testing TCP connectivity to[/muted] "
            f"[primary]{host}:{port}[/primary]…"
        )
        if not tcp_ping(host, port):
            console.print(
                f"[error]✗ TCP connection refused or timed out.[/error]\n"
                f"[muted]  Port {port} is not reachable from this machine.\n"
                f"  Possible causes:\n"
                f"    • Firewall blocking port {port}\n"
                f"    • Service bound to 127.0.0.1 only\n"
                f"    • Wrong IP address\n"
                f"    • VPN / SSH tunnel required[/muted]\n"
            )
            skip = ask_input("Skip probe and try attacks anyway? (yes/no)", "no").lower()
            if skip in ("yes", "y"):
                _render_skip_panel(host, port)
                return TargetInfo(host=host, port=port, version="Unknown", service="mysql")
            return None
        console.print(f"  [success]✓ TCP port {port} is open[/success]")

    console.print(f"[muted]Probing MySQL details at[/muted] [primary]{host}:{port}[/primary]…")
    try:
        info = probe_mysql(host, port, initial_banner=banner)
    except RuntimeError as exc:
        console.print(f"\n[error]{exc}[/error]\n")
        skip = ask_input("Skip probe and try attacks anyway? (yes/no)", "no").lower()
        if skip in ("yes", "y"):
            _render_skip_panel(host, port)
            return TargetInfo(host=host, port=port, version="Unknown", service="mysql")
        return None

    target = TargetInfo(
        host=host, port=port,
        version=info.get("version", "Unknown"),
        service="mysql", extra=info,
    )
    _render_target_panel(target)
    return target


def _run_ftp_setup(host: str, port_str: str) -> TargetInfo | None:
    """FTP-specific target setup. Returns TargetInfo or None to retry."""
    if port_str == "":
        port, banner_str = scan_ftp_port(host)
        if port is None:
            console.print(
                f"\n[error]No open FTP port found on {host}.[/error]\n"
                f"[muted]  → Make sure the FTP server is running and allows "
                f"external connections[/muted]\n"
            )
            return None
    else:
        port = int(port_str)
        console.print(
            f"\n[muted]Testing TCP connectivity to[/muted] "
            f"[primary]{host}:{port}[/primary]…"
        )
        if not tcp_ping(host, port):
            console.print(
                f"[error]✗ TCP connection refused or timed out.[/error]\n"
                f"[muted]  Port {port} is not reachable.[/muted]\n"
            )
            skip = ask_input("Skip probe and try attacks anyway? (yes/no)", "no").lower()
            if skip in ("yes", "y"):
                _render_skip_panel(host, port)
                return TargetInfo(host=host, port=port, version="Unknown", service="ftp")
            return None
        console.print(f"  [success]✓ TCP port {port} is open[/success]")

    console.print(f"[muted]Probing FTP details at[/muted] [primary]{host}:{port}[/primary]…")
    try:
        info = probe_ftp(host, port)
    except RuntimeError as exc:
        console.print(f"\n[error]{exc}[/error]\n")
        skip = ask_input("Skip probe and try attacks anyway? (yes/no)", "no").lower()
        if skip in ("yes", "y"):
            _render_skip_panel(host, port)
            return TargetInfo(host=host, port=port, version="Unknown", service="ftp")
        return None

    target = TargetInfo(
        host=host, port=port,
        version=info.get("version", "Unknown"),
        service="ftp", extra=info,
    )
    _render_ftp_panel(target)
    return target


def run_target_setup(service: str = "mysql") -> TargetInfo | list[TargetInfo]:
    """
    Interactive target setup flow.
    service: "mysql", "ftp", or "hybrid"

    For hybrid mode, runs both MySQL and FTP probes on the same host and
    returns a list of TargetInfo objects (one per reachable service).
    For single-service, returns a single TargetInfo.
    """
    console.print("\n[bold primary][ TARGET SETUP ][/bold primary]\n")

    while True:
        host = ask_input("Target IP / hostname", "localhost")
        port_str = ask_input("Port (leave blank to auto-detect)", "")

        if port_str != "" and not port_str.isdigit():
            console.print("[warning]Port must be a number.[/warning]")
            continue

        if service == "mysql":
            result = _run_mysql_setup(host, port_str)
            if result:
                return result
            continue

        elif service == "ftp":
            result = _run_ftp_setup(host, port_str)
            if result:
                return result
            continue

        elif service == "hybrid":
            console.print(
                "\n[bold secondary][ HYBRID MODE — scanning both MySQL & FTP ][/bold secondary]\n"
            )
            targets: list[TargetInfo] = []

            # MySQL scan
            console.print("[bold primary]— MySQL —[/bold primary]")
            mysql_result = _run_mysql_setup(host, "")
            if mysql_result:
                targets.append(mysql_result)
            else:
                console.print("[muted]  MySQL not reachable, skipping.[/muted]")

            # FTP scan
            console.print("\n[bold primary]— FTP —[/bold primary]")
            ftp_result = _run_ftp_setup(host, "")
            if ftp_result:
                targets.append(ftp_result)
            else:
                console.print("[muted]  FTP not reachable, skipping.[/muted]")

            if not targets:
                console.print(
                    f"\n[error]No reachable services found on {host}.[/error]\n"
                )
                continue

            return targets
