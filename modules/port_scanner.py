"""
Unified Port Scanner & Service Detector
Scans MySQL/FTP/HTTP/HTTPS/SMTP/SSH ports, grabs banners, returns TargetInfo list.
"""
import re
import shutil
import socket

from rich.panel import Panel
from rich.text import Text
from rich.box import DOUBLE

from Design.colors_cli import console
from modules.target import TargetInfo, parse_mysql_handshake, tcp_ping, SCAN_TIMEOUT


SERVICE_PORTS: dict[str, list[int]] = {
    "mysql":         [3306, 3307, 33060, 33061],
    "ftp":           [21, 2121, 990],
    "http":          [80, 8080, 8000, 8888],
    "https":         [443, 8443],
    "smtp":          [25, 465, 587, 2525],
    "ssh":           [22, 2222],
    "redis":         [6379, 6380],
    "mongodb":       [27017, 27018],
    "postgres":      [5432],
    "mssql":         [1433],
    "elasticsearch": [9200, 9300],
    "memcached":     [11211],
    "vnc":           [5900, 5901],
    "rdp":           [3389],
    "telnet":        [23],
    "ldap":          [389, 636],
    "docker":        [2375, 2376],
    "kubernetes":    [6443, 10250],
}

SERVICE_LABEL = {
    "mysql":         "MySQL / MariaDB",
    "ftp":           "FTP",
    "http":          "HTTP",
    "https":         "HTTPS",
    "smtp":          "SMTP",
    "ssh":           "SSH",
    "redis":         "Redis",
    "mongodb":       "MongoDB",
    "postgres":      "PostgreSQL",
    "mssql":         "MSSQL / SQL Server",
    "elasticsearch": "Elasticsearch",
    "memcached":     "Memcached",
    "vnc":           "VNC",
    "rdp":           "RDP",
    "telnet":        "Telnet",
    "ldap":          "LDAP",
    "docker":        "Docker API",
    "kubernetes":    "Kubernetes API",
}


def _grab(host: str, port: int, timeout: float = SCAN_TIMEOUT) -> bytes:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                return s.recv(1024)
            except Exception:
                return b""
    except Exception:
        return b""


def _probe_mysql(host, port):
    data = _grab(host, port)
    return parse_mysql_handshake(data) if data else {"version": "Unknown"}


def _probe_ftp(host, port):
    try:
        from modules.ftp_detect import detect_ftp_version
        res = detect_ftp_version(host, port, timeout=6)
        if res.get("raw_ok") or (res.get("banner") and res.get("version") != "Unknown"):
            return {
                "banner": res.get("banner", ""),
                "software": res.get("product", "Unknown"),
                "version": res.get("version", "Unknown"),
            }
    except Exception:
        pass

    # Fallback to direct raw socket read with 6.0s timeout
    data = _grab(host, port, timeout=6.0)
    banner = data.decode("utf-8", errors="replace").strip() if data else ""
    info = {"banner": banner, "software": "Unknown", "version": "Unknown"}
    m = re.search(r"(\d+\.\d+[\.\d]*)", banner)
    if m:
        info["version"] = m.group(1)
    bl = banner.lower()
    for sig, name in (
        ("vsftpd", "vsFTPd"), ("proftpd", "ProFTPD"),
        ("pure-ftpd", "Pure-FTPd"), ("filezilla", "FileZilla"),
        ("microsoft", "MS IIS FTP"), ("iis", "MS IIS FTP"),
        ("wu-ftpd", "WU-FTPD"),
    ):
        if sig in bl:
            info["software"] = name
            break
    return info


def _probe_http(host, port, use_tls=False):
    """Send HEAD and grab Server header. Uses raw socket; for HTTPS use ssl."""
    try:
        if use_tls:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = socket.create_connection((host, port), timeout=SCAN_TIMEOUT)
            sock = ctx.wrap_socket(raw, server_hostname=host)
        else:
            sock = socket.create_connection((host, port), timeout=SCAN_TIMEOUT)
        sock.settimeout(SCAN_TIMEOUT)
        req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        sock.sendall(req.encode())
        data = b""
        try:
            while len(data) < 4096:
                c = sock.recv(4096)
                if not c:
                    break
                data += c
        except Exception:
            pass
        sock.close()
        text = data.decode("utf-8", errors="replace")
        server = ""
        status = ""
        for line in text.split("\r\n"):
            low = line.lower()
            if low.startswith("server:"):
                server = line.split(":", 1)[1].strip()
            elif line.startswith("HTTP/"):
                status = line.strip()
        return {"banner": text[:300], "server": server, "status": status,
                "version": server or "Unknown"}
    except Exception:
        return {"banner": "", "server": "", "version": "Unknown"}


def _probe_smtp(host, port):
    data = _grab(host, port)
    banner = data.decode("utf-8", errors="replace").strip() if data else ""
    info = {"banner": banner, "software": "Unknown", "version": "Unknown"}
    m = re.search(r"(\d+\.\d+[\.\d]*)", banner)
    if m:
        info["version"] = m.group(1)
    bl = banner.lower()
    for sig, name in (
        ("postfix", "Postfix"), ("exim", "Exim"),
        ("sendmail", "Sendmail"), ("microsoft", "MS Exchange"),
        ("exchange", "MS Exchange"), ("qmail", "Qmail"),
    ):
        if sig in bl:
            info["software"] = name
            break
    return info


def _probe_ssh(host, port):
    data = _grab(host, port)
    banner = data.decode("utf-8", errors="replace").strip() if data else ""
    info = {"banner": banner, "software": "Unknown", "version": "Unknown"}
    m = re.search(r"SSH-[\d\.]+-(\S+)", banner)
    if m:
        info["software"] = m.group(1).split("_")[0]
        vm = re.search(r"_([\d\.]+)", banner)
        if vm:
            info["version"] = vm.group(1)
    return info


def _probe_redis(host, port):
    """Send PING and INFO server to Redis."""
    try:
        with socket.create_connection((host, port), timeout=SCAN_TIMEOUT) as s:
            s.settimeout(SCAN_TIMEOUT)
            s.sendall(b"*1\r\n$4\r\nPING\r\n")
            resp = s.recv(256)
            if b"PONG" not in resp and b"+PONG" not in resp:
                return {"version": "Unknown", "banner": ""}
            s.sendall(b"*1\r\n$4\r\nINFO\r\n")
            info_raw = b""
            try:
                while len(info_raw) < 4096:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    info_raw += chunk
            except Exception:
                pass
        text = info_raw.decode("utf-8", errors="replace")
        ver = "Unknown"
        m = re.search(r"redis_version:([\d\.]+)", text)
        if m:
            ver = m.group(1)
        return {"version": ver, "banner": text[:200]}
    except Exception:
        return {"version": "Unknown", "banner": ""}


def _probe_mongodb(host, port):
    """Send MongoDB isMaster wire-protocol message."""
    try:
        # Minimal OP_QUERY for isMaster
        import struct
        body = (
            b"\x01\x00\x00\x00"   # flags
            b"admin.$cmd\x00"      # collection name
            b"\x00\x00\x00\x00"   # skip
            b"\x01\x00\x00\x00"   # return 1
        )
        # BSON: {isMaster:1}
        bson_doc = b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"
        payload = body + bson_doc
        # MsgHeader: totalLen, reqId, respTo, opCode=2004
        header = struct.pack("<iiii", 16 + len(payload), 1, 0, 2004)
        msg = header + payload
        with socket.create_connection((host, port), timeout=SCAN_TIMEOUT) as s:
            s.settimeout(SCAN_TIMEOUT)
            s.sendall(msg)
            resp = s.recv(1024)
        if resp:
            return {"version": "Unknown", "banner": f"MongoDB open ({len(resp)} bytes)"}
        return {"version": "Unknown", "banner": ""}
    except Exception:
        return {"version": "Unknown", "banner": ""}


def _probe_postgres(host, port):
    """Send PostgreSQL StartupMessage and read auth response."""
    try:
        import struct
        # StartupMessage: len(4) + proto(4) + "user\0postgres\0\0"
        params = b"user\x00postgres\x00database\x00postgres\x00\x00"
        proto = struct.pack(">I", 196608)  # 3.0
        length = struct.pack(">I", 4 + 4 + len(params))
        with socket.create_connection((host, port), timeout=SCAN_TIMEOUT) as s:
            s.settimeout(SCAN_TIMEOUT)
            s.sendall(length + proto + params)
            resp = s.recv(256)
        if resp:
            if resp[0:1] == b"R":
                auth_type = int.from_bytes(resp[5:9], "big")
                ver = "auth_required" if auth_type != 0 else "no_auth"
                return {"version": ver, "banner": resp[:20].hex()}
        return {"version": "Unknown", "banner": ""}
    except Exception:
        return {"version": "Unknown", "banner": ""}


def _probe_mssql(host, port):
    """Send TDS pre-login packet and parse version bytes."""
    try:
        # Minimal TDS pre-login
        prelogin = bytes([
            0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x1a, 0x00, 0x06, 0x01, 0x00, 0x20, 0x00,
            0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03, 0x00,
            0x22, 0x00, 0x04, 0x04, 0x00, 0x26, 0x00, 0x01,
            0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        with socket.create_connection((host, port), timeout=SCAN_TIMEOUT) as s:
            s.settimeout(SCAN_TIMEOUT)
            s.sendall(prelogin)
            resp = s.recv(256)
        if resp and len(resp) >= 6:
            ver = f"{resp[3]}.{resp[4]}.{resp[5]}"
            return {"version": ver, "banner": resp[:16].hex()}
        return {"version": "Unknown", "banner": ""}
    except Exception:
        return {"version": "Unknown", "banner": ""}


def _probe_memcached(host, port):
    """Send stats command to Memcached."""
    try:
        with socket.create_connection((host, port), timeout=SCAN_TIMEOUT) as s:
            s.settimeout(SCAN_TIMEOUT)
            s.sendall(b"stats\r\n")
            resp = s.recv(1024).decode("utf-8", errors="replace")
        ver = "Unknown"
        m = re.search(r"STAT version ([\d\.]+)", resp)
        if m:
            ver = m.group(1)
        return {"version": ver, "banner": resp[:200]}
    except Exception:
        return {"version": "Unknown", "banner": ""}


def _probe_elasticsearch(host, port):
    """HTTP GET / to Elasticsearch."""
    try:
        with socket.create_connection((host, port), timeout=SCAN_TIMEOUT) as s:
            s.settimeout(SCAN_TIMEOUT)
            req = f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode())
            resp = b""
            while len(resp) < 2048:
                chunk = s.recv(2048)
                if not chunk:
                    break
                resp += chunk
        text = resp.decode("utf-8", errors="replace")
        ver = "Unknown"
        m = re.search(r'"number"\s*:\s*"([\d\.]+)"', text)
        if m:
            ver = m.group(1)
        return {"version": ver, "banner": text[:200]}
    except Exception:
        return {"version": "Unknown", "banner": ""}


def _probe_vnc(host, port):
    """Read RFB banner from VNC."""
    data = _grab(host, port)
    banner = data.decode("utf-8", errors="replace").strip() if data else ""
    ver = "Unknown"
    m = re.search(r"RFB ([\d\.]+)", banner)
    if m:
        ver = m.group(1)
    return {"version": ver, "banner": banner}


def _probe_docker(host, port):
    """HTTP GET /version to Docker daemon API."""
    try:
        with socket.create_connection((host, port), timeout=SCAN_TIMEOUT) as s:
            s.settimeout(SCAN_TIMEOUT)
            req = f"GET /version HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode())
            resp = b""
            while len(resp) < 2048:
                chunk = s.recv(2048)
                if not chunk:
                    break
                resp += chunk
        text = resp.decode("utf-8", errors="replace")
        ver = "Unknown"
        m = re.search(r'"Version"\s*:\s*"([^"]+)"', text)
        if m:
            ver = m.group(1)
        return {"version": ver, "banner": text[:200]}
    except Exception:
        return {"version": "Unknown", "banner": ""}


def _probe_kubernetes(host, port):
    """HTTPS GET /version to Kubernetes API server."""
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=SCAN_TIMEOUT)
        s = ctx.wrap_socket(raw, server_hostname=host)
        s.settimeout(SCAN_TIMEOUT)
        req = f"GET /version HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode())
        resp = b""
        while len(resp) < 2048:
            chunk = s.recv(2048)
            if not chunk:
                break
            resp += chunk
        s.close()
        text = resp.decode("utf-8", errors="replace")
        ver = "Unknown"
        m = re.search(r'"gitVersion"\s*:\s*"([^"]+)"', text)
        if m:
            ver = m.group(1)
        return {"version": ver, "banner": text[:200]}
    except Exception:
        return {"version": "Unknown", "banner": ""}


def _probe_ldap(host, port):
    """Anonymous LDAP bind — check if port speaks LDAP."""
    try:
        # Minimal LDAP BindRequest (anonymous)
        bind_req = bytes([
            0x30, 0x0c,                    # SEQUENCE
            0x02, 0x01, 0x01,              # messageID = 1
            0x60, 0x07,                    # BindRequest
            0x02, 0x01, 0x03,              # version = 3
            0x04, 0x00,                    # name = ""
            0x80, 0x00,                    # simple auth = ""
        ])
        with socket.create_connection((host, port), timeout=SCAN_TIMEOUT) as s:
            s.settimeout(SCAN_TIMEOUT)
            s.sendall(bind_req)
            resp = s.recv(256)
        if resp:
            return {"version": "LDAP", "banner": resp[:20].hex()}
        return {"version": "Unknown", "banner": ""}
    except Exception:
        return {"version": "Unknown", "banner": ""}


def _probe_telnet(host, port):
    """Read Telnet banner."""
    data = _grab(host, port)
    banner = data.decode("utf-8", errors="replace").strip() if data else ""
    ver = "Telnet" if data else "Unknown"
    return {"version": ver, "banner": banner[:100]}


def scan_service(host: str, service: str) -> TargetInfo | None:
    ports = SERVICE_PORTS.get(service, [])
    console.print(
        f"\n[muted]Scanning[/muted] [primary]{SERVICE_LABEL.get(service, service.upper())}[/primary] "
        f"[muted]on[/muted] [primary]{host}[/primary] "
        f"[muted]({len(ports)} port(s))…[/muted]"
    )
    for port in ports:
        if not tcp_ping(host, port):
            console.print(f"  [muted]  Port {port} — no response[/muted]")
            continue

        if service == "mysql":
            info = _probe_mysql(host, port)
        elif service == "ftp":
            info = _probe_ftp(host, port)
        elif service == "http":
            info = _probe_http(host, port, use_tls=False)
        elif service == "https":
            info = _probe_http(host, port, use_tls=True)
        elif service == "smtp":
            info = _probe_smtp(host, port)
        elif service == "ssh":
            info = _probe_ssh(host, port)
        elif service == "redis":
            info = _probe_redis(host, port)
        elif service == "mongodb":
            info = _probe_mongodb(host, port)
        elif service == "postgres":
            info = _probe_postgres(host, port)
        elif service == "mssql":
            info = _probe_mssql(host, port)
        elif service == "elasticsearch":
            info = _probe_elasticsearch(host, port)
        elif service == "memcached":
            info = _probe_memcached(host, port)
        elif service == "vnc":
            info = _probe_vnc(host, port)
        elif service == "docker":
            info = _probe_docker(host, port)
        elif service == "kubernetes":
            info = _probe_kubernetes(host, port)
        elif service == "ldap":
            info = _probe_ldap(host, port)
        elif service == "telnet":
            info = _probe_telnet(host, port)
        else:
            info = {"version": "Unknown"}

        ver = info.get("version", "Unknown")
        label = SERVICE_LABEL.get(service, service.upper())
        if ver and ver != "Unknown":
            label += f" {ver}"
        console.print(f"  [success]✓ Port {port} — {label}[/success]")

        return TargetInfo(
            host=host, port=port, version=ver, service=service, extra=info,
        )
    return None


def scan_target(host: str, services: list[str] | None = None) -> list[TargetInfo]:
    services = services or list(SERVICE_PORTS.keys())
    out: list[TargetInfo] = []
    try:
        for svc in services:
            t = scan_service(host, svc)
            if t:
                out.append(t)
    except KeyboardInterrupt:
        console.print("\n[warning]  Port scan stopped by user.[/warning]")
    return out


def render_scan_summary(host: str, targets: list[TargetInfo]) -> None:
    w = min(shutil.get_terminal_size(fallback=(80, 24)).columns, 100)
    content = Text(justify="left")
    content.append("  HOST : ", style="muted")
    content.append(f"{host}\n\n", style="success")

    if not targets:
        content.append("  [error]No services detected.[/error]")
    else:
        for t in targets:
            content.append("  ✓ ", style="success")
            content.append(f"{t.service.upper():<7}", style="primary")
            content.append("  port ", style="muted")
            content.append(f"{t.port:<6}", style="text")
            content.append(f"  v{t.version}\n", style="text")

    console.print(
        Panel(
            content,
            title="[bold primary]SCAN RESULTS[/bold primary]",
            border_style="primary", box=DOUBLE, padding=(1, 2), width=w,
        ),
        justify="center",
    )