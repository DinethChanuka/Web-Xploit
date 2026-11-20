"""
Flask server that serves the red hacker UI and exposes the Web-Xploit
modules through small JSON endpoints + an SSE terminal stream.
"""
import json
import os
import queue
import re
import sys
import threading
import time
import traceback
import types
import webbrowser

_BASE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_BASE)

if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
if _BASE not in sys.path:
    sys.path.insert(0, _BASE)

if "web_gui" not in sys.modules:
    pkg = types.ModuleType("web_gui")
    pkg.__path__ = [_BASE]
    pkg.__file__ = os.path.join(_BASE, "__init__.py")
    sys.modules["web_gui"] = pkg

try:
    from web_gui import runner
except ImportError:
    import runner

from flask import Flask, Response, jsonify, render_template, request, send_from_directory


# ------------------------------------------------------------------ factory
def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=os.path.join(_BASE, "templates"),
        static_folder=os.path.join(_BASE, "static"),
        static_url_path="/static",
    )
    app.config["JSON_SORT_KEYS"] = False

    # Also support /web-gui/static and /static for legacy/direct asset links
    @app.route("/static/<path:filename>")
    @app.route("/web-gui/static/<path:filename>")
    def serve_static(filename):
        resp = send_from_directory(os.path.join(_BASE, "static"), filename)
        resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return resp

    @app.route("/style.css")
    def serve_root_style():
        resp = send_from_directory(os.path.join(_BASE, "static"), "style.css", mimetype="text/css")
        resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return resp

    @app.route("/app.js")
    @app.route("/cyber_core.js")
    def serve_root_js():
        resp = send_from_directory(os.path.join(_BASE, "static"), "app.js", mimetype="application/javascript")
        resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return resp

    # ------------------------------------------------------------- pages
    @app.route("/")
    def index() -> str:
        return render_template("index.html")

    # ------------------------------------------------- SSE terminal stream
    @app.route("/stream")
    def stream() -> Response:
        sub_queue = runner.register_subscriber()

        def generate():
            try:
                # Immediate initial packet
                yield f"data: {json.dumps({'type': 'log', 'line': '[✓] Live event stream connected', 'level': 'system'})}\n\n"
                while True:
                    try:
                        msg = sub_queue.get(timeout=1.5)
                        yield f"data: {json.dumps(msg)}\n\n"
                    except queue.Empty:
                        yield ": keepalive\n\n"
            except GeneratorExit:
                pass
            finally:
                runner.unregister_subscriber(sub_queue)

        return Response(
            generate(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    # ------------------------------------------------------- system info
    @app.route("/api/system_info", methods=["GET"])
    def api_system_info():
        try:
            from Design.header import BANNER
            from modules.jsonreader import read_app_data
            data = read_app_data()
        except Exception:
            BANNER = "WEB-XPLOIT v2.0"
            data = {"version": "2.0.0", "author": "Mikey", "last_updated_at": "2026-11-19"}

        return jsonify({
            "banner": BANNER.strip("\n"),
            "author": data.get("author", "Mikey"),
            "version": data.get("version", "2.0.0"),
            "last_updated": data.get("last_updated_at", "2026-11-19"),
            "module_count": 63,
            "status": "ONLINE",
        })

    # ----------------------------------------------------------- scan API
    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        data = request.get_json(silent=True) or {}
        host = (data.get("host") or "").strip()
        services = data.get("services") or None
        if not host:
            return jsonify({"error": "host required"}), 400

        def _work() -> None:
            from modules.port_scanner import scan_target, render_scan_summary
            from modules.origin_ip import is_cdn_ip
            import socket

            runner.emit(f"[scan] Probing target {host} ...", "info")

            # Check if domain is behind CDN
            is_cdn = False
            try:
                resolved_ips = [info[4][0] for info in socket.getaddrinfo(host, None)]
                cdn_hits = [ip for ip in resolved_ips if is_cdn_ip(ip)]
                if cdn_hits:
                    is_cdn = True
                    runner.emit(
                        f"[!] Notice: '{host}' resolved to CDN/Cloudflare IP ({', '.join(cdn_hits[:2])})",
                        "warning",
                    )
                    runner.emit("    Use the CDN Bypass / Origin tab to discover backend server IP.", "warning")
            except Exception:
                pass

            targets = scan_target(host, services)
            try:
                render_scan_summary(host, targets)
            except Exception:
                pass

            runner.push_result(
                "scan",
                {
                    "host": host,
                    "is_cdn": is_cdn,
                    "targets": [
                        {
                            "host": t.host,
                            "port": t.port,
                            "service": t.service,
                            "version": t.version,
                        }
                        for t in targets
                    ],
                },
            )

        runner.run_in_thread(_work, kind="scan")
        return jsonify({"status": "started"})

    # -------------------------------------------------------- attacks API
    @app.route("/api/attacks", methods=["POST"])
    def api_attacks():
        data = request.get_json(silent=True) or {}
        service = (data.get("service") or "").strip().lower()
        try:
            from modules.attack_registry import get_attacks, get_label
            items = [
                {"value": a.value, "label": get_label(a)}
                for a in get_attacks(service)
            ]
            return jsonify({"service": service, "attacks": items})
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    # ---------------------------------------------------- all attacks API
    @app.route("/api/all_attacks", methods=["GET"])
    def api_all_attacks():
        try:
            from modules.attack_menu import AttackType
            from modules.attack_registry import ATTACK_LABELS, get_label
            from modules.attacks.full_auto import _ATTACK_BRIEF

            categories = {
                "auto": {
                    "title": "★ Automated Exploitation",
                    "items": [AttackType.FULL_AUTO, AttackType.AUTO_PWN],
                },
                "web": {
                    "title": "🌐 Web & API Vulnerabilities",
                    "items": [
                        AttackType.WEB_SQLI_EXTRACT, AttackType.WEB_LFI_RCE, AttackType.WEB_SSTI,
                        AttackType.WEB_SSRF, AttackType.WEB_XXE, AttackType.WEB_SHELL_UPLOAD,
                        AttackType.WEB_DESER, AttackType.WEB_OPEN_REDIRECT, AttackType.WEB_HOST_HEADER,
                        AttackType.WEB_SMUGGLING, AttackType.WEB_CACHE_POISON, AttackType.WEB_CSRF,
                        AttackType.WEB_WP_SCANNER, AttackType.WEB_API_SCAN, AttackType.WEB_SECRETS_SCAN,
                        AttackType.WEB_GRAPHQL, AttackType.HTTP_SCANNER, AttackType.DIR_MAP,
                        AttackType.EXPLOIT_UPLOAD, AttackType.SSL_SCAN,
                    ],
                },
                "auth": {
                    "title": "🔐 Authentication & Credentials",
                    "items": [
                        AttackType.WEB_AUTH_BYPASS, AttackType.WEB_JWT_ATTACK,
                        AttackType.WEB_PHP_TYPE_JUGGLING, AttackType.WEB_NOSQL_INJECTION,
                        AttackType.BRUTEFORCE, AttackType.DICTIONARY, AttackType.WORDLIST,
                        AttackType.HTTP_BRUTEFORCE, AttackType.CRED_SNIFFER,
                    ],
                },
                "db": {
                    "title": "🗄 Database Penetration",
                    "items": [
                        AttackType.MYSQL_EXPLOIT, AttackType.MYSQL_UDF, AttackType.MYSQL_BACKDOOR,
                        AttackType.MYSQL_AUTH_BYPASS, AttackType.CONFIG_ENUM, AttackType.REDIS_SCAN,
                        AttackType.REDIS_RCE, AttackType.MONGO_ENUM, AttackType.POSTGRES_SCAN,
                        AttackType.MSSQL_SCAN,
                    ],
                },
                "infra": {
                    "title": "📡 Network & Infrastructure",
                    "items": [
                        AttackType.VULN_SCAN, AttackType.FTP_ANON, AttackType.FTP_BOUNCE,
                        AttackType.FTP_PROFTPD_MODCOPY, AttackType.FTP_VSFTPD_BACKDOOR,
                        AttackType.FTP_WEBSHELL, AttackType.SSH_BRUTEFORCE, AttackType.SSH_SCANNER,
                        AttackType.SSH_KEY_BACKDOOR, AttackType.SSH_USER_ENUM,
                        AttackType.SMTP_ENUM, AttackType.SMTP_BRUTEFORCE, AttackType.SMTP_RELAY,
                        AttackType.SMTP_SPOOF_CHAIN, AttackType.SMTP_HEADER_INJECTION,
                        AttackType.DOCKER_ESCAPE, AttackType.KUBE_SECRETS, AttackType.ELASTIC_DUMP,
                        AttackType.MEMCACHED_DUMP, AttackType.VNC_SCAN, AttackType.LDAP_ENUM,
                        AttackType.TELNET_BRUTE,
                    ],
                },
            }

            def _get_severity(atk_val):
                val = str(atk_val).lower()
                if any(k in val for k in ('rce', 'sqli', 'udf', 'backdoor', 'shell', 'escape', 'deser', 'pwn', 'full_auto')):
                    return 'Critical'
                if any(k in val for k in ('bypass', 'lfi', 'ssti', 'ssrf', 'xxe', 'jwt', 'brute', 'dump', 'secrets')):
                    return 'High'
                if any(k in val for k in ('scan', 'enum', 'redirect', 'csrf', 'poison', 'smuggling')):
                    return 'Medium'
                return 'Info'

            result = {}
            for cat_id, cat_info in categories.items():
                items_list = []
                for atk in cat_info["items"]:
                    items_list.append({
                        "id": atk.value,
                        "value": atk.value,
                        "name": get_label(atk),
                        "label": get_label(atk),
                        "desc": _ATTACK_BRIEF.get(atk, "Advanced pentesting payload module."),
                        "brief": _ATTACK_BRIEF.get(atk, "Advanced pentesting payload module."),
                        "severity": _get_severity(atk.value),
                    })
                result[cat_id] = {
                    "title": cat_info["title"],
                    "attacks": items_list,
                    "items": items_list,
                }

            return jsonify({"categories": result, "total": len(AttackType)})
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    # ---------------------------------------------------- wordlists API
    @app.route("/api/wordlists", methods=["GET"])
    def api_wordlists():
        wl_dir = os.path.join(_REPO_ROOT, "wordlists")
        lists = []
        if os.path.isdir(wl_dir):
            for f in sorted(os.listdir(wl_dir)):
                p = os.path.join(wl_dir, f)
                if os.path.isfile(p) and not f.startswith("."):
                    lists.append({"name": f, "path": p, "size": os.path.getsize(p)})
        return jsonify({"wordlists": lists})

    # -------------------------------------------------- downloads & artifacts API
    @app.route("/api/downloads", methods=["GET"])
    def api_downloads():
        from modules.downloads import DEFAULT_DOWNLOAD_DIR
        result = {}
        if os.path.isdir(DEFAULT_DOWNLOAD_DIR):
            for host in sorted(os.listdir(DEFAULT_DOWNLOAD_DIR)):
                hpath = os.path.join(DEFAULT_DOWNLOAD_DIR, host)
                if not os.path.isdir(hpath) or host.startswith("."):
                    continue
                files = []
                for root, _, fnames in os.walk(hpath):
                    for fname in sorted(fnames):
                        if fname.startswith("."):
                            continue
                        fpath = os.path.join(root, fname)
                        rel = os.path.relpath(fpath, DEFAULT_DOWNLOAD_DIR)
                        subdir = os.path.relpath(root, hpath)
                        files.append({
                            "name": fname,
                            "path": rel,
                            "subdir": "" if subdir == "." else subdir,
                            "size": os.path.getsize(fpath),
                            "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(fpath))),
                        })
                result[host] = files
        return jsonify({"downloads": result, "total_hosts": len(result)})

    @app.route("/api/file_content", methods=["GET"])
    def api_file_content():
        from modules.downloads import DEFAULT_DOWNLOAD_DIR
        import gzip, string, re
        rel_path = request.args.get("path", "").strip()
        if not rel_path or ".." in rel_path:
            return jsonify({"error": "invalid path"}), 400
        full_path = os.path.join(DEFAULT_DOWNLOAD_DIR, rel_path)
        if not os.path.isfile(full_path):
            return jsonify({"error": "file not found"}), 404

        try:
            with open(full_path, "rb") as f:
                raw = f.read(500000)

            text = None
            if not raw.startswith(b"\x1f\x8b") and not raw.startswith(b"\x1f\xef\xbf\xbd"):
                try:
                    decoded = raw.decode("utf-8")
                    if "\x00" not in decoded:
                        text = decoded
                except UnicodeDecodeError:
                    pass

            if text is None and raw.startswith(b"\x1f\x8b"):
                try:
                    text = gzip.decompress(raw).decode("utf-8", "replace")
                except Exception:
                    pass

            if text is None:
                printable = set(bytes(string.printable, "ascii"))
                cleaned = [chr(b) if b in printable or b in (10, 13, 9) else " " for b in raw]
                text = re.sub(r" {3,}", "  ", "".join(cleaned)).strip()
                if not text:
                    text = "[Binary or Empty Payload]"

            return jsonify({
                "path": rel_path,
                "name": os.path.basename(full_path),
                "size": os.path.getsize(full_path),
                "content": text,
            })
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/download_raw", methods=["GET"])
    def api_download_raw():
        from modules.downloads import DEFAULT_DOWNLOAD_DIR
        rel_path = request.args.get("path", "").strip()
        if not rel_path or ".." in rel_path:
            return jsonify({"error": "invalid path"}), 400
        full_path = os.path.join(DEFAULT_DOWNLOAD_DIR, rel_path)
        if not os.path.isfile(full_path):
            return jsonify({"error": "file not found"}), 404
        dir_name = os.path.dirname(full_path)
        file_name = os.path.basename(full_path)
        return send_from_directory(dir_name, file_name, as_attachment=True)

    # --------------------------------------------------- CDN / Origin API
    @app.route("/api/origin", methods=["POST"])
    def api_origin():
        data = request.get_json(silent=True) or {}
        domain = (data.get("domain") or "").strip()
        # Clean domain of scheme and paths if passed
        domain = re.sub(r"^https?://", "", domain).split("/")[0].split(":")[0].strip()
        if not domain:
            return jsonify({"error": "domain required"}), 400

        def _work() -> None:
            from modules.origin_ip import resolve_origin_ips
            runner.emit(f"[origin] Searching for real backend Origin IP for {domain} ...", "info")
            try:
                candidates = resolve_origin_ips(domain, verbose=True)
                runner.push_result("origin", {
                    "domain": domain,
                    "candidates": candidates,
                })
                if candidates:
                    runner.emit(f"[origin] Found {len(candidates)} candidate(s) for {domain}", "success")
                else:
                    runner.emit(f"[origin] No origin IP could be confirmed for {domain}", "warning")
            except Exception as e:
                runner.emit(f"[origin] Error resolving origin: {e}", "error")

        runner.run_in_thread(_work, kind="origin")
        return jsonify({"status": "started"})

    # --------------------------------------------------- Directory Map API
    @app.route("/api/dir_map", methods=["GET", "POST"])
    def api_dir_map():
        data = request.get_json(silent=True) or {}
        url = (
            data.get("url")
            or data.get("target")
            or data.get("host")
            or request.form.get("url")
            or request.form.get("target")
            or request.form.get("host")
            or request.args.get("url")
            or request.args.get("target")
            or request.args.get("host")
            or ""
        ).strip()
        wordlist = (
            data.get("wordlist")
            or request.form.get("wordlist")
            or request.args.get("wordlist")
            or ""
        ).strip()
        host_header = (
            data.get("host_header")
            or request.form.get("host_header")
            or request.args.get("host_header")
            or ""
        ).strip() or None
        port = data.get("port") or request.form.get("port") or request.args.get("port")

        if not url:
            return jsonify({"error": "url or target host required"}), 400

        # Fix missing scheme or typos like http//
        if url.startswith("http//"):
            url = "http://" + url[6:]
        elif url.startswith("https//"):
            url = "https://" + url[7:]
        elif not url.startswith(("http://", "https://")):
            url = f"http://{url}"

        # If a port was specified and is not in url, attach it
        from urllib.parse import urlparse, urlunparse
        try:
            parsed = urlparse(url)
            if port and not parsed.port:
                p_int = int(port)
                netloc = f"{parsed.hostname}:{p_int}" if parsed.hostname else parsed.netloc
                url = urlunparse((parsed.scheme, netloc, parsed.path or "/", parsed.params, parsed.query, parsed.fragment))
        except Exception:
            pass

        def _work() -> None:
            from modules.dir_bruteforce import directory_bruteforce
            wl_path = wordlist

            # Default to directories.txt (1,500 entries) when not specified or fallback needed
            default_candidates = (
                "wordlists/directories.txt",
                "wordlists/directories_large.txt",
                "wordlists/passwords.txt",
                "wordlists/usernames.txt",
            )

            if wl_path and not os.path.isfile(wl_path):
                cand = os.path.join(_REPO_ROOT, "wordlists", os.path.basename(wl_path))
                if os.path.isfile(cand):
                    wl_path = cand
            if not wl_path or not os.path.isfile(wl_path):
                for cand in default_candidates:
                    p = os.path.join(_REPO_ROOT, cand)
                    if os.path.isfile(p):
                        wl_path = p
                        break

            runner.emit(f"[dir_map] Starting directory mapping on {url} ...", "info")
            if wl_path:
                runner.emit(f"[dir_map] Using wordlist: {os.path.basename(wl_path)}", "info")

            try:
                def _on_progress(completed: int, total: int, hit: dict) -> None:
                    if hit and hit.get("interesting"):
                        runner.push_result("dir_hit", hit)
                        loc = f" -> {hit.get('redirect')}" if hit.get("redirect") else ""
                        t_str = f" [{hit.get('title')}]" if hit.get("title") else ""
                        runner.emit(f"[dir_map] [+] {hit.get('status')} {hit.get('path')} ({hit.get('length')}B){loc}{t_str}", "success")
                    elif completed % 50 == 0 or completed == total:
                        runner.emit(f"[dir_map] Progress: {completed}/{total} endpoints probed...", "info")

                results = directory_bruteforce(url, wl_path, host_header=host_header, progress_callback=_on_progress)
                runner.push_result("dir_map", {"url": url, "hits": results})
                runner.emit(f"[dir_map] Completed! Found {len(results)} active endpoint(s)", "success")

                # Save results to downloads/<host>/
                parsed_res = urlparse(url)
                target_host = parsed_res.hostname or "localhost"
                target_port = parsed_res.port or (443 if parsed_res.scheme == "https" else 80)
                out_dir = ensure_dir(host_dir(target_host))
                report_file = os.path.join(out_dir, f"site_directory_map_{target_port}.txt")
                json_file = os.path.join(out_dir, f"site_directory_map_{target_port}.json")
                try:
                    with open(json_file, "w", encoding="utf-8") as fh:
                        json.dump(results, fh, indent=2)
                    with open(report_file, "w", encoding="utf-8") as fh:
                        fh.write(f"SITE DIRECTORY MAP — {target_host}:{target_port} ({time.strftime('%Y-%m-%d %H:%M:%S')})\n")
                        fh.write("=" * 70 + "\n\n")
                        for item in results:
                            loc = f" -> {item.get('redirect', '')}" if item.get("redirect") else ""
                            t_str = f" [{item.get('title', '')}]" if item.get("title") else ""
                            fh.write(f"[{item.get('status')}] {item.get('path')} ({item.get('length')} bytes){loc}{t_str}\n")
                    runner.emit(f"[dir_map] Saved artifacts to downloads/{target_host}/site_directory_map_{target_port}.txt", "info")
                except Exception as save_err:
                    runner.emit(f"[dir_map] Warning saving dump files: {save_err}", "warning")
            except Exception as exc:
                runner.emit(f"[dir_map] Error during scan: {exc}", "error")

        runner.run_in_thread(_work, kind="dir_map")
        return jsonify({"status": "started", "url": url})

    # --------------------------------------------------------- attack API
    @app.route("/api/attack", methods=["POST"])
    def api_attack():
        data = request.get_json(silent=True) or {}
        host = (data.get("host") or "").strip()
        service = (data.get("service") or "").strip().lower()
        port = int(data.get("port") or 0)
        attack_value = (data.get("attack") or "").strip()
        config_params = data.get("config") or {}

        if not host or not attack_value:
            return jsonify({"error": "host and attack required"}), 400

        def _work() -> None:
            _dispatch(host, service, port, attack_value, config_params)

        runner.run_in_thread(_work, kind="attack")
        return jsonify({"status": "started"})

    return app


# ---------------------------------------------------------------- dispatch
def _dispatch(host: str, service: str, port: int, attack_value: str, config_params: dict = None) -> None:
    """
    Map an AttackType value → the actual module call in main.DISPATCH.
    Every branch runs inside runner.run_in_thread(), so its stdout/stderr
    (including Rich console output) is streamed live to the browser.
    """
    from modules.attack_menu import AttackType
    from modules.target import TargetInfo
    from modules.attack_config import AttackConfig, CredentialMode
    from main import DISPATCH
    from web_gui import runner as R

    config_params = config_params or {}

    try:
        atk_type = AttackType(attack_value)
    except ValueError:
        R.emit(f"[dispatch] Unknown attack type '{attack_value}'", "error")
        return

    # Infer service/port defaults if missing
    if not port:
        port_defaults = {
            "mysql": 3306, "ftp": 21, "ssh": 22, "smtp": 25,
            "redis": 6379, "mongo": 27017, "postgres": 5432, "mssql": 1433,
            "http": 80, "https": 443, "vnc": 5900, "ldap": 389, "telnet": 23,
        }
        port = port_defaults.get(service, 80 if service == "http" else 443 if service == "https" else 3306)

    if not service:
        if port in (443, 8443):
            service = "https"
        elif port in (80, 8080, 8000, 5000):
            service = "http"
        elif port in (3306, 3307):
            service = "mysql"
        elif port in (21, 2121):
            service = "ftp"
        elif port == 22:
            service = "ssh"
        else:
            service = "http"

    target = TargetInfo(host=host, port=port, version="Unknown", service=service)
    config = AttackConfig(attack_type=atk_type)

    # Populate configuration fields from user inputs
    if config_params.get("username"):
        config.username_value = str(config_params["username"])
        config.username_mode = CredentialMode.FIXED
    if config_params.get("password"):
        config.password_value = str(config_params["password"])
        config.password_mode = CredentialMode.FIXED
    if config_params.get("wordlist"):
        config.password_file = str(config_params["wordlist"])
        config.password_mode = CredentialMode.RANDOM_FROM_LIST
    if config_params.get("http_path"):
        config.http_path = str(config_params["http_path"])
    if config_params.get("http_method"):
        config.http_method = str(config_params["http_method"])
    if config_params.get("http_params"):
        config.http_params = str(config_params["http_params"])
    if "tls" in config_params:
        config.http_use_tls = bool(config_params["tls"])
    else:
        config.http_use_tls = (service == "https" or port in (443, 8443))

    if atk_type in DISPATCH:
        R.emit(
            f"\n[>] EXECUTING: {atk_type.value.upper()} → {service.upper()} {host}:{port}",
            "success",
        )
        try:
            DISPATCH[atk_type](target, config)
        except Exception as exc:
            R.emit(f"[!] Attack runtime exception: {exc}", "error")
            R.emit(traceback.format_exc(), "error")
    else:
        R.emit(f"[!] Attack '{attack_value}' has no registered dispatch handler.", "error")


def _find_available_port(host: str, preferred: int = 5000) -> int:
    """Find preferred port or fallback to next available (avoids macOS AirPlay Receiver conflict on 5000)."""
    import socket
    for p in (preferred, 5001, 8080, 8888, 5050):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, p))
                return p
            except OSError:
                continue
    return preferred


# -------------------------------------------------------------- run server
def run_server(
    host: str = "127.0.0.1",
    port: int = 5000,
    open_browser: bool = True,
) -> None:
    """Start the Flask server and open the browser."""
    runner.attach_rich()          # ensure Rich output is streamed
    app = create_app()

    port = _find_available_port(host, port)
    url = f"http://{host}:{port}"

    print()
    print("  ╔══════════════════════════════════════════════════════════════╗")
    print("  ║           WEB-XPLOIT  //  THE WIRED WEB INTERFACE            ║")
    print("  ╠══════════════════════════════════════════════════════════════╣")
    print(f"  ║   Listening  : {url:<45}║")
    print("  ║   Mode       : Cyber Red // Multi-View Pentest Suite        ║")
    print("  ║   Shutdown   : Ctrl + C                                     ║")
    print("  ╚══════════════════════════════════════════════════════════════╝")
    print()

    if open_browser:
        def _open() -> None:
            time.sleep(1.2)
            try:
                webbrowser.open(url)
            except Exception:
                pass

        threading.Thread(target=_open, daemon=True).start()

    app.run(
        host=host,
        port=port,
        debug=False,
        use_reloader=False,
        threaded=True,
    )


if __name__ == "__main__":
    run_server()
