"""
Web reconnaissance + data extraction.

 15. web_wp_scanner      — WordPress version / plugin / theme / user enum
 16. web_api_scan        — REST API endpoint discovery + auth test
 17. web_secrets_scan    — exposed API keys/tokens/passwords in JS
 18. web_graphql         — GraphQL introspection + query probing
"""
import json
import re

from Design.colors_cli import console, escape
from modules.target import TargetInfo
from modules.attack_config import AttackConfig
from modules.attacks.web_exploits import _req
from modules.attacks.progress import found, fail, warn, section, explain, req_log
from modules.downloads import save_text, save_bytes


# ---------- 15. web_wp_scanner ----------

_WP_PATHS = [
    "/feed/", "/wp-feed.php", "/readme.html", "/license.txt",
    "/wp-login.php", "/xmlrpc.php", "/wp-cron.php",
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
    "/.htaccess", "/wp-content/debug.log", "/wp-includes/version.php",
    "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts",
    "/wp-json/wp/v2/pages", "/wp-json/",
    "/wp-content/uploads/", "/wp-admin/",
    "/wp-admin/admin-ajax.php", "/wp-sitemap.xml",
]


def run_web_wp_scanner(target, config):
    console.print(f"\n[bold primary][ WORDPRESS SCAN ][/bold primary]\n")
    explain(
        "WordPress fingerprinting: detect version via readme/feed/generator meta,\n"
        "enumerate plugins+themes from HTML source, dump user list via REST API,\n"
        "check xmlrpc.php (brute-force vector), exposed debug logs, config files,\n"
        "and author enumeration via ?author=N.\n"
        f"Testing {len(_WP_PATHS)} paths."
    )

    tls = config.http_use_tls
    h, port = target.host, target.port
    wp_detected = False
    findings = []

    section("Path Probing")
    for p in _WP_PATHS:
        console.print(f"  [dim]  {p}[/dim]", end="\r")
        r = _req(h, port, tls, p)
        if not r:
            continue
        status, size = r["status"], r["size"]
        body = r["body"].decode("utf-8", "replace")

        if status in (200, 301, 302, 403):
            req_log("GET", p, status, size)

        if status == 200 and size > 0:
            # Version from readme
            m = re.search(r"[Vv]ersion\s*[:\-]?\s*(\d+\.\d+[\.\d]*)", body)
            if m and ("readme" in p or "version.php" in p):
                found("WordPress version", m.group(1))
                wp_detected = True
                findings.append(f"version={m.group(1)}")

            # Version from RSS feed
            m2 = re.search(r"<generator>https://wordpress\.org/\?v=([\d.]+)</generator>", body)
            if m2:
                found("WordPress version (feed)", m2.group(1))
                wp_detected = True

            # Users from REST API
            if "wp/v2/users" in p:
                try:
                    users = json.loads(r["body"])
                    for u in users[:15]:
                        found("WP user", f"{u.get('slug','?')} (id={u.get('id')})")
                        findings.append(f"user={u.get('slug')}")
                        wp_detected = True
                except Exception:
                    if size > 10:
                        console.print(f"  [dim]  WP users endpoint returned {size}b (non-JSON)[/dim]")

            if p == "/xmlrpc.php":
                warn("xmlrpc.php enabled — XML-RPC brute-force vector active!")
            if "wp-config" in p and status == 200:
                warn(f"wp-config EXPOSED at {p}!")
                save_bytes(r["body"], "wp-config.php", host=h, subdir="web")
            if "debug.log" in p and status == 200:
                warn("wp-content/debug.log exposed!")
                save_bytes(r["body"], "debug.log", host=h, subdir="web")
        elif status == 403 and "wp-admin" in p:
            warn("wp-admin is accessible (403 — authentication required)")
            wp_detected = True

    console.print()

    section("Plugin & Theme Enum from HTML")
    req_log("GET", "/")
    r = _req(h, port, tls, "/")
    if r and r["status"] == 200:
        html = r["body"].decode("utf-8", "replace")
        plugins = sorted(set(re.findall(r"/wp-content/plugins/([a-z0-9\-_]+)/", html)))
        themes  = sorted(set(re.findall(r"/wp-content/themes/([a-z0-9\-_]+)/", html)))
        if plugins:
            found("Plugins detected", ", ".join(plugins[:20]))
            wp_detected = True
        if themes:
            found("Themes detected", ", ".join(themes[:10]))
        if not plugins and not themes:
            console.print("  [dim]No plugin/theme paths found in HTML[/dim]")

    section("Author Enumeration (?author=1..8)")
    for n in range(1, 9):
        console.print(f"  [dim]  ?author={n}[/dim]", end="\r")
        r = _req(h, port, tls, f"/?author={n}")
        if r:
            body = r["body"].decode("utf-8", "replace")
            m = re.search(r'author/([^/"]+)', body)
            if m:
                console.print()
                found(f"Author id={n}", m.group(1))
            elif r["status"] in (301, 302):
                loc = r["headers"].get("Location", r["headers"].get("location", ""))
                if "author" in loc.lower():
                    console.print()
                    found(f"Author redirect id={n}", loc)
    console.print()

    if not wp_detected:
        fail("WordPress not detected on this target")
        console.print("  [dim]  Checked: readme, feed, xmlrpc, wp-json, wp-admin, HTML source[/dim]")
    else:
        console.print(f"\n  [bold success]WordPress detected! {len(findings)} finding(s) recorded.[/bold success]")


# ---------- 16. web_api_scan ----------

_API_PATHS = [
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
    "/api/users", "/api/users/1", "/api/admin",
    "/api/auth", "/api/login", "/api/token", "/api/refresh",
    "/api/health", "/api/status", "/api/config", "/api/version",
    "/api/debug", "/api/metrics", "/api/swagger", "/api-docs",
    "/swagger.json", "/swagger-ui/", "/openapi.json",
    "/graphiql", "/graphql",
    "/rest", "/rest/v1", "/rest/api/2/",
    "/.well-known/openid-configuration",
    "/actuator", "/actuator/env", "/actuator/health",
    "/actuator/mappings", "/actuator/beans",
    "/actuator/logfile", "/actuator/httptrace",
    "/server-status", "/_debug", "/_health",
    "/debug/pprof", "/v1", "/v2", "/v3",
    "/api/keys", "/api/secrets", "/api/tokens",
    "/api/internal", "/internal/api",
    "/admin/api", "/api/admin/users",
    "/phpinfo.php", "/info.php", "/test.php",
    "/env", "/.env", "/.env.production",
]


def run_web_api_scan(target, config):
    console.print(f"\n[bold primary][ API DISCOVERY ][/bold primary]\n")
    explain(
        f"Probing {len(_API_PATHS)} common API and admin paths. Looking for:\n"
        "• Exposed REST endpoints (200 JSON responses)\n"
        "• Admin panels (401/403 indicate protected paths that exist)\n"
        "• Spring Boot actuators (/actuator/env leaks credentials/config)\n"
        "• Swagger/OpenAPI specs (complete API documentation)\n"
        "• Debug endpoints, health checks, and sensitive config files"
    )

    h, port, tls = target.host, target.port, config.http_use_tls
    hits = []

    for i, p in enumerate(_API_PATHS, 1):
        console.print(f"  [dim][{i:>2}/{len(_API_PATHS)}] GET {p}[/dim]", end="\r")
        r = _req(h, port, tls, p)
        if not r:
            continue
        status, size = r["status"], r["size"]
        if status in (200, 201, 301, 302, 401, 403):
            console.print()
            req_log("GET", p, status, size)
            hits.append((status, p, size))
            if status == 200 and size > 0:
                ct = r["headers"].get("Content-Type", r["headers"].get("content-type", ""))
                if "json" in ct or size < 100000:
                    save_bytes(r["body"],
                               p.strip("/").replace("/", "_")[:50] + ".json",
                               host=h, subdir="api")
                body_txt = r["body"].decode("utf-8", "replace").lower()
                if any(x in body_txt for x in ("password", "secret", "token", "credential", "private")):
                    warn(f"Sensitive keywords in response at {p}!")
                if any(x in p for x in ("/actuator", "/phpinfo", "/env", "/debug")):
                    warn(f"High-value endpoint: {p} (may leak server internals)")

    console.print()
    if hits:
        found(f"{len(hits)} API endpoints reachable",
              f"{sum(1 for s,_,_ in hits if s==200)} returning 200, {sum(1 for s,_,_ in hits if s in(401,403))} protected")
    else:
        fail("No API endpoints discovered", f"tested {len(_API_PATHS)} paths")


# ---------- 17. web_secrets_scan ----------

_SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}",                                        "AWS Access Key ID"),
    (r"(?:aws_secret|AWS_SECRET)[_A-Z]*\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})", "AWS Secret Key"),
    (r"AIza[0-9A-Za-z_\-]{35}",                                  "Google API Key"),
    (r"sk_live_[0-9a-zA-Z]{24,}",                                "Stripe Live Key"),
    (r"rk_live_[0-9a-zA-Z]{24,}",                                "Stripe Restricted Key"),
    (r"ghp_[0-9a-zA-Z]{36}",                                     "GitHub PAT"),
    (r"gho_[0-9a-zA-Z]{36}",                                     "GitHub OAuth Token"),
    (r"glpat-[0-9a-zA-Z\-_]{20}",                                "GitLab PAT"),
    (r"xox[baprs]-[0-9a-zA-Z]{10,}",                             "Slack Token"),
    (r"-----BEGIN RSA PRIVATE KEY-----",                         "RSA Private Key"),
    (r"-----BEGIN OPENSSH PRIVATE KEY-----",                     "OpenSSH Private Key"),
    (r"-----BEGIN EC PRIVATE KEY-----",                          "EC Private Key"),
    (r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", "JWT Token"),
    (r"(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]",  "Password Literal"),
    (r"mongodb(\+srv)?://[^\s\"']+",                             "MongoDB URI"),
    (r"postgres://[^\s\"']+",                                    "PostgreSQL URI"),
    (r"mysql://[^\s\"']+",                                       "MySQL URI"),
    (r"redis://[^\s\"']+",                                       "Redis URI"),
    (r"(?:api_key|apikey|api-key)\s*[:=]\s*['\"][^'\"]{10,}['\"]", "API Key"),
    (r"(?:secret|SECRET)\s*[:=]\s*['\"][^'\"]{8,}['\"]",        "Secret Value"),
    (r"authorization:\s*bearer\s+[a-zA-Z0-9\-_.=]{20,}",        "Bearer Token"),
]

_SCAN_PATHS = [
    "/", "/app.js", "/main.js", "/index.js", "/bundle.js",
    "/static/js/main.js", "/static/js/app.js", "/static/app.js",
    "/assets/js/app.js", "/assets/app.js", "/dist/app.js",
    "/js/app.js", "/js/main.js", "/js/config.js",
    "/.env", "/.env.local", "/.env.production", "/.env.development",
    "/config.json", "/config.js", "/settings.json", "/settings.js",
    "/app.config.js", "/web.config", "/appsettings.json",
    "/robots.txt", "/sitemap.xml",
    "/.git/config", "/.git/COMMIT_EDITMSG",
    "/backup.sql", "/db.sql", "/dump.sql",
]


def run_web_secrets_scan(target, config):
    console.print(f"\n[bold primary][ SECRET SCAN ][/bold primary]\n")
    explain(
        f"Scanning {len(_SCAN_PATHS)} paths for hardcoded secrets and API credentials.\n"
        "Checks: AWS keys, Google API, Stripe live keys, GitHub PAT, GitLab,\n"
        "Slack tokens, RSA/EC private keys, JWT tokens, database URIs,\n"
        f"password literals, and API key patterns. {len(_SECRET_PATTERNS)} regex patterns total."
    )

    h, port, tls = target.host, target.port, config.http_use_tls
    total_found = 0

    for i, p in enumerate(_SCAN_PATHS, 1):
        console.print(f"  [dim][{i:>2}/{len(_SCAN_PATHS)}] GET {p}[/dim]", end="\r")
        r = _req(h, port, tls, p)
        if not r or r["status"] != 200 or r["size"] == 0:
            continue
        console.print()
        req_log("GET", p, r["status"], r["size"])
        text = r["body"].decode("utf-8", "replace")
        path_hits = 0
        for pat, label in _SECRET_PATTERNS:
            for m in re.finditer(pat, text, re.IGNORECASE):
                val = m.group(0)
                found(label, f"in {p} → {val[:70]}")
                save_text(f"{label}\nsource={p}\nmatch={val}\n",
                          f"secret_{label.replace(' ','_')}.txt",
                          host=h, subdir="secrets")
                total_found += 1
                path_hits += 1
        if path_hits:
            console.print(f"  [muted]  ({path_hits} pattern(s) matched in {p})[/muted]")

    console.print()
    if total_found == 0:
        fail("No secrets found",
             f"scanned {len(_SCAN_PATHS)} paths × {len(_SECRET_PATTERNS)} patterns")
    else:
        found(f"{total_found} secret(s) found!", f"saved to downloads/{h}/secrets/")


# ---------- 18. web_graphql ----------

_INTROSPECTION = json.dumps({
    "query": "{ __schema { types { name kind description fields { name type { name kind } } } } }"
})

_GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
    "/query", "/gql", "/graphql/v1", "/graphql/v2",
    "/api/v1/graphql", "/api/v2/graphql", "/playground",
]

_DANGEROUS_QUERIES = [
    '{ users { id email password } }',
    '{ user(id: 1) { email role password } }',
    '{ allUsers { nodes { email password role } } }',
    '{ me { id email role token } }',
    '{ admin { username password } }',
]


def run_web_graphql(target, config):
    console.print(f"\n[bold primary][ GRAPHQL SCAN ][/bold primary]\n")
    explain(
        f"GraphQL introspection: discover full schema (types, queries, mutations).\n"
        "If introspection is open, attempt dangerous queries to list users and dump passwords.\n"
        f"Testing {len(_GRAPHQL_PATHS)} common GraphQL endpoint paths."
    )

    h, port, tls = target.host, target.port, config.http_use_tls
    gql_found = False

    section("Introspection Probe")
    for p in _GRAPHQL_PATHS:
        req_log("POST", p, note="introspection query")
        r = _req(h, port, tls, p, method="POST",
                 headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
                 body=_INTROSPECTION.encode())
        if not r:
            req_log("POST", p, note="no response / connection refused")
            continue
        req_log("POST", p, r["status"], r["size"])
        body = r["body"].decode("utf-8", "replace")

        if "__schema" in body:
            found("GraphQL introspection OPEN!", p)
            save_text(body, f"graphql_schema_{p.strip('/').replace('/','_')}.json",
                      host=h, subdir="api")
            gql_found = True

            section("Dangerous Query Probing")
            for q in _DANGEROUS_QUERIES:
                req_log("POST", p, note=q[:50])
                r2 = _req(h, port, tls, p, method="POST",
                          headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
                          body=json.dumps({"query": q}).encode())
                if r2 and r2["status"] == 200:
                    b2 = r2["body"].decode("utf-8", "replace")
                    if any(x in b2.lower() for x in ("email", "password", "role", "token")):
                        warn(f"Sensitive data returned from: {q[:50]}")
                        save_text(b2, f"graphql_data_{p.strip('/').replace('/','_')}.json",
                                  host=h, subdir="api")
                    elif '"data"' in b2 and '"errors"' not in b2:
                        console.print(f"  [muted]  Query returned data ({r2['size']}b)[/muted]")
            break

        elif r["status"] in (200, 400):
            if "errors" in body or "graphql" in body.lower():
                warn(f"GraphQL at {p} (introspection may be disabled)")
                gql_found = True

    if not gql_found:
        fail("No GraphQL endpoint found", f"tested {len(_GRAPHQL_PATHS)} paths")
        console.print("  [dim]  (tried all paths with introspection query, all returned non-GraphQL responses)[/dim]")
