#!/usr/bin/env python3
"""
Origin IP resolver.
Given a domain that is behind Cloudflare / Fastly / Akamai, try to discover
the real backend IP by:
  1. Fetching a CDN baseline content hash.
  2. Collecting candidate IPs from:
       - crt.sh certificate transparency subdomains
       - SPF / TXT / MX records
       - direct A / AAAA
  3. Filtering out known CDN ranges.
  4. Probing each candidate with Host: <domain> header and comparing
     content hash against the CDN baseline.
"""

import hashlib
import ipaddress
import socket
import ssl
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    requests = None

try:
    import dns.resolver
    import dns.exception
    _HAS_DNS = True
except ImportError:
    _HAS_DNS = False


# ---------------------------------------------------------------------------
# CDN ranges
# ---------------------------------------------------------------------------
CLOUDFLARE_V4 = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
CLOUDFLARE_V6 = [
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]
FASTLY_V4 = [
    "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23",
    "103.245.224.0/24", "104.156.80.0/20", "140.248.64.0/18", "140.248.128.0/17",
    "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17", "167.82.128.0/20",
    "167.82.160.0/20", "167.82.224.0/20", "172.111.64.0/18", "185.31.16.0/22",
    "199.27.72.0/21", "199.232.0.0/16",
]


def _load_nets(cidrs: List[str]) -> List[Any]:
    return [ipaddress.ip_network(c) for c in cidrs]


_CF_NETS = _load_nets(CLOUDFLARE_V4 + CLOUDFLARE_V6)
_FASTLY_NETS = _load_nets(FASTLY_V4)
_ALL_CDN_NETS = _CF_NETS + _FASTLY_NETS


def is_cdn_ip(ip_str: str) -> bool:
    """True if ip_str falls inside a known CDN range."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for net in _ALL_CDN_NETS:
        if ip in net:
            return True
    return False


# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------
def resolve_a(host: str) -> List[str]:
    """Resolve A + AAAA. Uses dnspython if available, else socket."""
    ips: List[str] = []
    if _HAS_DNS:
        for rectype in ("A", "AAAA"):
            try:
                answers = dns.resolver.resolve(host, rectype, lifetime=8)
                for r in answers:
                    ips.append(str(r))
            except Exception:
                continue
    if not ips:
        try:
            for info in socket.getaddrinfo(host, None):
                ips.append(info[4][0])
        except Exception:
            pass
    seen: Set[str] = set()
    out: List[str] = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def crtsh_subdomains(domain: str, timeout: Tuple[int, int] = (10, 30)) -> Set[str]:
    """Query crt.sh for subdomains that might leak the origin IP."""
    subs: Set[str] = set()
    if requests is None:
        return subs
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0"},
            verify=False,
        )
        if resp.status_code != 200:
            return subs
        data = resp.json()
    except Exception:
        return subs
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name.startswith("*."):
                name = name[2:]
            if name.endswith(domain) and name:
                subs.add(name)
    return subs


def dns_leak_ips(domain: str) -> Set[str]:
    """Collect IPs leaked by SPF, MX and TXT records."""
    ips: Set[str] = set()
    if not _HAS_DNS:
        return ips

    try:
        for txt in dns.resolver.resolve(domain, "TXT", lifetime=8):
            txt_str = txt.to_text().strip('"')
            if "v=spf1" in txt_str.lower():
                for part in txt_str.split():
                    if part.startswith("ip4:"):
                        ips.add(part[4:])
                    elif part.startswith("ip6:"):
                        ips.add(part[4:])
    except Exception:
        pass

    try:
        for mx in dns.resolver.resolve(domain, "MX", lifetime=8):
            mx_host = str(mx.exchange).rstrip(".")
            for ip in resolve_a(mx_host):
                ips.add(ip)
    except Exception:
        pass

    return ips


# ---------------------------------------------------------------------------
# HTTP probing
# ---------------------------------------------------------------------------
def fetch_baseline(domain: str, timeout: Tuple[int, int] = (5, 15)) -> Optional[str]:
    """Fetch the site through the CDN; return SHA-256 of the body."""
    if requests is None:
        return None
    for scheme in ("https", "http"):
        try:
            r = requests.get(
                f"{scheme}://{domain}/",
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0"},
                verify=False,
                allow_redirects=True,
            )
            if r.status_code < 500 and r.content:
                return hashlib.sha256(r.content).hexdigest()
        except Exception:
            continue
    return None


def verify_origin_ip(
    candidate_ip: str,
    domain: str,
    baseline_hash: Optional[str],
    timeout: Tuple[int, int] = (4, 8),
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Probe candidate_ip with Host: domain header.
    Returns (is_origin, scheme, body_hash).
    """
    if requests is None:
        return False, None, None
    for scheme in ("http", "https"):
        url = f"{scheme}://{candidate_ip}/"
        try:
            r = requests.get(
                url,
                timeout=timeout,
                headers={"Host": domain, "User-Agent": "Mozilla/5.0"},
                verify=False,
                allow_redirects=False,
            )
        except Exception:
            continue
        if r.status_code >= 500:
            continue
        body_hash = hashlib.sha256(r.content).hexdigest() if r.content else None

        if baseline_hash is None:
            return True, scheme, body_hash
        if body_hash and body_hash != baseline_hash:
            return True, scheme, body_hash
        if not is_cdn_ip(candidate_ip) and r.status_code == 200:
            return True, scheme, body_hash
    return False, None, None


# ---------------------------------------------------------------------------
# Main entry points
# ---------------------------------------------------------------------------
def resolve_origin_ips(
    domain: str,
    verbose: bool = True,
    max_probes: int = 60,
    timeout: Tuple[int, int] = (5, 15),
) -> List[Dict[str, Any]]:
    """Full pipeline. Returns sorted list of candidate IP dicts."""
    def log(msg: str) -> None:
        if verbose:
            print(f"[origin] {msg}", file=sys.stderr)

    log(f"Resolving origin IPs for {domain}")

    baseline = fetch_baseline(domain, timeout=timeout)
    log(f"CDN baseline hash: {baseline[:16] if baseline else 'N/A'}")

    candidates: Dict[str, str] = {}

    for ip in resolve_a(domain):
        if not is_cdn_ip(ip):
            candidates[ip] = "direct-A"

    subdomains = crtsh_subdomains(domain)
    log(f"crt.sh subdomains: {len(subdomains)}")
    for sub in sorted(subdomains)[:200]:
        for ip in resolve_a(sub):
            if not is_cdn_ip(ip) and ip not in candidates:
                candidates[ip] = f"crtsh:{sub}"

    leaked = dns_leak_ips(domain)
    log(f"DNS-leak IPs: {len(leaked)}")
    for ip in leaked:
        if not is_cdn_ip(ip) and ip not in candidates:
            candidates[ip] = "dns-leak"

    log(f"Candidate IPs (post-filter): {len(candidates)}")

    verified: List[Dict[str, Any]] = []
    probe_count = 0
    for ip, source in candidates.items():
        if probe_count >= max_probes:
            log(f"Reached max probes ({max_probes})")
            break
        probe_count += 1
        ok, scheme, body_hash = verify_origin_ip(
            ip, domain, baseline, timeout=(4, 8)
        )
        entry = {
            "ip": ip,
            "source": source,
            "verified": ok,
            "scheme": scheme,
            "body_hash": body_hash,
        }
        verified.append(entry)
        if ok:
            log(f"  [+] Verified origin: {ip} ({source}, {scheme})")

    verified.sort(key=lambda x: (not x["verified"], x["source"]))
    return verified


def best_origin_ip(domain: str, verbose: bool = True) -> Optional[str]:
    """Return the first verified origin IP, else None."""
    for r in resolve_origin_ips(domain, verbose=verbose):
        if r["verified"]:
            return r["ip"]
    return None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python origin_ip.py <domain>")
        sys.exit(1)
    for entry in resolve_origin_ips(sys.argv[1]):
        print(entry)