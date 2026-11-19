"""
IP Rotation — cycle through spoofed X-Forwarded-For IPs on every request.
Used by all HTTP attack modules to make traffic appear from different sources.
"""
import random
import itertools

# Realistic IP ranges used for rotation
_IP_POOLS = [
    # Residential ISP ranges (APAC)
    [f"110.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(20)],
    # US cable modem ranges
    [f"73.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(20)],
    # European residential
    [f"185.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(20)],
    # Cloud/CDN edge IPs
    [f"104.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(20)],
    # Mobile data ranges
    [f"49.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(20)],
]

_ALL_IPS = [ip for pool in _IP_POOLS for ip in pool]
_rotator = itertools.cycle(_ALL_IPS)

# Real-looking User-Agent rotation
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
]

_ua_cycle = itertools.cycle(random.sample(_USER_AGENTS, len(_USER_AGENTS)))


def next_ip() -> str:
    """Return the next spoofed IP from the rotation pool."""
    return next(_rotator)


def next_ua() -> str:
    """Return the next User-Agent from the rotation pool."""
    return next(_ua_cycle)


def rotation_headers() -> dict:
    """
    Return a full set of IP-spoofing + UA-rotation headers to inject
    into every outgoing HTTP request.
    """
    ip = next_ip()
    ua = next_ua()
    return {
        "X-Forwarded-For":     ip,
        "X-Real-IP":           ip,
        "X-Originating-IP":    ip,
        "X-Remote-IP":         ip,
        "X-Client-IP":         ip,
        "CF-Connecting-IP":    ip,
        "True-Client-IP":      ip,
        "User-Agent":          ua,
        "Accept":              "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language":     "en-US,en;q=0.9",
        "Accept-Encoding":     "gzip, deflate",
        "Cache-Control":       "no-cache",
        "Pragma":              "no-cache",
        "Connection":          "keep-alive",
    }
