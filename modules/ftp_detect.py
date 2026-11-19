#!/usr/bin/env python3
"""
FTP version detection module.
Fixes the "Version : Unknown" bug by correctly reading the 220 welcome banner
that every FTP server sends immediately after the TCP handshake.
"""

import ftplib
import re
import socket
from typing import Any, Dict, Tuple


DEFAULT_TIMEOUT = 10

KNOWN_FTP_SERVERS = [
    "vsFTPd",
    "ProFTPD",
    "Pure-FTPd",
    "FileZilla",
    "Serv-U",
    "WU-FTPD",
    "IIS FTP",
    "Microsoft FTP Service",
    "Cerberus FTP",
    "WS_FTP",
    "glFTPd",
    "BulletProof FTP",
    "Gene6 FTP",
    "Robo-FTP",
    "OpenSSH",
]


def parse_ftp_banner(banner: str) -> Tuple[str, str]:
    """
    Parse a banner such as:
        '220 ProFTPD 1.3.5 Server ready'
        '220 (vsFTPd 3.0.3)'
        '220 Microsoft FTP Service'
        '220-FileZilla Server 1.5.0'
    Returns (product, version). Version is 'Unknown' if not detected.
    """
    if not banner:
        return "Unknown", "Unknown"

    first_line = banner.strip().splitlines()[0].strip()

    # Strip the leading 3-digit reply code and optional dash
    first_line = re.sub(r"^\d{3}[- ]?", "", first_line).strip()
    if not first_line:
        return "Unknown", "Unknown"

    product = "Unknown"
    version = "Unknown"

    # Detect known product names first
    for known in KNOWN_FTP_SERVERS:
        if known.lower() in first_line.lower():
            idx = first_line.lower().find(known.lower())
            product = first_line[idx:idx + len(known)]
            break

    # Extract the first dotted version number
    ver_match = re.search(
        r"(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9._-]*)?)",
        first_line,
    )
    if ver_match:
        version = ver_match.group(1)

    if product == "Unknown":
        tokens = first_line.split()
        if tokens:
            product = tokens[0]

    return product, version


def detect_ftp_version(
    host: str,
    port: int = 21,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """
    Connect to FTP, read the welcome banner, try SYST and FEAT to strengthen
    version detection.  Returns a dict with product/version/banner/error.
    """
    result: Dict[str, Any] = {
        "host": host,
        "port": port,
        "banner": "",
        "product": "Unknown",
        "version": "Unknown",
        "raw_ok": False,
        "error": None,
    }

    ftp = ftplib.FTP()
    try:
        ftp.connect(host, port, timeout=timeout)

        # *** THE ACTUAL FIX ***
        # Read the 220 banner that the server sent right after connect().
        banner = ftp.getwelcome()
        result["banner"] = banner
        result["raw_ok"] = True

        product, version = parse_ftp_banner(banner)
        result["product"] = product
        result["version"] = version

        # If banner parsing gave nothing, ask the server for SYST
        if version == "Unknown":
            try:
                syst = ftp.sendcmd("SYST")
                result["banner"] += "\n" + syst
                prod2, ver2 = parse_ftp_banner(syst)
                if ver2 != "Unknown":
                    result["product"] = prod2
                    result["version"] = ver2
            except Exception:
                pass

        # FEAT is optional but logs the feature set in the banner field
        try:
            feat = ftp.sendcmd("FEAT")
            result["banner"] += "\n" + feat
        except Exception:
            pass

    except ftplib.all_errors as e:
        result["error"] = f"FTP error: {e}"
    except socket.timeout:
        result["error"] = "Connection timed out"
    except Exception as e:
        result["error"] = f"Unexpected error: {e}"
    finally:
        try:
            ftp.quit()
        except Exception:
            try:
                ftp.close()
            except Exception:
                pass

    return result


def detect_ftp_version_tls(
    host: str,
    port: int = 21,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """FTPS (explicit TLS) variant of detect_ftp_version."""
    result: Dict[str, Any] = {
        "host": host,
        "port": port,
        "banner": "",
        "product": "Unknown",
        "version": "Unknown",
        "raw_ok": False,
        "error": None,
    }

    ftp = ftplib.FTP_TLS()
    try:
        ftp.connect(host, port, timeout=timeout)
        banner = ftp.getwelcome()
        result["banner"] = banner
        result["raw_ok"] = True
        product, version = parse_ftp_banner(banner)
        result["product"] = product
        result["version"] = version
        try:
            ftp.auth()
            ftp.prot_p()
        except Exception:
            pass
    except Exception as e:
        result["error"] = f"FTPS error: {e}"
    finally:
        try:
            ftp.quit()
        except Exception:
            try:
                ftp.close()
            except Exception:
                pass

    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python ftp_detect.py <host> [port]")
        sys.exit(1)
    h = sys.argv[1]
    p = int(sys.argv[2]) if len(sys.argv) > 2 else 21
    info = detect_ftp_version(h, p)
    for k, v in info.items():
        print(f"{k:<10}: {v}")