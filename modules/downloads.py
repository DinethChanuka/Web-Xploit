"""
Central Download Manager
All file captures (HTTP, FTP, dirbust, etc.) go through here.
Default location: <project_root>/downloads/<host>/<subdir>/
"""
import os
import re
from datetime import datetime

from Design.colors_cli import console


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DOWNLOAD_DIR = os.path.join(PROJECT_ROOT, "downloads")


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def init_downloads() -> str:
    """Create the default downloads directory. Returns its path."""
    ensure_dir(DEFAULT_DOWNLOAD_DIR)
    return DEFAULT_DOWNLOAD_DIR


def safe_name(name: str) -> str:
    """Sanitize a path component for the filesystem."""
    name = re.sub(r"[^\w.\-]", "_", name or "")
    return name[:200] or "unnamed"


def host_dir(host: str) -> str:
    return ensure_dir(os.path.join(DEFAULT_DOWNLOAD_DIR, safe_name(host)))


def _unique_path(path: str) -> str:
    base, ext = os.path.splitext(path)
    candidate = path
    i = 1
    while os.path.exists(candidate):
        candidate = f"{base}.{i}{ext}"
        i += 1
    return candidate


def save_bytes(
    content: bytes,
    name: str,
    host: str = "unknown",
    subdir: str = "",
) -> str:
    """
    Save bytes to downloads/<host>/<subdir>/<name>.
    Returns the absolute file path.
    """
    d = host_dir(host)
    if subdir:
        d = ensure_dir(os.path.join(d, safe_name(subdir)))
    path = os.path.join(d, safe_name(name))
    path = _unique_path(path)
    try:
        with open(path, "wb") as fh:
            fh.write(content)
        console.print(f"  [success]✓ Downloaded:[/success] [text]{path}[/text]")
    except OSError as exc:
        console.print(f"  [warning]Download failed: {exc}[/warning]")
        return ""
    return path


def save_text(
    text: str,
    name: str,
    host: str = "unknown",
    subdir: str = "",
) -> str:
    return save_bytes(text.encode("utf-8", "replace"), name, host, subdir)


def save_discovered(text_content: str, host: str, label: str) -> str:
    """
    Convenience: write a discovered artifact under downloads/<host>/discovered/
    with an automatic timestamped name.
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_label = safe_name(label)[:80]
    return save_text(
        text_content,
        f"{safe_label}_{ts}.txt",
        host=host,
        subdir="discovered",
    )


def list_downloads(host: str | None = None) -> list[str]:
    """Return paths of all downloaded files (optionally scoped to a host)."""
    root = host_dir(host) if host else DEFAULT_DOWNLOAD_DIR
    if not os.path.isdir(root):
        return []
    out = []
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            out.append(os.path.join(dirpath, f))
    return out