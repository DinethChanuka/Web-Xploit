"""
Live progress helpers for attack modules.
Provides step counters, request loggers, and result printers.
"""
from Design.colors_cli import console, escape


def step(n: int, total: int, label: str):
    """Print a numbered step header."""
    console.print(f"  [dim]Step [{n}/{total}][/dim] [text]{label}[/text]")


def req_log(method: str, path: str, status: int | None = None, size: int | None = None, note: str = ""):
    """Print a live request line."""
    if status is not None:
        if 200 <= status < 300:
            st = f"[success]{status}[/success]"
        elif status in (301, 302, 401, 403):
            st = f"[warning]{status}[/warning]"
        else:
            st = f"[muted]{status}[/muted]"
        st_part = f" [{st}]"
    else:
        st_part = ""
    s = f"  [muted]→[/muted] [dim]{method}[/dim] [text]{escape(path[:70])}[/text]{st_part}"
    if size is not None:
        s += f" [dim]{size}b[/dim]"
    if note:
        s += f" [dim italic]{escape(note[:60])}[/dim italic]"
    console.print(s)


def probe_log(param: str, payload: str, result: str = ""):
    """Print a parameter probe line."""
    p = escape(payload[:50])
    r = f" [dim italic]→ {escape(result)}[/dim italic]" if result else ""
    console.print(f"  [muted]  ↳[/muted] [dim]{escape(param)}=[/dim][text]{p}[/text]{r}")


def found(label: str, value: str = ""):
    """Print a finding."""
    v = f" [text]{escape(str(value)[:120])}[/text]" if value else ""
    console.print(f"  [bold success]✓ FOUND[/bold success] [bold]{label}[/bold]{v}")


def fail(label: str, detail: str = ""):
    """Print a negative result."""
    d = f" [dim]{escape(detail)}[/dim]" if detail else ""
    console.print(f"  [dim]✗ {label}[/dim]{d}")


def warn(label: str):
    """Print a warning/partial finding."""
    console.print(f"  [bold warning]⚠ {label}[/bold warning]")


def section(title: str):
    """Print a section sub-header."""
    console.print(f"\n  [bold secondary]── {title} ──[/bold secondary]")


def explain(text: str):
    """Print a multi-line explanation block."""
    for line in text.strip().split("\n"):
        line = line.strip()
        if line:
            console.print(f"  [dim italic]{line}[/dim italic]")
