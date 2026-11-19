from rich.console import Console
from rich.theme import Theme
from rich.markup import escape as _rich_escape

COLORS = {
    "background": "#0D0000",
    "panel":      "#1A0000",
    "primary":    "#FF1A1A",
    "success":    "#00FF88",
    "secondary":  "#CC0000",
    "warning":    "#FFB020",
    "error":      "#FF4444",
    "text":       "#E6EDF3",
    "muted":      "#8A6060",
    "border":     "#3D0000",
}

custom_theme = Theme({
    "primary":   COLORS["primary"],
    "success":   COLORS["success"],
    "secondary": COLORS["secondary"],
    "warning":   COLORS["warning"],
    "error":     COLORS["error"],
    "text":      COLORS["text"],
    "muted":     COLORS["muted"],
})

console = Console(theme=custom_theme)


def escape(value) -> str:
    """Escape Rich markup in arbitrary user/server strings before printing."""
    return _rich_escape(str(value))


def safe_print(*renderables, **kwargs):
    """console.print that escapes every string renderable."""
    escaped = [escape(r) if isinstance(r, str) else r for r in renderables]
    console.print(*escaped, **kwargs)