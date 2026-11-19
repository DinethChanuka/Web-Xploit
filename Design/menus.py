import shutil

from rich.panel import Panel
from rich.text import Text
from rich.box import DOUBLE

from Design.colors_cli import console
from Design.prompts import GoBack


def render_menu(title: str, options: list[str], allow_back: bool = True) -> int:
    """
    Renders a styled Rich panel menu with numbered options.
    If allow_back is True, adds a 'b. Back' option and entering 'b' / Ctrl+B raises GoBack.
    Returns 0-based index of the chosen option.
    """
    terminal_width = shutil.get_terminal_size(fallback=(80, 24)).columns
    width = min(terminal_width, 100)

    content = Text(justify="left")
    for i, opt in enumerate(options, start=1):
        content.append(f"  {i}. ", style="primary")
        content.append(f"{opt}\n", style="text")

    if allow_back:
        content.append("  b. ", style="muted")
        content.append("Back (or press Ctrl+B / 'b')\n", style="muted")

    console.print(
        Panel(
            content,
            title=f"[bold primary]{title}[/bold primary]",
            border_style="primary",
            box=DOUBLE,
            padding=(1, 2),
            width=width,
        ),
        justify="center",
    )

    while True:
        try:
            raw = console.input("\n[primary]Select[/primary] [text]›[/text] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            if allow_back:
                raise GoBack()
            raise KeyboardInterrupt()

        if allow_back and raw.lower() in ("b", "back", "0", "\x02"):
            raise GoBack()

        if raw.isdigit():
            choice = int(raw)
            if 1 <= choice <= len(options):
                return choice - 1

        hint = f"1 to {len(options)}" + (", or 'b' to go back" if allow_back else "")
        console.print(f"[warning]Enter {hint}.[/warning]")
