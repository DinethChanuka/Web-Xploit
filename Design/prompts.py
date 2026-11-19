from Design.colors_cli import console


class GoBack(Exception):
    """Raised when user enters 'b', 'back', '0', or presses Ctrl+B / Cmd+B to return."""
    pass


def ask_input(label: str, default: str = "", allow_back: bool = True) -> str:
    """
    Styled Rich prompt. Returns stripped input or default if blank.
    If allow_back is True, entering 'b', 'back', or Ctrl+B (\x02) raises GoBack.
    """
    back_hint = " [muted](type 'b' to go back)[/muted]" if allow_back else ""
    if default:
        prompt_str = (
            f"[primary]{label}[/primary]{back_hint} "
            f"[muted](default: {default})[/muted] "
            f"[text]›[/text] "
        )
    else:
        prompt_str = f"[primary]{label}[/primary]{back_hint} [text]›[/text] "

    try:
        result = console.input(prompt_str).strip()
    except (EOFError, KeyboardInterrupt):
        # Treat Ctrl+C during input either as GoBack if allowed, or re-raise
        console.print()
        if allow_back:
            raise GoBack()
        raise KeyboardInterrupt()

    if allow_back and result in ("b", "B", "back", "Back", "BACK", "\x02"):
        raise GoBack()

    return result if result else default


def ask_choice(options: list[str], allow_back: bool = True) -> int:
    """
    Numbered list prompt. Returns 0-based index of chosen option.
    If allow_back is True, entering 'b', 'back', '0', or Ctrl+B raises GoBack.
    """
    for i, opt in enumerate(options, start=1):
        console.print(f"  [primary]{i}.[/primary] [text]{opt}[/text]")
    if allow_back:
        console.print("  [muted]b. Back (or press Ctrl+B / 'b')[/muted]")

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

        valid_hint = f"1 to {len(options)}" + (", or 'b' to go back" if allow_back else "")
        console.print(f"[warning]Please enter {valid_hint}.[/warning]")
