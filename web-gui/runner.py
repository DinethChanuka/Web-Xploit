"""
Streams every stdout/stderr write (plus Rich console output) into a
thread-safe Pub/Sub subscriber queue system for SSE streaming.
ANSI escapes and Rich markup are stripped so the browser sees plain text.
"""
import io
import queue
import re
import sys
import threading
import traceback
from typing import Any, Callable, List

# ------------------------------------------------------------------ cleaners
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
RICH_RE = re.compile(r"\[/?[a-zA-Z][a-zA-Z0-9 #]*(?:=[^\]]+)?\]")


def _clean(text: str) -> str:
    return RICH_RE.sub("", ANSI_RE.sub("", str(text)))


# ------------------------------------------------------------------- Pub/Sub Hub
_subscribers: List[queue.Queue] = []
_sub_lock = threading.Lock()

# Global legacy queue for fallback
output_queue: "queue.Queue[dict]" = queue.Queue(maxsize=10000)


def register_subscriber() -> queue.Queue:
    """Create and register a private queue for an SSE client."""
    q: queue.Queue = queue.Queue(maxsize=1000)
    with _sub_lock:
        _subscribers.append(q)
    return q


def unregister_subscriber(q: queue.Queue) -> None:
    """Safely unregister an SSE client queue."""
    with _sub_lock:
        if q in _subscribers:
            _subscribers.remove(q)


def _broadcast(item: dict) -> None:
    """Broadcast an event to all connected SSE clients."""
    with _sub_lock:
        for q in list(_subscribers):
            try:
                q.put_nowait(item)
            except queue.Full:
                pass

    try:
        output_queue.put_nowait(item)
    except queue.Full:
        pass


def emit(line: str | None, level: str = "info") -> None:
    """Push one line to the browser stream (never blocks)."""
    if line is None:
        return
    cleaned = _clean(line)
    if not cleaned.strip():
        return
    _broadcast({"type": "log", "line": cleaned, "level": level})


def emit_end() -> None:
    """Send the "run finished" marker so the client re-enables its buttons."""
    _broadcast({"type": "end", "line": "__END__", "level": "end"})


def push_result(kind: str, data: Any) -> None:
    """Send a structured result the JS layer will render specially."""
    _broadcast({"type": "result", "kind": kind, "data": data})


# -------------------------------------------------------------- stream shim
class WebStream(io.TextIOBase):
    """Replacement for sys.stdout / sys.stderr that emits to the queue."""

    def __init__(self, level: str = "info"):
        super().__init__()
        self.level = level
        self._buffer = ""

    def writable(self) -> bool:
        return True

    def readable(self) -> bool:
        return False

    def seekable(self) -> bool:
        return False

    def isatty(self) -> bool:
        return False

    def write(self, data: str) -> int:  # type: ignore[override]
        if not isinstance(data, str):
            data = str(data)
        self._buffer += data
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            emit(line, self.level)
        return len(data)

    def flush(self) -> None:
        if self._buffer:
            emit(self._buffer, self.level)
            self._buffer = ""


# -------------------------------------------------------- Rich integration
def attach_rich() -> None:
    """
    Redirect Rich's console output to the web stream.
    Call once at server startup.  Silently does nothing if Rich is absent.
    """
    try:
        from Design.colors_cli import console  # type: ignore
        console.file = WebStream("info")
    except Exception:
        pass


# ------------------------------------------------------------ thread runner
def run_in_thread(
    fn: Callable[..., Any],
    *args: Any,
    kind: str = "task",
    **kwargs: Any,
) -> threading.Thread:
    """
    Run `fn(*args, **kwargs)` in a daemon thread while redirecting its
    stdout/stderr into the browser stream.  Emits a final '__END__' marker
    when finished so the client can re-enable its UI.
    """

    def _target() -> None:
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout = WebStream("info")   # type: ignore[assignment]
        sys.stderr = WebStream("error")  # type: ignore[assignment]
        try:
            result = fn(*args, **kwargs)
            if result is not None and kind == "attack":
                emit(f"[{kind}] completed", "success")
        except Exception as exc:
            emit(f"[{kind}] {type(exc).__name__}: {exc}", "error")
            emit(traceback.format_exc(), "error")
        finally:
            sys.stdout, sys.stderr = old_out, old_err
            emit_end()

    t = threading.Thread(target=_target, daemon=True, name=f"web-{kind}")
    t.start()
    return t
