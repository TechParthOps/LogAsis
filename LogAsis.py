import logging
import sys
import os
import tempfile
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QIcon
from pathlib import Path

from gui.main_window import MainWindow
from gui.theme import apply_theme


def _configure_logging() -> Path:
    """Write AI retrieval/grounding diagnostics to a file the analyst can read.

    LogAsis already emits detailed AI RETRIEVAL TRACE / planner / grounding
    log lines (see ai/investigation_agent.py), but nothing previously called
    logging.basicConfig(), so those diagnostics were silently discarded.
    Without this, "the AI gave a weird answer" was undebuggable: there was no
    record of what was retrieved, what the model returned, or why grounding
    accepted/rejected each claim.

    When running as a frozen executable installed somewhere the user cannot
    write to (for example Program Files), the log directory falls back to a
    per-user location instead of crashing at startup.
    """
    candidates = [Path(__file__).resolve().parent / "runtime"]
    if getattr(sys, "frozen", False):
        # Next to the installed executable (cleaner than the _internal dir),
        # then per-user locations if the install folder is not writable.
        candidates.insert(
            0, Path(sys.executable).resolve().parent / "runtime"
        )
        candidates.append(
            Path(os.getenv("LOCALAPPDATA", str(Path.home()))) / "LogAsis" / "runtime"
        )
        candidates.append(Path(tempfile.gettempdir()) / "LogAsis" / "runtime")
    runtime_dir = candidates[0]
    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            runtime_dir = candidate
            break
        except Exception:
            continue
    log_path = runtime_dir / "logasis_ai_debug.log"
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    try:
        handlers.insert(0, logging.FileHandler(log_path, encoding="utf-8"))
    except Exception:
        pass
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
    )
    return log_path


def _set_windows_app_identity() -> None:
    """Give Windows a stable LogAsis taskbar identity when running from source.

    When launched with ``python LogAsis.py``, Windows otherwise tends to group
    the window under the Python executable and display the Python icon.  The
    AppUserModelID lets the OS treat LogAsis as its own desktop application.
    The call is a no-op on non-Windows systems.
    """
    if os.name != "nt":
        return
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "LogAsis.SecurityInvestigationWorkspace"
        )
    except Exception:
        pass


def main():
    _set_windows_app_identity()
    log_path = _configure_logging()
    logging.getLogger(__name__).info("LogAsis starting; AI diagnostics logging to %s", log_path)
    # Use Qt-owned dialogs so the LogAsis theme also covers file pickers and
    # message/input dialogs instead of handing them to the light Windows shell.
    QApplication.setAttribute(Qt.AA_DontUseNativeDialogs, True)
    app = QApplication(sys.argv)
    app.setApplicationName("LogAsis")
    app.setOrganizationName("LogAsis")
    assets_dir = Path(__file__).resolve().parent / "assets"
    icon_path = assets_dir / "logasis.ico"
    if not icon_path.exists():
        icon_path = assets_dir / "logasis.svg"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))
    apply_theme(app)
    window = MainWindow()
    # Launch maximized so the investigation workspace uses the full desktop.
    # The normal/restore button remains available and all responsive layouts
    # recalculate when the user returns to a mini window.
    window.showMaximized()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
