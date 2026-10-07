"""Central visual theme for the LogAsis desktop application.

The theme deliberately lives outside MainWindow so the UI can be refreshed
without touching investigation/business logic.  The default is a dark SOC
workspace: low-contrast surfaces, one primary accent, and semantic severity
colors used only where they carry meaning.
"""

from PySide6.QtCore import QObject, QEvent
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication, QWidget
import sys

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes


COLORS = {
    "bg": "#0B1120",
    "surface": "#111827",
    "surface_2": "#172033",
    "surface_3": "#1E293B",
    "border": "#263449",
    "border_strong": "#334155",
    "text": "#F8FAFC",
    "text_muted": "#94A3B8",
    "text_dim": "#64748B",
    "accent": "#38BDF8",
    "accent_hover": "#0EA5E9",
    "accent_pressed": "#0284C7",
    "success": "#22C55E",
    "warning": "#F59E0B",
    "danger": "#EF4444",
    "critical": "#F43F5E",
    "selection": "#164E63",
}


def _palette() -> QPalette:
    p = QPalette()
    p.setColor(QPalette.Window, QColor(COLORS["bg"]))
    p.setColor(QPalette.WindowText, QColor(COLORS["text"]))
    p.setColor(QPalette.Base, QColor(COLORS["surface"]))
    p.setColor(QPalette.AlternateBase, QColor(COLORS["surface_2"]))
    p.setColor(QPalette.ToolTipBase, QColor(COLORS["surface_3"]))
    p.setColor(QPalette.ToolTipText, QColor(COLORS["text"]))
    p.setColor(QPalette.Text, QColor(COLORS["text"]))
    p.setColor(QPalette.Button, QColor(COLORS["surface_2"]))
    p.setColor(QPalette.ButtonText, QColor(COLORS["text"]))
    p.setColor(QPalette.BrightText, QColor(COLORS["text"]))
    p.setColor(QPalette.Highlight, QColor(COLORS["selection"]))
    p.setColor(QPalette.HighlightedText, QColor(COLORS["text"]))
    p.setColor(QPalette.Link, QColor(COLORS["accent"]))
    p.setColor(QPalette.PlaceholderText, QColor(COLORS["text_dim"]))
    return p


def stylesheet() -> str:
    c = COLORS
    return f"""
    QWidget {{
        color: {c['text']};
        font-family: "Segoe UI", "Inter", Arial, sans-serif;
        font-size: 13px;
    }}

    QMainWindow, QWidget#appShell {{
        background: {c['bg']};
    }}
    QFrame#appHeader {{
        background: {c['surface']};
        border-bottom: 1px solid {c['border']};
    }}
    QLabel#brandLabel {{
        color: {c['text']};
        font-size: 18px;
        font-weight: 800;
        letter-spacing: 1px;
    }}
    QLabel#headerContext {{
        color: {c['text_muted']};
        font-size: 12px;
        font-weight: 600;
    }}
    QLabel#headerStatus {{
        color: {c['success']};
        font-size: 11px;
        font-weight: 800;
        padding: 5px 9px;
        background: {c['surface_2']};
        border: 1px solid {c['border']};
        border-radius: 10px;
    }}
    QFrame#headerDivider {{
        color: {c['border_strong']};
        background: {c['border_strong']};
        max-width: 1px;
    }}
    QFrame#sidebar {{
        background: {c['surface']};
        border-right: 1px solid {c['border']};
    }}
    QWidget#contentArea {{
        background: {c['bg']};
    }}
    QLabel#navSectionLabel {{
        color: {c['text_dim']};
        font-size: 10px;
        font-weight: 800;
        letter-spacing: 1px;
        padding: 4px 8px;
    }}
    QToolButton#navButton {{
        background: transparent;
        color: {c['text_muted']};
        border: 1px solid transparent;
        border-radius: 7px;
        text-align: left;
        padding: 9px 10px;
        min-height: 22px;
        font-weight: 600;
    }}
    QToolButton#navButton:hover {{
        background: {c['surface_2']};
        color: {c['text']};
    }}
    QToolButton#navButton:checked {{
        background: {c['selection']};
        color: {c['text']};
        border-color: #155E75;
        font-weight: 700;
    }}
    QLabel#pageTitle {{
        color: {c['text']};
        font-size: 18px;
        font-weight: 750;
        padding: 2px 0;
    }}
    QLabel#contextStatus {{
        color: {c['text_dim']};
        font-size: 11px;
        padding-left: 4px;
    }}
    QStatusBar#releaseStatus {{
        background: {c['surface']};
        color: {c['text_muted']};
        border-top: 1px solid {c['border']};
        padding: 2px 10px;
    }}

    QMenuBar {{
        background: {c['surface']};
        color: {c['text_muted']};
        border-bottom: 1px solid {c['border']};
        padding: 3px 8px;
    }}
    QMenuBar::item {{
        background: transparent;
        padding: 7px 11px;
        border-radius: 6px;
    }}
    QMenuBar::item:selected {{
        background: {c['surface_3']};
        color: {c['text']};
    }}
    QMenu {{
        background: {c['surface']};
        color: {c['text']};
        border: 1px solid {c['border_strong']};
        padding: 6px;
    }}
    QMenu::item {{
        padding: 8px 24px 8px 12px;
        border-radius: 5px;
    }}
    QMenu::item:selected {{
        background: {c['surface_3']};
    }}

    QFrame#dashboardContext {{
        background: {c['surface']};
        border: 1px solid {c['border']};
        border-radius: 10px;
    }}
    QLabel#dashboardEyebrow {{
        color: {c['accent']};
        font-size: 10px;
        font-weight: 800;
        letter-spacing: 1px;
    }}
    QLabel#dashboardContextText {{
        color: {c['text_muted']};
        font-size: 12px;
        font-weight: 600;
    }}
    QLabel#dashboardReady {{
        color: {c['success']};
        background: {c['surface_2']};
        border: 1px solid {c['border']};
        border-radius: 9px;
        padding: 5px 9px;
        font-size: 10px;
        font-weight: 800;
    }}
    QGroupBox#metricCard {{
        background: {c['surface']};
        border: 1px solid {c['border']};
        border-radius: 10px;
        margin-top: 0px;
        padding: 12px;
        min-height: 70px;
    }}
    QGroupBox#metricCard::title {{
        subcontrol-origin: padding;
        left: 0px;
        top: 0px;
        padding: 0px;
        color: {c['text_muted']};
        background: transparent;
        font-size: 10px;
        font-weight: 800;
        letter-spacing: 0.6px;
    }}
    QLabel#metricValue {{
        color: {c['text']};
        font-size: 24px;
        font-weight: 800;
        padding-top: 7px;
    }}
    QGroupBox#dashboardPanel {{
        background: {c['surface']};
        border: 1px solid {c['border']};
        border-radius: 10px;
        margin-top: 0px;
        padding: 12px;
        font-weight: 700;
    }}
    QGroupBox#dashboardPanel::title {{
        subcontrol-origin: padding;
        left: 12px;
        top: 8px;
        padding: 0 5px;
        color: {c['text_muted']};
        background: {c['surface']};
        font-size: 10px;
        font-weight: 800;
        letter-spacing: 0.8px;
    }}
    QTextEdit#dashboardSnapshot {{
        background: transparent;
        border: none;
        padding: 5px 0px;
        color: {c['text_muted']};
        font-family: "Cascadia Mono", "Consolas", monospace;
        font-size: 12px;
    }}
    QLabel#findingsSummary {{
        color: {c['text_muted']};
        font-size: 11px;
        font-weight: 700;
        padding-bottom: 2px;
    }}
    QFrame#findingCard {{
        background: {c['surface_2']};
        border: 1px solid {c['border']};
        border-left: 3px solid {c['border_strong']};
        border-radius: 8px;
    }}
    QFrame#findingCard[severity="critical"] {{
        border-left-color: {c['critical']};
    }}
    QFrame#findingCard[severity="high"] {{
        border-left-color: {c['danger']};
    }}
    QFrame#findingCard[severity="medium"] {{
        border-left-color: {c['warning']};
    }}
    QFrame#findingCard[severity="low"] {{
        border-left-color: {c['accent']};
    }}
    QLabel#severityBadge {{
        background: {c['surface_3']};
        color: {c['text_muted']};
        border: 1px solid {c['border_strong']};
        border-radius: 5px;
        padding: 4px 6px;
        font-size: 9px;
        font-weight: 900;
    }}
    QLabel#severityBadge[severity="critical"] {{
        color: {c['critical']};
        border-color: {c['critical']};
    }}
    QLabel#severityBadge[severity="high"] {{
        color: {c['danger']};
        border-color: {c['danger']};
    }}
    QLabel#severityBadge[severity="medium"] {{
        color: {c['warning']};
        border-color: {c['warning']};
    }}
    QLabel#severityBadge[severity="low"] {{
        color: {c['accent']};
        border-color: {c['accent']};
    }}
    QLabel#findingRule {{
        color: {c['text']};
        font-size: 11px;
        font-weight: 800;
    }}
    QLabel#findingSummary {{
        color: {c['text_muted']};
        font-size: 11px;
    }}
    QLabel#findingMeta {{
        color: {c['text_dim']};
        font-size: 10px;
    }}
    QLabel#dashboardEmpty {{
        color: {c['text_dim']};
        font-size: 11px;
        padding: 10px 2px;
    }}
    QPushButton#secondaryButton {{
        background: {c['surface_2']};
        color: {c['accent']};
        border: 1px solid {c['border_strong']};
        border-radius: 7px;
        padding: 7px 11px;
        font-weight: 700;
    }}
    QPushButton#secondaryButton:hover {{
        background: {c['surface_3']};
        border-color: {c['accent']};
    }}

    QLabel {{
        color: {c['text']};
    }}

    QPushButton {{
        background: {c['surface_2']};
        color: {c['text']};
        border: 1px solid {c['border_strong']};
        border-radius: 7px;
        padding: 7px 13px;
        min-height: 18px;
    }}
    QPushButton:hover {{
        background: {c['surface_3']};
        border-color: {c['accent']};
    }}
    QPushButton:pressed {{
        background: {c['accent_pressed']};
    }}
    QPushButton:disabled {{
        color: {c['text_dim']};
        background: {c['surface']};
        border-color: {c['border']};
    }}
    QPushButton#primaryButton {{
        background: {c['accent']};
        color: #06202B;
        border-color: {c['accent']};
        font-weight: 700;
    }}
    QPushButton#primaryButton:hover {{
        background: {c['accent_hover']};
        color: #FFFFFF;
    }}

    QLineEdit, QTextEdit, QTextBrowser, QComboBox {{
        background: {c['surface']};
        color: {c['text']};
        border: 1px solid {c['border']};
        border-radius: 7px;
        padding: 7px 9px;
        selection-background-color: {c['selection']};
        selection-color: {c['text']};
    }}
    QLineEdit:focus, QTextEdit:focus, QTextBrowser:focus, QComboBox:focus {{
        border-color: {c['accent']};
    }}
    QComboBox {{
        padding-right: 25px;
    }}
    QComboBox QAbstractItemView {{
        background: {c['surface']};
        color: {c['text']};
        border: 1px solid {c['border_strong']};
        selection-background-color: {c['selection']};
    }}

    QFrame#workspaceHeader {{
        background: {c['surface_2']};
        border: 1px solid {c['border']};
        border-radius: 9px;
    }}
    QLabel#workspaceEyebrow {{
        color: {c['accent']};
        font-size: 10px;
        font-weight: 900;
        letter-spacing: 1px;
    }}
    QLabel#workspaceSubtitle {{
        color: {c['text_muted']};
        font-size: 11px;
        font-weight: 600;
    }}
    QTextEdit#analystReport, QTextBrowser#analystReport {{
        background: {c['surface']};
        color: {c['text_muted']};
        border: 1px solid {c['border']};
        border-radius: 8px;
        padding: 12px;
        font-family: "Cascadia Mono", "Consolas", monospace;
        font-size: 11px;
        line-height: 1.35;
    }}
    QLabel#emptyStateTitle {{
        color: {c['text']};
        font-size: 15px;
        font-weight: 800;
    }}
    QLabel#emptyStateText {{
        color: {c['text_muted']};
        font-size: 11px;
    }}
    QToolButton#moreActions {{
        background: {c['surface_2']};
        color: {c['accent']};
        border: 1px solid {c['border_strong']};
        border-radius: 7px;
        padding: 7px 11px;
        font-weight: 700;
    }}

    QDialog, QMessageBox, QFileDialog {{
        background: {c['bg']};
        color: {c['text']};
    }}
    QDialog QLabel, QMessageBox QLabel {{
        color: {c['text']};
    }}
    QDialogButtonBox QPushButton {{
        min-width: 78px;
    }}

    QGroupBox {{
        background: {c['surface']};
        border: 1px solid {c['border']};
        border-radius: 9px;
        margin-top: 12px;
        padding: 14px 10px 10px 10px;
        font-weight: 600;
    }}
    QGroupBox::title {{
        subcontrol-origin: margin;
        left: 12px;
        padding: 0 7px;
        color: {c['text_muted']};
        background: {c['surface']};
    }}

    QTabWidget::pane {{
        background: {c['bg']};
        border: 1px solid {c['border']};
        border-radius: 9px;
        top: 0px;
    }}
    QTabBar::tab {{
        background: {c['surface']};
        color: {c['text_muted']};
        border: 1px solid transparent;
        padding: 9px 14px;
        margin-right: 3px;
        border-top-left-radius: 7px;
        border-top-right-radius: 7px;
    }}
    QTabBar::tab:hover {{
        color: {c['text']};
        background: {c['surface_2']};
    }}
    QTabBar::tab:selected {{
        color: {c['text']};
        background: {c['surface_2']};
        border-color: {c['border']};
        border-bottom-color: {c['accent']};
    }}

    QTableWidget, QTableView {{
        background: {c['surface']};
        alternate-background-color: {c['surface_2']};
        color: {c['text']};
        gridline-color: {c['border']};
        border: 1px solid {c['border']};
        border-radius: 7px;
        selection-background-color: {c['selection']};
        selection-color: {c['text']};
    }}
    QHeaderView::section {{
        background: {c['surface_3']};
        color: {c['text_muted']};
        border: none;
        border-right: 1px solid {c['border']};
        border-bottom: 1px solid {c['border_strong']};
        padding: 8px 9px;
        font-weight: 700;
    }}
    QTableCornerButton::section {{
        background: {c['surface_3']};
        border: none;
    }}

    QSplitter::handle {{
        background: {c['border']};
    }}
    QSplitter::handle:hover {{
        background: {c['accent']};
    }}

    QScrollBar:vertical {{
        background: {c['surface']};
        width: 10px;
        margin: 2px;
    }}
    QScrollBar::handle:vertical {{
        background: {c['border_strong']};
        border-radius: 5px;
        min-height: 24px;
    }}
    QScrollBar::handle:vertical:hover {{
        background: {c['text_dim']};
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical,
    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
        background: none;
        border: none;
    }}
    QScrollBar:horizontal {{
        background: {c['surface']};
        height: 10px;
        margin: 2px;
    }}
    QScrollBar::handle:horizontal {{
        background: {c['border_strong']};
        border-radius: 5px;
        min-width: 24px;
    }}

    QToolTip {{
        background: {c['surface_3']};
        color: {c['text']};
        border: 1px solid {c['border_strong']};
        padding: 6px 8px;
    }}

    QStatusBar {{
        background: {c['surface']};
        color: {c['text_muted']};
        border-top: 1px solid {c['border']};
    }}
    """



def apply_windows_titlebar_theme(window: QWidget | None) -> None:
    """Blend native Windows title bars into the LogAsis dark workspace.

    Windows 11 otherwise keeps a light caption bar even when the application
    palette is dark. DWM caption/border colors are used instead of removing the
    native frame, so resize, snap, minimize/maximize and accessibility behavior
    remain native and reliable.
    """
    if sys.platform != "win32" or window is None:
        return
    try:
        hwnd = int(window.winId())
        dwmapi = ctypes.windll.dwmapi
        # DWMWA_USE_IMMERSIVE_DARK_MODE is 20 on current Windows 10/11 and
        # 19 on some earlier builds.
        dark = wintypes.BOOL(True)
        applied = False
        for attribute in (20, 19):
            result = dwmapi.DwmSetWindowAttribute(
                wintypes.HWND(hwnd),
                wintypes.DWORD(attribute),
                ctypes.byref(dark),
                ctypes.sizeof(dark),
            )
            if result == 0:
                applied = True
                break
        if not applied:
            return

        def set_color(attribute: int, hex_color: str) -> None:
            value = int(hex_color.lstrip("#"), 16)
            colorref = wintypes.DWORD(value)
            dwmapi.DwmSetWindowAttribute(
                wintypes.HWND(hwnd),
                wintypes.DWORD(attribute),
                ctypes.byref(colorref),
                ctypes.sizeof(colorref),
            )

        # DWMWA_BORDER_COLOR=34, CAPTION_COLOR=35, TEXT_COLOR=36.
        set_color(34, COLORS["border"])
        set_color(35, COLORS["surface"])
        set_color(36, COLORS["text"])
    except (AttributeError, OSError, TypeError, ValueError):
        # Non-Windows environments and older DWM builds simply retain their
        # native title bar; the application stylesheet still applies.
        return


class _WindowChromeFilter(QObject):
    """Apply the LogAsis native titlebar treatment to every top-level window."""

    def eventFilter(self, obj, event):
        if event.type() in {
            QEvent.Show,
            QEvent.WindowActivate,
            QEvent.WindowStateChange,
        } and isinstance(obj, QWidget) and obj.isWindow():
            apply_windows_titlebar_theme(obj)
        return False


def apply_theme(app: QApplication) -> None:
    """Apply the LogAsis visual system to the whole application."""
    app.setPalette(_palette())
    app.setStyleSheet(stylesheet())

    # Keep a single filter alive for the application lifetime. This covers the
    # main window, decision dialogs, graph/comparison dialogs, AI configuration,
    # and other top-level Qt dialogs without requiring every caller to remember
    # a separate titlebar setup call.
    chrome_filter = _WindowChromeFilter(app)
    app.installEventFilter(chrome_filter)
    app._logasis_window_chrome_filter = chrome_filter
