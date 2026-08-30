from __future__ import annotations

from pathlib import Path
import html
import re

import pandas as pd
from PySide6.QtCore import Qt, QObject, QThread, Signal, QUrl, QTimer
from PySide6.QtGui import QAction, QColor, QBrush, QPen, QFont, QIcon
try:
    from shiboken6 import isValid as qt_is_valid
except ImportError:  # pragma: no cover - PySide6 normally bundles shiboken6
    def qt_is_valid(obj):
        return obj is not None

from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QToolButton,
    QFrame,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
    QGroupBox,
    QGridLayout,
    QLineEdit,
    QInputDialog,
    QMenu,
    QCheckBox,
    QScrollArea,
    QSplitter,
    QStatusBar,
    QGraphicsView,
    QGraphicsScene,
    QGraphicsEllipseItem,
    QGraphicsRectItem,
    QGraphicsLineItem,
    QGraphicsTextItem,
    QHeaderView,
    QSizePolicy,
    QProgressBar,
)

from parsers.syslog import SyslogParser
from parsers.json_log import JsonLogParser
from core.log_profile import detect_log_profile
from core.dashboard_profile_classifier import classify_dashboard_profile
from core.analytics import (
    apply_filters,
    events_to_dataframe,
    summary,
    top_source_ips,
    top_users,
    events_by_hour,
)
from core.investigation import build_investigation_report, build_event_investigation
from core.evidence import EvidenceStore
from core.cases import CaseStore
from core.investigation_case import create_case_from_candidate
from core.correlation import CorrelationEngine
from core.case_intelligence import CaseIntelligence
from core.case_comparison import CaseComparisonEngine
from core.case_graph import CaseGraphEngine
from core.case_decision import CaseDecisionEngine
from core.investigation_actions import InvestigationActionEngine
from core.case_workflow import CaseWorkflowStore
from core.ioc import extract_iocs, summarize_iocs, filter_iocs, IOC_TYPE_LABELS
from core.detections import DetectionEngine
from core.integrity import build_evidence_manifest
from core.workspace import InvestigationWorkspace
from core.investigation_session import InvestigationSession
from core.investigation_context import InvestigationContextBuilder
from core.investigation_intelligence import InvestigationIntelligence
from core.investigation_loop import InvestigationLoopEngine
from core.investigation_response import InvestigationResponseEngine
from core.reporting import build_investigation_pack, export_json as export_investigation_json, export_html as export_investigation_html, export_case_report_html
from core.case_handoff import CaseHandoffEngine
from core.case_package import CasePackageEngine, CasePackageError
from core.event_index import EventIndex
from core.workspace_journal import WorkspaceJournal
from core.investigation_guidance import derive_guidance
from ai.agent import LogInvestigatorAgent, clear_ai_session_cache
from ai.providers import AIProviderError
from ai.case_agent import CaseAIAnalyst
from ai.provider_config import load_live_config
from ai.provider_status import (
    get_provider_status,
    mark_provider_rate_limited,
    mark_provider_available,
    clear_provider_status,
)
from gui.live_ai_dialog import LiveAIConfigDialog
from gui.theme import apply_theme


SYSLOG_DISPLAY_COLUMNS = [
    ("timestamp", "Timestamp"),
    ("event_type", "Event Type"),
    ("source_ip", "Source IP"),
    ("destination_ip", "Destination IP"),
    ("username", "Username"),
    ("process_name", "Process"),
    ("command", "Command"),
    ("pid", "PID"),
    ("ppid", "PPID"),
    ("uid", "UID"),
    ("euid", "EUID"),
    ("auid", "AUID"),
    ("action", "Action"),
    ("severity", "Severity"),
    ("message", "Message"),
    ("line", "Line"),
]



AUTH_DISPLAY_COLUMNS = [
    ("timestamp", "Timestamp"),
    ("event_type", "Event Type"),
    ("source_ip", "Source IP"),
    ("destination_ip", "Destination IP"),
    ("username", "User"),
    ("process_name", "Process"),
    ("command", "Command"),
    ("action", "Action"),
    ("severity", "Severity"),
    ("pid", "PID"),
    ("uid", "UID"),
    ("auid", "AUID"),
    ("message", "Message"),
    ("line", "Line"),
]

SYSMON_DISPLAY_COLUMNS = [
    ("timestamp", "Timestamp"),
    ("event_id", "Event ID"),
    ("event_type", "Event Type"),
    ("rule_name", "Rule Name"),
    ("process_name", "Process / Image"),
    ("command", "Command Line"),
    ("parent_image", "Parent Image"),
    ("parent_command", "Parent Command Line"),
    ("pid", "PID"),
    ("ppid", "Parent PID"),
    ("username", "User"),
    ("source_ip", "Source IP"),
    ("source_port", "Source Port"),
    ("destination_ip", "Destination IP"),
    ("destination_port", "Destination Port"),
    ("protocol", "Protocol"),
    ("action", "Action"),
    ("severity", "Severity"),
    ("hashes", "Hashes"),
    ("message", "Message"),
    ("line", "Record"),
]

WINDOWS_DISPLAY_COLUMNS = [
    ("timestamp", "Timestamp"),
    ("event_id", "Event ID"),
    ("event_type", "Event Type"),
    ("Provider", "Provider"),
    ("Channel", "Channel"),
    ("username", "User"),
    ("process_name", "Process"),
    ("command", "Command"),
    ("pid", "PID"),
    ("source_ip", "Source IP"),
    ("destination_ip", "Destination IP"),
    ("action", "Action"),
    ("severity", "Severity"),
    ("message", "Message"),
    ("line", "Record"),
]

WEB_DISPLAY_COLUMNS = [
    ("timestamp", "Timestamp"),
    ("source_ip", "Client IP"),
    ("username", "User"),
    ("event_type", "Event Type"),
    ("action", "Action"),
    ("status_code", "Status"),
    ("request_method", "Method"),
    ("url", "URL"),
    ("uri", "URI"),
    ("user_agent", "User Agent"),
    ("destination_ip", "Server IP"),
    ("severity", "Severity"),
    ("message", "Message"),
    ("line", "Record"),
]

FIREWALL_DISPLAY_COLUMNS = [
    ("timestamp", "Timestamp"),
    ("source_ip", "Source IP"),
    ("source_port", "Source Port"),
    ("destination_ip", "Destination IP"),
    ("destination_port", "Destination Port"),
    ("protocol", "Protocol"),
    ("action", "Action"),
    ("event_type", "Event Type"),
    ("severity", "Severity"),
    ("rule_name", "Rule"),
    ("message", "Message"),
    ("line", "Record"),
]

DNS_DISPLAY_COLUMNS = [
    ("timestamp", "Timestamp"),
    ("source_ip", "Client IP"),
    ("destination_ip", "DNS Server"),
    ("query_name", "Query Name"),
    ("query_type", "Query Type"),
    ("rcode", "RCode"),
    ("action", "Action"),
    ("event_type", "Event Type"),
    ("severity", "Severity"),
    ("message", "Message"),
    ("line", "Record"),
]


def _dynamic_json_columns(df, preferred):
    columns = [(key, label) for key, label in preferred if key in df.columns]
    used = {key for key, _ in columns}
    internal = {"timestamp_dt", "hour", "date", "raw_log"}
    for key in df.columns:
        if key in used or key in internal or key.startswith("_"):
            continue
        # Keep the generic table useful: source fields first, not every derived field.
        label = str(key).replace("_", " ").strip().title()
        columns.append((key, label))
    return columns[:30]


def display_columns_for_profile(profile_id, df):
    if profile_id == "authentication_ssh":
        return AUTH_DISPLAY_COLUMNS
    if profile_id == "syslog":
        return SYSLOG_DISPLAY_COLUMNS
    if profile_id == "sysmon_json":
        return _dynamic_json_columns(df, SYSMON_DISPLAY_COLUMNS)
    if profile_id == "windows_json":
        return _dynamic_json_columns(df, WINDOWS_DISPLAY_COLUMNS)
    if profile_id == "web_server":
        return _dynamic_json_columns(df, WEB_DISPLAY_COLUMNS)
    if profile_id == "firewall_network":
        return _dynamic_json_columns(df, FIREWALL_DISPLAY_COLUMNS)
    if profile_id == "dns":
        return _dynamic_json_columns(df, DNS_DISPLAY_COLUMNS)
    return _dynamic_json_columns(df, [
        ("timestamp", "Timestamp"),
        ("event_type", "Event Type"),
        ("event_id", "Event ID"),
        ("source_ip", "Source IP"),
        ("destination_ip", "Destination IP"),
        ("username", "User"),
        ("process_name", "Process"),
        ("command", "Command"),
        ("action", "Action"),
        ("severity", "Severity"),
        ("message", "Message"),
        ("line", "Record"),
    ])


def _case_ai_to_html(answer: str, case: dict | None = None, question: str = "") -> str:
    """Render AI case analysis as a professional, navigable analyst report.

    Presentation only: deterministic case facts are not changed here.  AI
    Markdown links are converted to clean internal navigation anchors so
    schemes such as ``user://`` or ``evidence://`` never leak into the UI.
    """
    text = str(answer or "").replace("\r\n", "\n").strip()
    if not text:
        return "<p class='empty-report'>No analyst output was returned.</p>"

    # Normalize common formatting artifacts produced by local/remote models.
    text = re.sub(r"\[(CASE)?CASE-(\d{6})\]", r"CASE-\2", text, flags=re.IGNORECASE)
    text = re.sub(r"\bCASECASE-(\d{6})\b", r"CASE-\1", text, flags=re.IGNORECASE)

    # The report renderer owns case metadata and navigation. Strip provider
    # metadata and internal URI syntax before rendering so these implementation
    # details can never leak into the visible report.
    text = re.sub(
        r"(?im)^\s*(?:CASE\s*ID|CASE|STATUS|PRIORITY|TITLE)\s*[:：]?\s*"
        r"(?:CASE-\d{6}|Resolved|New|Investigation|In Progress|Closed|Open|"
        r"LOW|MEDIUM|HIGH|CRITICAL|[^\n]{0,120})\s*$",
        "",
        text,
    )
    text = re.sub(
        r"\[([^\]]+)\]\((?:user|ip|evidence|process|correlation)://[^)]+\)",
        r"\1",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(r"\b(?:user|ip|evidence|process|correlation)://[^\s)]+", "", text, flags=re.IGNORECASE)
    text = re.sub(r"^\s*#{1,6}\s*", "", text, flags=re.MULTILINE)

    headings = {
        "CASE ANALYST REPORT",
        "EXECUTIVE SUMMARY",
        "RISK ASSESSMENT",
        "OBSERVED EVIDENCE",
        "KEY FINDINGS",
        "EVIDENCE",
        "CORRELATION & CONTEXT",
        "CORRELATION",
        "ASSESSMENT & LIMITATIONS",
        "ASSESSMENT",
        "LIMITATIONS",
        "WHAT THE EVIDENCE SUPPORTS",
        "WHAT THE EVIDENCE DOES NOT PROVE",
        "WHAT THE EVIDENCE DOES NOT ESTABLISH",
        "MISSING CONTEXT",
        "MISSING CONTEXT / LIMITATIONS",
        "RECOMMENDED NEXT STEPS",
        "RECOMMENDED ACTIONS",
        "ANALYST CONCLUSION",
    }

    body = []
    in_list = None

    def close_list():
        nonlocal in_list
        if in_list == "ul":
            body.append("</ul>")
        elif in_list == "ol":
            body.append("</ol>")
        in_list = None

    def make_anchor(scheme: str, value: str, label: str, css="entity-link") -> str:
        return (
            f'<a href="{scheme}://{html.escape(value, quote=True)}" '
            f'class="{css}">{html.escape(label)}</a>'
        )

    def linkify(raw: str) -> str:
        # Convert explicit Markdown links first. This is the main fix for
        # output such as [btlo](user://btlo) appearing literally in the UI.
        protected = {}

        def protect(value: str) -> str:
            key = f"__LOGASIS_LINK_{len(protected)}__"
            protected[key] = value
            return key

        def md_link(match):
            label = re.sub(r"\*\*(.*?)\*\*", r"\1", match.group(1))
            target = match.group(2).strip()
            if "://" not in target:
                return match.group(0)
            scheme, value = target.split("://", 1)
            if scheme.lower() in {"evidence", "ip", "user", "process"}:
                return protect(make_anchor(scheme.lower(), value, label))
            if scheme.lower() == "correlation":
                return protect(
                    f'<a href="correlation://{html.escape(value, quote=True)}" '
                    f'class="correlation-link">{html.escape(label)}</a>'
                )
            return match.group(0)

        raw = re.sub(r"\[([^\]]+)\]\(([^)\s]+://[^)]+)\)", md_link, raw)

        # Bold/inline-code are handled after explicit links are protected.
        raw = re.sub(r"\*\*(.*?)\*\*", r"\1", raw)

        # Correlation pair is one navigation target.
        raw = re.sub(
            r"\b(EV-\d+)\s*(?:<->|↔|->)\s*(EV-\d+)\b",
            lambda m: protect(
                f'<a href="correlation://{m.group(1)}|{m.group(2)}" '
                f'class="correlation-link">{m.group(1)} ↔ {m.group(2)}</a>'
            ),
            raw,
            flags=re.IGNORECASE,
        )

        raw = re.sub(
            r"\bEV-\d+\b",
            lambda m: protect(make_anchor("evidence", m.group(0), m.group(0), "evidence-link")),
            raw,
            flags=re.IGNORECASE,
        )

        raw = re.sub(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            lambda m: protect(make_anchor("ip", m.group(0), m.group(0))),
            raw,
        )

        known_users = sorted(
            {str(x).strip() for x in (case or {}).get("users", []) if str(x).strip()},
            key=len, reverse=True,
        )
        known_processes = sorted(
            {
                str(e.get("process_name", "")).strip()
                for e in ((case or {}).get("timeline", []) or [])
                if str(e.get("process_name", "")).strip()
            },
            key=len, reverse=True,
        )
        for username in known_users:
            raw = re.sub(
                rf"(?<![\w]){re.escape(username)}(?![\w])",
                lambda m, u=username: protect(make_anchor("user", u, m.group(0))),
                raw,
                flags=re.IGNORECASE,
            )
        for process_name in known_processes:
            if len(process_name) < 2:
                continue
            raw = re.sub(
                rf"(?<![\w]){re.escape(process_name)}(?![\w])",
                lambda m, p=process_name: protect(make_anchor("process", p, m.group(0))),
                raw,
                flags=re.IGNORECASE,
            )

        safe = html.escape(raw)
        # The protected anchors contain HTML and therefore must be restored
        # after escaping the remaining text.
        for key, value in protected.items():
            safe = safe.replace(html.escape(key), value)
        safe = re.sub(r"`([^`]+)`", r'<span class="mono">\1</span>', safe)
        return safe

    for raw_line in text.split("\n"):
        line = raw_line.strip()
        if not line:
            close_list()
            continue

        normalized = re.sub(r"^\s*\d+[.)]\s*", "", line).strip().upper()
        normalized = re.sub(r"^\s*\*+\s*|\s*\*+\s*$", "", normalized)
        if normalized in headings:
            close_list()
            heading_name = re.sub(r"^\s*\d+[.)]\s*", "", line).strip()
            heading_name = re.sub(r"^\*+|\*+$", "", heading_name).strip()
            if heading_name.upper() == "CASE ANALYST REPORT":
                # The case header renders the report title exactly once.
                continue
            else:
                body.append(
                    f'<div class="report-section">{html.escape(heading_name.title())}</div>'
                )
            continue

        bullet = re.match(r"^(?:[-*•])\s+(.*)$", line)
        numbered = re.match(r"^\d+[.)]\s+(.*)$", line)
        if bullet:
            if in_list != "ul":
                close_list()
                body.append("<ul>")
                in_list = "ul"
            body.append(f"<li>{linkify(bullet.group(1))}</li>")
            continue
        if numbered:
            if in_list != "ol":
                close_list()
                body.append("<ol>")
                in_list = "ol"
            body.append(f"<li>{linkify(numbered.group(1))}</li>")
            continue

        close_list()
        body.append(f"<p>{linkify(line)}</p>")

    close_list()

    raw_case_id = str((case or {}).get("case_id", "") or "").strip()
    match = re.search(r"(\d{6})$", raw_case_id)
    case_id = f"CASE-{match.group(1)}" if match else raw_case_id
    priority = str((case or {}).get("priority", "") or "N/A")
    status = str((case or {}).get("status", "") or "N/A")
    title = str((case or {}).get("title", "") or "")
    question_text = str(question or "").strip()

    metadata = ""
    if case_id:
        metadata = f"""
        <div class="case-header">
          <div class="case-header-main">
            <div class="report-title">Case Analyst Report</div>
            <div class="case-title">{html.escape(title)}</div>
          </div>
          <div class="case-meta">
            <div><span class="meta-label">CASE</span><strong>{html.escape(case_id)}</strong></div>
            <div><span class="meta-label">STATUS</span><strong>{html.escape(status)}</strong></div>
            <div><span class="meta-label">PRIORITY</span><strong>{html.escape(priority)}</strong></div>
          </div>
        </div>
        """
    if question_text:
        metadata += f"""
        <div class="question-box">
          <div class="question-label">INVESTIGATION QUESTION</div>
          <div class="question-text">{html.escape(question_text)}</div>
        </div>
        """

    return """<!DOCTYPE html>
<html><head><style>
body {
  font-family: 'Segoe UI'; font-size: 10pt; color: #202124;
  background: #ffffff; margin: 8px 10px 18px 10px;
}
.case-header {
  border: 1px solid #d9dee7; border-radius: 7px; padding: 10px 12px;
  background: #fafbfc; margin-bottom: 10px;
}
.case-header-main { margin-bottom: 8px; }
.report-title { font-size: 17pt; font-weight: 700; margin: 0 0 3px 0; }
.case-title { color: #4b5563; font-size: 10pt; }
.case-meta { display: flex; gap: 24px; }
.meta-label { color: #6b7280; font-size: 8pt; font-weight: 700; margin-right: 6px; }
.question-box {
  background: #f6f8fa; border: 1px solid #dfe3e8; border-radius: 6px;
  padding: 9px 11px; margin: 8px 0 13px 0;
}
.question-label { color: #6b7280; font-size: 8pt; font-weight: 700; margin-bottom: 3px; }
.question-text { font-weight: 600; }
.report-section {
  font-size: 11pt; font-weight: 700; margin: 15px 0 6px 0;
  padding: 5px 0; border-bottom: 1px solid #d9dce1;
}
p { margin: 4px 0 7px 0; line-height: 1.42; }
ul, ol { margin-top: 3px; margin-bottom: 9px; }
li { margin: 4px 0; line-height: 1.4; }
.mono { font-family: Consolas, 'Courier New'; background: #f1f3f4; padding: 1px 3px; }
a { color: #175cd3; text-decoration: none; font-weight: 600; }
a:hover { text-decoration: underline; }
.empty-report { color: #6b7280; }
</style></head><body>""" + metadata + "".join(body) + "</body></html>"


class AIWorker(QObject):
    # answer, provider label, model name
    finished = Signal(str, str, str)
    failed = Signal(str)
    prepared = Signal(str)
    progress = Signal(int, str)

    def __init__(self, provider_name, question, df, source_file=""):
        super().__init__()
        self.provider_name = provider_name
        self.question = question
        self.df = df.copy()
        self.source_file = str(source_file or "")
        self.cancel_requested = False
        self.session_generation = 0

    def cancel(self):
        self.cancel_requested = True

    def run(self):
        try:
            self.prepared.emit(
                f"{len(self.df):,} parsed events • bounded agentic investigation • "
                "read-only evidence tools • shared grounding"
            )
            if self.cancel_requested:
                self.failed.emit("AI analysis cancelled by analyst.")
                return
            agent = LogInvestigatorAgent.with_provider(
                self.provider_name, progress_callback=self._progress
            )
            answer = agent.answer(self.question, self.df, self.source_file)
            provider = getattr(agent, "provider", None)
            provider_label = getattr(provider, "name", self.provider_name)
            model = getattr(provider, "model", "") or "configured model"
            if self.cancel_requested:
                self.failed.emit("AI analysis cancelled by analyst.")
                return
            if self.provider_name == "Live AI":
                mark_provider_available("Live AI")
            self.finished.emit(answer, str(provider_label), str(model))
        except AIProviderError as exc:
            if exc.is_rate_limited:
                retry = f" Retry-After: {exc.retry_after}." if exc.retry_after else ""
                mark_provider_rate_limited("Live AI", exc.retry_after)
                self.failed.emit(
                    "AI_RATE_LIMITED|"
                    "Live AI is temporarily unavailable because the provider rate/quota or free-tier quota has been reached. "
                    "Please try again later. No investigation data was changed." + retry
                )
            else:
                self.failed.emit(str(exc))
        except Exception as exc:
            self.failed.emit(str(exc))

    def _progress(self, percent, message):
        if not self.cancel_requested:
            self.progress.emit(int(percent), str(message))


class CaseAIWorker(QObject):
    finished = Signal(str, str, str)
    failed = Signal(str)
    def __init__(self, provider_name, question, report):
        super().__init__()
        self.provider_name, self.question, self.report = provider_name, question, report
    def run(self):
        try:
            analyst = CaseAIAnalyst(self.provider_name)
            answer = analyst.answer(self.question, self.report)
            provider = analyst.provider
            self.finished.emit(str(answer), str(getattr(provider, "name", self.provider_name)),
                               str(getattr(provider, "model", "") or "configured model"))
        except Exception as exc:
            self.failed.emit(str(exc))



class AnalysisWorker(QObject):
    """Runs expensive deterministic analysis away from the Qt GUI thread."""
    progress = Signal(int, str)
    finished = Signal(int, object)
    failed = Signal(int, str)

    def __init__(self, generation, events, source_file):
        super().__init__()
        self.generation = generation
        self.events = events
        self.source_file = source_file

    def run(self):
        try:
            self.progress.emit(10, "Preparing deterministic analysis…")
            self._check_cancel()
            events = list(self.events)

            self.progress.emit(30, "Building investigation candidates…")
            report = build_investigation_report(pd.DataFrame(events))

            self._check_cancel()
            self.progress.emit(55, "Extracting IOCs…")
            iocs = extract_iocs(events)

            self._check_cancel()
            self.progress.emit(75, "Running deterministic detections…")
            detections = DetectionEngine().run(events)

            self._check_cancel()
            self.progress.emit(90, "Building evidence integrity manifest…")
            manifest = build_evidence_manifest(self.source_file, events, [])

            self.progress.emit(100, "Analysis complete")
            self.finished.emit(self.generation, {
                "report": report,
                "iocs": iocs,
                "detections": detections,
                "manifest": manifest,
            })
        except Exception as exc:
            self.failed.emit(self.generation, str(exc))

    def _check_cancel(self):
        # Generation-based invalidation is handled by MainWindow. This worker
        # deliberately avoids mutating GUI state, so stale results are harmless.
        return


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LogAsis")
        assets_dir = Path(__file__).resolve().parent.parent / "assets"
        icon_path = assets_dir / "logasis.ico"
        if not icon_path.exists():
            icon_path = assets_dir / "logasis.svg"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))
        # Start at a comfortable size but never force a desktop-sized minimum.
        # The shell below adapts its navigation, toolbars and splitters so the
        # same workspace remains usable when maximised or restored to a small
        # laptop/windowed size.
        self.resize(1450, 850)
        # Keep the window genuinely resizable: the layout, not the window,
        # owns the responsive behavior.  A modest minimum still permits a
        # restored/mini window on a laptop while preventing unusable geometry.
        self.setMinimumSize(760, 500)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._responsive_compact = False
        self._responsive_tiny = False

        self.df = pd.DataFrame()
        self.filtered_df = pd.DataFrame()
        self.current_file = ""
        self.log_profile = {"id": "none", "name": "No log loaded", "parser": ""}
        # No table layout is selected before a log is loaded. The uploaded
        # log profile determines the table columns.
        self.display_columns = []
        self.evidence_store = EvidenceStore(Path("data/evidence.json"))
        self.case_store = CaseStore(Path("data/cases.json"))
        self.correlation_engine = CorrelationEngine(self.evidence_store)
        self.case_intelligence = CaseIntelligence(self.correlation_engine)
        self.case_workflow = CaseWorkflowStore(Path("data/case_workflow.json"))
        self.detection_engine = DetectionEngine()
        self.workspace = InvestigationWorkspace(Path("data/investigation_workspace.json"))
        self.investigation_session = InvestigationSession()
        self.investigation_context = InvestigationContextBuilder()
        self.investigation_intelligence = InvestigationIntelligence()
        self.investigation_loop = InvestigationLoopEngine()
        self._iocs = {k: [] for k in ("ipv4","domain","url","hash","username","process")}
        self._detections = []
        self._investigation_events = []
        # Large-dataset acceleration and paginated event rendering.
        self.event_index = EventIndex()
        self._analysis_generation = 0
        self._analysis_thread = None
        self._analysis_worker = None
        self._analysis_cache = None
        self._ai_thread = None
        self._ai_worker = None
        self._event_page = 0
        self._event_page_size = 500
        self._event_page_count = 1
        # Crash-safe workspace journal. Security conclusions remain in the
        # existing case/evidence stores; this only records resumable UI state.
        self.workspace_journal = WorkspaceJournal(Path("runtime"))
        self._recovery_prompted = False
        self._selected_case_id_cache = None
        self._case_ai_report_id = None
        self._case_ai_answer = ""
        self._case_ai_provider_label = ""
        self._case_ai_model = ""
        self._case_ai_question_snapshot = ""
        self._ai_cancelled = False
        # AI Analyst session generation prevents stale worker results from an older log.
        self._ai_session_generation = 0
        clear_ai_session_cache()
        # Provider status is process-local. The timer refreshes the UX after a
        # 429 but never retries a provider request automatically.
        self._ai_status_timer = QTimer(self)
        self._ai_status_timer.setInterval(1000)
        self._ai_status_timer.timeout.connect(self._refresh_ai_provider_status)
        self._ai_status_timer.start()

        # Responsive splitter state. A user drag is preserved; ordinary
        # window resizing recalculates geometry from the new viewport.
        self._case_workspace_ratios = None
        self._case_detail_ratios = None
        self._ops_bottom_ratios = None
        self._ops_inventory_ratios = None
        self._case_detail_orientation = None
        self._ops_inventory_orientation = None
        self._responsive_splitters_initialized = False

        self._build_ui()

    def _build_ui(self):
        """Build the release UI shell.

        The investigation widgets themselves remain unchanged.  This method
        only provides the modern navigation/presentation layer around them.
        """
        central = QWidget()
        central.setObjectName("appShell")
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        self.setCentralWidget(central)

        # ── Top application bar ──────────────────────────────────────────
        header = QFrame()
        header.setObjectName("appHeader")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 12, 20, 12)
        header_layout.setSpacing(14)

        brand = QLabel("◈  LOGASIS")
        brand.setObjectName("brandLabel")
        header_layout.addWidget(brand)

        divider = QFrame()
        divider.setObjectName("headerDivider")
        divider.setFrameShape(QFrame.VLine)
        header_layout.addWidget(divider)

        self.header_context = QLabel("Security Investigation Workspace")
        self.header_context.setObjectName("headerContext")
        header_layout.addWidget(self.header_context, 1)

        self.header_status = QLabel("●  READY")
        self.header_status.setObjectName("headerStatus")
        header_layout.addWidget(self.header_status)

        root.addWidget(header)

        # ── Main workspace ────────────────────────────────────────────────
        workspace = QHBoxLayout()
        workspace.setContentsMargins(0, 0, 0, 0)
        workspace.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setMinimumWidth(184)
        sidebar.setMaximumWidth(224)
        self._sidebar = sidebar
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(12, 16, 12, 14)
        sidebar_layout.setSpacing(4)

        nav_title = QLabel("WORKSPACE")
        nav_title.setObjectName("navSectionLabel")
        sidebar_layout.addWidget(nav_title)

        # Keep the real QTabWidget as the navigation/content controller.
        # Its tab bar is hidden; existing tests and feature code can continue
        # using self.tabs without modification.
        nav_items = [
            ("◉", "Dashboard", 1, "Overview"),
            ("≡", "Events", 0, "Event Log"),
            ("◷", "Timeline", 2, "Event Timeline"),
            ("◇", "IP Analysis", 3, "Network Analysis"),
            ("♙", "Authentication", 4, "Authentication / SSH"),
        ]
        self._nav_buttons = []
        for icon, label, index, context in nav_items:
            btn = self._make_nav_button(icon, label, index)
            btn.setProperty("navGroup", "analysis")
            btn.clicked.connect(lambda checked=False, i=index, c=context: self._navigate_to(i, c))
            sidebar_layout.addWidget(btn)
            self._nav_buttons.append(btn)

        invest_label = QLabel("INVESTIGATION")
        invest_label.setObjectName("navSectionLabel")
        sidebar_layout.addSpacing(14)
        sidebar_layout.addWidget(invest_label)

        nav_items = [
            ("⚠", "Investigation", 5, "Investigation Workspace"),
            ("⛨", "Evidence", 6, "Evidence Collection"),
            ("▣", "Cases", 7, "Case Management"),
        ]
        for icon, label, index, context in nav_items:
            btn = self._make_nav_button(icon, label, index)
            btn.setProperty("navGroup", "investigation")
            btn.clicked.connect(lambda checked=False, i=index, c=context: self._navigate_to(i, c))
            sidebar_layout.addWidget(btn)
            self._nav_buttons.append(btn)

        intel_label = QLabel("INTELLIGENCE")
        intel_label.setObjectName("navSectionLabel")
        sidebar_layout.addSpacing(14)
        sidebar_layout.addWidget(intel_label)

        nav_items = [
            ("✦", "AI Analyst", 8, "AI-Assisted Analysis"),
            ("⚙", "Findings", 9, "Findings & IOC Operations"),
        ]
        for icon, label, index, context in nav_items:
            btn = self._make_nav_button(icon, label, index)
            btn.setProperty("navGroup", "intelligence")
            btn.clicked.connect(lambda checked=False, i=index, c=context: self._navigate_to(i, c))
            sidebar_layout.addWidget(btn)
            self._nav_buttons.append(btn)

        sidebar_layout.addStretch(1)

        self.upload_btn = QPushButton("＋  Upload Log")
        self.upload_btn.setObjectName("primaryButton")
        self.upload_btn.setToolTip("Upload a security log for analysis")
        self.upload_btn.clicked.connect(self.upload_log)
        sidebar_layout.addWidget(self.upload_btn)

        workspace.addWidget(sidebar)

        # ── Content area ─────────────────────────────────────────────────
        content = QWidget()
        content.setObjectName("contentArea")
        self.contentArea = content
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(18, 16, 18, 10)
        content_layout.setSpacing(10)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self.page_title = QLabel("Dashboard")
        self.page_title.setObjectName("pageTitle")
        toolbar.addWidget(self.page_title)

        # Event filtering is page-local.  The old implementation placed the
        # event search in the global workspace toolbar, which made an Events
        # filter appear on unrelated pages and implied that it controlled every
        # workspace.  Keep the same widget/slot contracts, but build the actual
        # controls inside the Events page below.
        self.filter_combo = QComboBox()
        self.filter_combo.addItem("All fields", "All")
        self.filter_combo.setMinimumWidth(120)
        self.filter_combo.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self.filter_combo.setToolTip(
            "Choose an event field. Available values are populated automatically from the loaded log."
        )
        self.filter_combo.currentIndexChanged.connect(self._on_filter_field_changed)

        # Value selection is data-driven. The investigator never has to type an
        # IP/user/process/etc. manually: changing the field rebuilds this list
        # from the currently loaded dataframe.
        self.filter_value_combo = QComboBox()
        self.filter_value_combo.addItem("All values", "")
        self.filter_value_combo.setMinimumWidth(180)
        self.filter_value_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.filter_value_combo.setToolTip(
            "Choose a value discovered in the loaded log; matching events are shown immediately."
        )
        self.filter_value_combo.currentIndexChanged.connect(self.apply_current_filter)

        # Retain the text-search widget for backwards compatibility and for
        # power users, but the normal filter workflow does not require it.
        self.search = QLineEdit()
        self.search.setPlaceholderText("Optional text search…")
        self.search.setClearButtonEnabled(True)
        self.search.setMinimumWidth(120)
        self.search.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.search.textChanged.connect(self.apply_current_filter)

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear_filter)

        self.status = QLabel("No log loaded")
        self.status.setObjectName("contextStatus")

        toolbar.addStretch(1)
        toolbar.addWidget(self.status)
        content_layout.addLayout(toolbar)

        # Hidden until the Events page owns the controls.  Keeping these
        # objects here preserves compatibility with existing filter methods.
        self.filter_combo.setVisible(False)
        self.filter_value_combo.setVisible(False)
        self.search.setVisible(False)
        self.clear_btn.setVisible(False)

        self.tabs = QTabWidget()
        # The sidebar is the primary navigation. Keeping the QTabWidget
        # underneath preserves all existing feature/test contracts.
        self.tabs.tabBar().hide()
        content_layout.addWidget(self.tabs, 1)

        self.events_tab = QWidget()
        self.dashboard_tab = QWidget()
        self.timeline_tab = QWidget()
        self.ip_tab = QWidget()
        self.auth_tab = QWidget()
        self.investigation_tab = QWidget()
        self.evidence_tab = QWidget()
        self.cases_tab = QWidget()
        self.ai_tab = QWidget()
        self.operations_tab = QWidget()

        self.tabs.addTab(self.events_tab, "Events")
        self.tabs.addTab(self.dashboard_tab, "Dashboard")
        self.tabs.addTab(self.timeline_tab, "Timeline")
        self.tabs.addTab(self.ip_tab, "IP Analysis")
        self.tabs.addTab(self.auth_tab, "Authentication")
        self.tabs.addTab(self.investigation_tab, "Investigation")
        self.tabs.addTab(self.evidence_tab, "Evidence")
        self.tabs.addTab(self.cases_tab, "Cases")
        self.tabs.addTab(self.ai_tab, "AI Analysis")
        self.tabs.addTab(self.operations_tab, "Operations")

        self._build_events_tab()
        self._build_dashboard_tab()
        self._build_text_tabs()
        self._build_investigation_tab()
        self._build_evidence_tab()
        self._build_cases_tab()
        self._build_ai_tab()
        self._build_operations_tab()

        self.tabs.currentChanged.connect(self.refresh_active_tab)
        self.tabs.currentChanged.connect(self._sync_navigation)
        self.tabs.currentChanged.connect(self._sync_page_search_controls)

        # Default view.
        self.tabs.setCurrentIndex(1)
        self._sync_navigation(1)
        self._sync_page_search_controls(1)

        workspace.addWidget(content, 1)
        root.addLayout(workspace, 1)

        # ── Bottom status strip ──────────────────────────────────────────
        self.release_status = QStatusBar()
        self.release_status.setObjectName("releaseStatus")
        self.release_status.showMessage("Ready • No log loaded")
        self.setStatusBar(self.release_status)

        menu = self.menuBar().addMenu("File")
        export_action = QAction("Export Filtered CSV", self)
        export_action.triggered.connect(self.export_csv)
        menu.addAction(export_action)

        self.menuBar().setVisible(False)

    def _make_nav_button(self, icon: str, label: str, index: int) -> QToolButton:
        btn = QToolButton()
        btn.setObjectName("navButton")
        btn.setText(f"{icon}   {label}")
        btn.setToolTip(label)
        btn.setProperty("pageIndex", index)
        btn.setCheckable(True)
        btn.setAutoExclusive(True)
        btn.setCursor(Qt.PointingHandCursor)
        btn.setToolButtonStyle(Qt.ToolButtonTextOnly)
        btn.setSizePolicy(btn.sizePolicy().horizontalPolicy(), btn.sizePolicy().verticalPolicy())
        return btn

    def _navigate_to(self, index: int, context: str):
        self.tabs.setCurrentIndex(index)
        self.page_title.setText(context)
        self.header_context.setText(context)

    def _sync_page_search_controls(self, index: int):
        """Show search controls only on pages that own a search operation."""
        # Events is currently the only workspace whose global text search
        # directly filters the loaded event dataframe.  Evidence and Cases
        # already expose their own status/priority controls, while Timeline,
        # IP Analysis and Authentication are report workspaces rather than
        # independent event filters.
        visible = int(index) == 0
        for widget in (
            getattr(self, "filter_combo", None),
            getattr(self, "filter_value_combo", None),
            getattr(self, "search", None),
            getattr(self, "clear_btn", None),
        ):
            if widget is not None:
                widget.setVisible(visible)

    def _sync_navigation(self, index: int):
        for btn in getattr(self, "_nav_buttons", []):
            active = int(btn.property("pageIndex")) == index
            btn.setChecked(active)
        names = {
            0: "Event Log",
            1: "Dashboard",
            2: "Event Timeline",
            3: "Network Analysis",
            4: "Authentication / SSH",
            5: "Investigation Findings",
            6: "Evidence Collection",
            7: "Case Management",
            8: "AI-Assisted Analysis",
            9: "IOC & Detection Operations",
        }
        title = names.get(index, "Security Investigation Workspace")
        self.page_title.setText(title)
        self.header_context.setText(title)
    # ── Responsive UI helpers ────────────────────────────────────────────
    @staticmethod
    def _fit_table(table, stretch_columns=(), content_columns=(), min_row_height=28):
        """Give dense analyst tables predictable, responsive column behavior."""
        if table is None:
            return
        table.setWordWrap(True)
        table.setTextElideMode(Qt.ElideRight)
        table.setAlternatingRowColors(True)
        table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        table.verticalHeader().setDefaultSectionSize(min_row_height)
        table.verticalHeader().setMinimumSectionSize(min_row_height)
        header = table.horizontalHeader()
        header.setMinimumSectionSize(70)
        header.setStretchLastSection(False)
        for col in content_columns:
            if 0 <= col < table.columnCount():
                header.setSectionResizeMode(col, QHeaderView.ResizeToContents)
        for col in stretch_columns:
            if 0 <= col < table.columnCount():
                header.setSectionResizeMode(col, QHeaderView.Stretch)

    @staticmethod
    def _splitter_ratios(splitter):
        sizes = [max(0, int(v)) for v in splitter.sizes()]
        total = sum(sizes)
        if total <= 0:
            return None
        return [v / total for v in sizes]

    def _mark_case_workspace_resized(self, *_args):
        self._case_workspace_ratios = self._splitter_ratios(self.case_workspace_splitter)

    def _mark_case_detail_resized(self, *_args):
        self._case_detail_ratios = self._splitter_ratios(self.case_detail_splitter)

    def _mark_ops_bottom_resized(self, *_args):
        self._ops_bottom_ratios = self._splitter_ratios(self.ops_bottom_splitter)

    def _mark_ops_inventory_resized(self, *_args):
        self._ops_inventory_ratios = self._splitter_ratios(self.ops_inventory_splitter)

    @staticmethod
    def _set_splitter_sizes(splitter, sizes):
        """Set splitter sizes without treating the programmatic change as a drag."""
        if splitter is None:
            return
        blocker = splitter.blockSignals(True)
        try:
            splitter.setSizes([max(1, int(v)) for v in sizes])
        finally:
            splitter.blockSignals(blocker)

    def _configure_case_layout(self):
        """Adapt the case workspace to both wide and restored/mini windows."""
        splitter = getattr(self, "case_detail_splitter", None)
        if splitter is not None:
            vertical = self.width() < 1100
            new_orientation = Qt.Vertical if vertical else Qt.Horizontal
            old_orientation = getattr(self, "_case_detail_orientation", None)
            if old_orientation != new_orientation:
                splitter.setOrientation(new_orientation)
                self._case_detail_orientation = new_orientation
                # A breakpoint change invalidates the old pixel geometry.
                self._case_detail_ratios = None

            # The workflow panel must never collapse into a few text lines.
            if vertical:
                h = max(260, splitter.height())
                ratios = self._case_detail_ratios or [0.50, 0.50]
                self._set_splitter_sizes(
                    splitter, [int(h * ratios[0]), int(h * ratios[1])]
                )
            else:
                available = max(420, splitter.width())
                ratios = self._case_detail_ratios or [0.62, 0.38]
                self._set_splitter_sizes(
                    splitter, [int(available * ratios[0]), int(available * ratios[1])]
                )

            splitter.setChildrenCollapsible(False)
            if splitter.count() >= 2:
                splitter.widget(0).setMinimumWidth(260 if not vertical else 0)
                splitter.widget(1).setMinimumWidth(300 if not vertical else 0)

    def _configure_responsive_splitters(self):
        """Allocate splitter space from the current geometry, not fixed pixels.

        This is intentionally called after Qt completes a resize/layout pass.
        If the analyst drags a splitter, their choice is preserved until the
        next responsive breakpoint/orientation change.
        """
        if not getattr(self, "_responsive_splitters_initialized", False):
            self._responsive_splitters_initialized = True

        if hasattr(self, "case_workspace_splitter"):
            h = max(300, self.case_workspace_splitter.height())
            # Case list stays compact; investigation detail and results receive
            # the majority of the viewport. Analyst drag preferences are kept
            # as ratios, so they scale with the next window size.
            ratios = self._case_workspace_ratios or [0.15, 0.34, 0.51]
            self._set_splitter_sizes(
                self.case_workspace_splitter,
                [max(72, int(h * ratios[0])),
                 max(170, int(h * ratios[1])),
                 max(190, int(h * ratios[2]))]
            )

        if hasattr(self, "case_detail_splitter"):
            self._configure_case_layout()

        if hasattr(self, "ops_bottom_splitter"):
            h = max(300, self.ops_bottom_splitter.height())
            ratios = self._ops_bottom_ratios or [0.64, 0.36]
            self._set_splitter_sizes(
                self.ops_bottom_splitter,
                [max(220, int(h * ratios[0])), max(150, int(h * ratios[1]))]
            )

        if hasattr(self, "ops_inventory_splitter"):
            horizontal = self.width() >= 1180
            desired = Qt.Horizontal if horizontal else Qt.Vertical
            if getattr(self, "_ops_inventory_orientation", None) != desired:
                self.ops_inventory_splitter.setOrientation(desired)
                self._ops_inventory_orientation = desired
                self._ops_inventory_ratios = None
            ratios = self._ops_inventory_ratios or ([0.70, 0.30] if desired == Qt.Horizontal else [0.62, 0.38])
            if desired == Qt.Horizontal:
                w = max(420, self.ops_inventory_splitter.width())
                self._set_splitter_sizes(
                    self.ops_inventory_splitter,
                    [int(w * ratios[0]), int(w * ratios[1])]
                )
            else:
                h = max(220, self.ops_inventory_splitter.height())
                self._set_splitter_sizes(
                    self.ops_inventory_splitter,
                    [int(h * ratios[0]), int(h * ratios[1])]
                )

    def _apply_responsive_shell(self):
        """Adapt navigation, controls and content margins to the live window."""
        width = max(1, self.width())
        height = max(1, self.height())
        compact = width < 1100
        tiny = width < 900

        if compact != getattr(self, "_responsive_compact", False) or tiny != getattr(self, "_responsive_tiny", False):
            self._responsive_compact = compact
            self._responsive_tiny = tiny

            sidebar = getattr(self, "_sidebar", None)
            if sidebar is not None:
                if tiny:
                    sidebar.setMinimumWidth(136)
                    sidebar.setMaximumWidth(150)
                elif compact:
                    sidebar.setMinimumWidth(156)
                    sidebar.setMaximumWidth(174)
                else:
                    sidebar.setMinimumWidth(184)
                    sidebar.setMaximumWidth(224)

            if hasattr(self, "filter_combo"):
                self.filter_combo.setMinimumWidth(68 if tiny else 78 if compact else 90)
            if hasattr(self, "search"):
                self.search.setMinimumWidth(80 if tiny else 110 if compact else 140)
            if hasattr(self, "page_title"):
                self.page_title.setVisible(not tiny)

            content = getattr(self, "contentArea", None)
            if content is not None and content.layout() is not None:
                margins = 6 if tiny else 8 if compact else 18
                content.layout().setContentsMargins(
                    margins, 8 if compact else 16, margins, 6 if compact else 10
                )
                content.layout().setSpacing(5 if compact else 10)

            # Re-flow the findings/IOC controls and inventory orientation.
            self._configure_operations_controls()

        self._configure_case_layout()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._apply_responsive_shell()
        QTimer.singleShot(0, self._configure_responsive_splitters)

    def _build_operations_tab(self):
        layout = QVBoxLayout(self.operations_tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        header = QFrame()
        header.setObjectName("workspaceHeader")
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(14, 10, 14, 10)
        header_layout.setSpacing(2)
        title = QLabel("FINDINGS & IOC OPERATIONS")
        title.setObjectName("workspaceEyebrow")
        header_layout.addWidget(title)
        subtitle = QLabel("Deterministic findings, IOC inventory and investigation integrity. AI does not create findings.")
        subtitle.setObjectName("workspaceSubtitle")
        subtitle.setWordWrap(True)
        header_layout.addWidget(subtitle)
        layout.addWidget(header)

        # A grid rather than a single long toolbar prevents export controls
        # from falling off the right edge on restored/mini windows.
        controls = QGridLayout()
        controls.setHorizontalSpacing(6)
        controls.setVerticalSpacing(6)

        self.ops_ioc_btn = QPushButton("Extract IOCs")
        self.ops_ioc_btn.clicked.connect(self.refresh_operations)
        controls.addWidget(self.ops_ioc_btn, 0, 0)

        self._ops_ioc_type_label = QLabel("IOC Type:")
        controls.addWidget(self._ops_ioc_type_label, 0, 1)
        self.ops_ioc_type = QComboBox()
        self.ops_ioc_type.addItem("All")
        self.ops_ioc_type.addItems([IOC_TYPE_LABELS[key] for key in IOC_TYPE_LABELS])
        self.ops_ioc_type.currentTextChanged.connect(self._filter_ioc_inventory)
        controls.addWidget(self.ops_ioc_type, 0, 2)

        self.ops_ioc_search = QLineEdit()
        self.ops_ioc_search.setPlaceholderText("Search IOC, algorithm, source field or evidence ID…")
        self.ops_ioc_search.textChanged.connect(self._filter_ioc_inventory)
        controls.addWidget(self.ops_ioc_search, 0, 3, 1, 3)

        self.ops_export_ioc_btn = QPushButton("Export IOCs CSV")
        self.ops_export_ioc_btn.clicked.connect(self.export_iocs_csv)
        controls.addWidget(self.ops_export_ioc_btn, 1, 0)

        self.ops_copy_ioc_btn = QPushButton("Copy IOC")
        self.ops_copy_ioc_btn.clicked.connect(self.copy_selected_ioc)
        controls.addWidget(self.ops_copy_ioc_btn, 1, 1)

        self.ops_export_json_btn = QPushButton("Export Investigation JSON")
        self.ops_export_json_btn.clicked.connect(self.export_investigation_pack_json)
        controls.addWidget(self.ops_export_json_btn, 1, 2)

        self.ops_export_html_btn = QPushButton("Export Investigation HTML")
        self.ops_export_html_btn.clicked.connect(self.export_investigation_pack_html)
        controls.addWidget(self.ops_export_html_btn, 1, 3)

        self.ops_integrity = QLabel("Integrity: no log loaded")
        self.ops_integrity.setWordWrap(True)
        controls.addWidget(self.ops_integrity, 1, 4, 1, 2)

        controls.setColumnStretch(3, 1)
        controls.setColumnStretch(4, 1)
        controls.setColumnStretch(5, 1)
        layout.addLayout(controls)
        self._ops_controls_layout = controls

        summary_box = QGroupBox("Investigation Overview")
        grid = QGridLayout(summary_box)
        self.ops_metrics = {}
        for i, (key, label) in enumerate([
            ("events", "Events"),
            ("iocs", "IOCs"),
            ("detections", "Detections"),
            ("critical", "Critical findings"),
            ("high", "High findings"),
            ("cases", "Cases"),
        ]):
            box, value = self._metric(label)
            self.ops_metrics[key] = value
            grid.addWidget(box, i // 3, i % 3)
        layout.addWidget(summary_box)

        # Responsive evidence workspace:
        #   top = IOC inventory + selected IOC detail
        #   bottom = deterministic findings
        # The analyst can drag both splitters; no fixed pixel panel is required.
        self.ops_bottom_splitter = QSplitter(Qt.Vertical)
        self.ops_bottom_splitter.setChildrenCollapsible(False)
        self.ops_bottom_splitter.splitterMoved.connect(self._mark_ops_bottom_resized)

        self.ops_inventory_splitter = QSplitter(Qt.Horizontal)
        self.ops_inventory_splitter.setChildrenCollapsible(False)
        self.ops_inventory_splitter.splitterMoved.connect(self._mark_ops_inventory_resized)

        ioc_box = QGroupBox("IOC Inventory")
        ioc_layout = QVBoxLayout(ioc_box)
        ioc_layout.setContentsMargins(8, 8, 8, 8)
        self.ops_ioc_table = QTableWidget()
        self.ops_ioc_table.setColumnCount(7)
        self.ops_ioc_table.setHorizontalHeaderLabels([
            "Type", "Value", "Occurrences", "Scope", "Algorithm",
            "Evidence Count", "Source Fields",
        ])
        self.ops_ioc_table.setSortingEnabled(True)
        self.ops_ioc_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.ops_ioc_table.setSelectionMode(QTableWidget.SingleSelection)
        self.ops_ioc_table.cellClicked.connect(self._show_ioc_detail)
        self._fit_table(
            self.ops_ioc_table,
            stretch_columns=(1, 6),
            content_columns=(0, 2, 3, 4, 5),
        )
        ioc_layout.addWidget(self.ops_ioc_table, 1)
        self.ops_inventory_splitter.addWidget(ioc_box)

        detail_box = QGroupBox("IOC Detail / Evidence Pivot")
        detail_layout = QVBoxLayout(detail_box)
        detail_layout.setContentsMargins(8, 8, 8, 8)
        self.ops_ioc_detail = QTextEdit()
        self.ops_ioc_detail.setReadOnly(True)
        self.ops_ioc_detail.setLineWrapMode(QTextEdit.WidgetWidth)
        self.ops_ioc_detail.setPlaceholderText(
            "Select an IOC to inspect source fields, occurrences, timestamps and linked events."
        )
        detail_layout.addWidget(self.ops_ioc_detail, 1)

        pivot_controls = QHBoxLayout()
        self.ops_pivot_btn = QPushButton("Show Related Events")
        self.ops_pivot_btn.clicked.connect(self.pivot_selected_ioc)
        self.ops_reset_pivot_btn = QPushButton("Reset Event View")
        self.ops_reset_pivot_btn.clicked.connect(self.clear_filter)
        pivot_controls.addWidget(self.ops_pivot_btn)
        pivot_controls.addWidget(self.ops_reset_pivot_btn)
        pivot_controls.addStretch(1)
        detail_layout.addLayout(pivot_controls)
        self.ops_inventory_splitter.addWidget(detail_box)

        det_box = QGroupBox("Deterministic Detection Findings")
        det_layout = QVBoxLayout(det_box)
        det_layout.setContentsMargins(8, 8, 8, 8)
        self.ops_detection_table = QTableWidget()
        self.ops_detection_table.setColumnCount(5)
        self.ops_detection_table.setHorizontalHeaderLabels(
            ["Rule", "Severity", "Score", "Finding", "Evidence"]
        )
        self.ops_detection_table.setSortingEnabled(True)
        self._fit_table(
            self.ops_detection_table,
            stretch_columns=(3, 4),
            content_columns=(0, 1, 2),
        )
        det_layout.addWidget(self.ops_detection_table, 1)

        self.ops_bottom_splitter.addWidget(self.ops_inventory_splitter)
        self.ops_bottom_splitter.addWidget(det_box)
        layout.addWidget(self.ops_bottom_splitter, 1)

        self._configure_operations_controls()

    def _configure_operations_controls(self):
        """Reflow IOC controls so no action disappears off-screen."""
        grid = getattr(self, "_ops_controls_layout", None)
        if grid is None:
            return

        compact = self.width() < 1100

        widgets = [
            self.ops_ioc_btn, self.ops_ioc_type, self.ops_ioc_search,
            self.ops_export_ioc_btn, self.ops_copy_ioc_btn,
            self.ops_export_json_btn, self.ops_export_html_btn,
            self.ops_integrity,
        ]
        for widget in widgets:
            grid.removeWidget(widget)
        # The static IOC Type label is also repositioned.
        for item in [self._ops_ioc_type_label]:
            grid.removeWidget(item)

        if compact:
            # Two compact action rows + a dedicated integrity row.
            grid.addWidget(self.ops_ioc_btn, 0, 0)
            grid.addWidget(self._ops_ioc_type_label, 0, 1)
            grid.addWidget(self.ops_ioc_type, 0, 2)
            grid.addWidget(self.ops_ioc_search, 0, 3, 1, 3)

            self.ops_export_ioc_btn.setText("Export CSV")
            self.ops_export_json_btn.setText("Export JSON")
            self.ops_export_html_btn.setText("Export HTML")

            grid.addWidget(self.ops_export_ioc_btn, 1, 0)
            grid.addWidget(self.ops_copy_ioc_btn, 1, 1)
            grid.addWidget(self.ops_export_json_btn, 1, 2)
            grid.addWidget(self.ops_export_html_btn, 1, 3)
            grid.addWidget(self.ops_integrity, 2, 0, 1, 6)
            self.ops_ioc_search.setMinimumWidth(90)
        else:
            self.ops_export_ioc_btn.setText("Export IOCs CSV")
            self.ops_export_json_btn.setText("Export Investigation JSON")
            self.ops_export_html_btn.setText("Export Investigation HTML")

            grid.addWidget(self.ops_ioc_btn, 0, 0)
            grid.addWidget(self._ops_ioc_type_label, 0, 1)
            grid.addWidget(self.ops_ioc_type, 0, 2)
            grid.addWidget(self.ops_ioc_search, 0, 3, 1, 3)

            grid.addWidget(self.ops_export_ioc_btn, 1, 0)
            grid.addWidget(self.ops_copy_ioc_btn, 1, 1)
            grid.addWidget(self.ops_export_json_btn, 1, 2)
            grid.addWidget(self.ops_export_html_btn, 1, 3)
            grid.addWidget(self.ops_integrity, 1, 4, 1, 2)
            self.ops_ioc_search.setMinimumWidth(180)

        for col in range(6):
            grid.setColumnStretch(col, 0)
        grid.setColumnStretch(3, 1)
        if not compact:
            grid.setColumnStretch(4, 1)
            grid.setColumnStretch(5, 1)

    def _filtered_ioc_rows(self):
        return filter_iocs(
            self._iocs,
            query=self.ops_ioc_search.text(),
            ioc_type=self.ops_ioc_type.currentText(),
        )

    def _filter_ioc_inventory(self):
        if not hasattr(self, "ops_ioc_table"):
            return
        self._render_ioc_inventory(self._filtered_ioc_rows())

    def _render_ioc_inventory(self, rows):
        self.ops_ioc_table.setSortingEnabled(False)
        self.ops_ioc_table.setRowCount(0)

        for record in rows[:1000]:
            row = self.ops_ioc_table.rowCount()
            self.ops_ioc_table.insertRow(row)

            if record.get("type") == "ipv4":
                scope = "Private" if record.get("private") else "External"
            else:
                scope = "—"

            values = [
                record.get("type_label", record.get("type", "")),
                record.get("value", ""),
                record.get("occurrences", 0),
                scope,
                record.get("algorithm", "—"),
                len(record.get("evidence_ids", []) or []),
                ", ".join(record.get("source_fields", []) or []),
            ]
            for col, value in enumerate(values):
                self.ops_ioc_table.setItem(row, col, QTableWidgetItem(str(value)))

        self.ops_ioc_table.setSortingEnabled(True)

    def _selected_ioc_record(self):
        row = self.ops_ioc_table.currentRow()
        if row < 0:
            return None

        value_item = self.ops_ioc_table.item(row, 1)
        type_item = self.ops_ioc_table.item(row, 0)
        if not value_item or not type_item:
            return None

        return next(
            (
                item for item in self._filtered_ioc_rows()
                if str(item.get("value", "")) == value_item.text()
                and str(item.get("type_label", "")) == type_item.text()
            ),
            None,
        )

    def _show_ioc_detail(self, _row, _column):
        record = self._selected_ioc_record()
        if not record:
            self.ops_ioc_detail.clear()
            return

        evidence_ids = record.get("evidence_ids", []) or []
        timestamps = record.get("timestamps", []) or []
        refs = record.get("event_refs", []) or []

        if record.get("type") == "ipv4":
            scope = "Private" if record.get("private") else "External"
        else:
            scope = "N/A"

        lines = [
            f"Type: {record.get('type_label', record.get('type', ''))}",
            f"Value: {record.get('value', '')}",
            f"Occurrences: {record.get('occurrences', 0)}",
            f"Scope: {scope}",
            f"Algorithm: {record.get('algorithm', 'N/A')}",
            f"Source fields: {', '.join(record.get('source_fields', []) or []) or 'N/A'}",
            "",
            "Linked evidence:",
            ", ".join(evidence_ids) or "No promoted evidence IDs; source line references are used.",
            "",
            "Observed timestamps:",
        ]
        lines.extend(f"  • {stamp}" for stamp in timestamps[:20])
        lines.append("")
        lines.append(f"Source event references: {len(refs)}")
        for ref in refs[:20]:
            lines.append(
                f"  • line {ref.get('line', 'N/A')} | "
                f"{ref.get('timestamp') or 'timestamp unavailable'}"
            )

        if len(refs) > 20:
            lines.append(f"  • … {len(refs) - 20} additional event reference(s)")

        self.ops_ioc_detail.setPlainText("\n".join(lines))

    def copy_selected_ioc(self):
        record = self._selected_ioc_record()
        if not record:
            QMessageBox.information(self, "IOC", "Select an IOC first.")
            return
        QApplication.clipboard().setText(str(record.get("value", "")))
        self._safe_set_label_text(
            self.ops_integrity,
            f"Copied {record.get('type_label', 'IOC')}: {record.get('value', '')}",
        )

    def export_iocs_csv(self):
        if self.df.empty:
            QMessageBox.information(self, "IOC Export", "Upload a log first.")
            return

        rows = self._filtered_ioc_rows()
        if not rows:
            QMessageBox.information(self, "IOC Export", "No IOCs match the current filter.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Export IOC inventory", "", "CSV files (*.csv)"
        )
        if not path:
            return

        export_rows = []
        for row in rows:
            export_rows.append({
                "type": row.get("type_label", ""),
                "value": row.get("value", ""),
                "occurrences": row.get("occurrences", 0),
                "scope": (
                    "Private" if row.get("private") else "External"
                    if row.get("type") == "ipv4"
                    else ""
                ),
                "algorithm": row.get("algorithm", ""),
                "source_fields": ", ".join(row.get("source_fields", []) or []),
                "evidence_count": len(row.get("evidence_ids", []) or []),
                "evidence_ids": ", ".join(row.get("evidence_ids", []) or []),
                "timestamps": ", ".join(row.get("timestamps", []) or []),
            })

        pd.DataFrame(export_rows).to_csv(path, index=False)
        QMessageBox.information(
            self, "IOC Export", f"Exported {len(export_rows)} IOC record(s)."
        )

    def pivot_selected_ioc(self):
        record = self._selected_ioc_record()
        if not record:
            QMessageBox.information(self, "IOC Pivot", "Select an IOC first.")
            return

        refs = record.get("event_refs", []) or []
        evidence_ids = {
            str(ref.get("evidence_id"))
            for ref in refs
            if str(ref.get("evidence_id", "")).strip()
        }
        lines = {
            str(ref.get("line"))
            for ref in refs
            if str(ref.get("line", "")).strip()
        }
        timestamps = {
            str(ref.get("timestamp"))
            for ref in refs
            if str(ref.get("timestamp", "")).strip()
        }

        if self.df.empty:
            return

        # Prefer the strongest deterministic relationship available. Do not
        # OR together broad timestamp matches when a stable evidence/line
        # reference exists; that can pull unrelated events sharing a timestamp.
        mask = pd.Series(False, index=self.df.index)
        if "evidence_id" in self.df.columns and evidence_ids:
            mask = self.df["evidence_id"].astype(str).isin(evidence_ids)
        elif "line" in self.df.columns and lines:
            mask = self.df["line"].astype(str).isin(lines)
        elif "timestamp" in self.df.columns and timestamps:
            mask = self.df["timestamp"].astype(str).isin(timestamps)

        matched = self.df[mask].copy()
        if matched.empty:
            QMessageBox.information(
                self,
                "IOC Pivot",
                "The IOC has no source events that can be mapped back to the loaded table.",
            )
            return

        self.filtered_df = matched
        self.render_events(self.filtered_df)
        self._safe_set_label_text(
            self.status,
            f"IOC pivot: {record.get('value', '')} | Related events: {len(matched)}",
        )
        self.tabs.setCurrentWidget(self.events_tab)

    def refresh_operations(self):
        if self.df.empty:
            return

        events = self.df.fillna("").to_dict("records")
        if self._analysis_cache and len(self.filtered_df) == len(self.df):
            self._iocs = self._normalize_ioc_inventory(self._analysis_cache.get("iocs", {}))
            self._detections = list(self._analysis_cache.get("detections", []))
        else:
            self._iocs = extract_iocs(events)
            self._detections = self.detection_engine.run(events)
        counts = summarize_iocs(self._iocs)

        self._safe_set_label_text(self.ops_metrics.get("events"), str(len(events)))
        self._safe_set_label_text(self.ops_metrics.get("iocs"), str(sum(counts.values())))
        self._safe_set_label_text(self.ops_metrics.get("detections"), str(len(self._detections)))
        self._safe_set_label_text(
            self.ops_metrics.get("critical"),
            str(sum(1 for x in self._detections if x.get("severity") == "CRITICAL")),
        )
        self._safe_set_label_text(
            self.ops_metrics.get("high"),
            str(sum(1 for x in self._detections if x.get("severity") == "HIGH")),
        )
        self._safe_set_label_text(
            self.ops_metrics.get("cases"),
            str(len(self.case_store.records)),
        )

        self._render_ioc_inventory(self._filtered_ioc_rows())

        self.ops_detection_table.setSortingEnabled(False)
        self.ops_detection_table.setRowCount(0)
        for finding in self._detections:
            row = self.ops_detection_table.rowCount()
            self.ops_detection_table.insertRow(row)
            values = [
                finding.get("rule_id", ""),
                finding.get("severity", ""),
                finding.get("score", ""),
                finding.get("summary", ""),
                ", ".join(finding.get("evidence_ids", [])[:12]),
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if col == 1:
                    severity = str(value).upper()
                    palette = {
                        "CRITICAL": QColor("#F43F5E"),
                        "HIGH": QColor("#EF4444"),
                        "MEDIUM": QColor("#F59E0B"),
                        "LOW": QColor("#38BDF8"),
                    }
                    if severity in palette:
                        item.setForeground(QBrush(palette[severity]))
                self.ops_detection_table.setItem(row, col, item)
        self.ops_detection_table.setSortingEnabled(True)

        try:
            manifest = build_evidence_manifest(
                self.current_file, events, self.evidence_store.records
            )
            self._safe_set_label_text(
                self.ops_integrity,
                f"SHA-256: {manifest['source_sha256'][:20]}… | Events: {len(events)}",
            )
        except Exception as exc:
            self._safe_set_label_text(
                self.ops_integrity, f"Integrity unavailable: {exc}"
            )

    def _build_current_investigation_pack(self):
        events=self.df.fillna("").to_dict("records")
        if not events: return None
        if not self._iocs: self._iocs=extract_iocs(events)
        if not self._detections: self._detections=self.detection_engine.run(events)
        manifest=build_evidence_manifest(self.current_file,events,self.evidence_store.records)
        return build_investigation_pack(
            version="0.5.19", source_file=self.current_file, profile=self.log_profile,
            events=events, iocs=self._iocs, detections=self._detections,
            cases=self.case_store.records, evidence=self.evidence_store.records,
            manifest=manifest, analyst_reports=[],
        )

    def export_investigation_pack_json(self):
        pack=self._build_current_investigation_pack()
        if not pack:
            QMessageBox.information(self,"Investigation Pack","Upload a log first.")
            return
        path,_=QFileDialog.getSaveFileName(self,"Export Investigation Pack","","JSON files (*.json)")
        if not path: return
        export_investigation_json(pack,path)
        QMessageBox.information(self,"Investigation Pack",f"Exported investigation package to:\\n{path}")

    def export_investigation_pack_html(self):
        pack=self._build_current_investigation_pack()
        if not pack:
            QMessageBox.information(self,"Investigation Pack","Upload a log first.")
            return
        path,_=QFileDialog.getSaveFileName(self,"Export Investigation Report","","HTML files (*.html)")
        if not path: return
        export_investigation_html(pack,path)
        QMessageBox.information(self,"Investigation Report",f"Exported investigation report to:\\n{path}")

    def _build_events_tab(self):
        layout = QVBoxLayout(self.events_tab)
        layout.setSpacing(6)
        self.analysis_progress = QProgressBar()
        self.analysis_progress.setRange(0, 100)
        self.analysis_progress.setValue(0)
        self.analysis_progress.setTextVisible(True)
        self.analysis_progress.setFormat("Ready")
        self.analysis_progress.setMaximumHeight(18)
        layout.addWidget(self.analysis_progress)

        # Page-local event search/filter controls.  These controls are visible
        # only on Events; other workspaces keep their own purpose-specific
        # filters and are not affected by event searching.
        event_filter_bar = QHBoxLayout()
        event_filter_bar.setSpacing(7)

        event_filter_bar.addWidget(QLabel("Filter"))
        self.filter_combo.setVisible(True)
        self.filter_value_combo.setVisible(True)
        self.search.setVisible(False)
        self.clear_btn.setVisible(True)
        self.filter_combo.setToolTip(
            "Choose an event field. Values are discovered automatically from the loaded log."
        )
        self.filter_value_combo.setToolTip(
            "Choose a discovered value. Matching events are displayed immediately."
        )
        self.search.setToolTip(
            "Optional free-text refinement. Normal field/value filtering does not require typing."
        )
        self.clear_btn.setToolTip("Clear the event filter and restore all events.")

        event_filter_bar.addWidget(self.filter_combo)
        event_filter_bar.addWidget(QLabel("Value"))
        event_filter_bar.addWidget(self.filter_value_combo, 1)
        event_filter_bar.addWidget(self.clear_btn)
        layout.addLayout(event_filter_bar)

        pager = QHBoxLayout()
        self.events_page_info = QLabel("0 events")
        self.events_page_info.setObjectName("eventPageInfo")
        pager.addWidget(self.events_page_info, 1)

        self.events_prev = QPushButton("‹ Previous")
        self.events_next = QPushButton("Next ›")
        self.events_prev.setEnabled(False)
        self.events_next.setEnabled(False)
        self.events_prev.clicked.connect(lambda: self._change_event_page(-1))
        self.events_next.clicked.connect(lambda: self._change_event_page(1))
        pager.addWidget(self.events_prev)
        pager.addWidget(self.events_next)

        self.events_page_size = QComboBox()
        self.events_page_size.addItems(["250", "500", "1000"])
        self.events_page_size.setCurrentText("500")
        self.events_page_size.currentTextChanged.connect(self._change_event_page_size)
        pager.addWidget(QLabel("Rows:"))
        pager.addWidget(self.events_page_size)
        layout.addLayout(pager)

        self.events_table = QTableWidget()
        self.events_table.setAlternatingRowColors(True)
        self.events_table.setSortingEnabled(True)
        self.events_table.setWordWrap(False)
        self.events_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.events_table, 1)


    def _set_event_page_state(self, total_rows: int):
        page_size = max(1, int(self._event_page_size))
        self._event_page_count = max(1, (int(total_rows) + page_size - 1) // page_size)
        self._event_page = min(max(0, self._event_page), self._event_page_count - 1)
        start = self._event_page * page_size
        end = min(int(total_rows), start + page_size)

        if hasattr(self, "events_page_info"):
            if total_rows <= page_size:
                text = f"{total_rows:,} events"
            else:
                text = (
                    f"Showing {start + 1:,}–{end:,} of {total_rows:,} events"
                    f"  •  Page {self._event_page + 1}/{self._event_page_count}"
                )
            self.events_page_info.setText(text)
            self.events_prev.setEnabled(self._event_page > 0)
            self.events_next.setEnabled(self._event_page < self._event_page_count - 1)

    def _change_event_page(self, delta: int):
        if self.filtered_df.empty:
            return
        self._event_page = min(
            max(0, self._event_page + int(delta)),
            max(0, self._event_page_count - 1),
        )
        self.render_events(self.filtered_df)

    def _change_event_page_size(self, value: str):
        try:
            self._event_page_size = max(1, int(value))
        except (TypeError, ValueError):
            self._event_page_size = 500
        self._event_page = 0
        if hasattr(self, "filtered_df"):
            self.render_events(self.filtered_df)

    def _journal_workspace_state(self, status="idle", interrupted=False):
        try:
            current_file = str(getattr(self, "current_file", "") or "")
            status_value = str(status)
            # A running analysis is itself a recovery checkpoint.  The journal
            # must advertise recovery *before* the worker starts because a
            # hard process termination does not execute Qt closeEvent hooks.
            # When analysis completes, the finished state below clears this
            # marker.  This makes recovery work for crashes, forced closes,
            # and Windows "Close the program" termination.
            recovery_candidate = bool(interrupted) or status_value == "running"
            state = {
                "current_file": current_file,
                "analysis_status": status_value,
                "analysis_generation": int(getattr(self, "_analysis_generation", 0)),
                "event_count": int(len(self.df)) if hasattr(self, "df") else 0,
                "filtered_count": int(len(self.filtered_df)) if hasattr(self, "filtered_df") else 0,
                "recovery_available": recovery_candidate,
                "interrupted": recovery_candidate,
                "interrupted_reason": (
                    "Analysis was interrupted during the previous session."
                    if recovery_candidate else ""
                ),
            }
            self.workspace_journal.save(state)
        except Exception:
            # Recovery must never interfere with normal application behavior.
            pass

    def _check_workspace_recovery(self):
        if self._recovery_prompted:
            return
        self._recovery_prompted = True
        state = self.workspace_journal.load()
        if not state or not state.get("recovery_available"):
            return

        path = str(state.get("current_file", "") or "")
        if not path or not Path(path).exists():
            self.workspace_journal.clear()
            return

        from PySide6.QtWidgets import QMessageBox
        answer = QMessageBox.question(
            self,
            "Recover Investigation Workspace",
            (
                "LogAsis detected an interrupted analysis session.\n\n"
                f"Previous log: {Path(path).name}\n"
                f"Previous analysis state: {state.get('analysis_status', 'unknown')}\n\n"
                "Would you like to reopen the log and continue from the "
                "current workspace?"
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if answer == QMessageBox.StandardButton.Yes:
            # Use the same loader as a normal upload.  It reconstructs the
            # dataframe, refreshes the UI and starts the background analysis.
            # Do not clear the journal unless the recovery load actually
            # succeeds; otherwise a transient read/parse failure destroys the
            # only recovery checkpoint.
            if not self.load_log_file(path, show_errors=True):
                QMessageBox.warning(
                    self,
                    "Workspace Recovery",
                    "The previous log could not be reopened. The recovery checkpoint was preserved.",
                )
        else:
            self.workspace_journal.clear()

    def _build_dashboard_tab(self):
        """Build the analyst landing page.

        This is presentation-only: all values come from the existing parsed
        dataframe, deterministic detections, IOC inventory and case store.
        No detection or investigation logic is duplicated here.
        """
        layout = QVBoxLayout(self.dashboard_tab)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(10)

        # Context banner.
        context = QFrame()
        context.setObjectName("dashboardContext")
        context_layout = QHBoxLayout(context)
        context_layout.setContentsMargins(14, 11, 14, 11)
        context_layout.setSpacing(10)

        context_text = QVBoxLayout()
        context_text.setSpacing(2)
        self.dashboard_profile = QLabel("No security log loaded")
        self.dashboard_profile.setObjectName("dashboardEyebrow")
        context_text.addWidget(self.dashboard_profile)

        self.dashboard_source = QLabel(
            "Upload a log to begin a security investigation."
        )
        self.dashboard_source.setObjectName("dashboardContextText")
        self.dashboard_source.setWordWrap(True)
        context_text.addWidget(self.dashboard_source)
        context_layout.addLayout(context_text, 1)

        self.dashboard_ready = QLabel("● READY")
        self.dashboard_ready.setObjectName("dashboardReady")
        context_layout.addWidget(self.dashboard_ready, 0, Qt.AlignTop)
        layout.addWidget(context)

        # KPI cards. Existing metric_labels / metric_boxes are retained so
        # profile-specific dashboard code and existing tests keep working.
        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(10)
        self.metric_labels = {}
        self.metric_boxes = {}
        for i, title in enumerate([
            ("metric_1", "—"),
            ("metric_2", "—"),
            ("metric_3", "—"),
            ("metric_4", "—"),
            ("metric_5", "—"),
            ("metric_6", "—"),
        ]):
            box, label = self._metric(title[1])
            self.metric_labels[title[0]] = label
            self.metric_boxes[title[0]] = box
            grid.addWidget(box, i // 3, i % 3)
        layout.addLayout(grid)

        # Lower dashboard: activity + priority findings.
        lower = QHBoxLayout()
        lower.setSpacing(10)

        activity_box = QGroupBox("Activity Snapshot")
        activity_box.setObjectName("dashboardPanel")
        activity_layout = QVBoxLayout(activity_box)
        activity_layout.setContentsMargins(12, 12, 12, 12)
        self.dashboard_text = QTextEdit()
        self.dashboard_text.setObjectName("analystReport")
        self.dashboard_text.setReadOnly(True)
        self.dashboard_text.setMinimumHeight(150)
        self.dashboard_text.setMaximumHeight(205)
        self.dashboard_text.setPlainText(
            "No log loaded. Upload a security log to populate activity, "
            "source and user context."
        )
        activity_layout.addWidget(self.dashboard_text)
        lower.addWidget(activity_box, 3)

        findings_box = QGroupBox("Priority Findings")
        findings_box.setObjectName("dashboardPanel")
        findings_layout = QVBoxLayout(findings_box)
        findings_layout.setContentsMargins(12, 12, 12, 12)
        findings_layout.setSpacing(7)

        self.dashboard_findings_summary = QLabel(
            "0 findings  •  Deterministic detections appear here after analysis."
        )
        self.dashboard_findings_summary.setObjectName("findingsSummary")
        self.dashboard_findings_summary.setWordWrap(True)
        findings_layout.addWidget(self.dashboard_findings_summary)

        self.dashboard_findings_list = QVBoxLayout()
        self.dashboard_findings_list.setSpacing(7)
        findings_layout.addLayout(self.dashboard_findings_list)
        findings_layout.addStretch(1)

        self.dashboard_findings_action = QPushButton("Open Findings & IOCs →")
        self.dashboard_findings_action.setObjectName("secondaryButton")
        self.dashboard_findings_action.clicked.connect(
            lambda: self._navigate_to(9, "Findings & IOC Operations")
        )
        findings_layout.addWidget(self.dashboard_findings_action)
        lower.addWidget(findings_box, 2)

        layout.addLayout(lower, 1)

    def _metric(self, title):
        box = QGroupBox(title)
        box.setObjectName("metricCard")
        layout = QVBoxLayout(box)
        layout.setContentsMargins(12, 11, 12, 11)
        layout.setSpacing(3)

        label = QLabel("0")
        label.setObjectName("metricValue")
        label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        layout.addWidget(label)

        # Keep the title as the card's group title for compatibility, while
        # the stylesheet gives it the visual "eyebrow" treatment.
        return box, label

    def _clear_dashboard_findings(self):
        """Remove rendered finding cards without touching detection data."""
        if not hasattr(self, "dashboard_findings_list"):
            return
        while self.dashboard_findings_list.count():
            item = self.dashboard_findings_list.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def _render_dashboard_findings(self):
        """Render the top deterministic findings as compact dashboard cards."""
        self._clear_dashboard_findings()

        findings = list(getattr(self, "_detections", []) or [])
        if not findings and not self.df.empty:
            # refresh_all normally populates detections through Operations.
            # This fallback keeps the dashboard self-contained when it is
            # opened directly after a load.
            try:
                findings = self.detection_engine.run(
                    self.df.fillna("").to_dict("records")
                )
                self._detections = findings
            except Exception:
                findings = []

        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings = sorted(
            findings,
            key=lambda x: (
                order.get(str(x.get("severity", "")).upper(), 9),
                -float(x.get("score", 0) or 0),
            ),
        )

        counts = {
            level: sum(
                1 for x in findings
                if str(x.get("severity", "")).upper() == level
            )
            for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        }
        summary_bits = [
            f"{len(findings)} finding{'s' if len(findings) != 1 else ''}"
        ]
        for level in ("CRITICAL", "HIGH", "MEDIUM"):
            if counts[level]:
                summary_bits.append(f"{counts[level]} {level.title()}")
        self._safe_set_label_text(
            self.dashboard_findings_summary, "  •  ".join(summary_bits)
        )

        if not findings:
            empty = QLabel(
                "No deterministic findings for the current log.\n"
                "The dashboard will remain evidence-first; AI does not create findings."
            )
            empty.setObjectName("dashboardEmpty")
            empty.setWordWrap(True)
            self.dashboard_findings_list.addWidget(empty)
            return

        for finding in findings[:5]:
            card = QFrame()
            card.setObjectName("findingCard")
            severity = str(finding.get("severity", "MEDIUM")).upper()
            card.setProperty("severity", severity.lower())

            row = QHBoxLayout(card)
            row.setContentsMargins(10, 8, 10, 8)
            row.setSpacing(9)

            badge = QLabel(severity)
            badge.setObjectName("severityBadge")
            badge.setProperty("severity", severity.lower())
            badge.setAlignment(Qt.AlignCenter)
            badge.setMinimumWidth(68)
            row.addWidget(badge, 0, Qt.AlignTop)

            body = QVBoxLayout()
            body.setSpacing(2)
            rule = QLabel(
                f"{finding.get('rule_id', 'DETECTION')}  •  "
                f"Score {finding.get('score', '—')}"
            )
            rule.setObjectName("findingRule")
            body.addWidget(rule)

            summary = QLabel(
                str(finding.get("summary", "Deterministic finding"))
            )
            summary.setObjectName("findingSummary")
            summary.setWordWrap(True)
            body.addWidget(summary)

            evidence_ids = finding.get("evidence_ids", []) or []
            evidence_text = (
                f"{len(evidence_ids)} evidence record(s)"
                if evidence_ids
                else "Evidence references available in Findings"
            )
            meta = QLabel(evidence_text)
            meta.setObjectName("findingMeta")
            body.addWidget(meta)
            row.addLayout(body, 1)

            self.dashboard_findings_list.addWidget(card)

    def _update_dashboard_context(self):
        profile = self.log_profile or {}
        if self.df.empty:
            self._safe_set_label_text(self.dashboard_profile, "No security log loaded")
            self._safe_set_label_text(
                self.dashboard_source,
                "Upload a log to begin a security investigation."
            )
            self._safe_set_label_text(self.dashboard_ready, "● READY")
            self.dashboard_ready.setProperty("state", "ready")
            self.dashboard_ready.style().unpolish(self.dashboard_ready)
            self.dashboard_ready.style().polish(self.dashboard_ready)
            return

        name = profile.get("name", "Security Log")
        source = Path(self.current_file).name if self.current_file else "Loaded log"
        self._safe_set_label_text(self.dashboard_profile, str(name).upper())
        self._safe_set_label_text(
            self.dashboard_source,
            f"{source}  •  {len(self.filtered_df):,} events in current view"
        )
        self._safe_set_label_text(self.dashboard_ready, "● ANALYSIS READY")
        self.dashboard_ready.setProperty("state", "ready")
        self.dashboard_ready.style().unpolish(self.dashboard_ready)
        self.dashboard_ready.style().polish(self.dashboard_ready)

    def _build_text_tabs(self):
        """Build compact analyst workspaces for timeline, IP and authentication.

        The underlying refresh methods still write to ``_editor`` for backward
        compatibility.  The editor is presented as a report surface instead
        of a giant blank widget so empty and populated states have the same
        visual language.
        """
        specs = [
            (self.timeline_tab, "EVENT TIMELINE", "Temporal activity grouped by hour.", "timeline"),
            (self.ip_tab, "SOURCE IP ANALYSIS", "Top source addresses and event concentration.", "ip"),
            (self.auth_tab, "AUTHENTICATION / SSH", "Authentication outcomes and user activity.", "auth"),
        ]
        for tab, title, subtitle, key in specs:
            layout = QVBoxLayout(tab)
            layout.setContentsMargins(8, 8, 8, 8)
            layout.setSpacing(8)

            head = QFrame()
            head.setObjectName("workspaceHeader")
            h = QVBoxLayout(head)
            h.setContentsMargins(12, 10, 12, 10)
            h.setSpacing(2)
            title_label = QLabel(title)
            title_label.setObjectName("workspaceEyebrow")
            h.addWidget(title_label)
            sub = QLabel(subtitle)
            sub.setObjectName("workspaceSubtitle")
            h.addWidget(sub)
            layout.addWidget(head)

            editor = QTextEdit()
            editor.setReadOnly(True)
            editor.setObjectName("analystReport")
            editor.setPlaceholderText("Upload a security log to populate this workspace.")
            editor.setPlainText("No security log loaded.\n\nUpload a log to begin analysis.")
            layout.addWidget(editor, 1)
            tab._editor = editor
            tab._workspace_key = key

    def _build_investigation_tab(self):
        layout = QVBoxLayout(self.investigation_tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Priority:"))
        self.investigation_filter = QComboBox()
        self.investigation_filter.addItems(["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self.investigation_filter.currentTextChanged.connect(self.refresh_investigation)
        controls.addWidget(self.investigation_filter)

        self.investigation_summary = QLabel("No investigation candidates yet.")
        self.investigation_summary.setWordWrap(True)
        controls.addWidget(self.investigation_summary, 1)

        self.create_case_from_investigation_btn = QPushButton("Start Case from Selected")
        self.create_case_from_investigation_btn.setToolTip(
            "Promote the selected deterministic investigation candidate to Evidence and create/link a Case."
        )
        self.create_case_from_investigation_btn.clicked.connect(
            self._create_case_from_selected_investigation
        )
        controls.addWidget(self.create_case_from_investigation_btn)
        layout.addLayout(controls)

        splitter = QSplitter(Qt.Vertical)
        self.investigation_table = QTableWidget()
        self.investigation_table.setAlternatingRowColors(True)
        self.investigation_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.investigation_table.setSelectionMode(QTableWidget.SingleSelection)
        self.investigation_table.setSortingEnabled(True)
        self.investigation_table.cellClicked.connect(self._show_investigation_event)
        splitter.addWidget(self.investigation_table)

        detail_group = QGroupBox("Investigation Detail")
        detail_layout = QVBoxLayout(detail_group)
        self.investigation_detail = QTextEdit()
        self.investigation_detail.setReadOnly(True)
        self.investigation_detail.setObjectName("analystReport")
        self.investigation_detail.setPlaceholderText(
            "Select an investigation candidate to review its deterministic triage details."
        )
        detail_layout.addWidget(self.investigation_detail)
        splitter.addWidget(detail_group)
        splitter.setSizes([360, 300])
        layout.addWidget(splitter, 1)

    def _build_ai_tab(self):
        layout = QVBoxLayout(self.ai_tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        context = QFrame()
        context.setObjectName("workspaceHeader")
        context_layout = QVBoxLayout(context)
        context_layout.setContentsMargins(14, 11, 14, 11)
        context_layout.setSpacing(3)
        title = QLabel("AI ANALYST")
        title.setObjectName("workspaceEyebrow")
        context_layout.addWidget(title)
        self.ai_context = QLabel(
            "Agentic security investigation over normalized evidence. The analyst dynamically searches, correlates and timelines relevant evidence through bounded read-only tools. Live AI uses the shared investigation runtime and grounding rules."
        )
        self.ai_context.setObjectName("workspaceSubtitle")
        self.ai_context.setWordWrap(True)
        context_layout.addWidget(self.ai_context)
        layout.addWidget(context)

        controls = QHBoxLayout()
        controls.setSpacing(7)
        controls.addWidget(QLabel("Provider"))
        self.ai_provider = QComboBox()
        self.ai_provider.addItems(["Live AI"])
        self.ai_provider.currentTextChanged.connect(self._ai_provider_changed)
        controls.addWidget(self.ai_provider)

        self.ai_config_btn = QPushButton("Configure")
        self.ai_config_btn.clicked.connect(self.configure_live_ai)
        controls.addWidget(self.ai_config_btn)

        self.ai_question = QLineEdit()
        self.ai_question.setPlaceholderText("Ask a security question about the current investigation…")
        self.ai_question.setText("What are the most important security findings in this log?")
        controls.addWidget(self.ai_question, 1)

        self.ai_analyze_btn = QPushButton("Analyze")
        self.ai_analyze_btn.setObjectName("primaryButton")
        self.ai_analyze_btn.clicked.connect(self.run_ai_analysis)
        controls.addWidget(self.ai_analyze_btn)
        layout.addLayout(controls)

        suggestions = QVBoxLayout()
        suggestions.setSpacing(5)
        suggestions.addWidget(QLabel("Suggested questions"))
        suggestion_grid = QGridLayout()
        suggestion_grid.setHorizontalSpacing(6)
        suggestion_grid.setVerticalSpacing(5)
        suggested_questions = [
            "Which account was compromised?",
            "What attack type was used to gain initial access?",
            "What is the attacker's IP address?",
            "What file was exfiltrated once root was gained?",
            "What type of vulnerability is this?",
            "What is the name of the binary and PID used to gain root?",
            "What tool was used to perform system enumeration?",
            "What CVE was exploited to gain root access?",
            "Summarize highest-risk findings",
            "Explain critical activity",
            "Identify suspicious users",
            "What evidence supports the top finding?",
        ]
        for idx, text in enumerate(suggested_questions):
            btn = QPushButton(text)
            btn.setObjectName("secondaryButton")
            btn.setToolTip("Ask this question against the loaded log evidence.")
            btn.clicked.connect(lambda checked=False, q=text: self._set_ai_question(q))
            suggestion_grid.addWidget(btn, idx // 4, idx % 4)
        suggestions.addLayout(suggestion_grid)
        layout.addLayout(suggestions)

        self.ai_status = QLabel(
            "Live AI • agentic investigation ready"
        )
        self.ai_status.setObjectName("workspaceSubtitle")
        self.ai_status.setWordWrap(True)
        layout.addWidget(self.ai_status)

        output_group = QGroupBox("Analyst Assessment")
        output_group.setObjectName("dashboardPanel")
        output_layout = QVBoxLayout(output_group)
        self.ai_output = QTextBrowser()
        self.ai_output.setReadOnly(True)
        self.ai_output.setObjectName("analystReport")
        self.ai_output.setOpenLinks(False)
        self.ai_output.setPlaceholderText(
            "The analyst assessment will appear here after analysis."
        )
        self.ai_output.setPlainText(
            "No analysis has been run.\n\n"
            "Load a log, choose a question, and run Analyze."
        )
        output_layout.addWidget(self.ai_output, 1)
        layout.addWidget(output_group, 1)

        self.ai_grounding_toggle = QPushButton("▶ Evidence & Grounding Details")
        self.ai_grounding_toggle.setObjectName("secondaryButton")
        self.ai_grounding_toggle.setCheckable(True)
        self.ai_grounding_toggle.setChecked(False)
        self.ai_grounding_toggle.clicked.connect(self._toggle_ai_grounding_details)
        layout.addWidget(self.ai_grounding_toggle)

        self.ai_grounding_output = QTextBrowser()
        self.ai_grounding_output.setReadOnly(True)
        self.ai_grounding_output.setObjectName("analystReport")
        self.ai_grounding_output.setVisible(False)
        self.ai_grounding_output.setMaximumHeight(360)
        layout.addWidget(self.ai_grounding_output)

        self._ai_provider_changed(self.ai_provider.currentText())

    def _toggle_ai_grounding_details(self, checked):
        if not hasattr(self, "ai_grounding_output"):
            return
        self.ai_grounding_output.setVisible(bool(checked))
        self.ai_grounding_toggle.setText("▼ Evidence & Grounding Details" if checked else "▶ Evidence & Grounding Details")

    def _set_ai_question(self, question):
        self.ai_question.setText(question)
        self.ai_question.setFocus()

    def _ai_provider_changed(self, provider):
        if provider == "Live AI":
            self.ai_config_btn.setEnabled(True)
        else:
            self.ai_config_btn.setEnabled(False)
        self._refresh_ai_provider_status()

    def _refresh_ai_provider_status(self):
        if not hasattr(self, "ai_status") or not qt_is_valid(self.ai_status):
            return

        provider = self.ai_provider.currentText() if hasattr(self, "ai_provider") else ""
        if provider == "Live AI":
            config = load_live_config()
            if not config.configured:
                self._safe_set_label_text(
                    self.ai_status,
                    "Live AI • Configuration required • API key is stored securely"
                )
                if hasattr(self, "ai_analyze_btn") and self._ai_worker is None:
                    self.ai_analyze_btn.setVisible(True)
                    self.ai_analyze_btn.setEnabled(True)
                return

            state = get_provider_status("Live AI")
            if state.is_blocked:
                remaining = state.remaining_seconds
                self._safe_set_label_text(
                    self.ai_status,
                    f"Live AI • {config.provider or 'provider'} • "
                    f"{config.model or 'configured model'} • RATE LIMITED • try again in {remaining}s"
                )
                if hasattr(self, "ai_analyze_btn") and self._ai_worker is None:
                    # A provider-side 429 is not an actionable Analyze state.
                    # Hide the action completely during the cooldown so the UI
                    # cannot imply that another request can be sent. The
                    # existing 1-second status timer will restore it when the
                    # provider becomes available again.
                    self.ai_analyze_btn.setEnabled(False)
                    self.ai_analyze_btn.setVisible(False)
                return

            self._safe_set_label_text(
                self.ai_status,
                f"Live AI • {config.provider or 'provider'} • "
                f"{config.model or 'configured model'} • Ready"
            )
            if hasattr(self, "ai_analyze_btn") and self._ai_worker is None:
                self.ai_analyze_btn.setVisible(True)
                self.ai_analyze_btn.setEnabled(True)
        else:
            self._safe_set_label_text(
                self.ai_status,
                "Live AI • agentic investigation ready"
            )
            if hasattr(self, "ai_analyze_btn") and self._ai_worker is None:
                self.ai_analyze_btn.setVisible(True)
                self.ai_analyze_btn.setEnabled(True)

    def configure_live_ai(self):
        dialog = LiveAIConfigDialog(self)
        if dialog.exec() == QDialog.Accepted and getattr(dialog, "saved", False):
            clear_provider_status("Live AI")
            self._ai_provider_changed(self.ai_provider.currentText())
            self._case_ai_provider_changed(self.case_ai_provider.currentText())
            self._safe_set_label_text(self.case_ai_status, "Live AI configuration saved securely.")

    def _reset_ai_analyst_session(self, reason=""):
        """Reset only AI Analyst state for a new evidence session."""
        self._ai_session_generation = int(getattr(self, "_ai_session_generation", 0)) + 1
        clear_ai_session_cache()

        worker = getattr(self, "_ai_worker", None)
        if worker is not None:
            try:
                worker.cancel()
            except Exception:
                pass

        self._ai_cancelled = False
        if hasattr(self, "ai_output"):
            self.ai_output.setPlainText(
                "AI ANALYSIS\n\n"
                + (str(reason).strip() if reason else "Upload a security log to begin a new AI analysis.")
            )
        if hasattr(self, "ai_grounding_output"):
            self.ai_grounding_output.clear()
        if hasattr(self, "ai_status"):
            self._safe_set_label_text(
                self.ai_status,
                "AI Analyst session reset • previous AI result discarded."
            )

    def run_ai_analysis(self):
        if self._ai_worker is not None:
            self._ai_cancelled = True
            self._ai_worker.cancel()
            self._safe_set_label_text(self.ai_status, "Cancelling AI analysis… current provider request will finish safely.")
            self.ai_output.setPlainText("AI ANALYSIS CANCELLING\n\nThe current provider request is being allowed to finish safely.\nNo investigation data will be changed.")
            self.ai_analyze_btn.setEnabled(False)
            return
        if self.df.empty:
            self._safe_set_label_text(self.ai_status, "No parsed log evidence is available for analysis.")
            self.ai_output.setPlainText("NO LOG LOADED\n\nUpload a security log before running AI analysis.")
            return
        question = self.ai_question.text().strip()
        if not question:
            QMessageBox.warning(self, "Missing Question", "Enter an analysis question.")
            return

        if self.ai_provider.currentText() == "Live AI":
            state = get_provider_status("Live AI")
            if state.is_blocked:
                remaining = state.remaining_seconds
                self._safe_set_label_text(
                    self.ai_status,
                    f"Live AI unavailable • rate limit active • try again in {remaining}s"
                )
                self.ai_output.setPlainText(
                    "LIVE AI TEMPORARILY UNAVAILABLE\\n\\n"
                    "The configured Live AI provider has reached its rate/quota or free-tier limit.\\n"
                    f"Please try again in about {remaining} seconds.\\n\\n"
                    "No provider request was sent, and no investigation data was changed.\\n\\n"
                    "You can continue with deterministic LogAsis analysis while Live AI is unavailable."
                )
                self.statusBar().showMessage(
                    f"Live AI is rate limited. No request was sent. Try again in about {remaining}s.",
                    5000,
                )
                return

        self._ai_cancelled = False
        request_generation = int(getattr(self, "_ai_session_generation", 0))
        self.ai_analyze_btn.setEnabled(True)
        self.ai_analyze_btn.setText("Cancel Analysis")
        self.ai_output.setPlainText("AI ANALYSIS\n\nPreparing bounded evidence context…")
        self._ai_thread = QThread(self)
        # Use the full parsed dataset, not the Events-tab filtered view. AI
        # investigation must always see the complete log regardless of
        # whatever search/filter is currently applied to the events table --
        # otherwise an active filter silently narrows what the AI can see,
        # with no indication to the analyst that this happened.
        if len(self.filtered_df) != len(self.df):
            self.statusBar().showMessage(
                "Note: an Events filter is active, but AI investigation always analyzes the full log.",
                5000,
            )
        self._ai_worker = AIWorker(self.ai_provider.currentText(), question, self.df, self.current_file)
        self._ai_worker.session_generation = request_generation
        self._ai_worker.moveToThread(self._ai_thread)
        self._ai_thread.started.connect(self._ai_worker.run)
        self._ai_worker.prepared.connect(self._ai_prepared)
        self._ai_worker.progress.connect(self._ai_progress)
        self._ai_worker.finished.connect(self._ai_finished)
        self._ai_worker.failed.connect(self._ai_failed)
        self._ai_worker.finished.connect(self._ai_thread.quit)
        self._ai_worker.failed.connect(self._ai_thread.quit)
        self._ai_thread.finished.connect(self._ai_thread_finished)
        self._ai_thread.finished.connect(self._ai_worker.deleteLater)
        self._ai_thread.finished.connect(self._ai_thread.deleteLater)
        self._ai_thread.start()

    def _ai_progress(self, percent, message):
        if self._ai_cancelled:
            return
        provider = self.ai_provider.currentText()
        self._safe_set_label_text(self.ai_status, f"AI analysis • {provider} • {percent}% • {message}")
        self.ai_grounding_output.clear()
        self.ai_output.setPlainText(
            "AI EVIDENCE-GROUNDED INTELLIGENCE\n\n"
            f"{message}\n\n"
            f"Progress: {percent}%\n\n"
            "Deterministic evidence remains authoritative.\n"
            "The raw log is never pasted wholesale into the AI prompt.\nEvidence citations are validated against LogAsis retrieval."
        )

    def _ai_prepared(self, plan):
        provider = self.ai_provider.currentText()
        strategy = "shared bounded agentic investigation runtime"
        self.ai_grounding_output.clear()
        self.ai_output.setPlainText(
            "AI EVIDENCE-GROUNDED INTELLIGENCE\n\n"
            f"{plan}\n\n"
            f"Strategy: {strategy}\n\n"
            "The raw log is never pasted wholesale into the AI prompt.\nEvidence citations are validated against LogAsis retrieval.\n"
            "Preparing analyst synthesis…"
        )
        self._safe_set_label_text(self.ai_status, f"AI context prepared • {plan} • {strategy} • Evidence grounding enabled")

    @staticmethod
    def _humanize_ai_answer(answer):
        """Never expose provider JSON transport in the Analyst Assessment pane.

        Providers may occasionally ignore the human-readable output contract and
        return a JSON object (or fenced JSON). Grounding remains the source of
        truth in ai/agent.py; this is a presentation safety net for the GUI only.
        """
        import json
        import re

        raw = str(answer or "").strip()
        if not raw:
            return ""

        def parse_json(text):
            candidates = [text]
            candidates.extend(re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.I | re.S))
            for candidate in candidates:
                try:
                    obj = json.loads(candidate)
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
                if isinstance(obj, dict):
                    return obj
            # Balanced-object fallback for prose surrounding JSON.
            start = text.find("{")
            while start >= 0:
                depth = 0
                quoted = False
                escaped = False
                for i in range(start, len(text)):
                    ch = text[i]
                    if quoted:
                        if escaped:
                            escaped = False
                        elif ch == "\\":
                            escaped = True
                        elif ch == '"':
                            quoted = False
                    else:
                        if ch == '"':
                            quoted = True
                        elif ch == "{":
                            depth += 1
                        elif ch == "}":
                            depth -= 1
                            if depth == 0:
                                try:
                                    obj = json.loads(text[start:i + 1])
                                except (TypeError, ValueError, json.JSONDecodeError):
                                    break
                                if isinstance(obj, dict):
                                    return obj
                                break
                start = text.find("{", start + 1)
            return None

        obj = parse_json(raw)
        if not obj or not isinstance(obj.get("claims"), list):
            return raw

        lines = ["AI ANALYST ASSESSMENT"]
        overall = str(obj.get("overall_assessment") or "").strip()
        if overall:
            lines += ["", "AI ASSESSMENT", overall]

        claims = obj.get("claims") or []
        facts, interpretations, recommendations, review = [], [], [], []
        for claim in claims:
            if not isinstance(claim, dict):
                continue
            text = re.sub(r"\s*\[(?:EVID-\d+)\]", "", str(claim.get("text") or "")).strip()
            if not text:
                continue
            refs = [str(x).upper() for x in (claim.get("evidence_references") or []) if str(x).strip()]
            suffix = " " + " ".join(f"[{x}]" for x in refs) if refs else ""
            ctype = str(claim.get("type") or "").upper()
            status = str(claim.get("validation_status") or claim.get("grounding_status") or "").upper()
            item = text + suffix
            if ctype == "VERIFIED_FACT" and status not in {"REJECTED", "REJECTED_CONTRADICTED"}:
                facts.append(item)
            elif ctype == "GROUNDED_INTERPRETATION" and status not in {"REJECTED", "REJECTED_CONTRADICTED"}:
                interpretations.append(item)
            elif ctype in {"RECOMMENDATION", "RECOMMENDED_ACTION", "NEXT_STEP"}:
                recommendations.append(item)
            elif status in {"REVIEW_REQUIRED", "INSUFFICIENT_CONTEXT"} or ctype == "INSUFFICIENT_CONTEXT":
                review.append(item)

        if facts:
            lines += ["", "AI-REPORTED VERIFIED FACTS"]
            lines.extend(f"• {x}" for x in facts[:12])
        if interpretations:
            lines += ["", "AI INTERPRETATION (ADVISORY)"]
            lines.extend(f"• {x}" for x in interpretations[:12])
        limitations = [str(x).strip() for x in (obj.get("limitations") or []) if str(x).strip()]
        if limitations:
            lines += ["", "LIMITATIONS"]
            lines.extend(f"• {x}" for x in limitations[:8])
        next_steps = [str(x).strip() for x in (obj.get("next_steps") or []) if str(x).strip()]
        if next_steps:
            lines += ["", "RECOMMENDED INVESTIGATION"]
            lines.extend(f"• {x}" for x in next_steps[:8])
        if recommendations:
            lines += ["", "RECOMMENDED INVESTIGATION"]
            lines.extend(f"• {x}" for x in recommendations[:8])
        if review:
            lines += ["", "REQUIRES ADDITIONAL CONTEXT"]
            lines.extend(f"• {x}" for x in review[:8])

        if len(lines) == 1:
            lines += ["", "AI ASSESSMENT", overall or "The provider returned a structured response, but no displayable analyst claims were available."]
        return "\n".join(lines)

    def _ai_finished(self, answer, provider_label, model):
        worker = self.sender()
        if getattr(worker, "session_generation", self._ai_session_generation) != self._ai_session_generation:
            return
        if self._ai_cancelled:
            return
        rendered = self._humanize_ai_answer(answer)
        marker = "EVIDENCE & GROUNDING DETAILS\n"
        if marker in rendered:
            primary, details = rendered.split(marker, 1)
            self.ai_output.setPlainText(primary.strip())
            self.ai_grounding_output.setPlainText("EVIDENCE & GROUNDING DETAILS\n" + details.strip())
        else:
            self.ai_output.setPlainText(rendered)
            self.ai_grounding_output.clear()
        self._safe_set_label_text(
            self.ai_status,
            f"Analysis completed • {provider_label} • {model} • "
            "Deterministic evidence remains authoritative."
        )
        if self.ai_provider.currentText() == "Live AI":
            mark_provider_available("Live AI")

    def _ai_failed(self, message):
        worker = self.sender()
        if getattr(worker, "session_generation", self._ai_session_generation) != self._ai_session_generation:
            return
        if self._ai_cancelled and "cancelled" not in str(message).lower():
            return
        raw = str(message)
        if raw.startswith("AI_RATE_LIMITED|"):
            friendly = raw.split("|", 1)[1]
            self.ai_output.setPlainText(
                "LIVE AI TEMPORARILY UNAVAILABLE\n\n"
                + friendly
                + "\n\nThe investigation remains available. You can continue using deterministic LogAsis analysis while Live AI is unavailable."
            )
            self._refresh_ai_provider_status()
            self.statusBar().showMessage(
                "Live AI is temporarily unavailable because its provider quota/rate limit was reached.", 8000
            )
            return
        self.ai_output.setPlainText(
            "AI ANALYSIS FAILED\n\n" + raw
        )
        self._safe_set_label_text(
            self.ai_status,
            f"AI analysis failed using {self.ai_provider.currentText()}. No fallback provider was used."
        )

    def _ai_thread_finished(self):
        self.ai_analyze_btn.setText("Analyze")
        if self._ai_cancelled:
            self._safe_set_label_text(self.ai_status, "AI analysis cancelled. No investigation data was changed.")
        self._ai_worker = None
        self._ai_thread = None
        # A rate-limited Live AI provider must remain unavailable after the
        # worker exits. _refresh_ai_provider_status hides the action while the
        # cooldown is active and restores it automatically when it expires.
        self._refresh_ai_provider_status()

    def _build_evidence_tab(self):
        layout = QVBoxLayout(self.evidence_tab)

        controls = QHBoxLayout()
        self.evidence_status_filter = QComboBox()
        self.evidence_status_filter.addItems(["All", *EvidenceStore.STATUSES])
        self.evidence_status_filter.currentTextChanged.connect(self.refresh_evidence)
        controls.addWidget(QLabel("Status:"))
        controls.addWidget(self.evidence_status_filter)

        self.evidence_priority_filter = QComboBox()
        self.evidence_priority_filter.addItems(["All", *EvidenceStore.PRIORITIES])
        self.evidence_priority_filter.currentTextChanged.connect(self.refresh_evidence)
        controls.addWidget(QLabel("Priority:"))
        controls.addWidget(self.evidence_priority_filter)

        self.add_evidence_btn = QPushButton("Add Selected Investigation")
        self.add_evidence_btn.clicked.connect(self._add_selected_evidence)
        controls.addWidget(self.add_evidence_btn)

        self.save_evidence_btn = QPushButton("Save Changes")
        self.save_evidence_btn.clicked.connect(self._save_evidence_changes)
        controls.addWidget(self.save_evidence_btn)

        self.export_evidence_btn = QPushButton("Export Evidence JSON")
        self.export_evidence_btn.clicked.connect(self._export_evidence)
        controls.addWidget(self.export_evidence_btn)

        self.clear_evidence_btn = QPushButton("Clear Evidence")
        self.clear_evidence_btn.clicked.connect(self._clear_evidence)
        self.clear_evidence_btn.setToolTip(
            "Permanently remove all locally stored evidence records. Export first if needed."
        )
        controls.addWidget(self.clear_evidence_btn)

        self.create_case_btn = QPushButton("Create Case from Evidence")
        self.create_case_btn.clicked.connect(self._create_case_from_evidence)
        controls.addWidget(self.create_case_btn)

        controls.addStretch(1)
        layout.addLayout(controls)

        self.evidence_action_status = QLabel("Evidence is preserved locally and linked to investigation candidates.")
        self.evidence_action_status.setObjectName("workspaceSubtitle")
        self.evidence_action_status.setWordWrap(True)
        layout.addWidget(self.evidence_action_status)

        self.evidence_table = QTableWidget()
        self.evidence_table.setAlternatingRowColors(True)
        self.evidence_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.evidence_table.setSelectionMode(QTableWidget.SingleSelection)
        self.evidence_table.setSortingEnabled(True)
        self.evidence_table.cellClicked.connect(self._show_evidence_record)
        layout.addWidget(self.evidence_table, 2)

        detail_layout = QHBoxLayout()
        self.evidence_detail = QTextEdit()
        self.evidence_detail.setReadOnly(True)
        self.evidence_detail.setObjectName("analystReport")
        detail_layout.addWidget(self.evidence_detail, 2)

        notes_layout = QVBoxLayout()
        notes_layout.addWidget(QLabel("Analyst Notes"))
        self.evidence_notes = QTextEdit()
        self.evidence_notes.setPlaceholderText("Add analyst notes for the selected evidence record.")
        notes_layout.addWidget(self.evidence_notes)
        self.evidence_status = QComboBox()
        self.evidence_status.addItems(EvidenceStore.STATUSES)
        notes_layout.addWidget(QLabel("Record Status"))
        notes_layout.addWidget(self.evidence_status)
        detail_layout.addLayout(notes_layout, 1)

        layout.addLayout(detail_layout, 2)

    def _build_cases_tab(self):
        """Build the responsive case investigation workspace.

        The previous layout stacked several large widgets with independent
        minimum heights. On smaller screens this squeezed Analyst Workflow and
        made the investigation results appear to have no usable space.
        Splitters now let the analyst allocate space interactively while
        retaining sensible minimum sizes.
        """
        layout = QVBoxLayout(self.cases_tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        controls = QHBoxLayout()
        self.case_status_filter = QComboBox()
        self.case_status_filter.addItems(["All", *CaseStore.STATUSES])
        self.case_status_filter.currentTextChanged.connect(self.refresh_cases)
        controls.addWidget(QLabel("Status:"))
        controls.addWidget(self.case_status_filter)

        self.case_priority_filter = QComboBox()
        self.case_priority_filter.addItems(["All", *CaseStore.PRIORITIES])
        self.case_priority_filter.currentTextChanged.connect(self.refresh_cases)
        controls.addWidget(QLabel("Priority:"))
        controls.addWidget(self.case_priority_filter)

        self.save_case_btn = QPushButton("Save Case")
        self.save_case_btn.clicked.connect(self._save_case_changes)
        controls.addWidget(self.save_case_btn)

        self.export_cases_btn = QPushButton("Export Cases JSON")
        self.export_cases_btn.clicked.connect(self._export_cases)
        controls.addWidget(self.export_cases_btn)

        self.clear_cases_btn = QPushButton("Clear Cases")
        self.clear_cases_btn.clicked.connect(self._clear_cases)
        controls.addWidget(self.clear_cases_btn)
        controls.addStretch(1)
        layout.addLayout(controls)

        action_row = QHBoxLayout()
        action_row.setSpacing(7)
        self.case_correlate_btn = QPushButton("Correlate")
        self.case_correlate_btn.setObjectName("primaryButton")
        self.case_correlate_btn.clicked.connect(self._correlate_selected_case)
        action_row.addWidget(self.case_correlate_btn)

        self.case_timeline_btn = QPushButton("Timeline")
        self.case_timeline_btn.clicked.connect(self._show_case_timeline)
        action_row.addWidget(self.case_timeline_btn)

        self.case_link_evidence_btn = QPushButton("Link Evidence")
        self.case_link_evidence_btn.clicked.connect(self._link_evidence_to_selected_case)
        action_row.addWidget(self.case_link_evidence_btn)

        self.case_intelligence_btn = QPushButton("Intelligence")
        self.case_intelligence_btn.clicked.connect(self._show_case_intelligence)
        action_row.addWidget(self.case_intelligence_btn)

        self.case_more_btn = QPushButton("More Actions ▾")
        self.case_more_btn.setObjectName("secondaryButton")
        more_menu = QMenu(self.case_more_btn)
        self.case_more_btn.setMenu(more_menu)
        more_menu.addAction("Export Case Intelligence", self._export_case_intelligence)
        more_menu.addAction("Export Full Case Report", self._export_full_case_report)
        more_menu.addSeparator()
        more_menu.addAction("Compare Cases", self._compare_selected_case)
        more_menu.addAction("Investigation Graph", self._show_case_graph)
        more_menu.addAction("Decision & Evidence Gaps", self._show_case_decision)
        more_menu.addAction("Investigation Loop", self._show_investigation_loop)
        more_menu.addAction("Response & Closure", self._show_response_closure)
        more_menu.addAction("Incident Report & Handoff", self._show_case_handoff)
        more_menu.addAction("Export Reusable Investigation Package", self._export_case_package)
        more_menu.addAction("Import Investigation Package", self._import_case_package)
        action_row.addWidget(self.case_more_btn)

        # Keep the legacy button attributes for compatibility with existing
        # tests and integrations; advanced actions are now exposed through the menu.
        self.export_case_intelligence_btn = QPushButton("Export Case Intelligence JSON")
        self.export_case_intelligence_btn.clicked.connect(self._export_case_intelligence)
        self.export_case_intelligence_btn.hide()
        self.export_case_report_btn = QPushButton("Export Full Case Report")
        self.export_case_report_btn.clicked.connect(self._export_full_case_report)
        self.export_case_report_btn.hide()
        self.case_compare_btn = QPushButton("Compare Cases")
        self.case_compare_btn.clicked.connect(self._compare_selected_case)
        self.case_compare_btn.hide()
        self.case_graph_btn = QPushButton("Investigation Graph")
        self.case_graph_btn.clicked.connect(self._show_case_graph)
        self.case_graph_btn.hide()
        self.case_decision_btn = QPushButton("Decision & Evidence Gaps")
        self.case_decision_btn.clicked.connect(self._show_case_decision)
        self.case_decision_btn.hide()
        action_row.addStretch(1)
        layout.addLayout(action_row)

        self.case_action_status = QLabel(
            "Select a case to review its timeline, correlation, intelligence, AI analysis, and workflow."
        )
        self.case_action_status.setWordWrap(True)
        self.case_action_status.setMinimumHeight(24)
        layout.addWidget(self.case_action_status)

        # Case list. The table is deliberately compact; the analyst allocates
        # more vertical space with the workspace splitter when needed.
        self.cases_table = QTableWidget()
        self.cases_table.setAlternatingRowColors(True)
        self.cases_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.cases_table.setSelectionMode(QTableWidget.SingleSelection)
        self.cases_table.setSortingEnabled(True)
        self.cases_table.cellClicked.connect(self._show_case_record)
        self.cases_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # Selected case + analyst workflow. The splitter changes from side-by-side
        # to stacked when the application becomes narrow.
        detail_group = QGroupBox("Selected Case / Analyst Workflow")
        detail_group_layout = QVBoxLayout(detail_group)
        detail_group_layout.setContentsMargins(8, 8, 8, 8)

        self.case_detail_splitter = QSplitter(Qt.Horizontal)
        self.case_detail_splitter.setChildrenCollapsible(False)
        self.case_detail_splitter.splitterMoved.connect(self._mark_case_detail_resized)

        case_detail_panel = QGroupBox("Case Detail")
        case_detail_layout = QVBoxLayout(case_detail_panel)
        case_detail_layout.setContentsMargins(8, 8, 8, 8)
        self.case_detail = QTextEdit()
        self.case_detail.setReadOnly(True)
        self.case_detail.setPlaceholderText("Select a case to view its details.")
        self.case_detail.setPlainText(
            "NO CASE SELECTED\n\nSelect a case above to open its investigation workspace."
        )
        case_detail_layout.addWidget(self.case_detail, 1)
        self.case_detail_splitter.addWidget(case_detail_panel)

        workflow_group = QGroupBox("Analyst Workflow")
        workflow_group_layout = QVBoxLayout(workflow_group)
        workflow_group_layout.setContentsMargins(8, 8, 8, 8)
        workflow_group_layout.setSpacing(5)

        # The workflow form is scrollable so a restored/mini window never
        # crushes the notes, selectors or checklist into overlapping lines.
        workflow_scroll = QScrollArea()
        workflow_scroll.setWidgetResizable(True)
        workflow_scroll.setFrameShape(QFrame.NoFrame)
        workflow_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        workflow_body = QWidget()
        workflow_layout = QVBoxLayout(workflow_body)
        workflow_layout.setContentsMargins(2, 2, 4, 2)
        workflow_layout.setSpacing(6)

        workflow_layout.addWidget(QLabel("Case Notes"))
        self.case_notes = QTextEdit()
        self.case_notes.setPlaceholderText("Add analyst notes for the selected case.")
        self.case_notes.setMinimumHeight(58)
        self.case_notes.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        workflow_layout.addWidget(self.case_notes)

        workflow_grid = QGridLayout()
        workflow_grid.setHorizontalSpacing(7)
        workflow_grid.setVerticalSpacing(5)
        workflow_grid.addWidget(QLabel("Case Status"), 0, 0)
        self.case_status = QComboBox()
        self.case_status.addItems(CaseStore.STATUSES)
        workflow_grid.addWidget(self.case_status, 0, 1)
        workflow_grid.addWidget(QLabel("Case Priority"), 1, 0)
        self.case_priority = QComboBox()
        self.case_priority.addItems(CaseStore.PRIORITIES)
        workflow_grid.addWidget(self.case_priority, 1, 1)
        workflow_grid.addWidget(QLabel("Disposition"), 2, 0)
        self.case_disposition = QComboBox()
        self.case_disposition.addItems(self.case_workflow.DISPOSITIONS)
        workflow_grid.addWidget(self.case_disposition, 2, 1)
        workflow_grid.setColumnStretch(1, 1)
        workflow_layout.addLayout(workflow_grid)

        workflow_layout.addWidget(QLabel("Response Checklist"))
        self.workflow_checks = {}
        checklist_widget = QWidget()
        checklist_layout = QVBoxLayout(checklist_widget)
        checklist_layout.setContentsMargins(0, 0, 0, 0)
        checklist_layout.setSpacing(5)
        for key, label in self.case_workflow.RESPONSE_ACTIONS:
            check = QCheckBox(label)
            self.workflow_checks[key] = check
            checklist_layout.addWidget(check)
        workflow_layout.addWidget(checklist_widget)
        workflow_layout.addStretch(1)

        workflow_scroll.setWidget(workflow_body)
        workflow_group_layout.addWidget(workflow_scroll, 1)
        self.case_detail_splitter.addWidget(workflow_group)

        detail_group_layout.addWidget(self.case_detail_splitter, 1)

        # Investigation result views.
        self.case_results_tabs = QTabWidget()
        self.case_results_tabs.setDocumentMode(True)
        self.case_results_tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        timeline_page = QWidget()
        timeline_layout = QVBoxLayout(timeline_page)
        self.case_summary_label = QLabel("No case selected.")
        self.case_summary_label.setWordWrap(True)
        timeline_layout.addWidget(self.case_summary_label)
        self.case_timeline_table = QTableWidget()
        self.case_timeline_table.setAlternatingRowColors(True)
        self.case_timeline_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.case_timeline_table.setColumnCount(7)
        self.case_timeline_table.setHorizontalHeaderLabels([
            "Evidence ID", "Timestamp", "Priority", "Event Type",
            "Source IP", "Username", "Process",
        ])
        self.case_timeline_table.setSortingEnabled(True)
        self._fit_table(
            self.case_timeline_table,
            stretch_columns=(3, 6),
            content_columns=(0, 1, 2, 4, 5),
        )
        timeline_layout.addWidget(self.case_timeline_table, 1)
        self.case_results_tabs.addTab(timeline_page, "Case Timeline")

        correlation_page = QWidget()
        correlation_layout = QVBoxLayout(correlation_page)
        self.case_correlation_summary = QLabel("No correlation run.")
        self.case_correlation_summary.setWordWrap(True)
        correlation_layout.addWidget(self.case_correlation_summary)
        self.case_relationships = QTableWidget()
        self.case_relationships.setAlternatingRowColors(True)
        self.case_relationships.setSelectionBehavior(QTableWidget.SelectRows)
        self.case_relationships.setSelectionMode(QTableWidget.SingleSelection)
        self.case_relationships.setColumnCount(6)
        self.case_relationships.setHorizontalHeaderLabels([
            "Type", "Evidence A", "Evidence B / Candidate", "Strength", "Score", "Reason"
        ])
        self.case_relationships.setSortingEnabled(True)
        self._fit_table(
            self.case_relationships,
            stretch_columns=(2, 5),
            content_columns=(0, 1, 3, 4),
        )
        correlation_layout.addWidget(self.case_relationships, 1)
        self.case_correlation_note = QLabel(
            "Strong relationships use multiple shared attributes. Contextual relationships "
            "are based on temporal proximity only; they do not establish causation or malicious intent."
        )
        self.case_correlation_note.setWordWrap(True)
        correlation_layout.addWidget(self.case_correlation_note)
        self.case_results_tabs.addTab(correlation_page, "Correlation")

        # Investigation Command Center / Summary.
        # This keeps the legacy "Summary" tab contract while turning it into
        # the case-scoped control surface for the entire investigation chain.
        command_page = QScrollArea()
        command_page.setWidgetResizable(True)
        command_page.setFrameShape(QFrame.NoFrame)
        command_body = QWidget()
        command_layout = QVBoxLayout(command_body)
        command_layout.setContentsMargins(8, 8, 8, 8)
        command_layout.setSpacing(8)

        command_header = QLabel(
            "<b>INVESTIGATION COMMAND CENTER</b><br>"
            "Case-scoped view of evidence, findings, IOCs, correlation, decision state, "
            "evidence gaps and the next analyst action."
        )
        command_header.setWordWrap(True)
        command_layout.addWidget(command_header)

        self.case_progress = QProgressBar()
        self.case_progress.setRange(0, 100)
        self.case_progress.setValue(0)
        self.case_progress.setFormat("Investigation completeness: %p%")
        self.case_progress.setTextVisible(True)
        command_layout.addWidget(self.case_progress)

        metrics_box = QGroupBox("Investigation Context")
        metrics_grid = QGridLayout(metrics_box)
        self.case_context_metrics = {}
        for idx, (key, label) in enumerate([
            ("evidence", "Evidence"),
            ("findings", "Findings"),
            ("iocs", "IOCs"),
            ("relationships", "Correlations"),
            ("gaps", "Evidence Gaps"),
            ("audit", "Audit Entries"),
            ("related_cases", "Related Cases"),
            ("disposition", "Disposition"),
            ("next", "Next Step"),
        ]):
            card, value = self._metric(label)
            self.case_context_metrics[key] = value
            metrics_grid.addWidget(card, idx // 4, idx % 4)
        command_layout.addWidget(metrics_box)

        self.case_context_chain = QLabel("Events → Evidence → Findings → IOCs → Case → Correlation → Decision → Gaps")
        self.case_context_chain.setWordWrap(True)
        command_layout.addWidget(self.case_context_chain)

        next_box = QGroupBox("Recommended Next Investigation Step")
        next_layout = QVBoxLayout(next_box)
        self.case_next_step = QLabel("Select a case to calculate the next deterministic investigation step.")
        self.case_next_step.setWordWrap(True)
        next_layout.addWidget(self.case_next_step)
        next_buttons = QHBoxLayout()
        self.case_next_decision_btn = QPushButton("Review Decision / Gaps")
        self.case_next_decision_btn.clicked.connect(self._show_case_decision)
        self.case_next_loop_btn = QPushButton("Run Investigation Loop")
        self.case_next_loop_btn.setObjectName("primaryButton")
        self.case_next_loop_btn.clicked.connect(self._show_investigation_loop)
        self.case_next_timeline_btn = QPushButton("Open Timeline")
        self.case_next_timeline_btn.clicked.connect(self._show_case_timeline)
        self.case_next_correlation_btn = QPushButton("Open Correlation")
        self.case_next_correlation_btn.clicked.connect(self._correlate_selected_case)
        self.case_next_ai_btn = QPushButton("Open AI Analyst")
        self.case_next_ai_btn.clicked.connect(lambda: self.case_results_tabs.setCurrentIndex(4))
        self.case_next_response_btn = QPushButton("Response & Closure")
        self.case_next_response_btn.clicked.connect(self._show_response_closure)
        next_buttons.addWidget(self.case_next_decision_btn)
        next_buttons.addWidget(self.case_next_loop_btn)
        next_buttons.addWidget(self.case_next_timeline_btn)
        next_buttons.addWidget(self.case_next_correlation_btn)
        next_buttons.addWidget(self.case_next_ai_btn)
        next_buttons.addWidget(self.case_next_response_btn)
        next_buttons.addStretch(1)
        next_layout.addLayout(next_buttons)
        command_layout.addWidget(next_box)

        response_box = QGroupBox("Response & Closure Lifecycle")
        response_layout = QVBoxLayout(response_box)
        self.case_response_status = QLabel("Select a case to assess response readiness.")
        self.case_response_status.setWordWrap(True)
        response_layout.addWidget(self.case_response_status)
        response_actions = QHBoxLayout()
        self.case_response_open_btn = QPushButton("Open Response & Closure")
        self.case_response_open_btn.clicked.connect(self._show_response_closure)
        response_actions.addWidget(self.case_response_open_btn)
        self.case_response_report_btn = QPushButton("Prepare Final Report")
        self.case_response_report_btn.clicked.connect(self._prepare_final_case_report)
        response_actions.addWidget(self.case_response_report_btn)
        response_actions.addStretch(1)
        response_layout.addLayout(response_actions)
        command_layout.addWidget(response_box)

        stages_box = QGroupBox("Investigation Workflow")
        stages_layout = QVBoxLayout(stages_box)
        self.case_stage_table = QTableWidget(0, 3)
        self.case_stage_table.setHorizontalHeaderLabels(["Stage", "State", "Meaning"])
        self.case_stage_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.case_stage_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._fit_table(
            self.case_stage_table,
            stretch_columns=(2,),
            content_columns=(0, 1),
            min_row_height=26,
        )
        stages_layout.addWidget(self.case_stage_table)
        command_layout.addWidget(stages_box)

        self.case_findings_summary = QLabel("Evidence-backed findings will appear here.")
        self.case_findings_summary.setWordWrap(True)
        command_layout.addWidget(self.case_findings_summary)
        self.case_findings_table = QTableWidget()
        self.case_findings_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.case_findings_table.setColumnCount(5)
        self.case_findings_table.setHorizontalHeaderLabels([
            "Finding ID", "Classification", "Confidence", "Finding", "Evidence Provenance"
        ])
        self.case_findings_table.cellClicked.connect(self._command_center_finding_clicked)
        self._fit_table(
            self.case_findings_table,
            stretch_columns=(3, 4),
            content_columns=(0, 1, 2),
            min_row_height=30,
        )
        findings_box = QGroupBox("Related Findings")
        findings_layout = QVBoxLayout(findings_box)
        findings_layout.addWidget(self.case_findings_table)
        command_layout.addWidget(findings_box)

        self.case_ioc_summary = QLabel("Case-scoped IOC inventory will appear here.")
        self.case_ioc_summary.setWordWrap(True)
        command_layout.addWidget(self.case_ioc_summary)
        self.case_ioc_table = QTableWidget()
        self.case_ioc_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.case_ioc_table.setColumnCount(5)
        self.case_ioc_table.setHorizontalHeaderLabels([
            "Type", "Value", "Occurrences", "Evidence", "Algorithm"
        ])
        self.case_ioc_table.cellClicked.connect(self._command_center_ioc_clicked)
        self._fit_table(
            self.case_ioc_table,
            stretch_columns=(1,),
            content_columns=(0, 2, 3, 4),
            min_row_height=28,
        )
        ioc_box = QGroupBox("Case-Scoped IOC Inventory")
        ioc_layout = QVBoxLayout(ioc_box)
        ioc_layout.addWidget(self.case_ioc_table)
        ioc_actions = QHBoxLayout()
        self.case_open_ioc_btn = QPushButton("Open Findings & IOC Operations")
        self.case_open_ioc_btn.clicked.connect(self._open_case_ioc_operations)
        ioc_actions.addWidget(self.case_open_ioc_btn)
        ioc_actions.addStretch(1)
        ioc_layout.addLayout(ioc_actions)
        command_layout.addWidget(ioc_box)

        command_layout.addStretch(1)
        command_page.setWidget(command_body)
        self.case_results_tabs.addTab(command_page, "Summary")

        intelligence_page = QWidget()
        intelligence_layout = QVBoxLayout(intelligence_page)
        self.case_intelligence_view = QTextEdit()
        self.case_intelligence_view.setReadOnly(True)
        self.case_intelligence_view.setLineWrapMode(QTextEdit.WidgetWidth)
        self.case_intelligence_view.setPlaceholderText(
            "Deterministic case-level intelligence will appear here."
        )
        intelligence_layout.addWidget(self.case_intelligence_view)
        self.case_results_tabs.addTab(intelligence_page, "Case Intelligence")

        # AI Analyst workspace.
        ai_page = QWidget()
        ai_layout = QVBoxLayout(ai_page)
        ai_layout.setContentsMargins(8, 8, 8, 8)
        ai_layout.setSpacing(7)
        ai_controls = QHBoxLayout()
        ai_controls.addWidget(QLabel("Provider:"))
        self.case_ai_provider = QComboBox()
        self.case_ai_provider.addItems(["Live AI"])
        self.case_ai_provider.currentTextChanged.connect(self._case_ai_provider_changed)
        ai_controls.addWidget(self.case_ai_provider)
        self.case_ai_config_btn = QPushButton("Configure")
        self.case_ai_config_btn.clicked.connect(self.configure_live_ai)
        self.case_ai_config_btn.setEnabled(False)
        ai_controls.addWidget(self.case_ai_config_btn)
        ai_controls.addWidget(QLabel("Question:"))
        self.case_ai_question = QLineEdit()
        self.case_ai_question.setText("What happened in this case and what should I investigate next?")
        self.case_ai_question.setClearButtonEnabled(True)
        ai_controls.addWidget(self.case_ai_question, 1)
        self.case_ai_analyze_btn = QPushButton("Analyze Case")
        self.case_ai_analyze_btn.clicked.connect(self.run_case_ai_analysis)
        ai_controls.addWidget(self.case_ai_analyze_btn)
        ai_layout.addLayout(ai_controls)
        self.case_ai_status = QLabel(
            "AI interpretation is generated from bounded Case Intelligence. "
            "Deterministic case facts remain authoritative; raw log/message fields are excluded."
        )
        self.case_ai_status.setWordWrap(True)
        ai_layout.addWidget(self.case_ai_status)
        ai_report_actions = QHBoxLayout()
        self.case_ai_copy_btn = QPushButton("Copy Report")
        self.case_ai_copy_btn.clicked.connect(self._copy_case_ai_report)
        ai_report_actions.addWidget(self.case_ai_copy_btn)
        self.case_ai_export_btn = QPushButton("Export Analyst Report")
        self.case_ai_export_btn.clicked.connect(self._export_case_ai_report)
        ai_report_actions.addWidget(self.case_ai_export_btn)
        self.case_ai_clear_btn = QPushButton("Clear Analysis")
        self.case_ai_clear_btn.clicked.connect(self._clear_case_ai_report)
        ai_report_actions.addWidget(self.case_ai_clear_btn)
        ai_report_actions.addStretch(1)
        ai_layout.addLayout(ai_report_actions)
        self.case_ai_output = QTextBrowser()
        self.case_ai_output.setOpenLinks(False)
        self.case_ai_output.setOpenExternalLinks(False)
        self.case_ai_output.anchorClicked.connect(self._case_ai_link_clicked)
        self.case_ai_output.setPlaceholderText(
            "The professional case analyst report will appear here."
        )
        ai_layout.addWidget(self.case_ai_output, 1)
        self.case_results_tabs.addTab(ai_page, "AI Analyst")

        workflow_page = QWidget()
        workflow_page_layout = QVBoxLayout(workflow_page)
        self.case_workflow_summary = QTextEdit()
        self.case_workflow_summary.setReadOnly(True)
        self.case_workflow_summary.setLineWrapMode(QTextEdit.WidgetWidth)
        self.case_workflow_summary.setPlaceholderText(
            "Workflow status, checklist, and audit history will appear here."
        )
        workflow_page_layout.addWidget(self.case_workflow_summary)
        self.case_results_tabs.addTab(workflow_page, "Workflow & Audit")

        # Three-stage investigation workspace. QSplitter provides proportional
        # resizing instead of fixed heights, so the same UI works at 1080p,
        # laptop resolutions, and maximised windows.
        self.case_workspace_splitter = QSplitter(Qt.Vertical)
        self.case_workspace_splitter.setChildrenCollapsible(False)
        self.case_workspace_splitter.splitterMoved.connect(self._mark_case_workspace_resized)
        self.case_workspace_splitter.addWidget(self.cases_table)
        self.case_workspace_splitter.addWidget(detail_group)
        self.case_workspace_splitter.addWidget(self.case_results_tabs)
        self.case_workspace_splitter.setStretchFactor(0, 1)
        self.case_workspace_splitter.setStretchFactor(1, 2)
        self.case_workspace_splitter.setStretchFactor(2, 4)
        layout.addWidget(self.case_workspace_splitter, 1)

        self._case_ai_provider_changed(self.case_ai_provider.currentText())

    def _build_case_context(self, case, decision=None):
        """Build the deterministic context consumed by the command center."""
        try:
            context = self.investigation_context.build(
                case,
                self.evidence_store,
                self.correlation_engine,
                self.case_intelligence,
                self.case_workflow,
                detections=self._detections,
                all_iocs=self._iocs if self._iocs else None,
                decision=decision,
            )
            cross_case = self.investigation_intelligence.build(
                case, self.case_store.records, self.evidence_store, context
            )
            context["cross_case_intelligence"] = cross_case
            context["related_cases"] = int(cross_case.get("cross_case_match_count", 0))
            return context
        except Exception:
            # The command center is a presentation enhancement. A failure here
            # must never break the existing case workflow.
            return None

    def _render_case_command_center(self, case, decision=None):
        context = self._build_case_context(case, decision=decision)
        if not context:
            self.case_progress.setValue(0)
            self.case_next_step.setText(
                "Investigation context is temporarily unavailable. Existing case views remain usable."
            )
            return

        self.case_progress.setValue(int(context.get("progress", 0)))
        metrics = context.get("case_id", "")
        values = {
            "evidence": str(context.get("evidence_count", 0)),
            "findings": str(context.get("findings_count", 0)),
            "iocs": str(context.get("ioc_count", 0)),
            "relationships": str(context.get("relationship_count", 0)),
            "gaps": str(len(context.get("evidence_gaps", []) or [])),
            "audit": str(context.get("audit_count", 0)),
            "related_cases": str(context.get("related_cases", 0)),
            "disposition": str(context.get("disposition", "Undetermined")),
            "next": str(context.get("next_kind", "—")),
        }
        for key, value in values.items():
            self._safe_set_label_text(self.case_context_metrics.get(key), value)

        chain_parts = []
        for label, count in context.get("chain", []):
            chain_parts.append(f"{label} ({count})")
        self._safe_set_label_text(
            self.case_context_chain,
            "  →  ".join(chain_parts),
        )
        self._safe_set_label_text(
            self.case_next_step,
            f"<b>{html.escape(str(context.get('next_kind', 'Next step')))}</b>: "
            f"{html.escape(str(context.get('next_step', '')))}<br>"
            f"<span>{html.escape(str(context.get('next_reason', '')))}</span>",
        )

        response = context.get("response", {}) or {}
        response_text = (
            f"<b>{html.escape(str(response.get('lifecycle', 'RESPONSE_REQUIRED')))}</b> · "
            f"{html.escape(str(response.get('readiness', 'NOT_READY')))}<br>"
            f"{html.escape(str(response.get('recommendation', 'Assess response readiness.')))}"
        )
        self._safe_set_label_text(getattr(self, "case_response_status", None), response_text)
        if hasattr(self, "case_response_open_btn"):
            self.case_response_open_btn.setText(
                "Review Response & Closure" if response.get("readiness") != "READY_FOR_CLOSURE" else "Close / Handoff Review"
            )

        stages = context.get("stages", [])
        self.case_stage_table.setRowCount(len(stages))
        for row, stage in enumerate(stages):
            complete = bool(stage.get("complete"))
            values = [
                stage.get("label", ""),
                "COMPLETE" if complete else "PENDING",
                (
                    "Underlying evidence/analysis for this stage is available."
                    if complete
                    else "This stage still needs analyst attention."
                ),
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if col == 1:
                    item.setForeground(QBrush(QColor("#22C55E" if complete else "#F59E0B")))
                self.case_stage_table.setItem(row, col, item)

        findings = context.get("findings", []) or []
        # Fall back to case-intelligence findings because some case findings are
        # generated from deterministic intelligence rather than the global
        # DetectionEngine list.
        if not findings:
            findings = context.get("intelligence", {}).get("findings", []) or []
        self._safe_set_label_text(
            self.case_findings_summary,
            f"{len(findings)} evidence-backed finding(s) linked to {context.get('evidence_count', 0)} evidence record(s). "
            "Select a finding to pivot to its supporting evidence.",
        )
        self.case_findings_table.setSortingEnabled(False)
        self.case_findings_table.setRowCount(len(findings))
        for row, finding in enumerate(findings):
            vals = [
                finding.get("finding_id", finding.get("rule_id", "")),
                finding.get("classification", finding.get("severity", "")),
                finding.get("confidence", ""),
                finding.get("statement", finding.get("summary", finding.get("finding", ""))),
                ", ".join(finding.get("evidence_ids", []) or []) or "None",
            ]
            for col, value in enumerate(vals):
                self.case_findings_table.setItem(row, col, QTableWidgetItem(str(value)))
        self.case_findings_table.setSortingEnabled(True)

        iocs = context.get("iocs", []) or []
        self._safe_set_label_text(
            self.case_ioc_summary,
            f"{len(iocs)} unique IOC(s) are scoped to this case. "
            f"Related cases sharing these IOC values: {context.get('related_cases', 0)}.",
        )
        self.case_ioc_table.setSortingEnabled(False)
        self.case_ioc_table.setRowCount(len(iocs))
        for row, item in enumerate(iocs):
            vals = [
                item.get("type", ""),
                item.get("value", ""),
                item.get("occurrences", 0),
                len(item.get("evidence_ids", []) or []),
                item.get("algorithm", ""),
            ]
            for col, value in enumerate(vals):
                self.case_ioc_table.setItem(row, col, QTableWidgetItem(str(value)))
        self.case_ioc_table.setSortingEnabled(True)

    def _command_center_finding_clicked(self, row, _column=0):
        if row < 0:
            return
        evidence_item = self.case_findings_table.item(row, 4)
        if not evidence_item:
            return
        evidence_id = str(evidence_item.text()).split(",")[0].strip()
        if evidence_id and evidence_id != "None":
            self._navigate_to_evidence(evidence_id)

    def _command_center_ioc_clicked(self, row, _column=0):
        if row < 0:
            return
        type_item = self.case_ioc_table.item(row, 0)
        value_item = self.case_ioc_table.item(row, 1)
        if not type_item or not value_item:
            return
        self.investigation_session.select_ioc(type_item.text(), value_item.text())
        self._open_case_ioc_operations()

    def _open_case_ioc_operations(self):
        ioc_type = self.investigation_session.selected_ioc_type
        ioc_value = self.investigation_session.selected_ioc_value
        self.tabs.setCurrentIndex(9)
        if hasattr(self, "ops_ioc_search"):
            self.ops_ioc_search.setText(ioc_value)
        if hasattr(self, "ops_ioc_type"):
            self.ops_ioc_type.setCurrentText(ioc_type if ioc_type else "All")
        self.refresh_operations()
        self._journal_workspace_state("complete")

    def _open_case_command_center(self):
        if not self._selected_case_id():
            return
        self.case_results_tabs.setCurrentIndex(
            self.case_results_tabs.indexOf(self.case_findings_summary.parentWidget().parentWidget())
        )

    def _create_case_from_evidence(self):
        evidence_id = self._selected_evidence_id()
        if not evidence_id:
            QMessageBox.information(
                self, "Cases", "Select an evidence record first."
            )
            return

        evidence = self.evidence_store.get(evidence_id)
        if evidence is None:
            QMessageBox.warning(self, "Cases", "The selected evidence record no longer exists.")
            return

        case, created = self.case_store.create_from_evidence(evidence)
        if created:
            QMessageBox.information(
                self, "Cases",
                f"Created {case['case_id']} from {evidence_id}."
            )
        else:
            QMessageBox.information(
                self, "Cases",
                f"{evidence_id} is already linked to {case['case_id']}."
            )
        self.refresh_cases()
        self.tabs.setCurrentWidget(self.cases_tab)

    def _visible_cases(self):
        status = self.case_status_filter.currentText()
        priority = self.case_priority_filter.currentText()
        records = self.case_store.records
        if status != "All":
            records = [r for r in records if r.get("status") == status]
        if priority != "All":
            records = [r for r in records if r.get("priority") == priority]
        return list(records)

    def _selected_case_id(self):
        row = self.cases_table.currentRow()
        if row < 0:
            return self._selected_case_id_cache
        item = self.cases_table.item(row, 0)
        case_id = item.text().strip() if item else ""
        return case_id or self._selected_case_id_cache

    def _show_case_record(self, row, _column=0):
        if row < 0:
            return
        item = self.cases_table.item(row, 0)
        case_id = item.text().strip() if item else ""
        if not case_id:
            return
        case = self.case_store.get(case_id)
        if not case:
            return

        self._selected_case_id_cache = case_id
        self.investigation_session.select_case(case_id)
        self.investigation_session.set_view("Case Management")
        evidence_ids = list(case.get("evidence_ids", []) or [])
        evidence_lines = []
        for evidence_id in evidence_ids:
            ev = self.evidence_store.get(evidence_id)
            if ev:
                evidence_lines.append(
                    f"• {evidence_id} — {ev.get('priority', 'N/A')} — "
                    f"{ev.get('event_type', 'N/A')} — record {ev.get('line', 'N/A')}"
                )
            else:
                evidence_lines.append(f"• {evidence_id} — evidence record not found")

        self.case_detail.setPlainText("\n".join([
            f"CASE — {case.get('case_id', 'N/A')}",
            "=" * 72,
            "",
            f"Status: {case.get('status', 'N/A')}",
            f"Priority: {case.get('priority', 'N/A')}",
            f"Title: {case.get('title', 'N/A')}",
            f"Source file: {case.get('source_file', 'N/A')}",
            f"Created: {case.get('created_at', 'N/A')}",
            f"Updated: {case.get('updated_at', 'N/A')}",
            "",
            "DESCRIPTION",
            "-" * 72,
            str(case.get("description", "") or "N/A"),
            "",
            "LINKED EVIDENCE",
            "-" * 72,
            *(evidence_lines or ["• No evidence linked."]),
        ]))

        self.case_status.blockSignals(True)
        self.case_status.setCurrentText(str(case.get("status", "New")))
        self.case_status.blockSignals(False)
        self.case_priority.blockSignals(True)
        self.case_priority.setCurrentText(str(case.get("priority", "MEDIUM")))
        self.case_priority.blockSignals(False)
        self.case_notes.setPlainText(str(case.get("analyst_notes", "")))

        workflow = self.case_workflow.ensure(case)
        self.case_disposition.blockSignals(True)
        self.case_disposition.setCurrentText(str(workflow.get("disposition", "Undetermined")))
        self.case_disposition.blockSignals(False)
        actions = workflow.get("response_actions", {}) or {}
        for key, checkbox in self.workflow_checks.items():
            checkbox.blockSignals(True)
            checkbox.setChecked(bool(actions.get(key, False)))
            checkbox.blockSignals(False)

        self._render_case_correlation(case)
        self._render_case_intelligence(case)
        self._render_case_workflow(case)
        self._render_case_command_center(case)
        self.case_ai_output.clear()
        self._case_ai_report_id = None
        self._safe_set_label_text(
            self.case_action_status,
            f"Selected {case_id}. Use the investigation tabs below to review timeline, correlation, intelligence, AI analysis, and workflow audit history.",
        )

    def _render_case_correlation(self, case):
        result = self.correlation_engine.correlate_case(case)
        summary = result["summary"]
        summary_text = (
            f"Events: {summary['total_events']}  |  "
            f"Critical: {summary['critical']}  |  High: {summary['high']}  |  "
            f"Medium: {summary['medium']}  |  Low: {summary['low']}  |  "
            f"Users: {', '.join(summary['users']) or 'None'}  |  "
            f"Source IPs: {', '.join(summary['source_ips']) or 'None'}  |  "
            f"First: {summary['first_observed'] or 'N/A'}  |  "
            f"Last: {summary['last_observed'] or 'N/A'}"
        )
        self._safe_set_label_text(self.case_summary_label, summary_text)
        relationships = result.get("relationships", [])
        candidates = result.get("related_candidates", [])
        self._safe_set_label_text(
            self.case_correlation_summary,
            f"Linked relationships: {len(relationships)}  |  Potential unlinked candidates: {len(candidates)}  |  Case: {case.get('case_id', 'N/A')}"
        )

        timeline = result["timeline"]
        self.case_timeline_table.setSortingEnabled(False)
        self.case_timeline_table.clearContents()
        self.case_timeline_table.setRowCount(len(timeline))
        for row_idx, item in enumerate(timeline):
            values = [
                item.get("evidence_id", ""), item.get("timestamp", ""), item.get("priority", ""),
                item.get("event_type", ""), item.get("source_ip", ""), item.get("username", ""),
                item.get("process_name", ""),
            ]
            for col, value in enumerate(values):
                self.case_timeline_table.setItem(row_idx, col, QTableWidgetItem(str(value or "")))
        self.case_timeline_table.setSortingEnabled(True)

        rows = []
        for rel in relationships:
            score = int(rel.get("score", 0) or 0)
            strength = "Strong" if score >= 3 else "Moderate" if score == 2 else "Contextual"
            reasons = "; ".join(str(x) for x in rel.get("reasons", []) if x)
            rows.append(("Linked", rel.get("evidence_a", ""), rel.get("evidence_b", ""), strength, score, reasons))
        for item in candidates:
            score = int(item.get("score", 0) or 0)
            strength = "Strong candidate" if score >= 3 else "Moderate candidate" if score == 2 else "Contextual candidate"
            reasons = "; ".join(str(x) for x in item.get("reasons", []) if x)
            rows.append(("Candidate", item.get("related_to", ""), item.get("evidence_id", ""), strength, score, reasons))

        self.case_relationships.setSortingEnabled(False)
        self.case_relationships.clearContents()
        self.case_relationships.setRowCount(len(rows))
        for r, values in enumerate(rows):
            for c, value in enumerate(values):
                self.case_relationships.setItem(r, c, QTableWidgetItem(str(value)))
        self.case_relationships.setSortingEnabled(True)

        if relationships and candidates:
            note = (
                f"{len(relationships)} linked relationship(s) and {len(candidates)} unlinked candidate(s). "
                "Candidate evidence is not part of the case until explicitly linked."
            )
        elif candidates:
            note = (
                f"No linked relationships. {len(candidates)} contextual candidate(s) were found. "
                "Review them before linking."
            )
        elif relationships:
            note = (
                f"{len(relationships)} linked relationship(s) identified. "
                "Score 1 relationships are contextual only; stronger scores require additional shared attributes."
            )
        else:
            note = "No deterministic relationships or unlinked candidates were identified for this case."
        self._safe_set_label_text(self.case_correlation_note, note)

    def _render_case_intelligence(self, case):
        report = self.case_intelligence.build(case)
        context = self._build_case_context(case) or {}
        cross_case = context.get("cross_case_intelligence", {}) or {}
        base_text = self.case_intelligence.render(report)
        lines = [base_text, "", "CROSS-CASE INTELLIGENCE", "=" * 72]
        lines.append(f"Investigation health: {cross_case.get('case_health', 0)}%")
        lines.append(f"Related cases: {cross_case.get('cross_case_match_count', 0)}")
        lines.append(f"Shared indicators: {cross_case.get('shared_indicator_count', 0)}")
        lines.append("")
        observations = cross_case.get("observations", []) or []
        if observations:
            lines.append("Observations")
            lines.extend(f"- {item}" for item in observations)
        gaps = cross_case.get("coverage_gaps", []) or []
        if gaps:
            lines.append("")
            lines.append("Coverage Gaps")
            lines.extend(f"- {item}" for item in gaps)
        matches = cross_case.get("cross_case_matches", []) or []
        if matches:
            lines.append("")
            lines.append("Related Cases")
            for item in matches[:10]:
                shared = "; ".join(
                    f"{x.get('label')}: {', '.join(x.get('values', []))}"
                    for x in item.get("shared", [])
                )
                lines.append(f"- {item.get('case_id')}: {item.get('title') or 'Untitled'} | score {item.get('score', 0)} | {shared}")
        lines.append("")
        lines.append(f"Scope: {cross_case.get('scope', 'Structured case data only.')}")
        self.case_intelligence_view.setPlainText("\n".join(lines))

        findings = report.get("findings", []) or []
        self._safe_set_label_text(
            getattr(self, "case_findings_summary", None),
            f"{len(findings)} evidence-backed finding(s). Each finding is traceable to the Evidence IDs shown in the provenance column.",
        )
        if hasattr(self, "case_findings_table"):
            self.case_findings_table.setSortingEnabled(False)
            self.case_findings_table.clearContents()
            self.case_findings_table.setRowCount(len(findings))
            for row, finding in enumerate(findings):
                values = [
                    finding.get("finding_id", ""),
                    finding.get("classification", ""),
                    finding.get("confidence", ""),
                    finding.get("statement", ""),
                    ", ".join(finding.get("evidence_ids", []) or []) or "None",
                ]
                for col, value in enumerate(values):
                    self.case_findings_table.setItem(row, col, QTableWidgetItem(str(value)))
            self.case_findings_table.setSortingEnabled(True)

    def _render_case_workflow(self, case):
        workflow = self.case_workflow.ensure(case)
        lines = [
            f"CASE WORKFLOW — {case.get('case_id', 'N/A')}",
            "=" * 72,
            "",
            f"Status: {workflow.get('status', 'N/A')}",
            f"Priority: {workflow.get('priority', 'N/A')}",
            f"Disposition: {workflow.get('disposition', 'N/A')}",
            f"Updated: {workflow.get('updated_at', 'N/A')}",
            "",
            "RESPONSE CHECKLIST",
            "-" * 72,
        ]
        actions = workflow.get("response_actions", {}) or {}
        for key, label in self.case_workflow.RESPONSE_ACTIONS:
            lines.append(f"{'[x]' if actions.get(key) else '[ ]'} {label}")
        lines.extend(["", "AUDIT HISTORY", "-" * 72])
        history = workflow.get("audit_history", []) or []
        if history:
            for item in reversed(history[-25:]):
                lines.append(
                    f"{item.get('timestamp', 'N/A')} | {item.get('action', 'N/A')}"
                )
                if item.get("details"):
                    lines.append(f"  {item.get('details')}")
        else:
            lines.append("No workflow audit history.")
        self.case_workflow_summary.setPlainText("\n".join(lines))
    def _show_case_intelligence(self):
        case_id = self._selected_case_id()
        if not case_id:
            QMessageBox.information(self, "Case Intelligence", "Select a case first.")
            return
        case = self.case_store.get(case_id)
        if not case:
            QMessageBox.warning(self, "Case Intelligence", "The selected case no longer exists.")
            return
        self._render_case_intelligence(case)
        self.case_results_tabs.setCurrentIndex(self.case_results_tabs.indexOf(self.case_intelligence_view.parentWidget()))
        self._safe_set_label_text(
            self.case_action_status,
            f"Case intelligence refreshed for {case_id} from linked evidence and deterministic correlation signals."
        )


    def _loaded_event_records(self) -> list[dict]:
        """Return the current raw event dataset in the canonical evidence shape."""
        if self.df.empty:
            return []

        records = []
        existing = {}
        for item in self.evidence_store.records:
            key = (
                str(item.get("source_file", "") or ""),
                str(item.get("line", "") or ""),
                str(item.get("timestamp", "") or ""),
            )
            if key[0] or key[1] or key[2]:
                existing[key] = item

        for row in self.df.fillna("").to_dict("records"):
            event = dict(row)
            event["source_file"] = str(event.get("source_file", "") or self.current_file or "")
            key = (
                str(event.get("source_file", "") or ""),
                str(event.get("line", "") or ""),
                str(event.get("timestamp", "") or ""),
            )
            stored = existing.get(key)
            if stored:
                # Preserve the canonical evidence identity if this raw event
                # was already promoted to evidence in an earlier investigation.
                event["evidence_id"] = stored.get("evidence_id", "")
                event["triage_role"] = stored.get("triage_role", "Observed")
            records.append(event)
        return records

    def _run_case_investigation_action(self, parent_dialog, decision, action_id: str):
        """Execute one deterministic Next Action against the loaded log."""
        case_id = self._selected_case_id()
        case = self.case_store.get(case_id) if case_id else None
        if not case:
            QMessageBox.warning(parent_dialog, "Investigation Action", "The selected case no longer exists.")
            return

        intelligence = self.case_intelligence.build(case)
        linked_events = intelligence.get("timeline", []) or []
        candidates = self._loaded_event_records()

        if not candidates:
            QMessageBox.information(
                parent_dialog,
                "Investigation Action",
                "No loaded log events are available to search. Upload the source log first.",
            )
            return

        try:
            result = InvestigationActionEngine.run(
                action_id,
                case,
                linked_events,
                candidates,
            )
        except ValueError as exc:
            QMessageBox.warning(parent_dialog, "Investigation Action", str(exc))
            return

        action = result["action"]
        results = result.get("results", []) or []

        try:
            self.case_workflow.audit(
                case_id,
                "Investigation action executed",
                f"{action_id}: {len(results)} representative result(s) returned.",
            )
        except Exception:
            pass

        dialog = QDialog(parent_dialog)
        dialog.setWindowTitle(
            f"Investigation Results — {case_id} — {action.get('category', action_id)}"
        )
        dialog.resize(1250, 700)
        layout = QVBoxLayout(dialog)

        qualifying_count = int(result.get("qualifying_match_count", len(results)) or 0)
        representative_count = int(result.get("representative_match_count", len(results)) or 0)
        count_text = (
            f"<b>{representative_count} representative match(es)</b> found."
            if qualifying_count != representative_count
            else f"<b>{representative_count} match(es)</b> found."
        )
        if qualifying_count != representative_count:
            count_text += f" {qualifying_count} qualifying event(s) collapsed by semantic signature."

        header = QLabel(
            f"<b>{html.escape(action.get('name', action_id))}</b><br>"
            f"{html.escape(action.get('description', ''))}<br>"
            f"Search window: ±{result.get('window_seconds', 0) // 60} minutes from linked evidence. "
            f"{count_text}"
        )
        header.setWordWrap(True)
        layout.addWidget(header)

        table = QTableWidget(0, 9)
        table.setHorizontalHeaderLabels([
            "Timestamp", "Event Type", "Source IP", "Username",
            "Process", "Action", "Score", "Distance", "Why Matched",
        ])
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setSelectionMode(QTableWidget.ExtendedSelection)
        # Populate first, then enable sorting. Enabling sorting while setting
        # individual cells can reorder rows after the first column is written,
        # which causes later columns to land on different rows and produces the
        # misleading partially blank records seen in v0.5.7.
        table.setSortingEnabled(False)
        table.setWordWrap(True)
        layout.addWidget(table, 1)

        table.setRowCount(len(results))
        for row_idx, event in enumerate(results):
            distance = event.get("_distance_seconds")
            values = [
                str(event.get("timestamp", "") or "N/A"),
                str(event.get("event_type", "") or "N/A"),
                str(event.get("source_ip", "") or "N/A"),
                str(event.get("username", "") or "N/A"),
                str(event.get("process_name", "") or "N/A"),
                str(event.get("action", "") or "N/A"),
                str(event.get("_match_score", 0)),
                f"{int(distance)}s" if distance is not None else "N/A",
                "; ".join(event.get("_match_reasons", []) or []) or "Rule match",
            ]
            for col, value in enumerate(values):
                table.setItem(row_idx, col, QTableWidgetItem(value))
        table.resizeColumnsToContents()
        table.setColumnWidth(8, 330)
        table.setSortingEnabled(True)

        if results:
            note_text = (
                "Matches are triage candidates only. Linking a result makes it case evidence; "
                "it does not by itself prove causation, malicious intent, or compromise."
            )
        else:
            useful_limits = result.get("limitations", []) or []
            detail = useful_limits[-1] if useful_limits else "No candidate satisfied the investigation criteria."
            note_text = f"<b>No qualifying matches.</b> {html.escape(str(detail))}"
            diagnostics = result.get("diagnostics", {}) or {}
            if action_id == "G-005" and diagnostics:
                rejected = int(diagnostics.get("username_candidates_rejected", 0) or 0)
                coverage = diagnostics.get("anchor_identity_coverage", {}) or {}
                covered = ", ".join(f"{html.escape(str(k))}={int(v)}" for k, v in coverage.items())
                if rejected:
                    note_text += (
                        f"<br><b>Process attribution diagnostics:</b> {rejected} username-bearing "
                        "candidate(s) rejected; no qualifying identity relationship was established."
                    )
                if covered:
                    note_text += f"<br>Anchor identity coverage: {covered}."
        note = QLabel(note_text)
        note.setWordWrap(True)
        layout.addWidget(note)

        buttons = QHBoxLayout()
        support_btn = QPushButton("Link as Supporting")
        contradict_btn = QPushButton("Link as Contradicting")
        observed_btn = QPushButton("Link as Observed")
        refresh_btn = QPushButton("Refresh Decision")
        close_btn = QPushButton("Close")
        buttons.addWidget(support_btn)
        buttons.addWidget(contradict_btn)
        buttons.addWidget(observed_btn)
        buttons.addStretch(1)
        buttons.addWidget(refresh_btn)
        buttons.addWidget(close_btn)
        layout.addLayout(buttons)

        def selected_results():
            rows = sorted({index.row() for index in table.selectionModel().selectedRows()})
            return [results[row] for row in rows if 0 <= row < len(results)]

        def link_selected(role: str):
            selected = selected_results()
            if not selected:
                QMessageBox.information(
                    dialog,
                    "Investigation Results",
                    "Select one or more result rows first.",
                )
                return

            linked_count = 0
            for candidate in selected:
                clean_candidate = {
                    key: value
                    for key, value in candidate.items()
                    if not str(key).startswith("_")
                }
                clean_candidate["triage_role"] = role
                clean_candidate["investigation_action_id"] = action_id

                evidence, _created = self.evidence_store.add_candidate(
                    clean_candidate,
                    source_file=str(clean_candidate.get("source_file", "") or self.current_file),
                    raw_log=str(clean_candidate.get("raw_log", "") or clean_candidate.get("message", "")),
                )
                if not evidence:
                    continue

                self.evidence_store.update(
                    evidence["evidence_id"],
                    triage_role=role,
                    investigation_action_id=action_id,
                    status="Reviewed",
                    analyst_notes=(
                        f"Found by deterministic investigation action {action_id} "
                        f"({action.get('name', action_id)})."
                    ),
                )
                self.case_store.link_evidence(case_id, evidence["evidence_id"])
                linked_count += 1

            before_decision = decision

            self.refresh_all()

            try:
                refreshed_case = self.case_store.get(case_id) or case
                after_intelligence = self.case_intelligence.build(refreshed_case)
                after_decision = CaseDecisionEngine.build(
                    refreshed_case, after_intelligence, self._case_ai_question_snapshot
                )
                existing_workflow = self.case_workflow.ensure(refreshed_case)
                history = list(existing_workflow.get("investigation_history", []) or [])
                entry = self.investigation_loop.make_history_entry(
                    action_id,
                    result_count=len(results),
                    linked_count=linked_count,
                    role=role,
                    status="completed",
                    details=f"Linked {linked_count} result(s) as {role.lower()} evidence.",
                )
                loop_after = self.investigation_loop.after_action(
                    refreshed_case, before_decision, after_decision, history + [entry]
                )
                entry["resolved_gaps"] = loop_after.get("resolved_gaps", [])
                entry["introduced_gaps"] = loop_after.get("introduced_gaps", [])
                self.case_workflow.record_investigation_iteration(case_id, entry)
            except Exception:
                pass

            self._safe_set_label_text(
                self.case_action_status,
                f"Linked {linked_count} investigation result(s) to {case_id} as {role.lower()} evidence."
            )
            QMessageBox.information(
                dialog,
                "Investigation Results",
                f"{linked_count} result(s) linked to {case_id} as {role.lower()} evidence.\n\n"
                "Recalculate the case decision to include the newly linked evidence.",
            )

        def refresh_decision():
            dialog.accept()
            parent_dialog.accept()
            self._show_case_decision()

        support_btn.clicked.connect(lambda: link_selected("Supporting"))
        contradict_btn.clicked.connect(lambda: link_selected("Contradicting"))
        observed_btn.clicked.connect(lambda: link_selected("Observed"))
        refresh_btn.clicked.connect(refresh_decision)
        close_btn.clicked.connect(dialog.accept)
        dialog.exec()

    def _show_investigation_loop(self):
        """Show the deterministic investigation loop for the selected case."""
        case_id = self._selected_case_id()
        if not case_id:
            QMessageBox.information(self, "Investigation Loop", "Select a case first.")
            return
        case = self.case_store.get(case_id)
        if not case:
            QMessageBox.warning(self, "Investigation Loop", "The selected case no longer exists.")
            return

        intelligence = self.case_intelligence.build(case)
        decision = CaseDecisionEngine.build(case, intelligence, self._case_ai_question_snapshot)
        workflow = self.case_workflow.ensure(case)
        history = list(workflow.get("investigation_history", []) or [])
        plan = self.investigation_loop.build_plan(case, decision, workflow, history)

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Investigation Loop — {case_id}")
        dialog.resize(980, 640)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        title = QLabel(f"<b>{html.escape(case_id)}</b> — deterministic investigation loop")
        title.setObjectName("workspaceEyebrow")
        layout.addWidget(title)

        intro = QLabel(
            "The loop keeps the deterministic evidence, decision and workflow engines "
            "as the source of truth. An action searches the loaded log, selected results "
            "can be linked as evidence, and the decision is then recalculated."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        status_box = QGroupBox("Current Investigation State")
        status_grid = QGridLayout(status_box)
        state_values = [
            ("Phase", plan.get("phase", "")),
            ("State", plan.get("state", "")),
            ("Decision", plan.get("decision", "")),
            ("Confidence", plan.get("confidence", "")),
            ("Open Gaps", str(plan.get("open_gap_count", 0))),
            ("Iteration", str(plan.get("iteration", 0))),
        ]
        for index, (label, value) in enumerate(state_values):
            status_grid.addWidget(QLabel(f"<b>{html.escape(label)}</b>"), index // 3, (index % 3) * 2)
            value_label = QLabel(html.escape(value))
            value_label.setWordWrap(True)
            status_grid.addWidget(value_label, index // 3, (index % 3) * 2 + 1)
        layout.addWidget(status_box)

        next_box = QGroupBox("Next Deterministic Step")
        next_layout = QVBoxLayout(next_box)
        next_label = QLabel(
            f"<b>{html.escape(plan.get('next_step', 'No next step available.'))}</b><br>"
            f"{html.escape(plan.get('rationale', ''))}"
        )
        next_label.setWordWrap(True)
        next_layout.addWidget(next_label)

        gaps = plan.get("open_gaps", []) or []
        gap_table = QTableWidget(len(gaps), 4)
        gap_table.setHorizontalHeaderLabels(["Gap", "Category", "Severity", "Recommended Action"])
        gap_table.setWordWrap(True)
        gap_table.setAlternatingRowColors(True)
        for row, gap in enumerate(gaps):
            values = [
                gap.get("gap_id", ""),
                gap.get("category", ""),
                gap.get("severity", ""),
                gap.get("recommended_action", "") or gap.get("description", ""),
            ]
            for col, value in enumerate(values):
                gap_table.setItem(row, col, QTableWidgetItem(str(value)))
        self._fit_table(gap_table, stretch_columns=(3,), content_columns=(0, 1, 2))
        next_layout.addWidget(gap_table, 1)
        layout.addWidget(next_box, 1)

        progress_label = QLabel()
        progress_label.setWordWrap(True)
        layout.addWidget(progress_label)

        buttons = QHBoxLayout()
        run_btn = QPushButton(
            "Run Next Action" if plan.get("next_action_id") else "Review Decision"
        )
        run_btn.setObjectName("primaryButton")
        buttons.addWidget(run_btn)
        refresh_btn = QPushButton("Recalculate Loop")
        buttons.addWidget(refresh_btn)
        buttons.addStretch(1)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        buttons.addWidget(close_btn)
        layout.addLayout(buttons)

        def update_progress():
            current_case = self.case_store.get(case_id)
            if not current_case:
                progress_label.setText("Case no longer exists.")
                run_btn.setEnabled(False)
                return
            current_intelligence = self.case_intelligence.build(current_case)
            current_decision = CaseDecisionEngine.build(
                current_case,
                current_intelligence,
                self._case_ai_question_snapshot,
            )
            current_workflow = self.case_workflow.ensure(current_case)
            current_history = list(current_workflow.get("investigation_history", []) or [])
            current_plan = self.investigation_loop.build_plan(
                current_case, current_decision, current_workflow, current_history
            )
            resolved = []
            if current_history:
                resolved = []
                for entry in current_history:
                    resolved.extend(entry.get("resolved_gaps", []) or [])
            progress_label.setText(
                f"Latest iteration: {current_plan.get('iteration', 0)} | "
                f"Last action: {current_plan.get('last_action') or 'None'} | "
                f"Last results: {current_plan.get('last_result_count', 0)} | "
                f"Last linked: {current_plan.get('last_linked_count', 0)} | "
                f"Open gaps: {current_plan.get('open_gap_count', 0)}"
            )
            run_btn.setText(
                "Run Next Action" if current_plan.get("next_action_id") else "Review Decision"
            )
            run_btn.setEnabled(bool(current_plan.get("next_action_id")) or bool(current_plan.get("state") == "DECISION_REQUIRED"))

        update_progress()

        def run_next():
            current_case = self.case_store.get(case_id)
            if not current_case:
                QMessageBox.warning(dialog, "Investigation Loop", "The selected case no longer exists.")
                return
            current_intelligence = self.case_intelligence.build(current_case)
            current_decision = CaseDecisionEngine.build(
                current_case,
                current_intelligence,
                self._case_ai_question_snapshot,
            )
            current_workflow = self.case_workflow.ensure(current_case)
            current_history = list(current_workflow.get("investigation_history", []) or [])
            current_plan = self.investigation_loop.build_plan(
                current_case, current_decision, current_workflow, current_history
            )
            action_id = str(current_plan.get("next_action_id", "") or "")
            if not action_id:
                dialog.accept()
                self._show_case_decision()
                return
            dialog.accept()
            self._run_case_investigation_action(
                self,
                current_decision,
                action_id,
            )

        run_btn.clicked.connect(run_next)
        refresh_btn.clicked.connect(update_progress)
        dialog.exec()

    def _show_case_decision(self):
        """Show the deterministic decision and evidence-gap assessment."""
        case_id = self._selected_case_id()
        if not case_id:
            QMessageBox.information(self, "Decision & Evidence Gaps", "Select a case first.")
            return
        case = self.case_store.get(case_id)
        if not case:
            QMessageBox.warning(self, "Decision & Evidence Gaps", "The selected case no longer exists.")
            return

        intelligence = self.case_intelligence.build(case)
        question = self._case_ai_question_snapshot or self.case_ai_question.text().strip()
        if not question:
            question = "What does the currently linked evidence establish about this case?"
        decision = CaseDecisionEngine.build(case, intelligence, question)

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Decision & Evidence Gaps — {case_id}")
        dialog.resize(1080, 700)
        layout = QVBoxLayout(dialog)

        header = QLabel(
            f"<b>{html.escape(case_id)}</b> — deterministic investigation decision. "
            "The result is limited to evidence currently linked to the case and does not infer facts outside it."
        )
        header.setWordWrap(True)
        layout.addWidget(header)

        summary = QLabel(
            f"<b>Question:</b> {html.escape(decision.get('question') or '')}<br>"
            f"<b>Decision:</b> {html.escape(decision.get('decision', 'INSUFFICIENT_EVIDENCE'))}"
            f" &nbsp;&nbsp; <b>Confidence:</b> {html.escape(decision.get('confidence', 'LOW'))}<br>"
            f"<b>Rationale:</b> {html.escape(decision.get('rationale', ''))}"
        )
        summary.setWordWrap(True)
        layout.addWidget(summary)

        tabs = QTabWidget()

        facts_page = QWidget()
        facts_layout = QVBoxLayout(facts_page)
        facts_table = QTableWidget(0, 3)
        facts_table.setHorizontalHeaderLabels(["Evidence ID", "Role", "Interpretation"])
        facts_table.setAlternatingRowColors(True)
        fact_rows = []
        for eid in decision.get("successful_auth_evidence_ids", []):
            fact_rows.append((eid, "Decision-supporting", "Successful authentication observed."))
        for eid in decision.get("session_evidence_ids", []):
            fact_rows.append((eid, "Decision-supporting", "Session/login event observed."))
        for eid in decision.get("successful_privilege_evidence_ids", []):
            fact_rows.append((eid, "Decision-supporting", "Successful privilege-related activity observed."))
        for eid in decision.get("failed_auth_evidence_ids", []):
            fact_rows.append((eid, "Observed", "Failed authentication; does not itself establish compromise."))
        for eid in decision.get("observed_evidence_ids", []):
            if not any(row[0] == eid for row in fact_rows):
                fact_rows.append((eid, "Observed", "Security-relevant evidence linked to the case."))
        facts_table.setRowCount(len(fact_rows))
        for row, values in enumerate(fact_rows):
            for col, value in enumerate(values):
                facts_table.setItem(row, col, QTableWidgetItem(str(value)))
        facts_table.resizeColumnsToContents()
        facts_table.setColumnWidth(2, 560)
        facts_layout.addWidget(facts_table)
        tabs.addTab(facts_page, "Evidence Basis")

        gaps_page = QWidget()
        gaps_layout = QVBoxLayout(gaps_page)
        gaps_table = QTableWidget(0, 5)
        gaps_table.setHorizontalHeaderLabels(["Gap", "Category", "Severity", "Missing Evidence", "Recommended Action"])
        gaps_table.setAlternatingRowColors(True)
        gaps = decision.get("evidence_gaps", []) or []
        gaps_table.setRowCount(len(gaps))
        for row, gap in enumerate(gaps):
            values = [gap.get("gap_id", ""), gap.get("category", ""), gap.get("severity", ""), gap.get("description", ""), gap.get("recommended_action", "")]
            for col, value in enumerate(values):
                gaps_table.setItem(row, col, QTableWidgetItem(str(value)))
        gaps_table.resizeColumnsToContents()
        gaps_table.setColumnWidth(3, 360)
        gaps_table.setColumnWidth(4, 430)
        gaps_layout.addWidget(gaps_table)
        if not gaps:
            gaps_layout.addWidget(QLabel("No deterministic evidence gaps were identified by the current rules."))
        tabs.addTab(gaps_page, "Evidence Gaps")

        actions_page = QWidget()
        actions_layout = QVBoxLayout(actions_page)

        action_intro = QLabel(
            "<b>RECOMMENDED INVESTIGATION ACTIONS</b><br>"
            "Run an action to search the currently loaded log for the evidence needed "
            "to reduce the selected decision gap."
        )
        action_intro.setWordWrap(True)
        actions_layout.addWidget(action_intro)

        action_table = QTableWidget(0, 5)
        action_table.setHorizontalHeaderLabels([
            "Gap", "Category", "Severity", "Missing Evidence", "Investigation",
        ])
        action_table.setAlternatingRowColors(True)
        action_table.setSelectionBehavior(QTableWidget.SelectRows)
        action_table.setWordWrap(True)

        gaps_for_actions = decision.get("evidence_gaps", []) or []
        action_table.setRowCount(len(gaps_for_actions))
        for row, gap in enumerate(gaps_for_actions):
            values = [
                str(gap.get("gap_id", "")),
                str(gap.get("category", "")),
                str(gap.get("severity", "")),
                str(gap.get("description", "")),
            ]
            for col, value in enumerate(values):
                action_table.setItem(row, col, QTableWidgetItem(value))

            action_id = str(gap.get("gap_id", "") or "")
            run_btn = QPushButton("Investigate")
            run_btn.setToolTip(
                InvestigationActionEngine.ACTIONS.get(action_id, {}).get(
                    "description", "Run deterministic investigation."
                )
            )
            run_btn.clicked.connect(
                lambda _checked=False, aid=action_id: self._run_case_investigation_action(
                    dialog, decision, aid
                )
            )
            action_table.setCellWidget(row, 4, run_btn)

        action_table.resizeColumnsToContents()
        action_table.setColumnWidth(3, 390)
        action_table.setColumnWidth(4, 130)
        actions_layout.addWidget(action_table, 1)

        if not gaps_for_actions:
            actions_layout.addWidget(
                QLabel("No deterministic evidence gaps were identified by the current rules.")
            )

        limitations = QTextBrowser()
        limitations.setPlainText(
            "LIMITATIONS\n"
            + "=" * 60
            + "\n"
            + "\n".join(
                f"• {item}" for item in decision.get("limitations", []) or []
            )
        )
        limitations.setMaximumHeight(120)
        actions_layout.addWidget(limitations)

        tabs.addTab(actions_page, "Next Actions")

        layout.addWidget(tabs, 1)

        buttons = QHBoxLayout()
        export_btn = QPushButton("Export Decision JSON")
        close_btn = QPushButton("Close")
        buttons.addWidget(export_btn)
        buttons.addStretch(1)
        buttons.addWidget(close_btn)
        layout.addLayout(buttons)

        def export_decision():
            path, _ = QFileDialog.getSaveFileName(
                dialog,
                "Export Decision Assessment",
                f"{case_id}_decision.json",
                "JSON Files (*.json)",
            )
            if not path:
                return
            try:
                CaseDecisionEngine.export_json(path, decision)
                QMessageBox.information(dialog, "Decision & Evidence Gaps", f"Decision exported to:\n{path}")
            except OSError as exc:
                QMessageBox.warning(dialog, "Decision & Evidence Gaps", f"Could not export decision:\n{exc}")

        export_btn.clicked.connect(export_decision)
        close_btn.clicked.connect(dialog.accept)
        dialog.exec()


    def _export_case_intelligence(self):
        case_id = self._selected_case_id()
        if not case_id:
            QMessageBox.information(self, "Case Intelligence", "Select a case first.")
            return
        case = self.case_store.get(case_id)
        if not case:
            QMessageBox.warning(self, "Case Intelligence", "The selected case no longer exists.")
            return

        report = self.case_intelligence.build(case)
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export case intelligence",
            f"{case_id}_intelligence.json",
            "JSON files (*.json)",
        )
        if not path:
            return

        self.case_intelligence.export_json(path, report)
        self._safe_set_label_text(self.case_action_status, 
            f"Exported case intelligence for {case_id}."
        )
        QMessageBox.information(
            self,
            "Case Intelligence",
            f"Exported deterministic case intelligence for {case_id}."
        )

    def _build_response_assessment(self, case):
        intelligence = self.case_intelligence.build(case)
        decision = CaseDecisionEngine.build(
            case,
            intelligence,
            self._case_ai_question_snapshot or self.case_ai_question.text().strip(),
        )
        workflow = self.case_workflow.ensure(case)
        return InvestigationResponseEngine.build(case, decision, workflow, intelligence), decision, workflow

    def _prepare_final_case_report(self):
        case_id = self._selected_case_id()
        if not case_id:
            QMessageBox.information(self, "Case Report", "Select a case first.")
            return
        case = self.case_store.get(case_id)
        if not case:
            QMessageBox.warning(self, "Case Report", "The selected case no longer exists.")
            return
        assessment, _decision, _workflow = self._build_response_assessment(case)
        if assessment.get("open_gap_count", 0):
            QMessageBox.warning(
                self,
                "Final Report",
                "The case still has open evidence gaps. Review them before marking the final report ready.",
            )
            return
        try:
            self.case_workflow.set_closure_documentation(case_id, final_report_ready=True)
            self._safe_set_label_text(self.case_action_status, f"Final report marked ready for {case_id}.")
            refreshed = self.case_store.get(case_id)
            if refreshed:
                self._render_case_command_center(refreshed)
        except Exception as exc:
            QMessageBox.warning(self, "Final Report", f"Could not update report readiness:\n{exc}")

    def _show_response_closure(self):
        case_id = self._selected_case_id()
        if not case_id:
            QMessageBox.information(self, "Response & Closure", "Select a case first.")
            return
        case = self.case_store.get(case_id)
        if not case:
            QMessageBox.warning(self, "Response & Closure", "The selected case no longer exists.")
            return

        assessment, decision, workflow = self._build_response_assessment(case)
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Response & Closure — {case_id}")
        dialog.resize(1100, 760)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        title = QLabel(f"<b>{html.escape(case_id)}</b> — controlled response and closure lifecycle")
        title.setObjectName("workspaceEyebrow")
        layout.addWidget(title)
        intro = QLabel(
            "This workspace records analyst decisions and workflow actions only. "
            "It does not execute host containment, blocking, deletion, or other destructive response actions."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        summary_box = QGroupBox("Response Readiness")
        summary_grid = QGridLayout(summary_box)
        fields = [
            ("Lifecycle", assessment.get("lifecycle", "")),
            ("Readiness", assessment.get("readiness", "")),
            ("Decision", decision.get("decision", "")),
            ("Confidence", decision.get("confidence", "")),
            ("Disposition", workflow.get("disposition", "Undetermined")),
            ("Open Gaps", str(assessment.get("open_gap_count", 0))),
        ]
        for idx, (label, value) in enumerate(fields):
            r, c = divmod(idx, 3)
            summary_grid.addWidget(QLabel(f"<b>{html.escape(label)}</b>"), r, c * 2)
            summary_grid.addWidget(QLabel(html.escape(str(value))), r, c * 2 + 1)
        layout.addWidget(summary_box)

        recommendation = QLabel(
            f"<b>Recommendation:</b> {html.escape(str(assessment.get('recommendation', '')))}"
        )
        recommendation.setWordWrap(True)
        layout.addWidget(recommendation)

        actions_box = QGroupBox("Response Actions")
        actions_layout = QVBoxLayout(actions_box)
        action_checks = {}
        for item in assessment.get("actions", []) or []:
            cb = QCheckBox(
                f"{item.get('label', item.get('action_id', ''))}  [{item.get('state', 'OPTIONAL')}]"
            )
            cb.setChecked(bool(item.get("completed")))
            cb.setToolTip(str(item.get("reason", "")))
            action_checks[str(item.get("action_id"))] = cb
            actions_layout.addWidget(cb)
        layout.addWidget(actions_box)

        blockers_box = QGroupBox("Closure Gates")
        blockers_layout = QVBoxLayout(blockers_box)
        blockers = assessment.get("blockers", []) or []
        if blockers:
            for blocker in blockers:
                label = QLabel("• " + str(blocker))
                label.setWordWrap(True)
                blockers_layout.addWidget(label)
        else:
            blockers_layout.addWidget(QLabel("No deterministic closure blockers are present."))
        layout.addWidget(blockers_box)

        documentation_box = QGroupBox("Closure Documentation")
        documentation_layout = QVBoxLayout(documentation_box)
        disposition_row = QHBoxLayout()
        disposition_row.addWidget(QLabel("Disposition:"))
        disposition = QComboBox()
        disposition.addItems(list(self.case_workflow.DISPOSITIONS))
        disposition.setCurrentText(str(workflow.get("disposition", "Undetermined")))
        disposition_row.addWidget(disposition, 1)
        documentation_layout.addLayout(disposition_row)
        closure_note = QTextEdit()
        closure_note.setPlaceholderText("Record the evidence-backed rationale for the final disposition.")
        closure_note.setPlainText(str(workflow.get("closure_note", "")))
        closure_note.setMinimumHeight(90)
        documentation_layout.addWidget(closure_note)
        report_ready = QCheckBox("Final investigation report prepared / ready for handoff")
        report_ready.setChecked(bool(workflow.get("final_report_ready", False)))
        documentation_layout.addWidget(report_ready)
        layout.addWidget(documentation_box)

        history = QTableWidget(0, 4)
        history.setHorizontalHeaderLabels(["Timestamp", "Action", "Status", "Details"])
        response_history = workflow.get("response_history", []) or []
        history.setRowCount(len(response_history))
        for row, item in enumerate(reversed(response_history[-20:])):
            vals = [item.get("timestamp", ""), item.get("action", ""), item.get("status", ""), item.get("details", "")]
            for col, value in enumerate(vals):
                history.setItem(row, col, QTableWidgetItem(str(value)))
        self._fit_table(history, stretch_columns=(3,), content_columns=(0, 1, 2), min_row_height=26)
        history_box = QGroupBox("Response Audit")
        history_layout = QVBoxLayout(history_box)
        history_layout.addWidget(history)
        layout.addWidget(history_box, 1)

        status_label = QLabel()
        status_label.setWordWrap(True)
        layout.addWidget(status_label)

        buttons = QHBoxLayout()
        save_btn = QPushButton("Save Response State")
        save_btn.setObjectName("primaryButton")
        buttons.addWidget(save_btn)
        close_case_btn = QPushButton("Close Case")
        buttons.addWidget(close_case_btn)
        buttons.addStretch(1)
        close_btn = QPushButton("Close Window")
        close_btn.clicked.connect(dialog.accept)
        buttons.addWidget(close_btn)
        layout.addLayout(buttons)

        def save_response():
            selected_actions = {key: cb.isChecked() for key, cb in action_checks.items()}
            try:
                self.case_workflow.update(
                    case_id,
                    disposition=disposition.currentText(),
                    response_actions=selected_actions,
                    audit_action="Response lifecycle saved",
                )
                self.case_workflow.set_closure_documentation(
                    case_id,
                    final_report_ready=report_ready.isChecked(),
                    closure_note=closure_note.toPlainText().strip(),
                )
                for key, value in selected_actions.items():
                    if value:
                        self.case_workflow.record_response_action(
                            case_id,
                            key,
                            status="completed",
                            details="Analyst marked workflow response action complete.",
                        )
                refreshed = self.case_store.get(case_id)
                if refreshed:
                    self._render_case_command_center(refreshed)
                    self._render_case_workflow(refreshed)
                status_label.setText("Response state saved. Recalculate readiness after the workflow changes.")
                self._safe_set_label_text(self.case_action_status, f"Response lifecycle updated for {case_id}.")
            except Exception as exc:
                QMessageBox.warning(dialog, "Response & Closure", f"Could not save response state:\n{exc}")

        def close_case():
            save_response()
            refreshed = self.case_store.get(case_id)
            if not refreshed:
                return
            assessment_now, decision_now, workflow_now = self._build_response_assessment(refreshed)
            if not InvestigationResponseEngine.can_close(assessment_now):
                QMessageBox.warning(
                    dialog,
                    "Case Closure Blocked",
                    "The case cannot be closed yet.\n\n" + "\n".join(assessment_now.get("blockers", [])),
                )
                return
            try:
                self.case_store.update(case_id, status="Closed")
                self.case_workflow.update(
                    case_id,
                    status="Closed",
                    disposition=workflow_now.get("disposition", "Undetermined"),
                    audit_action="Case closed",
                    audit_details=(
                        f"Closed after deterministic response readiness: "
                        f"{decision_now.get('decision', '')}/{decision_now.get('confidence', '')}."
                    ),
                )
                self.case_workflow.record_response_action(
                    case_id,
                    "case_close",
                    status="completed",
                    details="Case closed after closure gates passed.",
                )
                self.refresh_cases(preferred_case_id=case_id)
                refreshed = self.case_store.get(case_id)
                if refreshed:
                    self._render_case_command_center(refreshed)
                status_label.setText("Case closed successfully. The audit trail records the closure gate result.")
                self._safe_set_label_text(self.case_action_status, f"Case {case_id} closed.")
            except Exception as exc:
                QMessageBox.warning(dialog, "Case Closure", f"Could not close case:\n{exc}")

        save_btn.clicked.connect(save_response)
        close_case_btn.clicked.connect(close_case)
        dialog.exec()

    def _export_full_case_report(self):
        case_id = self._selected_case_id()
        if not case_id:
            QMessageBox.information(self, "Case Report", "Select a case first.")
            return
        case = self.case_store.get(case_id)
        if not case:
            QMessageBox.warning(self, "Case Report", "The selected case no longer exists.")
            return
        intelligence = self.case_intelligence.build(case)
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Full Case Report", f"{case_id}_case_report.html",
            "HTML report (*.html)"
        )
        if not path:
            return
        try:
            export_case_report_html(
                case=case,
                intelligence=intelligence,
                analyst_report=self._case_ai_answer,
                question=self._case_ai_question_snapshot or self.case_ai_question.text().strip(),
                path=path,
            )
        except OSError as exc:
            QMessageBox.critical(self, "Case Report", f"Could not export report:\\n{exc}")
            return
        self._safe_set_label_text(self.case_action_status, f"Full case report exported: {Path(path).name}")
        QMessageBox.information(self, "Case Report", f"Professional case report exported to:\\n{path}")

    def _export_case_package(self):
        """Export a portable, case-scoped investigation package."""
        case_id = self._selected_case_id()
        if not case_id:
            QMessageBox.information(self, "Investigation Package", "Select a case first.")
            return
        case = self.case_store.get(case_id)
        if not case:
            QMessageBox.warning(self, "Investigation Package", "The selected case no longer exists.")
            return

        try:
            workflow = self.case_workflow.ensure(case)
            intelligence = self.case_intelligence.build(case)
            decision = CaseDecisionEngine.build(case, intelligence)
            response, _decision, _workflow = self._build_response_assessment(case)
            handoff = workflow.get("handoff", {}) or {}
            package = CaseHandoffEngine.build(
                case=case,
                intelligence=intelligence,
                workflow=workflow,
                decision=decision,
                response=response,
                analyst_report=self._case_ai_answer or "",
                question=self._case_ai_question_snapshot or "",
                evidence=self.evidence_store.records,
                handoff_type=str(handoff.get("type", "Incident Response") or "Incident Response"),
                recipient=str(handoff.get("recipient", "") or ""),
                owner=str(handoff.get("owner", "") or ""),
                handoff_note=str(handoff.get("note", "") or ""),
            )
            reusable = CasePackageEngine.build(
                case=case,
                workflow=workflow,
                evidence=self.evidence_store.records,
                investigation_package=package,
            )
        except Exception as exc:
            QMessageBox.warning(self, "Investigation Package", f"Could not build package:\n{exc}")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Reusable Investigation Package",
            f"{case_id}_investigation_package.json",
            "LogAsis Investigation Package (*.json)",
        )
        if not path:
            return
        try:
            CasePackageEngine.export_json(reusable, path)
            self._safe_set_label_text(
                self.case_action_status,
                f"Reusable investigation package exported for {case_id}.",
            )
            QMessageBox.information(
                self,
                "Investigation Package",
                f"Portable investigation package exported to:\n{path}\n\n"
                "The package contains only the selected case and its linked evidence.",
            )
        except (OSError, CasePackageError) as exc:
            QMessageBox.warning(self, "Investigation Package", f"Could not export package:\n{exc}")

    def _import_case_package(self):
        """Import a portable case package without silently overwriting local state."""
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Investigation Package",
            "",
            "LogAsis Investigation Package (*.json)",
        )
        if not path:
            return

        try:
            package = CasePackageEngine.load_json(path)
            validation = CasePackageEngine.validate(package)
            if not validation.get("valid"):
                raise CasePackageError("; ".join(validation.get("errors", [])))

            result = CasePackageEngine.import_into_stores(
                package,
                self.case_store,
                self.evidence_store,
                self.case_workflow,
            )
        except (OSError, CasePackageError) as exc:
            QMessageBox.warning(self, "Import Investigation Package", f"Import failed:\n{exc}")
            return

        imported_id = result["case_id"]
        self.investigation_session.select_case(imported_id)
        self._selected_case_id_cache = imported_id
        try:
            self.refresh_cases()
        except Exception:
            pass
        self._safe_set_label_text(
            self.case_action_status,
            f"Imported {imported_id}. Reassessment is required before closure.",
        )
        QMessageBox.information(
            self,
            "Import Investigation Package",
            f"Case imported as {imported_id}.\n\n"
            f"Evidence imported: {result['imported_evidence_count']}\n"
            f"Existing identical evidence reused: {result['reused_evidence_count']}\n\n"
            "The imported case is marked for deterministic reassessment. "
            "Handoff readiness and final-report readiness have been reset.",
        )

    def _show_case_handoff(self):
        """Build and optionally export the professional incident handoff package."""
        case_id = self._selected_case_id()
        if not case_id:
            QMessageBox.information(self, "Incident Report & Handoff", "Select a case first.")
            return
        case = self.case_store.get(case_id)
        if not case:
            QMessageBox.warning(self, "Incident Report & Handoff", "The selected case no longer exists.")
            return

        intelligence = self.case_intelligence.build(case)
        question = self._case_ai_question_snapshot or self.case_ai_question.text().strip()
        if not question:
            question = "What does the currently linked evidence establish about this case?"
        decision = CaseDecisionEngine.build(case, intelligence, question)
        workflow = self.case_workflow.ensure(case)
        response = InvestigationResponseEngine.build(case, decision, workflow, intelligence)

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Incident Report & Handoff — {case_id}")
        dialog.resize(1180, 780)
        layout = QVBoxLayout(dialog)

        header = QLabel(
            f"<b>{html.escape(case_id)}</b> — professional investigation package and controlled analyst handoff.<br>"
            "The package is generated only from the selected case, deterministic intelligence, workflow history, "
            "and optional advisory AI output."
        )
        header.setWordWrap(True)
        layout.addWidget(header)

        form = QGridLayout()
        type_combo = QComboBox()
        type_combo.addItems(CaseHandoffEngine.HANDOFF_TYPES)
        saved_handoff = workflow.get("handoff", {}) or {}
        saved_type = str(saved_handoff.get("type", "Incident Response") or "Incident Response")
        if saved_type in CaseHandoffEngine.HANDOFF_TYPES:
            type_combo.setCurrentText(saved_type)
        recipient = QLineEdit(str(saved_handoff.get("recipient", "") or ""))
        recipient.setPlaceholderText("SOC / incident owner / reviewer")
        owner = QLineEdit(str(saved_handoff.get("owner", "") or ""))
        owner.setPlaceholderText("Analyst or team responsible for handoff")
        note = QLineEdit(str(saved_handoff.get("note", "") or ""))
        note.setPlaceholderText("Short handoff context or requested follow-up")
        form.addWidget(QLabel("Handoff Type"), 0, 0)
        form.addWidget(type_combo, 0, 1)
        form.addWidget(QLabel("Recipient"), 1, 0)
        form.addWidget(recipient, 1, 1)
        form.addWidget(QLabel("Owner"), 2, 0)
        form.addWidget(owner, 2, 1)
        form.addWidget(QLabel("Handoff Note"), 3, 0)
        form.addWidget(note, 3, 1)
        layout.addLayout(form)

        status = QLabel()
        status.setWordWrap(True)
        layout.addWidget(status)

        tabs = QTabWidget()
        summary_view = QTextBrowser()
        decision_view = QTextBrowser()
        response_view = QTextBrowser()
        package_view = QTextBrowser()
        tabs.addTab(summary_view, "Executive Summary")
        tabs.addTab(decision_view, "Decision")
        tabs.addTab(response_view, "Response Readiness")
        tabs.addTab(package_view, "Package Contents")
        layout.addWidget(tabs, 1)

        package = None

        def render(current):
            nonlocal package
            package = current
            validation = CaseHandoffEngine.validate(current)
            h = current.get("handoff", {})
            status.setText(
                f"<b>Readiness:</b> {html.escape(str(current.get('response_readiness', {}).get('readiness', 'NOT_READY')))}"
                f" &nbsp; <b>Handoff:</b> {'READY' if validation.get('handoff_ready') else 'NOT READY'}"
                + (f"<br><b>Blockers:</b> {html.escape('; '.join(validation.get('blockers', [])))}"
                   if validation.get("blockers") else "")
            )
            summary_view.setHtml(
                f"<h3>Executive Summary</h3><p>{html.escape(str(current.get('executive_summary','')))}</p>"
                f"<p><b>Case:</b> {html.escape(str(current.get('case',{}).get('case_id','')))}"
                f" &nbsp; <b>Priority:</b> {html.escape(str(current.get('case',{}).get('priority','')))}</p>"
            )
            d = current.get("decision", {})
            decision_view.setHtml(
                f"<h3>{html.escape(str(d.get('decision','INSUFFICIENT_EVIDENCE')))}"
                f" / {html.escape(str(d.get('confidence','LOW')))}</h3>"
                f"<p>{html.escape(str(d.get('rationale','')))}</p>"
                f"<p><b>Evidence basis:</b> {len(current.get('evidence',[]) or [])} linked record(s), "
                f"{len(current.get('findings',[]) or [])} finding(s), "
                f"{len(current.get('correlation',[]) or [])} relationship(s).</p>"
            )
            r = current.get("response_readiness", {})
            response_view.setHtml(
                f"<h3>{html.escape(str(r.get('readiness','NOT_READY')))}</h3>"
                f"<p><b>Lifecycle:</b> {html.escape(str(r.get('lifecycle','')))}</p>"
                f"<p>{html.escape(str(r.get('recommendation','')))}</p>"
                f"<ul>{''.join('<li>'+html.escape(str(x))+'</li>' for x in r.get('blockers',[]) or []) or '<li>No blockers recorded.</li>'}</ul>"
            )
            package_view.setHtml(
                "<h3>Package Contents</h3><ul>"
                f"<li>Executive summary</li><li>Incident overview</li>"
                f"<li>{len(current.get('evidence',[]) or [])} evidence record(s)</li>"
                f"<li>{len(current.get('findings',[]) or [])} evidence-backed finding(s)</li>"
                f"<li>{sum(len(v or []) for v in (current.get('iocs',{}) or {}).values())} extracted IOC record(s)</li>"
                f"<li>{len(current.get('timeline',[]) or [])} timeline record(s)</li>"
                f"<li>{len(current.get('correlation',[]) or [])} correlation relationship(s)</li>"
                f"<li>{len(current.get('evidence_gaps',[]) or [])} evidence gap(s)</li>"
                f"<li>Response lifecycle and audit history</li>"
                f"<li>AI analyst output: {'included as advisory' if current.get('ai_analyst',{}).get('included') else 'not included'}</li>"
                "</ul>"
                f"<p><b>Handoff type:</b> {html.escape(str(h.get('type','')))}<br>"
                f"<b>Recipient:</b> {html.escape(str(h.get('recipient','') or 'Not specified'))}</p>"
            )

        def build_package():
            nonlocal package
            current_workflow = self.case_workflow.ensure(case)
            package = CaseHandoffEngine.build(
                case=case,
                intelligence=intelligence,
                workflow=current_workflow,
                decision=decision,
                response=response,
                analyst_report=self._case_ai_answer,
                question=question,
                evidence=self.evidence_store.records,
                handoff_type=type_combo.currentText(),
                recipient=recipient.text().strip(),
                owner=owner.text().strip(),
                handoff_note=note.text().strip(),
            )
            validation = CaseHandoffEngine.validate(package)
            try:
                self.case_workflow.set_handoff(
                    case_id,
                    handoff_type=type_combo.currentText(),
                    recipient=recipient.text().strip(),
                    owner=owner.text().strip(),
                    note=note.text().strip(),
                    ready=validation.get("handoff_ready", False),
                    package_generated_at=package.get("generated_at", ""),
                )
                self.case_workflow.set_closure_documentation(
                    case_id,
                    final_report_ready=True,
                )
                package = CaseHandoffEngine.build(
                    case=case,
                    intelligence=intelligence,
                    workflow=self.case_workflow.ensure(case),
                    decision=decision,
                    response=response,
                    analyst_report=self._case_ai_answer,
                    question=question,
                    evidence=self.evidence_store.records,
                    handoff_type=type_combo.currentText(),
                    recipient=recipient.text().strip(),
                    owner=owner.text().strip(),
                    handoff_note=note.text().strip(),
                )
            except Exception as exc:
                QMessageBox.warning(dialog, "Incident Report & Handoff", f"Could not persist handoff metadata:\n{exc}")
            render(package)
            self._safe_set_label_text(self.case_action_status, f"Incident package prepared for {case_id}.")

        def export_html_report():
            if package is None:
                build_package()
            if package is None:
                return
            path, _ = QFileDialog.getSaveFileName(
                dialog, "Export Incident Handoff HTML",
                f"{case_id}_incident_handoff.html", "HTML report (*.html)"
            )
            if not path:
                return
            try:
                CaseHandoffEngine.export_html(package, path)
                QMessageBox.information(dialog, "Incident Report & Handoff", f"Incident package exported to:\n{path}")
            except OSError as exc:
                QMessageBox.warning(dialog, "Incident Report & Handoff", f"Could not export package:\n{exc}")

        def export_json_report():
            if package is None:
                build_package()
            if package is None:
                return
            path, _ = QFileDialog.getSaveFileName(
                dialog, "Export Incident Handoff JSON",
                f"{case_id}_incident_handoff.json", "JSON files (*.json)"
            )
            if not path:
                return
            try:
                CaseHandoffEngine.export_json(package, path)
                QMessageBox.information(dialog, "Incident Report & Handoff", f"Incident package exported to:\n{path}")
            except OSError as exc:
                QMessageBox.warning(dialog, "Incident Report & Handoff", f"Could not export package:\n{exc}")

        build_btn = QPushButton("Build / Refresh Package")
        html_btn = QPushButton("Export Professional HTML")
        json_btn = QPushButton("Export Package JSON")
        close_btn = QPushButton("Close")
        build_btn.setObjectName("primaryButton")
        build_btn.clicked.connect(build_package)
        html_btn.clicked.connect(export_html_report)
        json_btn.clicked.connect(export_json_report)
        close_btn.clicked.connect(dialog.accept)

        buttons = QHBoxLayout()
        buttons.addWidget(build_btn)
        buttons.addWidget(html_btn)
        buttons.addWidget(json_btn)
        buttons.addStretch(1)
        buttons.addWidget(close_btn)
        layout.addLayout(buttons)

        build_package()
        dialog.exec()

    def _show_case_graph(self):
        """Show a deterministic evidence/entity graph for the selected case."""
        case_id = self._selected_case_id()
        if not case_id:
            QMessageBox.information(self, "Investigation Graph", "Select a case first.")
            return

        current = self.case_store.get(case_id)
        if not current:
            QMessageBox.warning(
                self, "Investigation Graph", "The selected case no longer exists."
            )
            return

        report = self.case_intelligence.build(current)
        graph = CaseGraphEngine.build(report)
        summary = graph.get("summary", {})

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Investigation Graph — {case_id}")
        dialog.resize(1180, 700)
        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel(
            f"<b>{case_id}</b> — deterministic evidence/entity graph. "
            "Nodes and edges are derived only from linked case evidence."
        ))

        summary_label = QLabel(
            "Nodes: {node_count}  |  Edges: {edge_count}  |  Evidence: {evidence_count}  | "
            "Identity entities: {identity_entity_count}  | Temporal links: {temporal_link_count}  | "
            "Correlation links: {correlation_link_count}".format(**{
                key: summary.get(key, 0)
                for key in (
                    "node_count", "edge_count", "evidence_count",
                    "identity_entity_count", "temporal_link_count",
                    "correlation_link_count",
                )
            })
        )
        summary_label.setWordWrap(True)
        layout.addWidget(summary_label)

        tabs = QTabWidget()

        node_page = QWidget()
        node_layout = QVBoxLayout(node_page)
        nodes = graph.get("nodes", [])
        node_table = QTableWidget(len(nodes), 4)
        node_table.setHorizontalHeaderLabels(["Type", "Node", "Label", "Context"])
        node_table.setAlternatingRowColors(True)
        node_table.setWordWrap(True)
        for row, node in enumerate(nodes):
            context = []
            for key in ("timestamp", "event_type", "priority", "status"):
                value = str(node.get(key, "") or "")
                if value:
                    context.append(f"{key}: {value}")
            values = [
                str(node.get("type", "")),
                str(node.get("id", "")),
                str(node.get("label", "")),
                "\n".join(context) or "—",
            ]
            for col, value in enumerate(values):
                node_table.setItem(row, col, QTableWidgetItem(value))
        node_table.resizeColumnsToContents()
        node_table.setColumnWidth(2, 240)
        node_table.setColumnWidth(3, 360)
        node_layout.addWidget(node_table)
        tabs.addTab(node_page, "Nodes")

        edge_page = QWidget()
        edge_layout = QVBoxLayout(edge_page)
        edges = graph.get("edges", [])
        edge_table = QTableWidget(len(edges), 5)
        edge_table.setHorizontalHeaderLabels([
            "Type", "Source", "Target", "Label", "Details"
        ])
        edge_table.setAlternatingRowColors(True)
        edge_table.setWordWrap(True)
        for row, edge in enumerate(edges):
            details = []
            if edge.get("seconds") is not None:
                details.append(f"{edge['seconds']}s")
            if edge.get("score") is not None:
                details.append(f"score={edge['score']}")
            reasons = edge.get("reasons", [])
            if reasons:
                details.append(", ".join(str(x) for x in reasons))
            values = [
                str(edge.get("type", "")),
                str(edge.get("source", "")),
                str(edge.get("target", "")),
                str(edge.get("label", "")),
                " | ".join(details) or "—",
            ]
            for col, value in enumerate(values):
                edge_table.setItem(row, col, QTableWidgetItem(value))
        edge_table.resizeColumnsToContents()
        edge_table.setColumnWidth(1, 250)
        edge_table.setColumnWidth(2, 250)
        edge_table.setColumnWidth(4, 330)
        edge_layout.addWidget(edge_table)
        tabs.addTab(edge_page, "Relationships")

        # Visual investigation chain: chronological evidence cards connected
        # only when deterministic temporal/correlation context exists.
        chain = CaseGraphEngine.build_investigation_chain(graph)
        visual_page = QWidget()
        visual_layout = QVBoxLayout(visual_page)

        chain_header = QLabel(
            "<b>Potential Investigation Chain</b> — chronological evidence context, "
            "not an inferred attack path."
        )
        chain_header.setWordWrap(True)
        visual_layout.addWidget(chain_header)

        chain_scene = QGraphicsScene()
        chain_view = QGraphicsView(chain_scene)
        chain_view.setRenderHints(
            chain_view.renderHints()
        )
        chain_view.setMinimumHeight(420)
        chain_view.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        chain_view.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        steps = chain.get("steps", [])
        card_w, card_h = 285, 185
        gap = 95
        x0, y0 = 30, 45

        # Draw a horizontal evidence chain. Keep layout deterministic so the
        # same evidence always produces the same visual ordering.
        for idx, step in enumerate(steps):
            x = x0 + idx * (card_w + gap)
            rect = QGraphicsRectItem(x, y0, card_w, card_h)
            rect.setBrush(QBrush(QColor("#F7FAFC")))
            rect.setPen(QPen(QColor("#2D3748"), 1.5))
            chain_scene.addItem(rect)

            title = QGraphicsTextItem(
                f"#{step['step']}  {step['evidence_id']}"
            )
            title.setDefaultTextColor(QColor("#1A202C"))
            title.setFont(QFont("Segoe UI", 10, QFont.Bold))
            title.setPos(x + 12, y0 + 8)
            chain_scene.addItem(title)

            meta = [
                f"Time: {step.get('timestamp') or 'Unknown'}",
                f"Priority: {step.get('priority') or 'MEDIUM'}",
                f"Event: {step.get('event_type') or 'Unknown'}",
            ]
            for context in step.get("context", []):
                meta.append(f"{context.get('label')}: {context.get('value')}")

            body = QGraphicsTextItem("\n".join(meta))
            body.setTextWidth(card_w - 24)
            body.setDefaultTextColor(QColor("#2D3748"))
            body.setPos(x + 12, y0 + 38)
            chain_scene.addItem(body)

            if idx < len(steps) - 1:
                next_x = x + card_w
                line = QGraphicsLineItem(next_x, y0 + card_h / 2,
                                        next_x + gap, y0 + card_h / 2)
                line.setPen(QPen(QColor("#718096"), 2))
                chain_scene.addItem(line)

                links = step.get("links_to_next", [])
                link_text = " + ".join(
                    str(link.get("label") or link.get("type") or "relationship")
                    for link in links
                ) or "sequence only"
                link_item = QGraphicsTextItem(link_text)
                link_item.setDefaultTextColor(QColor("#4A5568"))
                link_item.setTextWidth(gap - 8)
                link_item.setPos(next_x + 4, y0 + card_h / 2 - 38)
                chain_scene.addItem(link_item)

        if not steps:
            empty = QGraphicsTextItem("No linked evidence is available for a chain.")
            empty.setDefaultTextColor(QColor("#4A5568"))
            empty.setPos(30, 60)
            chain_scene.addItem(empty)

        scene_w = max(900, x0 + max(1, len(steps)) * (card_w + gap))
        chain_scene.setSceneRect(0, 0, scene_w, 310)
        visual_layout.addWidget(chain_view, 1)

        assessment = QLabel(
            f"<b>Assessment:</b> {html.escape(str(chain.get('assessment', '')))}"
        )
        assessment.setWordWrap(True)
        visual_layout.addWidget(assessment)

        chain_details = QTextBrowser()
        chain_details.setMaximumHeight(115)
        detail_lines = []
        for step in steps:
            context_text = ", ".join(
                f"{c.get('label')}: {c.get('value')}" for c in step.get("context", [])
            )
            detail_lines.append(
                f"Step {step['step']} — {step['evidence_id']} — "
                f"{step.get('event_type') or 'Unknown'} — {context_text or 'No additional context'}"
            )
        detail_lines.append("")
        detail_lines.extend(f"• {item}" for item in chain.get("limitations", []))
        chain_details.setPlainText("\n".join(detail_lines))
        visual_layout.addWidget(chain_details)

        tabs.addTab(visual_page, "Visual Chain")

        # Evidence Relationship Explorer: a filtered, evidence-to-evidence view
        # derived only from fields and deterministic links already in the graph.
        explorer_page = QWidget()
        explorer_layout = QVBoxLayout(explorer_page)

        explorer_header = QLabel(
            "<b>Evidence Relationship Explorer</b> — filter observable relationships "
            "between linked evidence records. Relationship strength is triage context, "
            "not an assertion of causation or common ownership."
        )
        explorer_header.setWordWrap(True)
        explorer_layout.addWidget(explorer_header)

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Relationship filter:"))
        relationship_filter = QComboBox()
        relationship_filter.addItems([
            "All",
            "Same Source IP",
            "Same User",
            "Same Process",
            "Same Event Type",
            "Same Action",
            "Temporal Proximity",
            "Deterministic Correlation",
        ])
        filter_row.addWidget(relationship_filter)
        filter_row.addWidget(QLabel("Strength:"))
        strength_filter = QComboBox()
        strength_filter.addItems(["All", "MEDIUM", "LOW"])
        filter_row.addWidget(strength_filter)
        filter_row.addStretch(1)
        explorer_layout.addLayout(filter_row)

        explorer_relationships = CaseGraphEngine.build_relationship_explorer(graph)

        map_scene = QGraphicsScene()
        map_view = QGraphicsView(map_scene)
        map_view.setMinimumHeight(260)
        map_view.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        map_view.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        explorer_layout.addWidget(map_view, 1)

        relationship_table = QTableWidget(0, 6)
        relationship_table.setHorizontalHeaderLabels([
            "Source", "Target", "Strength", "Relationship",
            "Observed Value / Detail", "Interpretation",
        ])
        relationship_table.setAlternatingRowColors(True)
        relationship_table.setWordWrap(True)
        relationship_table.setSelectionBehavior(QTableWidget.SelectRows)
        relationship_table.setSelectionMode(QTableWidget.SingleSelection)
        explorer_layout.addWidget(relationship_table, 1)

        relationship_detail = QTextBrowser()
        relationship_detail.setMaximumHeight(145)
        relationship_detail.setOpenExternalLinks(False)
        explorer_layout.addWidget(relationship_detail)

        def relationship_matches(item):
            selected = relationship_filter.currentText()
            strength = strength_filter.currentText()
            if strength != "All" and item.get("strength") != strength:
                return False
            if selected == "All":
                return True
            mapping = {
                "Same Source IP": "SAME_SOURCE_IP",
                "Same User": "SAME_USER",
                "Same Process": "SAME_PROCESS",
                "Same Event Type": "SAME_EVENT_TYPE",
                "Same Action": "SAME_ACTION",
                "Temporal Proximity": "TEMPORAL",
                "Deterministic Correlation": "CORRELATION",
            }
            wanted = mapping.get(selected)
            return any(r.get("type") == wanted for r in item.get("relationships", []))

        def render_relationship_map(filtered):
            map_scene.clear()
            if not filtered:
                item = QGraphicsTextItem("No relationships match the selected filters.")
                item.setDefaultTextColor(QColor("#4A5568"))
                item.setPos(30, 45)
                map_scene.addItem(item)
                map_scene.setSceneRect(0, 0, 900, 180)
                return

            # Stable evidence-node placement. Multiple relationships to the
            # same evidence record reuse the same card.
            ids = []
            for rel in filtered:
                for node_id in (rel.get("source_id"), rel.get("target_id")):
                    if node_id not in ids:
                        ids.append(node_id)
            node_pos = {}
            card_w, card_h = 220, 82
            gap_x, gap_y = 70, 55
            columns = 3
            for idx, node_id in enumerate(ids):
                col, row = idx % columns, idx // columns
                node_pos[node_id] = (30 + col * (card_w + gap_x), 30 + row * (card_h + gap_y))

            # Draw edges first.
            for rel in filtered:
                sx, sy = node_pos[rel["source_id"]]
                tx, ty = node_pos[rel["target_id"]]
                line = QGraphicsLineItem(
                    sx + card_w, sy + card_h / 2,
                    tx, ty + card_h / 2,
                )
                line.setPen(QPen(QColor("#718096"), 2))
                map_scene.addItem(line)
                labels = ", ".join(r.get("label", r.get("type", "")) for r in rel["relationships"])
                label = QGraphicsTextItem(labels)
                label.setTextWidth(180)
                label.setDefaultTextColor(QColor("#4A5568"))
                label.setPos((sx + tx + card_w) / 2 - 90, (sy + ty) / 2 - 20)
                map_scene.addItem(label)

            for node_id in ids:
                x, y = node_pos[node_id]
                node = next(
                    (n for n in graph.get("nodes", []) if n.get("id") == node_id),
                    {},
                )
                rect = QGraphicsRectItem(x, y, card_w, card_h)
                rect.setBrush(QBrush(QColor("#F7FAFC")))
                rect.setPen(QPen(QColor("#2D3748"), 1.3))
                map_scene.addItem(rect)
                title = QGraphicsTextItem(str(node.get("label") or node_id))
                title.setDefaultTextColor(QColor("#1A202C"))
                title.setFont(QFont("Segoe UI", 10, QFont.Bold))
                title.setPos(x + 10, y + 8)
                map_scene.addItem(title)
                subtitle = QGraphicsTextItem(
                    f"{node.get('event_type') or 'Evidence'}\n"
                    f"{node.get('username') or node.get('source_ip') or node.get('process_name') or 'Observed evidence'}"
                )
                subtitle.setDefaultTextColor(QColor("#4A5568"))
                subtitle.setTextWidth(card_w - 20)
                subtitle.setPos(x + 10, y + 31)
                map_scene.addItem(subtitle)

            width = max(900, columns * (card_w + gap_x) + 30)
            rows = max(1, (len(ids) + columns - 1) // columns)
            height = max(180, rows * (card_h + gap_y) + 30)
            map_scene.setSceneRect(0, 0, width, height)

        def refresh_relationships():
            filtered = [item for item in explorer_relationships if relationship_matches(item)]
            relationship_table.setRowCount(len(filtered))
            for row, item in enumerate(filtered):
                rel_text = ", ".join(
                    str(r.get("label") or r.get("type") or "")
                    for r in item.get("relationships", [])
                )
                details = []
                for rel in item.get("relationships", []):
                    if rel.get("value"):
                        details.append(str(rel["value"]))
                    if rel.get("seconds") is not None:
                        details.append(f"{rel['seconds']}s")
                    if rel.get("reasons"):
                        details.extend(str(x) for x in rel["reasons"])
                values = [
                    str(item.get("source", "")),
                    str(item.get("target", "")),
                    str(item.get("strength", "")),
                    rel_text or "—",
                    ", ".join(details) or "—",
                    str(item.get("interpretation", "")),
                ]
                for col, value in enumerate(values):
                    relationship_table.setItem(row, col, QTableWidgetItem(value))
            relationship_table.resizeColumnsToContents()
            relationship_table.setColumnWidth(0, 125)
            relationship_table.setColumnWidth(1, 125)
            relationship_table.setColumnWidth(3, 180)
            relationship_table.setColumnWidth(4, 240)
            relationship_table.setColumnWidth(5, 420)
            render_relationship_map(filtered)
            if not filtered:
                relationship_detail.setPlainText(
                    "No evidence relationships match the selected filters."
                )
            else:
                relationship_table.selectRow(0)
                show_relationship_detail(0)

        def show_relationship_detail(row):
            filtered = [item for item in explorer_relationships if relationship_matches(item)]
            if row < 0 or row >= len(filtered):
                return
            item = filtered[row]
            lines = [
                f"Relationship: {item['source']} ↔ {item['target']}",
                f"Strength: {item['strength']}",
                "",
                "Observed relationships:",
            ]
            for rel in item.get("relationships", []):
                detail = rel.get("label") or rel.get("type")
                if rel.get("value"):
                    detail += f" = {rel['value']}"
                if rel.get("seconds") is not None:
                    detail += f" ({rel['seconds']}s)"
                if rel.get("score") is not None:
                    detail += f" (score={rel['score']})"
                if rel.get("reasons"):
                    detail += f" — {', '.join(str(x) for x in rel['reasons'])}"
                lines.append(f"• {detail}")
            lines.extend([
                "",
                f"Interpretation: {item['interpretation']}",
                f"Limitation: {item['limitation']}",
            ])
            relationship_detail.setPlainText("\n".join(lines))

        relationship_filter.currentIndexChanged.connect(refresh_relationships)
        strength_filter.currentIndexChanged.connect(refresh_relationships)
        relationship_table.cellClicked.connect(lambda row, _col: show_relationship_detail(row))
        tabs.addTab(explorer_page, "Evidence Map")
        refresh_relationships()

        layout.addWidget(tabs, 1)

        limitation = QLabel(
            " | ".join(graph.get("limitations", []))
        )
        limitation.setWordWrap(True)
        layout.addWidget(limitation)

        buttons = QHBoxLayout()
        export_btn = QPushButton("Export Graph JSON")
        close_btn = QPushButton("Close")
        buttons.addWidget(export_btn)
        buttons.addStretch(1)
        buttons.addWidget(close_btn)
        layout.addLayout(buttons)

        def export_graph():
            path, _ = QFileDialog.getSaveFileName(
                dialog,
                "Export Investigation Graph",
                f"{case_id}_investigation_graph.json",
                "JSON Files (*.json)",
            )
            if not path:
                return
            try:
                CaseGraphEngine.export_json(path, graph)
                QMessageBox.information(
                    dialog,
                    "Investigation Graph",
                    f"Graph exported to:\n{path}",
                )
            except OSError as exc:
                QMessageBox.warning(
                    dialog,
                    "Investigation Graph",
                    f"Could not export graph:\n{exc}",
                )

        export_btn.clicked.connect(export_graph)
        close_btn.clicked.connect(dialog.accept)
        dialog.exec()


    def _compare_selected_case(self):
        """Compare the selected case against every other stored case.

        The comparison is a deterministic triage aid. It intentionally shows
        cases with no IP/user overlap as well, because process, event type and
        temporal context can still be useful investigation leads.
        """
        case_id = self._selected_case_id()
        if not case_id:
            QMessageBox.information(self, "Compare Cases", "Select a case first.")
            return

        current = self.case_store.get(case_id)
        if not current:
            QMessageBox.warning(self, "Compare Cases", "The selected case no longer exists.")
            return

        others = [c for c in self.case_store.all() if c.get("case_id") != case_id]
        if not others:
            QMessageBox.information(
                self,
                "Compare Cases",
                "At least two cases are required for comparison.",
            )
            return

        current_report = self.case_intelligence.build(current)
        other_reports = [
            self.case_intelligence.build(case)
            for case in others
        ]
        results = CaseComparisonEngine.compare_many(current_report, other_reports)

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Case Comparison — {case_id}")
        dialog.resize(1180, 620)
        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel(
            f"Comparing {case_id} against {len(results)} other case(s). "
            "Results are deterministic triage indicators, not proof of causation or a common incident."
        ))

        table = QTableWidget(len(results), 8)
        table.setHorizontalHeaderLabels([
            "Score",
            "Classification",
            "Case",
            "Shared IPs",
            "Shared Users",
            "Shared Processes",
            "Event/Time Overlap",
            "Assessment",
        ])
        table.setWordWrap(True)

        for row, result in enumerate(results):
            event_overlap = []
            event_types = result.get("shared_event_types", [])
            actions = result.get("shared_actions", [])
            if event_types:
                event_overlap.append("Events: " + ", ".join(event_types))
            if actions:
                event_overlap.append("Actions: " + ", ".join(actions))
            if result.get("temporal_proximity"):
                seconds = result.get("nearest_event_seconds")
                if isinstance(seconds, (int, float)):
                    event_overlap.append(f"Time: {seconds:.1f}s")
                else:
                    event_overlap.append("Time: ≤5m")
            if not event_overlap:
                event_overlap.append("None")

            values = [
                str(result.get("score", 0)),
                str(result.get("classification", "")),
                f"{result.get('case_id', '')}\n{result.get('title', '')}",
                ", ".join(result.get("shared_source_ips", [])) or "None",
                ", ".join(result.get("shared_users", [])) or "None",
                ", ".join(result.get("shared_processes", [])) or "None",
                "\n".join(event_overlap),
                str(result.get("explanation", "")),
            ]
            for col, value in enumerate(values):
                table.setItem(row, col, QTableWidgetItem(value))

        table.resizeColumnsToContents()
        table.setColumnWidth(7, 390)
        table.setMinimumHeight(390)
        layout.addWidget(table)

        summary = QLabel(
            "Interpretation: shared IPs/users are stronger identity indicators; "
            "process/event/time overlap is weaker context. No comparison result "
            "establishes causation or compromise."
        )
        summary.setWordWrap(True)
        layout.addWidget(summary)

        close = QPushButton("Close")
        close.clicked.connect(dialog.accept)
        layout.addWidget(close)

        dialog.exec()

    def _correlate_selected_case(self):
        case_id = self._selected_case_id()
        if not case_id:
            QMessageBox.information(self, "Correlation", "Select a case first.")
            return
        case = self.case_store.get(case_id)
        if not case:
            QMessageBox.warning(self, "Correlation", "The selected case no longer exists.")
            return
        self._render_case_correlation(case)
        self._render_case_intelligence(case)
        self._render_case_command_center(case)
        result = self.correlation_engine.correlate_case(case)
        candidate_count = len(result.get("related_candidates", []))
        relationship_count = len(result.get("relationships", []))
        self.case_results_tabs.setCurrentIndex(self.case_results_tabs.indexOf(self.case_relationships.parentWidget()))
        self._safe_set_label_text(
            self.case_action_status,
            f"Correlation complete for {case_id}: {relationship_count} linked relationship(s), {candidate_count} potential related evidence record(s)."
        )

    def _show_case_timeline(self):
        case_id = self._selected_case_id()
        if not case_id:
            QMessageBox.information(self, "Timeline", "Select a case first.")
            return
        case = self.case_store.get(case_id)
        if not case:
            QMessageBox.warning(self, "Timeline", "The selected case no longer exists.")
            return
        self._render_case_correlation(case)
        self._render_case_intelligence(case)
        timeline = self.correlation_engine.build_timeline(case.get("evidence_ids", []) or [])
        self.case_results_tabs.setCurrentIndex(self.case_results_tabs.indexOf(self.case_timeline_table.parentWidget()))
        self._safe_set_label_text(
            self.case_action_status,
            f"Case timeline displayed for {case_id}: {len(timeline)} event(s), ordered chronologically by timestamp."
        )

    def _link_evidence_to_selected_case(self):
        case_id = self._selected_case_id()
        if not case_id:
            QMessageBox.information(self, "Cases", "Select a case first.")
            return
        case = self.case_store.get(case_id)
        if not case:
            QMessageBox.warning(self, "Cases", "The selected case no longer exists.")
            return

        linked = set(str(item) for item in (case.get("evidence_ids", []) or []))
        available = [
            record for record in self.evidence_store.records
            if str(record.get("evidence_id", "")) not in linked
        ]
        if not available:
            QMessageBox.information(
                self, "Link Evidence", "All available evidence records are already linked to this case."
            )
            return

        labels = []
        by_label = {}
        for record in available:
            label = (
                f"{record.get('evidence_id', 'N/A')} | "
                f"{record.get('priority', 'N/A')} | "
                f"{record.get('event_type', 'N/A')} | "
                f"{record.get('timestamp', 'N/A')}"
            )
            labels.append(label)
            by_label[label] = record

        selected, ok = QInputDialog.getItem(
            self, "Link Evidence to Case",
            f"Select an evidence record to link to {case_id}:",
            labels, 0, False,
        )
        if not ok or not selected:
            return

        evidence_id = str(by_label[selected].get("evidence_id", ""))
        updated = self.case_store.link_evidence(case_id, evidence_id)
        if updated is None:
            QMessageBox.warning(self, "Cases", "The selected case no longer exists.")
            return

        self.refresh_cases(preferred_case_id=case_id)
        refreshed_case = self.case_store.get(case_id)
        if refreshed_case:
            self._render_case_command_center(refreshed_case)
        self._safe_set_label_text(self.case_action_status, 
            f"Linked {evidence_id} to {case_id}. Run Correlate Case to analyze the relationship."
        )

    def _case_ai_link_clicked(self, url: QUrl):
        """Handle analyst-report navigation links without opening external URLs."""
        target = url.toString()
        try:
            scheme, value = target.split("://", 1)
        except ValueError:
            return

        scheme = scheme.lower()
        value = value.strip()
        if scheme == "evidence":
            self._navigate_to_evidence(value)
        elif scheme == "correlation":
            parts = [p.strip() for p in value.split("|", 1)]
            if len(parts) == 2:
                self._navigate_to_correlation(parts[0], parts[1])
        elif scheme == "ip":
            self._navigate_to_ip(value)
        elif scheme == "user":
            self._navigate_to_auth(value)
        elif scheme == "process":
            self._navigate_to_investigation(value)

    def _navigate_to_evidence(self, evidence_id: str):
        record = self.evidence_store.get(evidence_id)
        if not record:
            QMessageBox.information(self, "Evidence", f"{evidence_id} is not available.")
            return
        records = self._visible_evidence_records()
        for row, item in enumerate(records):
            if str(item.get("evidence_id", "")) == evidence_id:
                self.tabs.setCurrentWidget(self.evidence_tab)
                self.evidence_table.selectRow(row)
                self._show_evidence_record(row, 0)
                return
        self.tabs.setCurrentWidget(self.evidence_tab)
        self._safe_set_label_text(
            getattr(self, "evidence_action_status", None),
            f"{evidence_id} exists but is hidden by the current Evidence filters.",
        ) if hasattr(self, "evidence_action_status") else None
        self.evidence_detail.setPlainText(
            "\n".join([
                f"EVIDENCE — {evidence_id}",
                "=" * 72,
                f"Status: {record.get('status', 'N/A')}",
                f"Priority: {record.get('priority', 'N/A')}",
                f"Timestamp: {record.get('timestamp', 'N/A')}",
                f"Event Type: {record.get('event_type', 'N/A')}",
                f"Source IP: {record.get('source_ip', 'N/A')}",
                f"Username: {record.get('username', 'N/A')}",
                f"Process: {record.get('process_name', 'N/A')}",
            ])
        )

    def _navigate_to_correlation(self, evidence_a: str, evidence_b: str):
        case_id = self._selected_case_id()
        if not case_id:
            return
        case = self.case_store.get(case_id)
        if not case:
            return
        self._render_case_correlation(case)
        self.tabs.setCurrentWidget(self.cases_tab)
        self.case_results_tabs.setCurrentIndex(1)
        for row in range(self.case_relationships.rowCount()):
            a = self.case_relationships.item(row, 1)
            b = self.case_relationships.item(row, 2)
            if a and b and {a.text(), b.text()} == {evidence_a, evidence_b}:
                self.case_relationships.selectRow(row)
                return

    def _navigate_to_ip(self, ip: str):
        self.tabs.setCurrentWidget(self.ip_tab)
        current = self.ip_tab._editor.toPlainText()
        self.ip_tab._editor.setPlainText(
            f"SOURCE IP ANALYSIS\n\n"
            f"Selected IP: {ip}\n\n"
            f"Review the loaded-log IP analysis below. The report reference "
            f"was {ip}.\n\n{current}"
        )

    def _navigate_to_auth(self, username: str):
        self.tabs.setCurrentWidget(self.auth_tab)
        current = self.auth_tab._editor.toPlainText()
        self.auth_tab._editor.setPlainText(
            f"AUTHENTICATION ANALYSIS\n\n"
            f"Selected user: {username}\n\n{current}"
        )

    def _navigate_to_investigation(self, process_name: str):
        self.tabs.setCurrentWidget(self.investigation_tab)
        for row in range(self.investigation_table.rowCount()):
            for col in range(self.investigation_table.columnCount()):
                item = self.investigation_table.item(row, col)
                if item and process_name.lower() in item.text().lower():
                    self.investigation_table.selectRow(row)
                    self._show_investigation_event(row, 0)
                    return

    def _copy_case_ai_report(self):
        """Copy the rendered analyst report as clean text, never raw URI markup."""
        if not hasattr(self, "case_ai_output"):
            return
        report_text = self.case_ai_output.toPlainText().strip()
        if not report_text or report_text.lower().startswith("no analyst output"):
            QMessageBox.information(self, "AI Analyst", "There is no analyst report to copy.")
            return
        QApplication.clipboard().setText(report_text)
        self._safe_set_label_text(
            self.case_ai_status,
            "Analyst report copied to the clipboard.",
        )

    def _export_case_ai_report(self):
        """Export the selected case's analyst report in TXT or JSON format."""
        case_id = self._selected_case_id() or self._case_ai_report_id
        if not case_id:
            QMessageBox.information(self, "AI Analyst", "Select a case with an analyst report first.")
            return

        plain_report = self.case_ai_output.toPlainText().strip()
        if not plain_report or plain_report.lower().startswith("no analyst output"):
            QMessageBox.information(self, "AI Analyst", "Run an AI analysis before exporting the report.")
            return

        default_name = f"{case_id}_analyst_report"
        path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export Analyst Report",
            default_name,
            "Text report (*.txt);;JSON report (*.json)",
        )
        if not path:
            return

        try:
            if "JSON" in selected_filter or path.lower().endswith(".json"):
                import json
                payload = {
                    "version": "0.4.45",
                    "case_id": case_id,
                    "question": self._case_ai_question_snapshot or self.case_ai_question.text().strip(),
                    "provider": self._case_ai_provider_label,
                    "model": self._case_ai_model,
                    "generated_report": plain_report,
                    "deterministic_case_intelligence": self.case_intelligence.build(
                        self.case_store.get(case_id) or {}
                    ),
                }
                Path(path).write_text(
                    json.dumps(payload, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
            else:
                Path(path).write_text(plain_report + "\n", encoding="utf-8")
        except OSError as exc:
            QMessageBox.critical(self, "AI Analyst", f"Could not export the report:\n{exc}")
            return

        self._safe_set_label_text(
            self.case_ai_status,
            f"Analyst report exported: {Path(path).name}",
        )

    def _clear_case_ai_report(self):
        self._case_ai_answer = ""
        self._case_ai_provider_label = ""
        self._case_ai_model = ""
        self._case_ai_question_snapshot = ""
        self._ai_cancelled = False
        if hasattr(self, "case_ai_output"):
            self.case_ai_output.clear()
        self._safe_set_label_text(
            getattr(self, "case_ai_status", None),
            "AI Analyst report cleared. Deterministic Case Intelligence remains unchanged.",
        )

    def _case_ai_provider_changed(self, provider):
        if provider == "Live AI":
            self.case_ai_config_btn.setEnabled(True)
            config = load_live_config()
            if config.configured:
                self._safe_set_label_text(
                    self.case_ai_status,
                    f"Live AI • {config.model or 'configured model'} • Ready • Bounded case context"
                )
            else:
                self._safe_set_label_text(
                    self.case_ai_status,
                    "Live AI requires configuration. API keys remain outside the evidence package."
                )

    def run_case_ai_analysis(self):
        case_id = self._selected_case_id()
        if not case_id:
            QMessageBox.information(self, "AI Analyst", "Select a case first.")
            return
        case = self.case_store.get(case_id)
        if not case:
            QMessageBox.warning(self, "AI Analyst", "The selected case no longer exists.")
            return
        question = self.case_ai_question.text().strip()
        if not question:
            QMessageBox.information(self, "AI Analyst", "Enter an analyst question.")
            return

        report = self.case_intelligence.build(case)
        self._case_ai_report_id = case_id
        self._case_ai_question_snapshot = question
        self.case_results_tabs.setCurrentIndex(3)
        self.case_ai_analyze_btn.setEnabled(False)
        provider = self.case_ai_provider.currentText()
        self._safe_set_label_text(
            self.case_ai_status,
            f"Analyzing {case_id} with {provider}. Only bounded Case Intelligence is sent to the selected provider."
        )
        self.case_ai_output.setPlainText("Preparing professional case analyst report…")

        self.case_ai_thread = QThread(self)
        self.case_ai_worker = CaseAIWorker(provider, question, report)
        self.case_ai_worker.moveToThread(self.case_ai_thread)
        self.case_ai_thread.started.connect(self.case_ai_worker.run)
        self.case_ai_worker.finished.connect(self._case_ai_finished)
        self.case_ai_worker.failed.connect(self._case_ai_failed)
        self.case_ai_worker.finished.connect(self.case_ai_thread.quit)
        self.case_ai_worker.failed.connect(self.case_ai_thread.quit)
        self.case_ai_thread.finished.connect(self._case_ai_thread_finished)
        self.case_ai_thread.finished.connect(self.case_ai_worker.deleteLater)
        self.case_ai_thread.finished.connect(self.case_ai_thread.deleteLater)
        self.case_ai_thread.start()

    def _case_ai_finished(self, answer, provider_label, model):
        current_case = self._selected_case_id()
        if self._case_ai_report_id and current_case and self._case_ai_report_id != current_case:
            self._safe_set_label_text(
                self.case_ai_status,
                f"AI result for {self._case_ai_report_id} completed, but the selected case is now {current_case}. Result was not attached to the new case."
            )
            return
        report = self.case_intelligence.build(self.case_store.get(self._case_ai_report_id) or {})
        self._case_ai_answer = str(answer or "")
        self._case_ai_provider_label = str(provider_label or "")
        self._case_ai_model = str(model or "")
        self.case_ai_output.setHtml(
            _case_ai_to_html(
                self._case_ai_answer,
                report,
                self._case_ai_question_snapshot or self.case_ai_question.text().strip(),
            )
        )
        self._safe_set_label_text(
            self.case_ai_status,
            f"Analysis completed • {provider_label} • {model} • Deterministic case facts remain authoritative."
        )

    def _case_ai_failed(self, message):
        self._case_ai_answer = (
            "CASE ANALYST REPORT\n\n"
            "ASSESSMENT & LIMITATIONS\n\n"
            "The selected AI provider could not complete the analysis.\n\n"
            + str(message)
        )
        self.case_ai_output.setHtml(_case_ai_to_html(
            self._case_ai_answer,
            self.case_store.get(self._case_ai_report_id) if self._case_ai_report_id else None,
            self._case_ai_question_snapshot or self.case_ai_question.text().strip(),
        ))
        self._safe_set_label_text(
            self.case_ai_status,
            f"AI Analyst failed using {self.case_ai_provider.currentText()}. No fallback provider was used."
        )

    def _case_ai_thread_finished(self):
        self.case_ai_analyze_btn.setEnabled(True)
        self.case_ai_worker = None
        self.case_ai_thread = None

    def _save_case_changes(self):
        case_id = self._selected_case_id()
        if not case_id:
            QMessageBox.information(self, "Cases", "Select a case first.")
            return
        record = self.case_store.update(
            case_id,
            status=self.case_status.currentText(),
            priority=self.case_priority.currentText(),
            analyst_notes=self.case_notes.toPlainText().strip(),
        )
        if record is None:
            QMessageBox.warning(self, "Cases", "The selected case no longer exists.")
            return

        response_actions = {
            key: checkbox.isChecked() for key, checkbox in self.workflow_checks.items()
        }
        workflow = self.case_workflow.update(
            case_id,
            status=self.case_status.currentText(),
            priority=self.case_priority.currentText(),
            disposition=self.case_disposition.currentText(),
            analyst_notes=self.case_notes.toPlainText().strip(),
            response_actions=response_actions,
            audit_action="Case workflow saved",
        )
        self._selected_case_id_cache = case_id
        self.refresh_cases(preferred_case_id=case_id)
        refreshed_case = self.case_store.get(case_id)
        if refreshed_case:
            self._render_case_command_center(refreshed_case)
        self._render_case_workflow(record)
        self._safe_set_label_text(
            self.case_action_status,
            f"Saved case {case_id}. Workflow state and audit history updated."
        )

    def _export_cases(self):
        if not self.case_store.records:
            QMessageBox.information(self, "Cases", "There are no cases to export.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export cases", "", "JSON files (*.json)"
        )
        if not path:
            return
        self.case_store.export_json(path)
        QMessageBox.information(
            self, "Cases",
            f"Exported {len(self.case_store.records)} case(s)."
        )

    def _clear_cases(self):
        count = len(self.case_store.records)
        if count == 0:
            QMessageBox.information(self, "Cases", "The case collection is already empty.")
            return
        answer = QMessageBox.warning(
            self,
            "Clear Cases",
            (
                f"This will permanently remove all {count} case(s) from the local case collection.\n\n"
                "Linked evidence records will NOT be deleted.\n"
                "Export cases first if you may need them later.\n\n"
                "Do you want to continue?"
            ),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        removed = self.case_store.clear()
        self.case_workflow.clear()
        self._selected_case_id_cache = None
        self.refresh_cases()
        QMessageBox.information(self, "Cases", f"Cleared {removed} case(s) and their workflow metadata.")

    def refresh_cases(self, preferred_case_id=None):
        if not hasattr(self, "cases_table"):
            return
        preferred_case_id = preferred_case_id or self._selected_case_id_cache
        records = self._visible_cases()
        self.cases_table.setSortingEnabled(False)
        self.cases_table.clearContents()
        columns = [
            ("case_id", "Case ID"),
            ("status", "Status"),
            ("priority", "Priority"),
            ("title", "Title"),
            ("evidence_ids", "Evidence"),
            ("updated_at", "Updated"),
        ]
        self.cases_table.setColumnCount(len(columns))
        self.cases_table.setHorizontalHeaderLabels([label for _, label in columns])
        self.cases_table.setRowCount(len(records))
        target_row = 0
        for row_idx, record in enumerate(records):
            for col_idx, (key, _) in enumerate(columns):
                value = record.get(key, "")
                if key == "evidence_ids":
                    value = len(record.get("evidence_ids", []) or [])
                if value in ("", None):
                    value = "N/A"
                self.cases_table.setItem(row_idx, col_idx, QTableWidgetItem(str(value)))
            if preferred_case_id and str(record.get("case_id")) == str(preferred_case_id):
                target_row = row_idx
        self.cases_table.resizeColumnsToContents()
        self.cases_table.setSortingEnabled(True)

        if records:
            self.cases_table.selectRow(target_row)
            self._show_case_record(target_row, 0)
        else:
            self._selected_case_id_cache = None
            self.case_detail.clear()
            self.case_notes.clear()
            self.case_ai_output.clear()
            self.case_intelligence_view.clear()
            self.case_relationships.clear()
            self.case_workflow_summary.clear()

    def _safe_set_label_text(self, label, text):
        """Update a QLabel only while its underlying Qt C++ object is alive.

        PySide6 can retain a Python wrapper after Qt has destroyed the underlying
        QLabel. Import/refresh callbacks should never turn that lifecycle race
        into an "Import failed" dialog.
        """
        try:
            if label is not None and qt_is_valid(label):
                label.setText(str(text))
                return True
        except RuntimeError as exc:
            if "already deleted" not in str(exc):
                raise
        return False

    def closeEvent(self, event):
        """Destroy all AI Analyst session state when LogAsis closes."""
        try:
            self._ai_session_generation = int(getattr(self, "_ai_session_generation", 0)) + 1
            clear_ai_session_cache()
            worker = getattr(self, "_ai_worker", None)
            if worker is not None:
                try:
                    worker.cancel()
                except Exception:
                    pass
        finally:
            super().closeEvent(event)

    def upload_log(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select log file",
            "",
            "Log files (*.log *.txt *.out *.audit *.json *.ndjson);;JSON logs (*.json *.ndjson);;All files (*.*)",
        )
        if not path:
            return
        self.load_log_file(path, show_errors=True)

    def load_log_file(self, path, show_errors=False):
        """Load a known log path and start the normal analysis pipeline.

        This is intentionally shared by the file picker and crash-recovery
        paths.  Recovery must invoke the exact same loader as a normal upload;
        otherwise reopening the journal only restores metadata without
        rebuilding the parsed dataframe and restarting background analysis.
        """
        try:
            path = str(Path(path).expanduser().resolve())
            text = Path(path).read_text(encoding="utf-8", errors="replace")
            base_profile = detect_log_profile(path, text)

            if base_profile["parser"] == "json":
                events = JsonLogParser().parse(text)
            else:
                events = SyslogParser().parse(text)

            # Parser type and dashboard type are intentionally separate.
            decision = classify_dashboard_profile(
                base_profile,
                events=events,
                raw_text=text,
            )
            self.log_profile = {
                "id": decision.profile_id,
                "name": decision.name,
                "parser": base_profile.get("parser", ""),
                "confidence": decision.confidence,
                "matched_signals": decision.matched_signals,
            }

            # Successful upload starts a new AI Analyst session. A parse failure
            # leaves the current investigation and its AI session untouched.
            self._reset_ai_analyst_session(
                f"New log loaded: {Path(path).name}. Previous AI analysis was cleared."
            )
            self.df = events_to_dataframe(events)
            self.filtered_df = self.df.copy()
            self.current_file = path
            self.event_index.build(self.df.fillna("").to_dict("records"))
            self._event_page = 0
            self._journal_workspace_state("loaded")
            self.display_columns = display_columns_for_profile(self.log_profile["id"], self.df)
            self._rebuild_filter_fields()
            self._safe_set_label_text(
                self.dashboard_profile,
                f"Dashboard profile: {self.log_profile['name']} • {Path(path).name}",
            )
            self.tabs.setTabText(
                self.tabs.indexOf(self.dashboard_tab),
                f"Dashboard • {self.log_profile['name']}",
            )

            self._safe_set_label_text(
                self.status,
                f"{Path(path).name} | Parser: {base_profile['name']} | "
                f"Dashboard: {self.log_profile['name']} | Events: {len(self.df)}",
            )

            self.render_events(self.filtered_df)
            self.refresh_all(include_heavy=False)
            self.tabs.setCurrentWidget(self.events_tab)
            self._start_background_analysis()
            return True
        except Exception as exc:
            if show_errors:
                QMessageBox.critical(self, "Import failed", str(exc))
            return False

    @staticmethod
    def _filter_field_label(field):
        """Return the user-facing label for an Events filter field.

        The dataframe column name remains the source key (stored as the
        QComboBox item data); this method only controls display text.  Labels
        are generated from the actual source field rather than from a static
        list so vendor/custom JSON and text-log fields remain filterable.
        """
        key = str(field or "").strip()
        if not key:
            return ""
        labels = {
            "source_ip": "Source IP",
            "destination_ip": "Destination IP",
            "source_port": "Source Port",
            "destination_port": "Destination Port",
            "pid": "PID",
            "ppid": "PPID",
            "ip": "IP",
            "url": "URL",
            "uri": "URI",
            "uid": "UID",
            "gid": "GID",
        }
        if key in labels:
            return labels[key]
        # Preserve the historical display contract for generic keys: split
        # underscores, then title-case.  CamelCase is intentionally not split
        # here; e.g. EventData_CommandLine -> Eventdata Commandline.
        return key.replace("_", " ").strip().title() or key

    @classmethod
    def _available_filter_fields(cls, df):
        """Return source keys for populated, user-meaningful event fields.

        This is deliberately data-driven.  It is used by the Events page and
        by tests without constructing the full Qt window, and it never turns
        empty/vendor-absent fields into filters.
        """
        if df is None or getattr(df, "empty", True):
            return []

        internal = {"timestamp_dt", "hour", "date", "raw_log"}
        fields = []
        for column in df.columns:
            key = str(column)
            if key in internal:
                continue
            try:
                values = df[column].fillna("").astype(str).str.strip()
                populated = bool(values.ne("").any())
            except Exception:
                populated = False
            if populated:
                fields.append(key)
        return fields

    def _rebuild_filter_fields(self):
        """Build the field selector from populated fields in the loaded log.

        The value selector is rebuilt at the same time, so filtering is a
        click-only workflow: choose a field, then choose one of the values
        actually present in the log. No manual value entry is required.
        """
        current_key = self.filter_combo.currentData() or self.filter_combo.currentText()
        source_fields = self._available_filter_fields(self.df)
        fields = [("All", "All fields")] + [
            (key, self._filter_field_label(key)) for key in source_fields
        ]

        self.filter_combo.blockSignals(True)
        self.filter_combo.clear()
        for key, label in fields:
            self.filter_combo.addItem(label, key)

        target_index = 0
        for i in range(self.filter_combo.count()):
            if self.filter_combo.itemData(i) == current_key:
                target_index = i
                break
        self.filter_combo.setCurrentIndex(target_index)
        self.filter_combo.blockSignals(False)
        self._populate_filter_values()

    def _populate_filter_values(self):
        """Populate filter values from the currently loaded dataframe.

        Values are sorted naturally as text and retain the original value for
        exact filtering. Internal dataframe columns are never exposed.
        """
        combo = getattr(self, "filter_value_combo", None)
        if combo is None:
            return

        field = self.filter_combo.currentData() or self.filter_combo.currentText()
        previous = combo.currentData()
        combo.blockSignals(True)
        combo.clear()
        combo.addItem("All values", "")

        if field != "All" and field in self.df.columns and not self.df.empty:
            try:
                values = (
                    self.df[field]
                    .fillna("")
                    .astype(str)
                    .str.strip()
                )
                unique_values = sorted(
                    {value for value in values.tolist() if value},
                    key=lambda value: value.casefold(),
                )
                for value in unique_values:
                    # Keep long commands/messages usable without flooding the
                    # selector; the stored itemData remains the complete value.
                    display = value if len(value) <= 140 else value[:137] + "…"
                    combo.addItem(display, value)
            except Exception:
                pass

        target = 0
        if previous:
            for i in range(combo.count()):
                if combo.itemData(i) == previous:
                    target = i
                    break
        combo.setCurrentIndex(target)
        combo.blockSignals(False)

    def _on_filter_field_changed(self, *_args):
        """Rebuild discovered values and immediately apply the selection."""
        self._populate_filter_values()
        self.apply_current_filter()

    def apply_current_filter(self):
        if self.df.empty:
            return

        field = self.filter_combo.currentData() or self.filter_combo.currentText()
        selected_value = ""
        if hasattr(self, "filter_value_combo"):
            selected_value = str(self.filter_value_combo.currentData() or "").strip()
        text_query = self.search.text().strip()

        # The click-driven field/value filter is the primary workflow. It uses
        # the complete row as the result, so every field of a correlated event
        # remains visible in the Events table. Optional free-text search can
        # further narrow those results without being required.
        if field != "All" and selected_value:
            # Values chosen from the discovered-value combo represent one
            # concrete observable. Use equality rather than substring matching
            # so an IP such as 192.168.1.1 cannot accidentally match
            # 192.168.1.10. The complete matching rows remain visible, including
            # every other field needed to inspect correlated activity.
            values = self.df[field].fillna("").astype(str).str.strip()
            self.filtered_df = self.df[values.str.casefold() == selected_value.casefold()].copy()
        else:
            self.filtered_df = self.df.copy()

        if text_query:
            self.filtered_df = apply_filters(self.filtered_df, "All", text_query)

        if field != "All" and selected_value:
            self._safe_set_label_text(
                self.status,
                f"Filter: {self._filter_field_label(field)} = {selected_value} | "
                f"Related events: {len(self.filtered_df):,}",
            )

        self._event_page = 0
        self.render_events(self.filtered_df)
        self.refresh_all(include_heavy=False)
        self._start_background_analysis()

    def clear_filter(self):
        self.search.blockSignals(True)
        self.search.clear()
        self.search.blockSignals(False)
        if hasattr(self, "filter_value_combo"):
            self.filter_value_combo.blockSignals(True)
            if self.filter_value_combo.count():
                self.filter_value_combo.setCurrentIndex(0)
            self.filter_value_combo.blockSignals(False)
        if self.filter_combo.count():
            self.filter_combo.blockSignals(True)
            self.filter_combo.setCurrentIndex(0)
            self.filter_combo.blockSignals(False)
        self._populate_filter_values()
        self.filtered_df = self.df.copy()
        self._event_page = 0
        self.render_events(self.filtered_df)
        if not self.df.empty:
            self._safe_set_label_text(self.status, f"Events: {len(self.df):,} | Filter cleared")
        self.refresh_all(include_heavy=False)
        self._start_background_analysis()

    def render_events(self, df):
        self.events_table.setSortingEnabled(False)
        self.events_table.clear()

        total_rows = len(df)
        self._set_event_page_state(total_rows)

        if total_rows == 0:
            self.events_table.setRowCount(0)
            self.events_table.setColumnCount(0)
            self.events_table.setHorizontalHeaderLabels([])
            self.events_table.setSortingEnabled(True)
            return

        page_size = max(1, int(self._event_page_size))
        start_row = self._event_page * page_size
        page_df = df.iloc[start_row:start_row + page_size]

        columns = self.display_columns or display_columns_for_profile(
            self.log_profile.get("id", "generic_text"), df
        )
        self.events_table.setColumnCount(len(columns))
        self.events_table.setHorizontalHeaderLabels([x[1] for x in columns])
        self.events_table.setRowCount(len(page_df))

        for row_idx, (_, row) in enumerate(page_df.iterrows()):
            for col_idx, (key, _) in enumerate(columns):
                value = row.get(key, "")
                if pd.isna(value) or str(value).strip() == "":
                    value = "N/A"
                self.events_table.setItem(row_idx, col_idx, QTableWidgetItem(str(value)))

        # Avoid resizeColumnsToContents() across huge datasets. Sampling the
        # visible page keeps the UI responsive while preserving the established
        # responsive-column behavior.
        self.events_table.resizeColumnsToContents()
        self.events_table.setSortingEnabled(total_rows <= page_size)

    def refresh_all(self, include_heavy=True):
        self.refresh_dashboard()
        self.refresh_text_tabs()
        self.refresh_evidence()
        self.refresh_cases()
        if include_heavy:
            self.refresh_investigation()
            if hasattr(self, "operations_tab") and not self.df.empty:
                self.refresh_operations()

    def _start_background_analysis(self):
        if self.df.empty:
            return

        self._analysis_generation += 1
        self._journal_workspace_state("running")
        generation = self._analysis_generation

        # Existing thread is allowed to finish, but its generation becomes stale
        # and its result will be ignored.
        self._analysis_cache = None
        # Do not overwrite an active AI worker reference here. It may still be
        # finishing after a log change; session generation guards its result.
        self.analysis_progress.setValue(0)
        self.analysis_progress.setFormat("Analyzing in background…")
        self.statusBar().showMessage(
            "Deterministic analysis is running in the background; the interface remains available."
        )

        thread = QThread(self)
        worker = AnalysisWorker(
            generation,
            self.df.fillna("").to_dict("records"),
            self.current_file,
        )
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(self._analysis_progress)
        worker.finished.connect(self._analysis_finished)
        worker.failed.connect(self._analysis_failed)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        self._analysis_thread = thread
        self._analysis_worker = worker
        thread.start()

    def _analysis_progress(self, value, message):
        if hasattr(self, "analysis_progress"):
            self.analysis_progress.setValue(int(value))
            self.analysis_progress.setFormat(str(message))
        if hasattr(self, "status"):
            self._safe_set_label_text(self.status, str(message))


    def _normalize_ioc_inventory(self, value):
        """Keep worker/cache IOC data in the canonical grouped shape."""
        ioc_types = ("ipv4", "domain", "url", "hash", "username", "process")

        if isinstance(value, dict):
            normalized = {key: [] for key in ioc_types}
            for key in ioc_types:
                records = value.get(key, [])
                normalized[key] = list(records) if isinstance(records, (list, tuple)) else []
            return normalized

        normalized = {key: [] for key in ioc_types}
        if isinstance(value, (list, tuple)):
            for record in value:
                if not isinstance(record, dict):
                    continue
                key = str(record.get("type", "")).strip().lower()
                if key in normalized:
                    item = dict(record)
                    item.pop("type", None)
                    normalized[key].append(item)
        return normalized

    def _analysis_finished(self, generation, result):
        if generation != self._analysis_generation:
            return
        self._analysis_cache = result
        self._iocs = self._normalize_ioc_inventory(result.get("iocs", {}))
        self._detections = result.get("detections", [])
        self._investigation_events = list(
            result.get("report", {}).get("investigation_events", []) or []
        )
        self.refresh_investigation()
        if hasattr(self, "operations_tab") and not self.df.empty:
            self.refresh_operations()
        self.analysis_progress.setValue(100)
        self.analysis_progress.setFormat("Background analysis complete")
        # The successful result is now the clean checkpoint.  Clearing the
        # recovery marker prevents a normal restart from prompting the analyst.
        self._journal_workspace_state("complete")
        self.statusBar().showMessage("Background analysis complete.", 5000)

    def _analysis_failed(self, generation, message):
        if generation != self._analysis_generation:
            return
        self.analysis_progress.setValue(0)
        self.analysis_progress.setFormat("Analysis failed")
        self.statusBar().showMessage("Background analysis failed: " + str(message), 8000)
        QMessageBox.warning(self, "Background analysis", str(message))

    def _set_dashboard_metrics(self, items):
        """Set the six metric cards according to the detected dashboard profile."""
        for idx, (title, value) in enumerate(items[:6], start=1):
            key = f"metric_{idx}"
            self.metric_boxes[key].setTitle(title)
            self._safe_set_label_text(self.metric_labels.get(key), str(value))

        # Always clear unused cards so a previous profile cannot leak metrics
        # into the next uploaded log.
        for idx in range(len(items) + 1, 7):
            key = f"metric_{idx}"
            self.metric_boxes[key].setTitle("—")
            self._safe_set_label_text(self.metric_labels.get(key), "0")

    @staticmethod
    def _count_contains(df, column, pattern):
        if column not in df.columns:
            return 0
        return int(df[column].fillna("").astype(str).str.contains(
            pattern, case=False, regex=True
        ).sum())

    @staticmethod
    def _unique_nonempty(df, column):
        if column not in df.columns:
            return 0
        return int(df[column].replace("", pd.NA).dropna().nunique())

    @staticmethod
    def _value_counts(df, column, limit=10):
        if column not in df.columns:
            return pd.Series(dtype="int64")
        return df[column].replace("", pd.NA).dropna().value_counts().head(limit)

    def _refresh_profile_metrics(self, profile_id):
        df = self.filtered_df
        stats = summary(df)

        if profile_id == "authentication_ssh":
            failed = int((df["action"] == "failed_login").sum()) if "action" in df.columns else 0
            successful = int((df["action"] == "successful_login").sum()) if "action" in df.columns else 0
            total_auth = failed + successful
            failure_rate = f"{(failed / total_auth * 100):.1f}%" if total_auth else "0.0%"
            self._set_dashboard_metrics([
                ("AUTH EVENTS", len(df)),
                ("SOURCE IPs", stats["unique_ips"]),
                ("TARGET USERS", stats["unique_users"]),
                ("FAILED LOGINS", failed),
                ("SUCCESSFUL LOGINS", successful),
                ("FAILURE RATE", failure_rate),
            ])
            return

        if profile_id == "sysmon_json":
            process_create = int(
                df["event_id"].astype(str).isin(["1", "1.0"]).sum()
            ) if "event_id" in df.columns else 0
            network_events = int(
                df["event_id"].astype(str).isin(["3", "3.0"]).sum()
            ) if "event_id" in df.columns else 0
            powershell = self._count_contains(df, "process_name", r"powershell|pwsh")
            powershell += self._count_contains(df, "command", r"powershell|pwsh")
            suspicious = self._count_contains(
                df, "command", r"-enc|encodedcommand|invoke-webrequest|downloadstring|frombase64string"
            )
            self._set_dashboard_metrics([
                ("SYSMON EVENTS", len(df)),
                ("PROCESS CREATIONS", process_create),
                ("NETWORK CONNECTIONS", network_events),
                ("UNIQUE IMAGES", self._unique_nonempty(df, "process_name")),
                ("POWERSHELL EVENTS", powershell),
                ("ENCODED / DOWNLOAD", suspicious),
            ])
            return

        if profile_id == "windows_json":
            self._set_dashboard_metrics([
                ("WINDOWS EVENTS", len(df)),
                ("UNIQUE EVENT IDs", self._unique_nonempty(df, "event_id")),
                ("PROVIDERS", self._unique_nonempty(df, "Provider")),
                ("CHANNELS", self._unique_nonempty(df, "Channel")),
                ("FAILED EVENTS", stats["failed_logins"]),
                ("HIGH / CRITICAL", stats["high_critical"]),
            ])
            return

        if profile_id == "web_server":
            status = df["status_code"].astype(str) if "status_code" in df.columns else pd.Series("", index=df.index)
            four_xx = int(status.str.match(r"4\d\d", na=False).sum())
            five_xx = int(status.str.match(r"5\d\d", na=False).sum())
            requests = self._count_contains(df, "event_type", r"http|request|access")
            if requests == 0:
                requests = len(df)
            self._set_dashboard_metrics([
                ("HTTP REQUESTS", requests),
                ("CLIENT IPs", stats["unique_ips"]),
                ("4xx RESPONSES", four_xx),
                ("5xx RESPONSES", five_xx),
                ("UNIQUE URLs", self._unique_nonempty(df, "url") + self._unique_nonempty(df, "uri")),
                ("SUSPICIOUS REQUESTS", self._count_contains(
                    df, "url", r"\.\./|%2e|union(\+|%20)select|<script|/etc/passwd|cmd=|powershell"
                )),
            ])
            return

        if profile_id == "firewall_network":
            action_text = df["action"].fillna("").astype(str).str.lower() if "action" in df.columns else pd.Series("", index=df.index)
            message_text = df["message"].fillna("").astype(str).str.lower() if "message" in df.columns else pd.Series("", index=df.index)
            combined = action_text + " " + message_text
            blocked = int(combined.str.contains(r"deny|drop|block|blocked|reject", regex=True).sum())
            allowed = int(combined.str.contains(r"allow|accept|accepted", regex=True).sum())
            self._set_dashboard_metrics([
                ("NETWORK EVENTS", len(df)),
                ("SOURCE IPs", stats["unique_ips"]),
                ("DESTINATION IPs", self._unique_nonempty(df, "destination_ip")),
                ("BLOCKED / DROPPED", blocked),
                ("ALLOWED", allowed),
                ("DESTINATION PORTS", self._unique_nonempty(df, "destination_port")),
            ])
            return

        if profile_id == "dns":
            rcode = df["rcode"].fillna("").astype(str).str.upper() if "rcode" in df.columns else pd.Series("", index=df.index)
            nxdomain = int(rcode.str.contains("NXDOMAIN|3", regex=True).sum())
            self._set_dashboard_metrics([
                ("DNS EVENTS", len(df)),
                ("CLIENT IPs", stats["unique_ips"]),
                ("UNIQUE QUERIES", self._unique_nonempty(df, "query_name")),
                ("QUERY TYPES", self._unique_nonempty(df, "query_type")),
                ("NXDOMAIN", nxdomain),
                ("DNS SERVERS", self._unique_nonempty(df, "destination_ip")),
            ])
            return

        # Generic profiles deliberately keep only neutral metrics.
        self._set_dashboard_metrics([
            ("TOTAL EVENTS", stats["total_events"]),
            ("UNIQUE IPs", stats["unique_ips"]),
            ("UNIQUE USERS", stats["unique_users"]),
            ("ACTIONS", self._unique_nonempty(df, "action")),
            ("HIGH / CRITICAL", stats["high_critical"]),
            ("EVENT TYPES", self._unique_nonempty(df, "event_type")),
        ])

    def refresh_dashboard(self):
        self._update_dashboard_context()
        self._render_dashboard_findings()
        profile_id = self.log_profile.get("id", "none")
        self._refresh_profile_metrics(profile_id)

        if profile_id == "authentication_ssh":
            self._refresh_auth_ssh_dashboard(summary(self.filtered_df))
            return
        if profile_id == "sysmon_json":
            self._refresh_sysmon_dashboard(summary(self.filtered_df))
            return
        if profile_id == "windows_json":
            self._refresh_windows_dashboard(summary(self.filtered_df))
            return
        if profile_id == "generic_json":
            self._refresh_generic_json_dashboard(summary(self.filtered_df))
            return
        if profile_id == "web_server":
            self._refresh_web_dashboard()
            return
        if profile_id == "firewall_network":
            self._refresh_firewall_dashboard()
            return
        if profile_id == "dns":
            self._refresh_dns_dashboard()
            return

        df = self.filtered_df
        top_ips = top_source_ips(df)
        top_users_series = top_users(df)
        peak = events_by_hour(df)
        lines = [
            f"LOG TYPE: {self.log_profile.get('name', 'GENERIC / SYSLOG').upper()}",
            "",
            f"Total events: {len(df)}",
            f"Unique source IPs: {self._unique_nonempty(df, 'source_ip')}",
            f"Unique users: {self._unique_nonempty(df, 'username')}",
            "",
            "Top Source IPs:",
        ]
        lines += [f"  {ip}: {int(count)} events" for ip, count in top_ips.items()] if not top_ips.empty else ["  None"]
        lines += ["", "Top Users:"]
        lines += [f"  {user}: {int(count)} events" for user, count in top_users_series.items()] if not top_users_series.empty else ["  None"]
        lines += ["", "Events by Hour:"]
        lines += [f"  {int(hour):02d}:00  {int(count)} events" for hour, count in peak.items()] if not peak.empty else ["  No valid timestamps"]
        self.dashboard_text.setPlainText("\n".join(lines))

    def _refresh_generic_json_dashboard(self, stats):
        """Render a neutral dashboard for JSON logs with no stronger profile."""
        df = self.filtered_df
        event_types = self._value_counts(df, "event_type")
        actions = self._value_counts(df, "action")
        ips = self._value_counts(df, "source_ip")

        ignored = {"timestamp_dt", "hour", "date", "raw_log"}
        field_names = [str(c) for c in df.columns if str(c) not in ignored and not str(c).startswith("_")]

        lines = [
            "LOG TYPE: GENERIC JSON",
            "",
            f"Total records: {len(df)}",
            f"Unique source IPs: {stats['unique_ips']}",
            f"Unique users: {stats['unique_users']}",
            f"Parsed fields: {len(field_names)}",
            "",
            "Detected Fields:",
            "  " + ", ".join(field_names[:30]) if field_names else "  None",
            "",
            "Top Event Types:",
        ]
        lines += [f"  {k}: {int(v)} records" for k, v in event_types.items()] if not event_types.empty else ["  Event type field not parsed."]
        lines += ["", "Top Actions:"]
        lines += [f"  {k}: {int(v)} events" for k, v in actions.items()] if not actions.empty else ["  Action field not parsed."]
        lines += ["", "Top Source IPs:"]
        lines += [f"  {k}: {int(v)} events" for k, v in ips.items()] if not ips.empty else ["  Source IP field not parsed."]
        lines += ["", self._profile_selection_text()]
        self.dashboard_text.setPlainText("\n".join(lines))

    def _refresh_web_dashboard(self):
        df = self.filtered_df
        status = self._value_counts(df, "status_code")
        methods = self._value_counts(df, "request_method")
        urls = self._value_counts(df, "url")
        if urls.empty:
            urls = self._value_counts(df, "uri")

        lines = [
            "LOG TYPE: WEB SERVER",
            "",
            f"HTTP records: {len(df)}",
            f"Unique client IPs: {self._unique_nonempty(df, 'source_ip')}",
            "",
            "HTTP Status Codes:",
        ]
        lines += [f"  {k}: {int(v)} responses" for k, v in status.items()] if not status.empty else ["  Status field not parsed."]
        lines += ["", "Request Methods:"]
        lines += [f"  {k}: {int(v)} requests" for k, v in methods.items()] if not methods.empty else ["  Method field not parsed."]
        lines += ["", "Top Requested URLs:"]
        lines += [f"  {k}: {int(v)} requests" for k, v in urls.items()] if not urls.empty else ["  URL field not parsed."]
        suspicious_pattern = r"\.\./|%2e|union(\+|%20)select|<script|/etc/passwd|cmd=|powershell"
        suspicious_url_matches = self._count_contains(df, "url", suspicious_pattern)
        lines += [
            "",
            "Suspicious request indicators:",
            f"  {suspicious_url_matches} URL matches",
            "",
            self._profile_selection_text(),
        ]
        self.dashboard_text.setPlainText("\n".join(lines))

    def _refresh_firewall_dashboard(self):
        df = self.filtered_df
        action_counts = self._value_counts(df, "action")
        protocols = self._value_counts(df, "protocol")
        dest_ports = self._value_counts(df, "destination_port")
        lines = [
            "LOG TYPE: FIREWALL / NETWORK",
            "",
            f"Network records: {len(df)}",
            f"Unique source IPs: {self._unique_nonempty(df, 'source_ip')}",
            f"Unique destination IPs: {self._unique_nonempty(df, 'destination_ip')}",
            "",
            "Actions:",
        ]
        lines += [f"  {k}: {int(v)} events" for k, v in action_counts.items()] if not action_counts.empty else ["  Action field not parsed."]
        lines += ["", "Protocols:"]
        lines += [f"  {k}: {int(v)} events" for k, v in protocols.items()] if not protocols.empty else ["  Protocol field not parsed."]
        lines += ["", "Top Destination Ports:"]
        lines += [f"  {k}: {int(v)} events" for k, v in dest_ports.items()] if not dest_ports.empty else ["  Destination port field not parsed."]
        lines += ["", self._profile_selection_text()]
        self.dashboard_text.setPlainText("\n".join(lines))

    def _refresh_dns_dashboard(self):
        df = self.filtered_df
        queries = self._value_counts(df, "query_name")
        qtypes = self._value_counts(df, "query_type")
        rcodes = self._value_counts(df, "rcode")
        lines = [
            "LOG TYPE: DNS",
            "",
            f"DNS records: {len(df)}",
            f"Unique client IPs: {self._unique_nonempty(df, 'source_ip')}",
            f"Unique queries: {self._unique_nonempty(df, 'query_name')}",
            "",
            "Query Types:",
        ]
        lines += [f"  {k}: {int(v)} queries" for k, v in qtypes.items()] if not qtypes.empty else ["  Query type field not parsed."]
        lines += ["", "Response Codes:"]
        lines += [f"  {k}: {int(v)} responses" for k, v in rcodes.items()] if not rcodes.empty else ["  RCode field not parsed."]
        lines += ["", "Top Queries:"]
        lines += [f"  {k}: {int(v)} queries" for k, v in queries.items()] if not queries.empty else ["  Query name field not parsed."]
        lines += ["", self._profile_selection_text()]
        self.dashboard_text.setPlainText("\n".join(lines))

    def _profile_selection_text(self):
        signals = self.log_profile.get("matched_signals", [])
        return (
            "PROFILE SELECTION\n"
            f"  Confidence: {self.log_profile.get('confidence', 0.50):.2f}\n"
            "  Evidence signals: " + (", ".join(signals) if signals else "none")
        )

    def _refresh_auth_ssh_dashboard(self, stats):
        df = self.filtered_df

        def values(col):
            if col not in df.columns:
                return pd.Series(dtype="string")
            return df[col].replace("", pd.NA).dropna()

        failed = int((df["action"] == "failed_login").sum()) if "action" in df.columns else 0
        successful = int((df["action"] == "successful_login").sum()) if "action" in df.columns else 0

        ips = values("source_ip").value_counts().head(10)
        users = values("username").value_counts().head(10)
        processes = values("process_name").value_counts().head(10)
        event_types = values("event_type").value_counts().head(10)

        # Failed-login concentration is more useful for this profile than the
        # generic "top IPs" summary. Show the number of failed events per IP.
        failed_by_ip = (
            df[df["action"] == "failed_login"]["source_ip"]
            .replace("", pd.NA).dropna().value_counts().head(10)
            if "action" in df.columns and "source_ip" in df.columns
            else pd.Series(dtype="int64")
        )

        lines = [
            "LOG TYPE: AUTHENTICATION / SSH",
            "",
            f"Total authentication-related records: {len(df)}",
            f"Unique source IPs: {stats['unique_ips']}",
            f"Unique users: {stats['unique_users']}",
            f"Failed logins: {failed}",
            f"Successful logins: {successful}",
            "",
            "Top Source IPs:",
        ]
        lines += (
            [f"  {ip}: {int(count)} events" for ip, count in ips.items()]
            if not ips.empty else ["  None"]
        )
        lines += ["", "Failed Logins by Source IP:"]
        lines += (
            [f"  {ip}: {int(count)} failed attempts" for ip, count in failed_by_ip.items()]
            if not failed_by_ip.empty else ["  None"]
        )
        lines += ["", "Target Users:"]
        lines += (
            [f"  {user}: {int(count)} events" for user, count in users.items()]
            if not users.empty else ["  None"]
        )
        lines += ["", "Authentication Processes:"]
        lines += (
            [f"  {proc}: {int(count)} events" for proc, count in processes.items()]
            if not processes.empty else ["  None"]
        )
        lines += ["", "Event Types:"]
        lines += (
            [f"  {event_type}: {int(count)} records" for event_type, count in event_types.items()]
            if not event_types.empty else ["  None"]
        )

        # Show the evidence that caused the profile to be selected.
        lines += [
            "",
            self._profile_selection_text(),
            "",
            "The table and dashboard are selected from the uploaded log's "
            "authentication/SSH evidence, not from a fixed default profile."
        ]
        self.dashboard_text.setPlainText("\n".join(lines))

    def _refresh_sysmon_dashboard(self, stats):
        df = self.filtered_df

        def nonempty_unique(col):
            if col not in df.columns:
                return 0
            return int(df[col].replace("", pd.NA).dropna().nunique())

        def count_contains(col, pattern):
            if col not in df.columns:
                return 0
            return int(df[col].fillna("").astype(str).str.contains(
                pattern, case=False, regex=True
            ).sum())

        event_ids = (
            df["event_id"].replace("", pd.NA).dropna().value_counts().head(12)
            if "event_id" in df.columns else pd.Series(dtype="int64")
        )
        processes = (
            df["process_name"].replace("", pd.NA).dropna().value_counts().head(10)
            if "process_name" in df.columns else pd.Series(dtype="int64")
        )

        process_create = int(
            df["event_id"].astype(str).isin(["1", "1.0"]).sum()
        ) if "event_id" in df.columns else 0
        network_events = int(
            df["event_id"].astype(str).isin(["3", "3.0"]).sum()
        ) if "event_id" in df.columns else 0
        command_events = nonempty_unique("command")
        powershell = count_contains("process_name", r"powershell|pwsh") + count_contains(
            "command", r"powershell|pwsh|-enc|encodedcommand"
        )
        suspicious = count_contains(
            "command", r"-enc|encodedcommand|invoke-webrequest|downloadstring|frombase64string"
        )

        lines = [
            "LOG TYPE: WINDOWS SYSMON JSON",
            "",
            f"Total Sysmon records: {len(df)}",
            f"Unique process images: {nonempty_unique('process_name')}",
            f"Unique users: {nonempty_unique('username')}",
            f"Process creation (Event ID 1): {process_create}",
            f"Network connection (Event ID 3): {network_events}",
            f"Records with command lines: {command_events}",
            f"PowerShell-related records: {powershell}",
            f"Encoded/download indicators: {suspicious}",
            "",
            "Top Event IDs:",
        ]
        lines += (
            [f"  {k}: {int(v)} records" for k, v in event_ids.items()]
            if not event_ids.empty else ["  None"]
        )
        lines += ["", "Top Process Images:"]
        lines += (
            [f"  {k}: {int(v)} events" for k, v in processes.items()]
            if not processes.empty else ["  None"]
        )
        lines += [
            "",
            "This dashboard is generated from Sysmon-specific evidence "
            "(Event ID, Image, CommandLine, ParentImage, PID/PPID and network fields)."
        ]
        self.dashboard_text.setPlainText("\n".join(lines))

    def _refresh_windows_dashboard(self, stats):
        df = self.filtered_df
        event_ids = (
            df["event_id"].replace("", pd.NA).dropna().value_counts().head(12)
            if "event_id" in df.columns else pd.Series(dtype="int64")
        )
        providers = (
            df["Provider"].replace("", pd.NA).dropna().value_counts().head(10)
            if "Provider" in df.columns else pd.Series(dtype="int64")
        )
        channels = (
            df["Channel"].replace("", pd.NA).dropna().value_counts().head(10)
            if "Channel" in df.columns else pd.Series(dtype="int64")
        )
        lines = [
            "LOG TYPE: WINDOWS EVENT JSON",
            "",
            f"Total records: {len(df)}",
            f"Unique source IPs: {stats['unique_ips']}",
            f"Unique users: {stats['unique_users']}",
            f"Failed authentication events: {stats['failed_logins']}",
            f"Successful authentication events: {stats['successful_logins']}",
            "",
            "Top Event IDs:",
        ]
        lines += (
            [f"  {k}: {int(v)} records" for k, v in event_ids.items()]
            if not event_ids.empty else ["  None"]
        )
        lines += ["", "Providers:"]
        lines += (
            [f"  {k}: {int(v)} records" for k, v in providers.items()]
            if not providers.empty else ["  None"]
        )
        lines += ["", "Channels:"]
        lines += (
            [f"  {k}: {int(v)} records" for k, v in channels.items()]
            if not channels.empty else ["  None"]
        )
        lines += [
            "",
            "This dashboard is generated from Windows Event JSON fields "
            "rather than the Syslog layout."
        ]
        self.dashboard_text.setPlainText("\n".join(lines))

    def refresh_text_tabs(self):
        # Timeline
        timeline = events_by_hour(self.filtered_df)
        timeline_lines = ["EVENTS BY HOUR", ""]
        for hour, count in timeline.items():
            timeline_lines.append(f"{int(hour):02d}:00 - {int(count)} events")
        if len(timeline_lines) == 2:
            timeline_lines.append("No valid timestamps.")
        self.timeline_tab._editor.setPlainText("\n".join(timeline_lines))

        # IP
        ips = top_source_ips(self.filtered_df, 25)
        ip_lines = ["SOURCE IP ANALYSIS", ""]
        if ips.empty:
            ip_lines.append("No source IPs found.")
        else:
            for ip, count in ips.items():
                ip_lines.append(f"{ip:<24} {int(count)} events")
        self.ip_tab._editor.setPlainText("\n".join(ip_lines))

        # Authentication
        failed = (
            int((self.filtered_df["action"] == "failed_login").sum())
            if "action" in self.filtered_df.columns else 0
        )
        successful = (
            int((self.filtered_df["action"] == "successful_login").sum())
            if "action" in self.filtered_df.columns else 0
        )
        auth_lines = [
            "AUTHENTICATION ANALYSIS",
            "",
            f"Failed logins:      {failed}",
            f"Successful logins:  {successful}",
            "",
            "Users:",
        ]
        if "username" in self.filtered_df.columns and not self.filtered_df.empty:
            users = self.filtered_df["username"].replace("", pd.NA).dropna().value_counts()
            auth_lines += [f"  {u}: {int(c)} events" for u, c in users.items()]
        self.auth_tab._editor.setPlainText("\n".join(auth_lines))

        # Evidence is now a dedicated Evidence Management tab.
        # Do not treat evidence_tab as a text-tab editor; it is a QWidget
        # containing its own table/detail controls.

    def refresh_investigation(self):
        if (
            self._analysis_cache
            and len(self.filtered_df) == len(self.df)
        ):
            report = self._analysis_cache.get("report", {})
        else:
            report = build_investigation_report(self.filtered_df)
        events = report.get("investigation_events", [])
        self._investigation_events = list(events)

        selected_priority = self.investigation_filter.currentText()
        if selected_priority != "All":
            events = [item for item in events if item["priority"] == selected_priority]

        self.investigation_summary.setText(
            f"Candidates: {len(events)}  •  Critical: {report.get('critical_count', 0)}  •  "
            f"High: {report.get('high_count', 0)}  •  Medium: {report.get('medium_count', 0)}"
        )

        self.investigation_table.setSortingEnabled(False)
        self.investigation_table.clear()
        columns = [
            ("priority", "Priority"),
            ("score", "Score"),
            ("line", "Record"),
            ("timestamp", "Timestamp"),
            ("event_type", "Event Type"),
            ("process_name", "Process / Image"),
            ("command", "Command"),
            ("source_ip", "Source IP"),
            ("destination_ip", "Destination IP"),
        ]
        self.investigation_table.setColumnCount(len(columns))
        self.investigation_table.setHorizontalHeaderLabels([label for _, label in columns])
        self.investigation_table.setRowCount(len(events))

        for row_idx, item in enumerate(events):
            for col_idx, (key, _) in enumerate(columns):
                value = item.get(key, "")
                if value in ("", None):
                    value = "N/A"
                cell = QTableWidgetItem(str(value))
                self.investigation_table.setItem(row_idx, col_idx, cell)

        self.investigation_table.resizeColumnsToContents()
        self.investigation_table.setSortingEnabled(True)

        if not events:
            self.investigation_detail.setPlainText(
                "No investigation candidates matched the current log/filter."
            )
            return

        # Keep the first candidate visible after a refresh, unless the user is
        # already looking at another row.
        self.investigation_table.selectRow(0)
        self._show_investigation_event(0, 0)

    def _create_case_from_selected_investigation(self):
        """Promote the selected investigation candidate into Evidence and a Case.

        This is the intentional end-to-end analyst path:
        Investigation candidate -> Evidence -> Case -> Case workspace.
        The operation reuses existing stores and is idempotent.
        """
        row = self.investigation_table.currentRow()
        if row < 0 or row >= self.investigation_table.rowCount():
            QMessageBox.information(
                self,
                "Start Case",
                "Select an investigation candidate first.",
            )
            return

        line_item = self.investigation_table.item(row, 2)
        if line_item is None:
            QMessageBox.warning(self, "Start Case", "The selected record could not be identified.")
            return

        try:
            line_number = int(line_item.text())
        except ValueError:
            QMessageBox.warning(self, "Start Case", "The selected record number is invalid.")
            return

        candidate = next(
            (
                item for item in self._investigation_events
                if int(item.get("line", 0) or 0) == line_number
            ),
            None,
        )
        if candidate is None:
            QMessageBox.warning(
                self,
                "Start Case",
                "The selected investigation candidate is no longer available.",
            )
            return

        matches = self.filtered_df[
            pd.to_numeric(
                self.filtered_df.get("line", pd.Series(dtype="int64")),
                errors="coerce",
            ) == line_number
        ]
        raw_log = ""
        if not matches.empty:
            raw_log = str(
                matches.iloc[0].get("raw_log", "")
                or matches.iloc[0].get("message", "")
                or ""
            )

        try:
            result = create_case_from_candidate(
                candidate,
                evidence_store=self.evidence_store,
                case_store=self.case_store,
                source_file=self.current_file,
                raw_log=raw_log,
            )
            case = result["case"]
            evidence = result["evidence"]
            # Initialize the existing analyst workflow metadata without
            # changing its status/disposition semantics.
            self.case_workflow.ensure(case)
        except (TypeError, ValueError, RuntimeError, OSError) as exc:
            QMessageBox.critical(
                self,
                "Start Case",
                f"Could not create the investigation case:\n{exc}",
            )
            return

        evidence_state = "created" if result["evidence_created"] else "reused"
        case_state = "created" if result["case_created"] else "reused"

        self._selected_case_id_cache = case.get("case_id")
        self.refresh_evidence()
        self.refresh_cases(preferred_case_id=case.get("case_id"))
        self.tabs.setCurrentWidget(self.cases_tab)

        self._safe_set_label_text(
            self.case_action_status,
            (
                f"Started investigation workflow: {evidence.get('evidence_id')} "
                f"({evidence_state}) -> {case.get('case_id')} ({case_state}). "
                "Review the linked evidence before making a case disposition."
            ),
        )

        QMessageBox.information(
            self,
            "Investigation Case Started",
            (
                f"Evidence: {evidence.get('evidence_id')} ({evidence_state})\n"
                f"Case: {case.get('case_id')} ({case_state})\n\n"
                "The candidate is now available in the Cases workspace. "
                "This action records observed evidence; it does not establish malicious intent."
            ),
        )

    def _show_investigation_event(self, row, _column=0):
        if row < 0 or row >= self.investigation_table.rowCount():
            return

        line_item = self.investigation_table.item(row, 2)
        if line_item is None:
            return

        try:
            line_number = int(line_item.text())
        except ValueError:
            self.investigation_detail.setPlainText("Unable to identify the selected record.")
            return

        matches = self.filtered_df[
            pd.to_numeric(self.filtered_df.get("line", pd.Series(dtype="int64")), errors="coerce")
            == line_number
        ]
        if matches.empty:
            self.investigation_detail.setPlainText(
                f"Record {line_number} is no longer present in the current filtered view."
            )
            return

        event = build_event_investigation(matches.iloc[0], self.filtered_df)
        lines = [
            f"INVESTIGATION — {event['priority']}",
            "=" * 72,
            "",
            f"Investigation score: {event['score']}",
            "",
            "WHY THIS EVENT DESERVES REVIEW",
            "-" * 72,
        ]
        lines.extend(f"• {reason}" for reason in event["reasons"])

        lines += ["", "EVENT EVIDENCE", "-" * 72]
        for key, value in event["fields"].items():
            lines.append(f"{key}: {value}")

        if event["message"]:
            lines += ["", "MESSAGE", "-" * 72, event["message"]]

        lines += [
            "",
            "ANALYST NOTE",
            "-" * 72,
            "This is a deterministic triage result. Validate the surrounding events, "
            "process ancestry, network activity, hashes, and host context before treating "
            "the event as malicious.",
        ]

        self.investigation_detail.setPlainText("\n".join(lines))

    def refresh_evidence(self):
        if not hasattr(self, "evidence_table"):
            return

        records = self.evidence_store.filter(
            self.evidence_status_filter.currentText(),
            self.evidence_priority_filter.currentText(),
        )
        self.evidence_table.setSortingEnabled(False)
        self.evidence_table.clear()
        columns = [
            ("evidence_id", "Evidence ID"),
            ("status", "Status"),
            ("priority", "Priority"),
            ("score", "Score"),
            ("line", "Record"),
            ("timestamp", "Timestamp"),
            ("event_type", "Event Type"),
            ("process_name", "Process / Image"),
            ("source_ip", "Source IP"),
        ]
        self.evidence_table.setColumnCount(len(columns))
        self.evidence_table.setHorizontalHeaderLabels([label for _, label in columns])
        self.evidence_table.setRowCount(len(records))

        for row_idx, record in enumerate(records):
            for col_idx, (key, _) in enumerate(columns):
                value = record.get(key, "")
                if value in ("", None):
                    value = "N/A"
                self.evidence_table.setItem(row_idx, col_idx, QTableWidgetItem(str(value)))

        self.evidence_table.resizeColumnsToContents()
        self.evidence_table.setSortingEnabled(True)

        if records:
            self.evidence_table.selectRow(0)
            self._show_evidence_record(0, 0)
        else:
            self.evidence_detail.clear()
            self.evidence_notes.clear()

    def _visible_evidence_records(self):
        return self.evidence_store.filter(
            self.evidence_status_filter.currentText(),
            self.evidence_priority_filter.currentText(),
        )

    def _selected_evidence_id(self):
        row = self.evidence_table.currentRow()
        if row < 0:
            return None
        item = self.evidence_table.item(row, 0)
        return item.text() if item else None

    def _show_evidence_record(self, row, _column=0):
        records = self._visible_evidence_records()
        if row < 0 or row >= len(records):
            return
        record = records[row]
        self.evidence_detail.setPlainText(
            "\n".join([
                f"EVIDENCE — {record.get('evidence_id', 'N/A')}",
                "=" * 72,
                "",
                f"Status: {record.get('status', 'N/A')}",
                f"Priority: {record.get('priority', 'N/A')}",
                f"Investigation score: {record.get('score', 'N/A')}",
                f"Source file: {record.get('source_file', 'N/A')}",
                f"Record: {record.get('line', 'N/A')}",
                f"Timestamp: {record.get('timestamp', 'N/A')}",
                f"Event Type: {record.get('event_type', 'N/A')}",
                f"Event ID: {record.get('event_id', 'N/A')}",
                f"Source IP: {record.get('source_ip', 'N/A')}",
                f"Destination IP: {record.get('destination_ip', 'N/A')}",
                f"Destination Port: {record.get('destination_port', 'N/A')}",
                f"User: {record.get('username', 'N/A')}",
                f"Process: {record.get('process_name', 'N/A')}",
                f"Command: {record.get('command', 'N/A')}",
                f"Parent Process: {record.get('parent_image', 'N/A')}",
                f"Action: {record.get('action', 'N/A')}",
                f"Log Severity: {record.get('severity', 'N/A')}",
                f"Hashes: {record.get('hashes', 'N/A')}",
                "",
                "WHY THIS EVIDENCE WAS COLLECTED",
                "-" * 72,
                *[f"• {reason}" for reason in record.get("reasons", [])],
                "",
                "MESSAGE",
                "-" * 72,
                str(record.get("message", "") or "N/A"),
            ])
        )
        self.evidence_status.blockSignals(True)
        self.evidence_status.setCurrentText(str(record.get("status", "New")))
        self.evidence_status.blockSignals(False)
        self.evidence_notes.setPlainText(str(record.get("analyst_notes", "")))

    def _add_selected_evidence(self):
        row = self.investigation_table.currentRow()
        if row < 0 or row >= self.investigation_table.rowCount():
            QMessageBox.information(
                self, "Evidence", "Select an investigation candidate first."
            )
            return

        line_item = self.investigation_table.item(row, 2)
        if line_item is None:
            return
        try:
            line_number = int(line_item.text())
        except ValueError:
            QMessageBox.warning(self, "Evidence", "The selected record number is invalid.")
            return

        candidates = self._investigation_events
        candidate = next(
            (item for item in candidates if int(item.get("line", 0) or 0) == line_number),
            None,
        )
        if candidate is None:
            QMessageBox.warning(self, "Evidence", "The selected investigation candidate is no longer available.")
            return

        matches = self.filtered_df[
            pd.to_numeric(
                self.filtered_df.get("line", pd.Series(dtype="int64")),
                errors="coerce",
            ) == line_number
        ]
        raw_log = ""
        if not matches.empty:
            raw_log = str(matches.iloc[0].get("raw_log", "") or matches.iloc[0].get("message", "") or "")

        record, created = self.evidence_store.add_candidate(
            candidate,
            source_file=self.current_file,
            raw_log=raw_log,
        )
        if created:
            QMessageBox.information(self, "Evidence", f"Added {record['evidence_id']} to the evidence collection.")
        else:
            QMessageBox.information(self, "Evidence", f"{record['evidence_id']} is already in the evidence collection.")
        self.refresh_evidence()
        self.tabs.setCurrentWidget(self.evidence_tab)

    def _save_evidence_changes(self):
        evidence_id = self._selected_evidence_id()
        if not evidence_id:
            QMessageBox.information(self, "Evidence", "Select an evidence record first.")
            return

        record = self.evidence_store.update(
            evidence_id,
            status=self.evidence_status.currentText(),
            analyst_notes=self.evidence_notes.toPlainText().strip(),
        )
        if record is None:
            QMessageBox.warning(self, "Evidence", "The selected evidence record no longer exists.")
            return
        self.refresh_evidence()

    def _export_evidence(self):
        if not self.evidence_store.records:
            QMessageBox.information(self, "Evidence", "There are no evidence records to export.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Export evidence collection", "", "JSON files (*.json)"
        )
        if not path:
            return
        self.evidence_store.export_json(path)
        QMessageBox.information(
            self,
            "Evidence",
            f"Exported {len(self.evidence_store.records)} evidence records.",
        )

    def _clear_evidence(self):
        """Clear the entire persistent evidence collection after explicit confirmation."""
        count = len(self.evidence_store.records)
        if count == 0:
            QMessageBox.information(
                self,
                "Evidence",
                "The evidence collection is already empty.",
            )
            return

        answer = QMessageBox.warning(
            self,
            "Clear Evidence",
            (
                f"This will permanently remove all {count} evidence record(s) "
                "from the local evidence collection.\n\n"
                "If you may need these records later, export the evidence first.\n\n"
                "Do you want to continue?"
            ),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return

        removed = self.evidence_store.clear()
        self.refresh_evidence()
        QMessageBox.information(
            self,
            "Evidence",
            f"Cleared {removed} evidence record(s).",
        )

    def refresh_active_tab(self, _index):
        self.refresh_all()

    def export_csv(self):
        if self.filtered_df.empty:
            QMessageBox.information(self, "Export", "There are no events to export.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Export filtered events", "", "CSV files (*.csv)"
        )
        if not path:
            return

        export_df = self.filtered_df.drop(
            columns=["timestamp_dt"], errors="ignore"
        )
        export_df.to_csv(path, index=False)
        QMessageBox.information(self, "Export", f"Exported {len(export_df)} events.")

    def showEvent(self, event):
        super().showEvent(event)
        if not self._recovery_prompted:
            self._check_workspace_recovery()
