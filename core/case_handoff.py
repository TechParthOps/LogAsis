from __future__ import annotations

"""Deterministic incident reporting and analyst handoff package for LogAsis v0.6.4.

The handoff package is a structured, evidence-provenanced snapshot of one case.
It never invents facts and never executes response actions. AI output is marked
advisory and is kept separate from deterministic case facts.
"""

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.case_decision import CaseDecisionEngine
from core.integrity import _json_default
from core.investigation_response import InvestigationResponseEngine
from core.ioc import extract_iocs


class CaseHandoffEngine:
    HANDOFF_TYPES = (
        "Incident Response",
        "SOC Escalation",
        "Management Review",
        "Forensic Review",
        "Case Archive",
    )

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    @staticmethod
    def _clean(value: Any) -> str:
        return str(value or "").strip()

    @classmethod
    def build(
        cls,
        *,
        case: dict[str, Any],
        intelligence: dict[str, Any],
        workflow: dict[str, Any] | None = None,
        decision: dict[str, Any] | None = None,
        response: dict[str, Any] | None = None,
        analyst_report: str = "",
        question: str = "",
        evidence: list[dict[str, Any]] | None = None,
        handoff_type: str = "Incident Response",
        recipient: str = "",
        owner: str = "",
        handoff_note: str = "",
    ) -> dict[str, Any]:
        workflow = workflow or {}
        evidence = evidence or []
        decision = decision or CaseDecisionEngine.build(case, intelligence, question)
        response = response or InvestigationResponseEngine.build(
            case, decision, workflow, intelligence
        )
        if handoff_type not in cls.HANDOFF_TYPES:
            handoff_type = "Incident Response"

        linked_ids = set(str(x) for x in (case.get("evidence_ids", []) or []) if x)
        linked_evidence = [
            dict(item) for item in evidence
            if str(item.get("evidence_id", "") or "") in linked_ids
        ]

        ioc_source = linked_evidence or list(intelligence.get("timeline", []) or [])
        iocs = extract_iocs(ioc_source)
        finding_rows = list(intelligence.get("findings", []) or [])
        gaps = list(decision.get("evidence_gaps", []) or [])
        relationships = list(intelligence.get("relationships", []) or [])

        # The executive summary is deterministic and deliberately avoids
        # labeling an event malicious unless the deterministic decision says so.
        assessment = cls._clean(intelligence.get("assessment"))
        decision_name = cls._clean(decision.get("decision") or "INSUFFICIENT_EVIDENCE")
        confidence = cls._clean(decision.get("confidence") or "LOW")
        disposition = cls._clean(workflow.get("disposition") or case.get("disposition") or "Undetermined")
        executive_summary = (
            f"{case.get('case_id', 'Case')} is assessed as {decision_name} with "
            f"{confidence} confidence. {assessment or 'No deterministic assessment was generated.'}"
        )
        if gaps:
            executive_summary += f" {len(gaps)} evidence gap(s) remain open."
        elif disposition != "Undetermined":
            executive_summary += f" Recorded disposition: {disposition}."

        timeline = list(intelligence.get("timeline", []) or [])
        audit = list(workflow.get("audit_history", []) or [])
        response_history = list(workflow.get("response_history", []) or [])
        investigation_history = list(workflow.get("investigation_history", []) or [])

        readiness = response.get("readiness", "NOT_READY")
        handoff_ready = readiness in {"READY_FOR_HANDOFF", "READY_FOR_CLOSURE"}
        package = {
            "package_type": "LogAsis Incident Investigation & Handoff",
            "schema_version": "0.6.4",
            "generated_at": cls._now(),
            "handoff": {
                "type": handoff_type,
                "recipient": cls._clean(recipient),
                "owner": cls._clean(owner),
                "note": cls._clean(handoff_note),
                "ready": handoff_ready,
                "readiness": readiness,
            },
            "case": {
                "case_id": case.get("case_id", ""),
                "status": case.get("status", "New"),
                "priority": case.get("priority", "MEDIUM"),
                "title": case.get("title", ""),
                "description": case.get("description", ""),
                "source_file": case.get("source_file", ""),
                "created_at": case.get("created_at", ""),
                "updated_at": case.get("updated_at", ""),
                "disposition": disposition,
            },
            "executive_summary": executive_summary,
            "investigation_question": cls._clean(question),
            "decision": decision,
            "response_readiness": response,
            "timeline": timeline,
            "evidence": linked_evidence,
            "findings": finding_rows,
            "iocs": iocs,
            "correlation": relationships,
            "evidence_gaps": gaps,
            "recommended_actions": list(intelligence.get("recommended_actions", []) or []),
            "response_history": response_history,
            "investigation_history": investigation_history,
            "workflow_audit": audit,
            "analyst_notes": cls._clean(workflow.get("analyst_notes") or case.get("analyst_notes")),
            "closure": {
                "final_report_ready": bool(workflow.get("final_report_ready", False)),
                "closure_note": cls._clean(workflow.get("closure_note")),
            },
            "ai_analyst": {
                "included": bool(cls._clean(analyst_report)),
                "advisory": True,
                "question": cls._clean(question),
                "report": cls._clean(analyst_report),
            },
            "limitations": [
                "Deterministic case evidence remains authoritative.",
                "IOC extraction identifies observable indicators; it does not establish maliciousness.",
                "Correlation and temporal proximity do not establish causation.",
                "AI analyst output is advisory and bounded by the supplied case context.",
                "Response actions recorded by LogAsis are analyst-controlled workflow records; LogAsis does not execute host containment or destructive actions.",
            ],
        }
        return package

    @classmethod
    def validate(cls, package: dict[str, Any]) -> dict[str, Any]:
        case = package.get("case", {}) or {}
        response = package.get("response_readiness", {}) or {}
        required = [
            ("case_id", bool(case.get("case_id"))),
            ("decision", bool(package.get("decision"))),
            ("evidence", bool(package.get("evidence"))),
            ("response_assessment", bool(response.get("readiness"))),
        ]
        missing = [name for name, ok in required if not ok]
        blockers = list(response.get("blockers", []) or [])
        return {
            "valid": not missing,
            "missing": missing,
            "blockers": blockers,
            "handoff_ready": bool(package.get("handoff", {}).get("ready", False)) and not blockers,
        }

    @staticmethod
    def export_json(package: dict[str, Any], path: str | Path) -> Path:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(package, indent=2, ensure_ascii=False, default=_json_default),
            encoding="utf-8",
        )
        return destination

    @staticmethod
    def export_html(package: dict[str, Any], path: str | Path) -> Path:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        esc = html.escape

        case = package.get("case", {})
        decision = package.get("decision", {})
        response = package.get("response_readiness", {})
        handoff = package.get("handoff", {})
        findings = package.get("findings", []) or []
        evidence = package.get("evidence", []) or []
        timeline = package.get("timeline", []) or []
        gaps = package.get("evidence_gaps", []) or []
        correlations = package.get("correlation", []) or []
        iocs = package.get("iocs", {}) or {}
        audit = package.get("workflow_audit", []) or []

        def table(rows: list[dict[str, Any]], columns: list[tuple[str, str]]) -> str:
            body = []
            for row in rows:
                body.append(
                    "<tr>" + "".join(
                        f"<td>{esc(str(row.get(key, '') or ''))}</td>"
                        for key, _ in columns
                    ) + "</tr>"
                )
            return "".join(body) or f'<tr><td colspan="{len(columns)}">None recorded</td></tr>'

        def headers(columns: list[tuple[str, str]]) -> str:
            return "".join(f"<th>{esc(label)}</th>" for _, label in columns)

        finding_cols = [
            ("finding_id", "Finding ID"), ("classification", "Classification"),
            ("confidence", "Confidence"), ("statement", "Finding"),
        ]
        evidence_cols = [
            ("evidence_id", "Evidence ID"), ("timestamp", "Timestamp"),
            ("priority", "Priority"), ("event_type", "Event Type"),
            ("source_ip", "Source IP"), ("username", "User"),
            ("process_name", "Process"),
        ]
        timeline_cols = evidence_cols + [("action", "Action")]
        gap_cols = [
            ("gap_id", "Gap"), ("category", "Category"),
            ("severity", "Severity"), ("description", "Missing Evidence"),
            ("recommended_action", "Recommended Action"),
        ]
        corr_cols = [
            ("evidence_a", "Evidence A"), ("evidence_b", "Evidence B"),
            ("score", "Score"), ("reasons", "Reason"),
        ]

        ioc_rows = []
        for kind, values in iocs.items():
            for item in values or []:
                row = dict(item)
                row["type"] = kind
                ioc_rows.append(row)

        html_doc = f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>LogAsis Incident Package — {esc(str(case.get('case_id', '')))}</title>
<style>
:root{{color-scheme:dark}}
body{{margin:0;background:#080d18;color:#dbe7f5;font-family:Segoe UI,Arial,sans-serif}}
main{{max-width:1400px;margin:28px auto;padding:0 24px}}
header,.card{{background:#0e1625;border:1px solid #24354d;border-radius:14px;padding:22px;margin-bottom:18px;box-shadow:0 8px 24px #0005}}
header{{border-top:3px solid #21b6ed}}
h1{{margin:0 0 8px;font-size:28px}}h2{{font-size:18px;margin:0 0 14px;color:#8fd8ff}}
.meta{{display:flex;gap:22px;flex-wrap:wrap;color:#9fb2c8}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}}
.metric{{background:#0a1220;border:1px solid #20324a;border-radius:10px;padding:14px}}
.metric b{{display:block;color:#6fcbff;font-size:12px;text-transform:uppercase;margin-bottom:5px}}
table{{width:100%;border-collapse:collapse;font-size:12px;overflow:hidden}}
th,td{{border-bottom:1px solid #203149;padding:9px;text-align:left;vertical-align:top}}
th{{background:#152238;color:#9fdcff}}tr:hover td{{background:#111e30}}
.badge{{display:inline-block;padding:5px 9px;border-radius:999px;border:1px solid #28506a;background:#0d2737}}
pre{{white-space:pre-wrap;background:#09111e;border:1px solid #20324a;padding:16px;border-radius:10px;line-height:1.55}}
.small{{color:#8da1b8;font-size:12px}}li{{margin:6px 0}}
@media print{{body{{background:#fff;color:#17202a}}header,.card{{box-shadow:none;background:#fff;border-color:#ccd5df}}}}
</style></head><body><main>
<header>
<h1>LogAsis Incident Investigation &amp; Handoff Package</h1>
<div class="meta">
<span><b>Case:</b> {esc(str(case.get('case_id','N/A')))}</span>
<span><b>Priority:</b> {esc(str(case.get('priority','N/A')))}</span>
<span><b>Status:</b> {esc(str(case.get('status','N/A')))}</span>
<span><b>Disposition:</b> {esc(str(case.get('disposition','Undetermined')))}</span>
</div>
<p><b>{esc(str(case.get('title','')))}</b></p>
<p class="small">Generated {esc(str(package.get('generated_at','')))}</p>
</header>

<section class="card"><h2>1. Executive Summary</h2>
<p>{esc(str(package.get('executive_summary','')))}</p>
<div class="grid">
<div class="metric"><b>Decision</b>{esc(str(decision.get('decision','')))}</div>
<div class="metric"><b>Confidence</b>{esc(str(decision.get('confidence','')))}</div>
<div class="metric"><b>Response Readiness</b>{esc(str(response.get('readiness','')))}</div>
<div class="metric"><b>Open Evidence Gaps</b>{len(gaps)}</div>
<div class="metric"><b>Linked Evidence</b>{len(evidence)}</div>
<div class="metric"><b>Findings</b>{len(findings)}</div>
</div></section>

<section class="card"><h2>2. Incident Overview</h2>
<p><b>Investigation Question:</b> {esc(str(package.get('investigation_question','') or 'Not specified'))}</p>
<p><b>Description:</b> {esc(str(case.get('description','')))}</p>
<p><b>Source:</b> {esc(str(case.get('source_file','') or 'Not recorded'))}</p>
</section>

<section class="card"><h2>3. Decision &amp; Rationale</h2>
<p><span class="badge">{esc(str(decision.get('decision','INSUFFICIENT_EVIDENCE')))} / {esc(str(decision.get('confidence','LOW')))}</span></p>
<p>{esc(str(decision.get('rationale','')))}</p>
</section>

<section class="card"><h2>4. Evidence-Backed Findings</h2>
<table><tr>{headers(finding_cols)}</tr>{table(findings, finding_cols)}</table></section>

<section class="card"><h2>5. Case Timeline</h2>
<table><tr>{headers(timeline_cols)}</tr>{table(timeline, timeline_cols)}</table></section>

<section class="card"><h2>6. IOC Inventory</h2>
<table><tr><th>Type</th><th>Value</th><th>Occurrences</th><th>Algorithm</th><th>Evidence Count</th></tr>
{''.join(f"<tr><td>{esc(str(r.get('type','')))}</td><td>{esc(str(r.get('value','')))}</td><td>{esc(str(r.get('occurrences','')))}</td><td>{esc(str(r.get('algorithm','')))}</td><td>{len(r.get('evidence_ids',[]) or [])}</td></tr>" for r in ioc_rows) or '<tr><td colspan="5">No IOCs extracted from linked evidence.</td></tr>'}
</table></section>

<section class="card"><h2>7. Correlation</h2>
<table><tr>{headers(corr_cols)}</tr>
{table([{**r, "reasons": "; ".join(r.get("reasons", []) or [])} for r in correlations], corr_cols)}
</table><p class="small">Correlation is an investigative relationship signal and does not establish causation or malicious intent.</p></section>

<section class="card"><h2>8. Evidence Gaps &amp; Recommended Actions</h2>
<table><tr>{headers(gap_cols)}</tr>{table(gaps, gap_cols)}</table>
<ol>{''.join(f"<li>{esc(str(x))}</li>" for x in package.get('recommended_actions', []) or []) or '<li>No additional deterministic actions recorded.</li>'}</ol>
</section>

<section class="card"><h2>9. Response &amp; Closure</h2>
<p><b>Lifecycle:</b> {esc(str(response.get('lifecycle','')))} &nbsp; <b>Readiness:</b> {esc(str(response.get('readiness','')))}</p>
<p><b>Recommendation:</b> {esc(str(response.get('recommendation','')))}</p>
<ul>{''.join(f"<li>{esc(str(x))}</li>" for x in response.get('blockers', []) or []) or '<li>No response blockers recorded.</li>'}</ul>
<p><b>Disposition:</b> {esc(str(case.get('disposition','Undetermined')))}</p>
<p><b>Closure rationale:</b> {esc(str(package.get('closure',{}).get('closure_note','') or 'Not recorded'))}</p>
</section>

<section class="card"><h2>10. Handoff</h2>
<div class="grid">
<div class="metric"><b>Type</b>{esc(str(handoff.get('type','')))}</div>
<div class="metric"><b>Recipient</b>{esc(str(handoff.get('recipient','') or 'Not specified'))}</div>
<div class="metric"><b>Owner</b>{esc(str(handoff.get('owner','') or 'Not specified'))}</div>
<div class="metric"><b>Ready</b>{'YES' if handoff.get('ready') else 'NO'}</div>
</div>
<p>{esc(str(handoff.get('note','') or 'No handoff note recorded.'))}</p>
</section>

<section class="card"><h2>11. AI Analyst — Advisory</h2>
<pre>{esc(str(package.get('ai_analyst',{}).get('report') or 'No AI analyst report included.'))}</pre>
</section>

<section class="card"><h2>12. Audit &amp; Investigation History</h2>
<table><tr><th>Timestamp</th><th>Action</th><th>Details</th></tr>
{''.join(f"<tr><td>{esc(str(x.get('timestamp','')))}</td><td>{esc(str(x.get('action','')))}</td><td>{esc(str(x.get('details','')))}</td></tr>" for x in audit) or '<tr><td colspan="3">No audit history.</td></tr>'}
</table>
</section>

<section class="card"><h2>13. Limitations</h2>
<ul>{''.join(f"<li>{esc(str(x))}</li>" for x in package.get('limitations', []) or [])}</ul>
</section>
<footer class="small">Generated by LogAsis. Deterministic case evidence remains authoritative. This package records analyst workflow and recommendations; it does not execute response actions.</footer>
</main></body></html>"""
        destination.write_text(html_doc, encoding="utf-8")
        return destination
