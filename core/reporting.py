from __future__ import annotations
import json, html
from pathlib import Path

from core.case_decision import CaseDecisionEngine
from core.integrity import _json_default
from typing import Any

def build_investigation_pack(*, version, source_file, profile, events, iocs, detections, cases, evidence, manifest, analyst_reports=None):
    return {
        "logasis_version":version,
        "source_file":source_file,
        "profile":profile,
        "integrity":manifest,
        "statistics":{"events":len(events),"iocs":{k:len(v) for k,v in iocs.items()},"detections":len(detections),"cases":len(cases),"evidence":len(evidence)},
        "iocs":iocs,"detections":detections,"cases":cases,"evidence":evidence,
        "analyst_reports":analyst_reports or [],
    }

def export_json(pack,path):
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(pack,indent=2,ensure_ascii=False,default=_json_default),encoding="utf-8"); return p

def export_html(pack,path):
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True)
    rows=[]
    for d in pack.get("detections",[]):
        rows.append(f"<tr><td>{html.escape(str(d.get('rule_id','')))}</td><td>{html.escape(str(d.get('title','')))}</td><td>{html.escape(str(d.get('severity','')))}</td><td>{html.escape(str(d.get('confidence','')))}</td><td>{html.escape(str(d.get('summary','')))}</td></tr>")
    ioc_counts="".join(f"<li>{html.escape(k)}: {len(v)}</li>" for k,v in pack.get("iocs",{}).items())
    doc=f"""<!doctype html><html><head><meta charset="utf-8"><title>LogAsis Investigation Pack</title>
    <style>body{{font-family:Segoe UI,Arial;margin:32px;color:#202124}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:8px;text-align:left}}th{{background:#f3f4f6}}code{{font-family:Consolas}}</style></head>
    <body><h1>LogAsis Investigation Pack</h1><p><b>Version:</b> {html.escape(str(pack.get('logasis_version')))}</p>
    <p><b>Source:</b> {html.escape(str(pack.get('source_file')))}</p><h2>Statistics</h2><ul><li>Events: {pack['statistics']['events']}</li><li>Detections: {pack['statistics']['detections']}</li><li>Cases: {pack['statistics']['cases']}</li><li>Evidence: {pack['statistics']['evidence']}</li>{ioc_counts}</ul>
    <h2>Integrity</h2><p>Source SHA-256: <code>{html.escape(str(pack['integrity'].get('source_sha256','')))}</code></p>
    <h2>Detections</h2><table><tr><th>Rule</th><th>Finding</th><th>Severity</th><th>Confidence</th><th>Summary</th></tr>{''.join(rows) or '<tr><td colspan="5">No deterministic findings</td></tr>'}</table>
    </body></html>"""
    p.write_text(doc,encoding="utf-8"); return p


def export_case_report_html(*, case, intelligence, analyst_report="", question="", path="case_report.html"):
    """Export a self-contained professional case report with evidence provenance."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    esc = html.escape
    timeline = intelligence.get("timeline", []) or []
    findings = intelligence.get("findings", []) or []
    relationships = intelligence.get("relationships", []) or []
    def rows(items, cols):
        out=[]
        for item in items:
            out.append("<tr>" + "".join(f"<td>{esc(str(item.get(c, '') or ''))}</td>" for c in cols) + "</tr>")
        return "".join(out)
    timeline_html = rows(timeline, ["evidence_id","timestamp","priority","event_type","source_ip","username","process_name","action"])
    finding_html = "".join(
        f"<tr><td>{esc(str(f.get('finding_id','')))}</td>"
        f"<td>{esc(str(f.get('classification','')))}</td>"
        f"<td>{esc(str(f.get('confidence','')))}</td>"
        f"<td>{esc(str(f.get('statement','')))}</td>"
        f"<td>{esc(', '.join(f.get('evidence_ids',[]) or []))}</td></tr>"
        for f in findings
    )
    rel_html = "".join(
        f"<tr><td>{esc(str(r.get('evidence_a','')))}</td><td>{esc(str(r.get('evidence_b','')))}</td>"
        f"<td>{esc(str(r.get('score','')))}</td><td>{esc('; '.join(r.get('reasons',[]) or []))}</td></tr>"
        for r in relationships
    )
    decision = CaseDecisionEngine.build(case, intelligence, question)
    gap_html = "".join(
        f"<tr><td>{esc(str(g.get('gap_id','')))}</td><td>{esc(str(g.get('category','')))}</td>"
        f"<td>{esc(str(g.get('severity','')))}</td><td>{esc(str(g.get('description','')))}</td>"
        f"<td>{esc(str(g.get('recommended_action','')))}</td></tr>"
        for g in decision.get('evidence_gaps', []) or []
    )
    doc=f"""<!doctype html><html><head><meta charset="utf-8">
<title>LogAsis Case Report — {esc(str(case.get('case_id','')))}</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#f5f7fa;color:#17202a;margin:0}}
main{{max-width:1200px;margin:32px auto;padding:0 20px}}
header,.card{{background:#fff;border:1px solid #dfe3e8;border-radius:12px;padding:22px;margin-bottom:18px}}
h1{{margin:0 0 8px}}h2{{margin-top:0;font-size:18px}}
.meta{{display:flex;gap:24px;flex-wrap:wrap;color:#4b5563}}
table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{border-bottom:1px solid #e5e7eb;padding:9px;text-align:left;vertical-align:top}}
th{{background:#f3f4f6}}pre{{white-space:pre-wrap;background:#0f172a;color:#e5e7eb;padding:18px;border-radius:10px;line-height:1.5}}
.badge{{font-weight:700}}
.small{{color:#6b7280;font-size:12px}}
</style></head><body><main>
<header><h1>LogAsis Case Investigation Report</h1>
<div class="meta"><span><b>Case:</b> {esc(str(case.get('case_id','N/A')))}</span>
<span><b>Status:</b> {esc(str(case.get('status','N/A')))}</span>
<span><b>Priority:</b> {esc(str(case.get('priority','N/A')))}</span>
<span><b>Disposition:</b> {esc(str(case.get('disposition','Undetermined')))}</span></div>
<p><b>Title:</b> {esc(str(case.get('title','')))}</p>
<p><b>Investigation question:</b> {esc(str(question or ''))}</p></header>
<section class="card"><h2>Deterministic Assessment</h2>
<p>{esc(str(intelligence.get('assessment','')))}</p>
<p><b>Uncertainty / limitations:</b></p><ul>{''.join('<li>'+esc(str(x))+'</li>' for x in intelligence.get('uncertainty',[]) or [])}</ul></section>
<section class="card"><h2>Evidence-Backed Findings</h2>
<table><tr><th>ID</th><th>Classification</th><th>Confidence</th><th>Finding</th><th>Evidence</th></tr>{finding_html or '<tr><td colspan="5">No findings</td></tr>'}</table></section>
<section class="card"><h2>Decision &amp; Evidence Gaps</h2>
<p><b>Decision:</b> <span class="badge">{esc(str(decision.get('decision','INSUFFICIENT_EVIDENCE')))}</span> &nbsp; <b>Confidence:</b> {esc(str(decision.get('confidence','LOW')))}</p>
<p><b>Rationale:</b> {esc(str(decision.get('rationale','')))}</p>
<table><tr><th>Gap</th><th>Category</th><th>Severity</th><th>Missing Evidence</th><th>Recommended Action</th></tr>{gap_html or '<tr><td colspan="5">No deterministic evidence gaps identified</td></tr>'}</table></section>
<section class="card"><h2>Case Timeline</h2>
<table><tr><th>Evidence</th><th>Timestamp</th><th>Priority</th><th>Event</th><th>Source IP</th><th>User</th><th>Process</th><th>Action</th></tr>{timeline_html or '<tr><td colspan="8">No linked evidence</td></tr>'}</table></section>
<section class="card"><h2>Correlation</h2>
<table><tr><th>Evidence A</th><th>Evidence B</th><th>Score</th><th>Reason</th></tr>{rel_html or '<tr><td colspan="4">No deterministic relationships</td></tr>'}</table>
<p class="small">Correlation and temporal proximity do not establish causation or malicious intent.</p></section>
<section class="card"><h2>Recommended Next Steps</h2><ol>{''.join('<li>'+esc(str(x))+'</li>' for x in intelligence.get('recommended_actions',[]) or [])}</ol></section>
<section class="card"><h2>AI Analyst Report</h2><pre>{esc(str(analyst_report or 'No AI analyst report generated.'))}</pre></section>
<footer class="small">Generated by LogAsis. Deterministic evidence remains authoritative; AI analysis is advisory and bounded by the supplied case evidence.</footer>
</main></body></html>"""
    p.write_text(doc, encoding="utf-8")
    return p
