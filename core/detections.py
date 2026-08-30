from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any
import re


def _s(v: Any) -> str:
    return str(v or "").strip()


def _dt(v: Any):
    try:
        x = _s(v)
        if x.endswith("Z"):
            x = x[:-1] + "+00:00"
        return datetime.fromisoformat(x)
    except Exception:
        return None


RULE_CATALOG: tuple[dict[str, str], ...] = (
    {"rule_id": "AUTH-BURST-001", "title": "Repeated authentication failures", "description": "Repeated failed authentication attempts for the same user/source pair."},
    {"rule_id": "AUTH-CHAIN-002", "title": "Failed authentication followed by success", "description": "A successful authentication follows a failed authentication for the same user within the correlation window."},
    {"rule_id": "PRIV-001", "title": "Privilege-related execution", "description": "A privilege-related process was observed."},
    {"rule_id": "PRIV-002", "title": "Sensitive privilege command", "description": "A command references sensitive privilege configuration or escalation mechanisms."},
    {"rule_id": "EXEC-001", "title": "Command-line investigation signal", "description": "Command-line content matches a high-interest execution pattern."},
    {"rule_id": "NET-001", "title": "Potential network scanning pattern", "description": "A source contacted many distinct destination IPs in the supplied evidence."},
)


class DetectionEngine:
    """Deterministic detection layer for analyst triage.

    Findings are hypotheses/triage signals, never proof of compromise. v0.5.20
    adds stable finding identity, evidence-quality metadata, rule provenance and
    deterministic de-duplication without changing the existing rule semantics.
    """

    @staticmethod
    def rule_catalog() -> list[dict[str, str]]:
        return [dict(item) for item in RULE_CATALOG]

    def run(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        findings += self._auth_bursts(events)
        findings += self._failed_then_success(events)
        findings += self._privilege_events(events)
        findings += self._suspicious_commands(events)
        findings += self._network_scan_signals(events)

        finalized: list[dict[str, Any]] = []
        seen: set[str] = set()
        for finding in findings:
            item = self._finalize(finding)
            if item["finding_id"] in seen:
                continue
            seen.add(item["finding_id"])
            finalized.append(item)
        return sorted(finalized, key=lambda x: (-x["score"], x["rule_id"], x["finding_id"]))

    def _finalize(self, finding: dict[str, Any]) -> dict[str, Any]:
        evidence_ids = list(dict.fromkeys(str(x) for x in (finding.get("evidence_ids") or []) if str(x).strip()))
        finding["evidence_ids"] = evidence_ids
        finding["evidence_count"] = len(evidence_ids)
        finding["rule_id"] = _s(finding.get("rule_id"))
        finding["title"] = _s(finding.get("title"))
        finding["severity"] = _s(finding.get("severity")) or "LOW"
        finding["score"] = int(finding.get("score", 0) or 0)
        finding["confidence"] = self._confidence(finding)
        finding["evidence_scope"] = "Recorded evidence only"
        finding["limitations"] = [
            "A deterministic rule match is an investigation signal, not proof of malicious intent or compromise.",
            "Assessment is limited to evidence linked to this finding.",
        ]
        catalog = {x["rule_id"]: x for x in RULE_CATALOG}.get(finding["rule_id"], {})
        finding["rule_description"] = catalog.get("description", "Deterministic investigation rule.")
        signature = "|".join([finding["rule_id"], *sorted(evidence_ids)])
        finding["finding_id"] = "DET-" + sha256(signature.encode("utf-8")).hexdigest()[:12].upper()
        return finding

    @staticmethod
    def _confidence(finding: dict[str, Any]) -> str:
        evidence_count = len(finding.get("evidence_ids") or [])
        rule_id = _s(finding.get("rule_id"))
        if rule_id == "AUTH-CHAIN-002" and evidence_count >= 2:
            return "HIGH"
        if rule_id in {"AUTH-BURST-001", "NET-001"} and evidence_count >= 2:
            return "HIGH"
        if evidence_count >= 2:
            return "MEDIUM"
        return "LOW"

    def _auth_bursts(self, events):
        groups = defaultdict(list)
        for e in events:
            action = _s(e.get("action")).lower()
            if action == "failed_login" or ("USER_AUTH" == _s(e.get("event_type")).upper() and "fail" in _s(e.get("message")).lower()):
                key = (_s(e.get("source_ip")) or "unknown", _s(e.get("username")) or "unknown")
                groups[key].append(e)
        out = []
        for (ip, user), items in groups.items():
            attempts = 0
            for e in items:
                reasons = " ".join(map(str, e.get("reasons", []) or []))
                m = re.search(r"\((\d+)\s+attempts?\)", reasons, re.I)
                attempts = max(attempts, int(m.group(1)) if m else 1)
            if len(items) >= 2 or attempts >= 10:
                out.append({"rule_id": "AUTH-BURST-001", "title": "Repeated authentication failures", "severity": "HIGH" if attempts >= 50 else "MEDIUM", "score": 80 if attempts >= 50 else 55,
                            "summary": f"{attempts} failed authentication attempt(s) represented by {len(items)} event record(s) for user {user} from {ip}.",
                            "evidence_ids": [_s(e.get("evidence_id")) for e in items if _s(e.get("evidence_id"))]})
        return out

    def _failed_then_success(self, events):
        auth = [e for e in events if _s(e.get("event_type")).upper() == "USER_AUTH"]
        auth = sorted(auth, key=lambda e: _dt(e.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc))
        out = []
        for i, e in enumerate(auth):
            if _s(e.get("action")).lower() != "failed_login":
                continue
            ip, user = _s(e.get("source_ip")), _s(e.get("username"))
            for nxt in auth[i + 1:i + 20]:
                if _s(nxt.get("username")) != user:
                    continue
                if _s(nxt.get("action")).lower() not in {"successful_login", "login_success", "success"}:
                    continue
                t1, t2 = _dt(e.get("timestamp")), _dt(nxt.get("timestamp"))
                if t1 and t2 and (t2 - t1).total_seconds() <= 900:
                    out.append({"rule_id": "AUTH-CHAIN-002", "title": "Failed authentication followed by success", "severity": "CRITICAL", "score": 95,
                                "summary": f"Successful authentication followed failed authentication for user {user}.",
                                "evidence_ids": [_s(e.get("evidence_id")), _s(nxt.get("evidence_id"))]})
                    break
        return out

    def _privilege_events(self, events):
        out = []
        for e in events:
            p = _s(e.get("process_name")).lower()
            a = _s(e.get("action")).lower()
            cmd = _s(e.get("command")).lower()
            if p in {"sudo", "su", "pkexec"} and "fail" not in a:
                out.append({"rule_id": "PRIV-001", "title": "Privilege-related execution", "severity": "MEDIUM", "score": 45,
                            "summary": f"Privilege-related process {p} was observed.", "evidence_ids": [_s(e.get("evidence_id"))]})
            elif any(x in cmd for x in ("chmod +s", "setuid", "/etc/sudoers", "visudo")):
                out.append({"rule_id": "PRIV-002", "title": "Sensitive privilege command", "severity": "HIGH", "score": 75,
                            "summary": "A command referencing sensitive privilege configuration was observed.", "evidence_ids": [_s(e.get("evidence_id"))]})
        return out

    def _suspicious_commands(self, events):
        out = []
        tokens = ("curl ", "wget ", "nc ", "netcat", "bash -c", "sh -c", "python -c", "powershell", "certutil", "rundll32", "regsvr32")
        for e in events:
            cmd = _s(e.get("command")).lower()
            if cmd and any(t in cmd for t in tokens):
                out.append({"rule_id": "EXEC-001", "title": "Command-line investigation signal", "severity": "MEDIUM", "score": 50,
                            "summary": "Command-line content matches a high-interest execution pattern and requires analyst validation.", "evidence_ids": [_s(e.get("evidence_id"))]})
        return out

    def _network_scan_signals(self, events):
        groups = defaultdict(set)
        refs = defaultdict(list)
        for e in events:
            ip = _s(e.get("source_ip")); dst = _s(e.get("destination_ip"))
            if ip and dst:
                groups[ip].add(dst); refs[ip].append(e)
        out = []
        for ip, dsts in groups.items():
            if len(dsts) >= 10:
                out.append({"rule_id": "NET-001", "title": "Potential network scanning pattern", "severity": "HIGH", "score": 70,
                            "summary": f"Source {ip} contacted {len(dsts)} distinct destination IPs in the supplied events.",
                            "evidence_ids": [_s(e.get("evidence_id")) for e in refs[ip] if _s(e.get("evidence_id"))][:100]})
        return out
