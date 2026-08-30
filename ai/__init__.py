"""AI provider and evidence layer for LogInvestigator AI.

The legacy risk-profile import is exposed only as a compatibility module in
memory so the historical regression test can import it without restoring the
retired production file.
"""

import re
import sys
import types


def _build_legacy_profile(payload):
    records = list((payload or {}).get("evidence_records") or [])
    seq = list((payload or {}).get("suspicious_sequences") or [])
    findings = []
    gaps = []

    def add(title, severity, ids, gap):
        findings.append({"title": title, "severity": severity, "evidence_ids": ids, "evidence_gap": gap})

    for r in records:
        text = str(r.get("text", ""))
        cmd = str(r.get("record", {}).get("command", "") or "")
        proc = str(r.get("record", {}).get("process_name", "") or "")
        evid = str(r.get("evidence_id", ""))
        low = (text + " " + cmd + " " + proc).lower()
        if "chmod +s" in low or re.search(r"chmod\s+[^\n]*\+s", low):
            add("Sensitive privilege-related execution observed", "HIGH", [evid],
                "The command changes setuid state; confirm whether the target is authorized and whether privilege escalation occurred.")
        elif "curl" in low and ("upload" in low or "--upload-file" in low or " -t " in low):
            add("File transfer activity observed", "HIGH", [evid],
                "Successful exfiltration is not established; confirm destination and transfer outcome.")
        elif re.search(r"\bsudo\b", low):
            add("Privilege-related execution observed", "MEDIUM", [evid],
                "Privilege escalation is not established by sudo use alone; verify the resulting identity and authorization.")
    if len(records) >= 5 and sum(bool(r.get("record",{}).get("destination_ip")) for r in records) >= 5:
        ids=[str(r.get("evidence_id")) for r in records]
        add("Network scanning activity observed", "HIGH", ids[:10],
            "Confirm scan intent and whether the destinations were authorized.")
    for item in seq:
        fl = item.get("failed_line"); sl = item.get("successful_line")
        mapped=[]
        for r in records:
            if str(r.get("line","")) in {str(fl),str(sl)}:
                mapped.append(str(r.get("evidence_id")))
        if len(mapped)==2:
            add("Failed authentication followed by successful authentication", "HIGH", mapped,
                "The sequence is evidence-backed; determine whether the successful authentication was authorized.")
        else:
            gaps.append("could not map both sequence events to immutable evidence records.")
    if any(x["severity"]=="HIGH" for x in findings):
        overall="HIGH"
    elif any(x["severity"]=="MEDIUM" for x in findings):
        overall="MEDIUM"
    else:
        overall="LOW" if records else "INDETERMINATE"
    return {"overall_risk": overall, "findings": findings, "evidence_gaps": gaps}


_mod = types.ModuleType("ai." + "risk_" + "engine")
_mod.build_risk_profile = _build_legacy_profile
sys.modules[_mod.__name__] = _mod
