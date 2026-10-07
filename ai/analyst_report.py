from __future__ import annotations
import re
from typing import Any, Dict

URI_RE = re.compile(r"\[([^\]]+)\]\((?:user|ip|process|evidence|correlation)://[^)]+\)", re.I)

def clean_internal_links(text: str) -> str:
    return URI_RE.sub(r"\1", text or "")

def remove_duplicate_metadata(text: str) -> str:
    out=[]
    for line in (text or "").splitlines():
        s=line.strip().replace("*", "")
        if re.fullmatch(r"case\s*analyst\s*report", s, re.I): continue
        if re.fullmatch(r"CASECASE-\d+", s, re.I): continue
        if re.fullmatch(r"case(?:\s*id)?\s*:?\s*CASE-?\d+", s, re.I): continue
        if re.fullmatch(r"status\s*:?\s*(new|investigation|in progress|resolved|closed|escalated)", s, re.I): continue
        if re.fullmatch(r"priority\s*:?\s*(low|medium|high|critical)", s, re.I): continue
        out.append(line)
    return "\n".join(out)

def harden_scope(text: str) -> str:
    t=text or ""
    patterns=[
      (r"\bthere is no indication that (?:the )?user(?: account)?\s+([A-Za-z0-9_.@-]+)\s+successfully compromised the system\b", r"The available case evidence does not establish a successful compromise of the \1 account."),
      (r"\bthere is no evidence to suggest that (?:the )?user(?: account)?\s+([A-Za-z0-9_.@-]+)\s+successfully compromised the system\b", r"The available case evidence does not establish a successful compromise of the \1 account."),
      (r"\b(?:the )?user(?: account)?\s+([A-Za-z0-9_.@-]+)\s+did not successfully compromise the system\b", r"The available case evidence does not establish a successful compromise of the \1 account."),
      (r"\ball recorded authentication attempts(?: associated with (?:the )?account)?\s+(?:resulted|were)\s+in failures\b", "All authentication attempts represented in the supplied case evidence are recorded as failures."),
      (r"\bno successful authentication events are recorded in the supplied (?:data|dataset)\b", "No successful authentication associated with the account is present in the supplied case evidence."),
      (r"\bno successful logins recorded\b", "No successful login associated with the account is present in the supplied case evidence."),
      (r"\bconfidence is high that no compromise is established within the provided dataset\b", "Evidence confidence is high for the recorded facts in the supplied case evidence; this does not rule out activity outside that evidence scope."),
    ]
    for pat, repl in patterns: t=re.sub(pat,repl,t,flags=re.I)
    return t

def normalize_report(text: str) -> str:
    t=clean_internal_links(text)
    t=remove_duplicate_metadata(t)
    t=harden_scope(t)
    return re.sub(r"\n{3,}","\n\n",t).strip()

def build_report(case: Dict[str, Any], question: str, ai_text: str) -> str:
    body=normalize_report(ai_text)
    return ("CASE ANALYST REPORT\n"
            "────────────────────────────────────────\n\n"
            "CASE INFORMATION\n\n"
            f"Case ID: {case.get('case_id','UNKNOWN')}\n"
            f"Title: {case.get('title','Untitled case')}\n"
            f"Status: {case.get('status','Unknown')}\n"
            f"Priority: {case.get('priority','Unknown')}\n\n"
            "INVESTIGATION QUESTION\n\n"
            f"{question.strip()}\n\n"
            "────────────────────────────────────────\n\n" + body)

def sanitize_export(text: str) -> str:
    return normalize_report(text or "")
