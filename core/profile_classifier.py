from __future__ import annotations
from dataclasses import dataclass

PROFILE_GENERIC="Generic Text Log"
PROFILE_AUTH="Authentication / SSH"
PROFILE_SYSMON="Windows Sysmon JSON"
PROFILE_WEB="Web Server"
PROFILE_NETWORK="Firewall / Network"
PROFILE_DNS="DNS"
PROFILE_JSON="Generic JSON"

@dataclass
class ProfileDecision:
    profile: str
    confidence: float
    matched_signals: list[str]
    scores: dict[str,float]

def classify(events, parser_type=""):
    text = (parser_type + "\n" + "\n".join(str(e.to_dict()) for e in events)).lower()
    rules = {
        PROFILE_AUTH: ["user_auth","user_login","sshd","failed_login","successful_login","pam:authentication","addr="],
        PROFILE_SYSMON: ["sysmon","eventid","parentimage","commandline"],
        PROFILE_WEB: ["http","uri","user_agent","status_code","apache","nginx","iis"],
        PROFILE_NETWORK: ["src_ip","dst_ip","source_port","destination_port","allow","deny","drop","blocked"],
        PROFILE_DNS: ["dns","query_name","query_type","rcode","domain"],
    }
    scores={}
    hits={}
    for name, signals in rules.items():
        h=[s for s in signals if s in text]
        hits[name]=h
        scores[name]=float(len(h))
    hint=parser_type.lower()
    if "sysmon" in hint and scores[PROFILE_SYSMON] >= 2:
        selected=PROFILE_SYSMON
    else:
        selected=max(scores, key=scores.get)
    if scores[selected] < 2:
        selected=PROFILE_JSON if "json" in hint else PROFILE_GENERIC
        confidence=.50
    else:
        confidence=min(.99,.50+scores[selected]/20)
    return ProfileDecision(selected,round(confidence,2),list(dict.fromkeys(hits.get(selected,[]))),scores)
