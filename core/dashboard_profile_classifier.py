from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping


@dataclass
class ProfileDecision:
    profile_id: str
    name: str
    confidence: float
    scores: dict[str, float] = field(default_factory=dict)
    matched_signals: list[str] = field(default_factory=list)


# Signals are intentionally grouped by semantic profile.  Structural JSON
# detection still has priority for strong Sysmon/Windows exports; these
# signals refine generic logs after parsing.
AUTH_SIGNALS = {
    "USER_AUTH": 5.0,
    "USER_LOGIN": 5.0,
    "USER_ACCT": 3.0,
    "sshd": 5.0,
    "/usr/sbin/sshd": 5.0,
    "failed_login": 5.0,
    "successful_login": 5.0,
    "PAM:authentication": 4.0,
    'acct="': 2.0,
    "terminal=ssh": 3.0,
    "res=failed": 3.0,
    "res=success": 3.0,
    "authentication failure": 4.0,
    "failed password": 4.0,
    "accepted password": 4.0,
    "accepted publickey": 4.0,
}

SYSMON_SIGNALS = {
    "sysmon": 8.0,
    "eventid": 2.0,
    "commandline": 2.0,
    "parentimage": 2.0,
    "destinationip": 2.0,
    "destinationport": 2.0,
    "processid": 2.0,
    "parentprocessid": 2.0,
}

WEB_SIGNALS = {
    "access.log": 7.0,
    "nginx": 5.0,
    "apache": 5.0,
    "http/1.1": 4.0,
    "http/2": 4.0,
    "request_method": 4.0,
    "status_code": 4.0,
    "user_agent": 3.0,
    "referer": 2.0,
    "url": 2.0,
    "uri": 2.0,
    "GET ": 2.0,
    "POST ": 2.0,
    " 404 ": 3.0,
    " 500 ": 3.0,
}

FIREWALL_SIGNALS = {
    "firewall": 6.0,
    "iptables": 6.0,
    "ufw": 6.0,
    "suricata": 6.0,
    "source_ip": 2.0,
    "destination_ip": 2.0,
    "source_port": 2.0,
    "destination_port": 2.0,
    "allow": 2.0,
    "deny": 3.0,
    "drop": 3.0,
    "blocked": 3.0,
    "accept": 2.0,
}

DNS_SIGNALS = {
    "query_name": 5.0,
    "query_type": 4.0,
    "rcode": 4.0,
    "dnsmasq": 6.0,
    "named": 5.0,
    "bind": 4.0,
    "nxdomain": 4.0,
    "dns query": 5.0,
}


def _event_text(events: Iterable[Any] | None, max_events: int = 3000) -> str:
    chunks: list[str] = []
    for index, event in enumerate(events or []):
        if index >= max_events:
            break
        if isinstance(event, Mapping):
            chunks.extend(str(k) for k in event.keys())
            chunks.extend(str(v) for v in event.values())
        elif hasattr(event, "to_dict"):
            data = event.to_dict()
            chunks.extend(str(k) for k in data.keys())
            chunks.extend(str(v) for v in data.values())
        else:
            chunks.append(str(event))
    return "\n".join(chunks).lower()


def _score(text: str, signals: dict[str, float]) -> tuple[float, list[str]]:
    score = 0.0
    hits: list[str] = []
    for signal, weight in signals.items():
        if signal.lower() in text:
            score += weight
            hits.append(signal)
    return score, hits


def classify_dashboard_profile(
    base_profile: dict[str, str],
    events: Iterable[Any] | None = None,
    raw_text: str = "",
) -> ProfileDecision:
    """Select the analyst-facing dashboard from the actual uploaded evidence.

    Parser detection answers "how can I read this file?".
    Semantic classification answers "what kind of security evidence is this?".
    The latter is deterministic and never calls an LLM.
    """
    text = f"{raw_text}\n{_event_text(events)}".lower()

    profile_signals = (
        ("authentication_ssh", AUTH_SIGNALS),
        ("sysmon_json", SYSMON_SIGNALS),
        ("web_server", WEB_SIGNALS),
        ("firewall_network", FIREWALL_SIGNALS),
        ("dns", DNS_SIGNALS),
    )

    scores: dict[str, float] = {}
    hits: dict[str, list[str]] = {}
    for profile_id, signals in profile_signals:
        score, matched = _score(text, signals)
        scores[profile_id] = score
        hits[profile_id] = matched

    base_id = base_profile.get("id", "generic_text")

    # Strong structural profiles are never reclassified by generic text
    # keywords. This prevents a Sysmon export containing "http" or "source_ip"
    # from accidentally becoming a Web/Firewall dashboard.
    if base_id == "sysmon_json":
        selected = "sysmon_json"
    elif base_id == "windows_json":
        selected = "windows_json"
    else:
        ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
        selected = base_id

        if ranked:
            best_id, best_score = ranked[0]
            second_score = ranked[1][1] if len(ranked) > 1 else 0.0
            best_hits = hits.get(best_id, [])

            # Require both a minimum score and enough independent indicators.
            # Authentication is deliberately stricter because ordinary logs
            # often contain the word "user" or "login" without being SSH logs.
            thresholds = {
                "authentication_ssh": (9.0, 3),
                "web_server": (8.0, 2),
                "firewall_network": (8.0, 2),
                "dns": (8.0, 2),
                "sysmon_json": (8.0, 2),
            }
            min_score, min_hits = thresholds.get(best_id, (999.0, 99))

            # A small score lead is required so one generic keyword does not
            # decide the dashboard when two profiles are plausible.
            margin_ok = best_score >= second_score + 2.0
            if best_score >= min_score and len(best_hits) >= min_hits and margin_ok:
                selected = best_id

    profile_info = {
        "authentication_ssh": ("Authentication / SSH", "syslog"),
        "sysmon_json": ("Windows Sysmon JSON", "json"),
        "windows_json": ("Windows Event JSON", "json"),
        "web_server": ("Web Server", base_profile.get("parser", "syslog")),
        "firewall_network": ("Firewall / Network", base_profile.get("parser", "syslog")),
        "dns": ("DNS", base_profile.get("parser", "syslog")),
        "generic_json": ("Generic JSON", "json"),
        "generic_text": ("Generic Text Log", "syslog"),
        "syslog": ("Syslog / Linux Audit", "syslog"),
    }
    name, _parser = profile_info.get(
        selected,
        (base_profile.get("name", "Generic Text Log"), base_profile.get("parser", "syslog")),
    )

    # Confidence reflects evidence strength, not a probabilistic ML model.
    selected_score = scores.get(selected, 0.0)
    if selected in {"sysmon_json", "windows_json"} and base_id == selected:
        confidence = 0.99
    elif selected_score:
        confidence = min(0.99, 0.50 + selected_score / 30.0)
    else:
        confidence = 0.50

    return ProfileDecision(
        profile_id=selected,
        name=name,
        confidence=round(confidence, 2),
        scores={k: round(v, 2) for k, v in scores.items()},
        matched_signals=hits.get(selected, []),
    )
