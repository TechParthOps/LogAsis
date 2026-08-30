from __future__ import annotations

from typing import Any, Dict, Iterable, Optional
import pandas as pd


COLUMNS = [
    "timestamp", "event_type", "source_ip", "destination_ip", "username",
    "process_name", "command", "pid", "ppid", "uid", "euid", "auid", "audit_serial", "action", "severity", "message", "line", "raw_log"
]


def events_to_dataframe(events: Iterable[Any]) -> pd.DataFrame:
    rows = []
    for event in events:
        if hasattr(event, "to_dict"):
            rows.append(event.to_dict())
        elif isinstance(event, dict):
            rows.append(event)
        else:
            rows.append(vars(event))

    df = pd.DataFrame(rows)
    for col in COLUMNS:
        if col not in df.columns:
            df[col] = ""

    # IMPORTANT: timestamp stays a column. Never use df.index.dt.
    df["timestamp_dt"] = pd.to_datetime(
        df["timestamp"].astype(str),
        errors="coerce",
        format="mixed",
    )

    # Support "Aug 15 10:01:01" timestamps by attaching the current year.
    missing_year = df["timestamp_dt"].isna() & df["timestamp"].astype(str).str.len().gt(0)
    if missing_year.any():
        current_year = pd.Timestamp.now().year
        repaired = pd.to_datetime(
            df.loc[missing_year, "timestamp"].astype(str).map(
                lambda x: f"{current_year} {x}"
            ),
            errors="coerce",
            format="mixed",
        )
        df.loc[missing_year, "timestamp_dt"] = repaired

    df["hour"] = df["timestamp_dt"].dt.hour
    df["date"] = df["timestamp_dt"].dt.date.astype("string")

    # Preserve source-specific fields (for example Sysmon EventID, Image,
    # ParentImage, DestinationPort and Hashes). The normalized COLUMNS remain
    # first so existing analytics/AI code keeps the same schema.
    extra_columns = [
        col for col in df.columns
        if col not in COLUMNS + ["timestamp_dt", "hour", "date"]
    ]
    return df[COLUMNS + extra_columns + ["timestamp_dt", "hour", "date"]]


def apply_filters(
    df: pd.DataFrame,
    field: str = "All",
    value: str = "",
) -> pd.DataFrame:
    if df.empty or not value.strip():
        return df.copy()

    value = value.strip().lower()

    if field == "All":
        mask = pd.Series(False, index=df.index)
        searchable_columns = [
            col for col in df.columns
            if col not in {"timestamp_dt", "hour", "date", "raw_log"}
            and not str(col).startswith("_")
        ]
        for col in searchable_columns:
            mask |= df[col].fillna("").astype(str).str.lower().str.contains(
                value, regex=False
            )
        return df[mask]

    if field not in df.columns:
        return df.copy()

    return df[
        df[field].fillna("").astype(str).str.lower().str.contains(
            value, regex=False
        )
    ]


def summary(df: pd.DataFrame) -> Dict[str, Any]:
    if df.empty:
        return {
            "total_events": 0,
            "unique_ips": 0,
            "unique_users": 0,
            "failed_logins": 0,
            "successful_logins": 0,
            "high_critical": 0,
        }

    ips = _column_values(df, "source_ip").nunique()
    users = _column_values(df, "username").nunique()
    actions = df["action"] if "action" in df.columns else pd.Series(dtype="string")
    severity = df["severity"] if "severity" in df.columns else pd.Series(dtype="string")

    return {
        "total_events": len(df),
        "unique_ips": int(ips),
        "unique_users": int(users),
        "failed_logins": int((actions == "failed_login").sum()),
        "successful_logins": int((actions == "successful_login").sum()),
        "high_critical": int(severity.isin(["high", "critical"]).sum()),
    }


def _column_values(df: pd.DataFrame, column: str) -> pd.Series:
    """Return a safe string Series even when df is empty/uninitialized.

    Qt can refresh a tab before a log has been loaded. In that state pandas may
    contain a completely empty DataFrame with a RangeIndex and no columns.
    Analytics must treat that as "no data", not as a schema error.
    """
    if column not in df.columns:
        return pd.Series(dtype="string")
    return df[column].replace("", pd.NA).dropna()


def top_source_ips(df: pd.DataFrame, limit: int = 10) -> pd.Series:
    values = _column_values(df, "source_ip")
    return values.value_counts().head(limit)


def top_users(df: pd.DataFrame, limit: int = 10) -> pd.Series:
    values = _column_values(df, "username")
    return values.value_counts().head(limit)


def events_by_hour(df: pd.DataFrame) -> pd.Series:
    if df.empty:
        return pd.Series(dtype="int64")

    # Correct pandas usage: hour is already a Series derived from timestamp_dt.
    return df.dropna(subset=["timestamp_dt"]).groupby("hour").size().sort_index()


def peak_hour(df: pd.DataFrame) -> Optional[int]:
    counts = events_by_hour(df)
    if counts.empty:
        return None
    return int(counts.idxmax())


def authentication_activity(df: pd.DataFrame) -> Dict[str, int]:
    return {
        "failed": int((df["action"] == "failed_login").sum()),
        "successful": int((df["action"] == "successful_login").sum()),
    }


def _auth_sequence_events(df: pd.DataFrame) -> pd.DataFrame:
    """Return authentication events in defensible chronological/log order."""
    if df.empty or "action" not in df.columns:
        return df.iloc[0:0].copy()

    auth = df[df["action"].isin(["failed_login", "successful_login"])].copy()
    if auth.empty:
        return auth

    # timestamp_dt is preferred when valid; original line order is the fallback.
    if "timestamp_dt" in auth.columns and auth["timestamp_dt"].notna().any():
        auth["_order_time"] = auth["timestamp_dt"]
        auth["_order_line"] = pd.to_numeric(auth.get("line", 0), errors="coerce").fillna(0)
        auth = auth.sort_values(["_order_time", "_order_line"], kind="stable")
    else:
        auth = auth.sort_values("line", kind="stable")
    return auth


def authentication_sequences(df: pd.DataFrame) -> list[dict[str, Any]]:
    """Find failed->successful authentication sequences using actual event order."""
    auth = _auth_sequence_events(df)
    if auth.empty:
        return []

    sequences = []
    for ip in auth["source_ip"].replace("", pd.NA).dropna().unique():
        sub = auth[auth["source_ip"] == ip].copy()
        failures = sub[sub["action"] == "failed_login"]
        successes = sub[sub["action"] == "successful_login"]
        if failures.empty or successes.empty:
            continue

        # A sequence exists only when a failure occurs before a success.
        for _, success in successes.iterrows():
            # Compare using the sorted row positions rather than raw DataFrame order.
            success_pos = sub.index.get_loc(success.name)
            prior_failures = sub.iloc[:success_pos]
            prior_failures = prior_failures[prior_failures["action"] == "failed_login"]
            if prior_failures.empty:
                continue

            first_failure = prior_failures.iloc[-1]
            sequences.append({
                "source_ip": str(ip),
                "username": str(success.get("username", "") or ""),
                "failed_line": int(first_failure.get("line", 0) or 0),
                "successful_line": int(success.get("line", 0) or 0),
                "failed_time": str(first_failure.get("timestamp", "") or ""),
                "successful_time": str(success.get("timestamp", "") or ""),
                "failed_count_before_success": int(len(prior_failures)),
                "description": (
                    f"{len(prior_failures)} failed authentication event(s) "
                    f"preceded a successful authentication from the same source IP."
                ),
            })
            break
    return sequences


def command_statistics(df: pd.DataFrame) -> dict[str, Any]:
    if df.empty or "action" not in df.columns:
        return {"count": 0, "unique_count": 0, "commands": [], "processes": []}

    rows = df[df["action"] == "command_exec"].copy()
    commands = []
    processes = []

    if "command" in rows.columns:
        for _, row in rows.iterrows():
            command = str(row.get("command", "") or "").strip()
            if command:
                commands.append({
                    "line": int(row.get("line", 0) or 0),
                    "command": command,
                    "process": str(row.get("process_name", "") or ""),
                })

    if "process_name" in rows.columns:
        counts = rows["process_name"].replace("", pd.NA).dropna().value_counts()
        processes = [{"process": str(k), "events": int(v)} for k, v in counts.items()]

    unique_commands = {item["command"] for item in commands if item.get("command")}
    return {"count": int(len(rows)), "unique_count": int(len(unique_commands)), "commands": commands, "processes": processes}


def investigation_candidates(df: pd.DataFrame) -> Dict[str, Any]:
    """Deterministic evidence extraction used by the AI layer."""
    result: Dict[str, Any] = {
        "candidate_ips": [],
        "candidate_users": [],
        "suspicious_sequences": authentication_sequences(df),
    }

    if df.empty:
        return result

    auth = df[df["action"].isin(["failed_login", "successful_login"])].copy()

    if not auth.empty:
        ip_counts = auth["source_ip"].replace("", pd.NA).dropna().value_counts()
        result["candidate_ips"] = [
            {
                "ip": str(ip),
                "events": int(count),
                "failed": int(
                    ((auth["source_ip"] == ip) & (auth["action"] == "failed_login")).sum()
                ),
                "successful": int(
                    ((auth["source_ip"] == ip) & (auth["action"] == "successful_login")).sum()
                ),
            }
            for ip, count in ip_counts.head(10).items()
        ]

        user_counts = auth["username"].replace("", pd.NA).dropna().value_counts()
        result["candidate_users"] = [
            {"username": str(user), "events": int(count)}
            for user, count in user_counts.head(10).items()
        ]

    return result
