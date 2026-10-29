import json
from datetime import datetime, timedelta

import pytest

from authtriage import build_report, detect, load_config, parse_lines, to_markdown
from authtriage.cli import main

START = datetime(2026, 10, 29, 10, 0, 0)


def line(offset, message, pid=1):
    ts = (START + timedelta(seconds=offset)).strftime("%b %d %H:%M:%S")
    return f"{ts} web-01 sshd[{pid}]: {message}"


def failures(count, ip="203.0.113.5", user="root", step=5, start=0):
    return [line(start + i * step, f"Failed password for {user} from {ip} port {4000 + i} ssh2")
            for i in range(count)]


def invalids(users, ip="203.0.113.77", step=10, start=0):
    out = []
    for i, user in enumerate(users):
        out.append(line(start + i * step, f"Invalid user {user} from {ip} port {3000 + i}"))
        out.append(line(start + i * step + 1,
                        f"Failed password for invalid user {user} from {ip} port {3000 + i} ssh2"))
    return out


def run(lines, **overrides):
    config = load_config(None, **overrides)
    return detect(list(parse_lines(lines, year=2026)), config)


def test_brute_force_fires_at_threshold():
    alerts = run(failures(8))
    assert [a.rule for a in alerts] == ["brute_force"]
    assert alerts[0].source_ip == "203.0.113.5"
    assert alerts[0].observed == 8
    assert alerts[0].usernames == ["root"]


def test_brute_force_silent_one_below_threshold():
    assert run(failures(7)) == []


def test_brute_force_silent_when_spread_past_the_window():
    # 10 failures at 40s apart: never more than 4 inside the 120s window.
    assert run(failures(10, step=40)) == []


def test_one_alert_per_burst_not_per_event():
    alerts = run(failures(30, step=2))
    assert len(alerts) == 1 and alerts[0].observed == 30


def test_two_separated_bursts_give_two_alerts():
    alerts = run(failures(8, start=0) + failures(8, start=5000))
    assert len(alerts) == 2


def test_severity_escalates_with_volume():
    assert run(failures(8))[0].severity == "medium"
    assert run(failures(16, step=2))[0].severity == "high"
    assert run(failures(30, step=2))[0].severity == "critical"


def test_pam_and_preauth_lines_do_not_inflate_the_count():
    # One real attempt emits three lines. Only the canonical one is counted,
    # so 7 attempts must stay below the threshold of 8.
    lines = []
    for i in range(7):
        offset = i * 5
        lines += [
            line(offset, "pam_unix(sshd:auth): authentication failure; logname= uid=0 "
                         "euid=0 tty=ssh ruser= rhost=203.0.113.5  user=root", pid=100 + i),
            line(offset, "Failed password for root from 203.0.113.5 port 44001 ssh2", pid=100 + i),
            line(offset + 1, "Connection closed by authenticating user root 203.0.113.5 "
                             "port 44001 [preauth]", pid=100 + i),
        ]
    assert run(lines) == []
    # Opting pam lines in doubles the count and crosses the threshold.
    assert run(lines, failure_kinds=["failed_password", "pam_failure"])[0].rule == "brute_force"


def test_user_enumeration_counts_distinct_users_only():
    repeats = invalids(["oracle"] * 7)  # one username, below the brute force threshold
    assert run(repeats) == []
    distinct = invalids(["oracle", "postgres", "ubuntu", "test", "deploy"])
    rules = [a.rule for a in run(distinct)]
    assert "user_enumeration" in rules
    assert run(distinct)[0].observed == 5


def test_enumeration_fires_without_brute_force_when_volume_is_low():
    alerts = run(invalids(["a", "b", "c", "d", "e", "f", "g"], step=25))
    assert [a.rule for a in alerts] == ["user_enumeration"]


def test_success_after_failures():
    lines = failures(5, ip="192.0.2.44", user="backup", step=30)
    lines.append(line(200, "Accepted password for backup from 192.0.2.44 port 22110 ssh2"))
    alerts = run(lines)
    assert [a.rule for a in alerts] == ["success_after_failures"]
    assert alerts[0].severity == "high"
    assert "backup" in alerts[0].usernames
    assert alerts[0].evidence[-1].endswith("Accepted password for backup from 192.0.2.44 port 22110 ssh2")


def test_success_after_failures_ignores_stale_failures():
    lines = failures(5, ip="192.0.2.44", user="backup", step=30)
    lines.append(line(10_000, "Accepted password for backup from 192.0.2.44 port 22110 ssh2"))
    assert run(lines) == []


def test_success_from_a_different_ip_does_not_trigger():
    lines = failures(6, ip="192.0.2.44", step=30)
    lines.append(line(200, "Accepted password for alice from 198.51.100.9 port 1 ssh2"))
    assert run(lines) == []


def test_ignore_ips_suppresses_everything_from_that_source():
    assert run(failures(20, step=2), ignore_ips=["203.0.113.5"]) == []


def test_thresholds_are_configurable():
    assert run(failures(4), **{"brute_force.min_failures": 3})[0].observed == 4


def test_evidence_is_capped_and_elided():
    alert = run(failures(30, step=2))[0]
    assert len(alert.evidence) == 6
    assert "further lines omitted" in alert.evidence[3]
    assert alert.evidence[0].startswith("L1:") and alert.evidence[-1].startswith("L30:")


def test_config_rejects_bad_values():
    with pytest.raises(ValueError):
        load_config(None, **{"brute_force.min_failures": 0})
    with pytest.raises(ValueError):
        load_config(None, **{"nonexistent": 1})


def test_report_json_and_markdown():
    alerts = run(failures(10, step=2))
    report = build_report(alerts, "auth.log", load_config(None), event_count=10)
    assert json.loads(json.dumps(report))["alert_count"] == 1
    markdown = to_markdown(report)
    assert "# SSH auth triage" in markdown
    assert "Suggested response" in markdown
    assert "203.0.113.5" in markdown
    assert "\u2014" not in markdown


def test_markdown_when_nothing_fires():
    markdown = to_markdown(build_report([], "auth.log", load_config(None), 3))
    assert "No activity crossed the configured thresholds" in markdown


def test_cli_end_to_end(tmp_path, capsys):
    log = tmp_path / "auth.log"
    log.write_text("\n".join(failures(12, step=2)) + "\n", encoding="utf-8")
    json_out, md_out = tmp_path / "out.json", tmp_path / "out.md"
    code = main([str(log), "--year", "2026", "--json-out", str(json_out),
                 "--md-out", str(md_out), "--fail-on-alert"])
    assert code == 2
    report = json.loads(json_out.read_text(encoding="utf-8"))
    assert report["alert_count"] == 1 and report["events_parsed"] == 12
    assert "brute_force" in md_out.read_text(encoding="utf-8")
    assert "alert(s)" in capsys.readouterr().out


def test_cli_clean_log_exits_zero(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("\n".join(failures(2)) + "\n", encoding="utf-8")
    assert main([str(log), "--year", "2026", "--json-out", str(tmp_path / "o.json"),
                 "--quiet", "--fail-on-alert"]) == 0
