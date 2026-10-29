"""Alerts as a JSON document and a markdown incident summary. The suggested
response sections are advisory text for a human analyst: authtriage never
blocks, never edits firewall state, never touches accounts.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Sequence

from .detectors import Alert

SCHEMA_VERSION = "1.0"

RESPONSES: Dict[str, List[str]] = {
    "brute_force": [
        "Confirm the source is not a misconfigured internal host, monitoring agent or VPN exit before acting.",
        "Check whether any attempt from this IP succeeded; if one did, work the success_after_failures alert first.",
        "Rate-limit or block the source at the network edge through your change process, and confirm password auth is disabled for the targeted accounts.",
    ],
    "user_enumeration": [
        "Treat the username list as reconnaissance output, not as a list of real accounts.",
        "Cross-check whether any attempted name matches a real local or directory account, which raises the priority.",
        "Look for the same source IP in other services' logs; enumeration is usually part of a wider sweep.",
    ],
    "success_after_failures": [
        "Escalate first. A success following a failure run is the highest-value signal in this report.",
        "Identify the session: subsequent sudo use, new authorized_keys entries, cron or systemd changes, outbound connections.",
        "Contact the account owner out of band; if the login is unconfirmed, rotate the credential and revoke sessions per your incident process.",
    ],
}

_EMPTY = ("No activity crossed the configured thresholds. That is not proof of absence: check "
          "the log covers the period you care about and that thresholds match this baseline.")


def build_report(alerts: Sequence[Alert], source: str, config: Dict[str, Any],
                 event_count: int) -> Dict[str, Any]:
    counts = Counter(alert.severity for alert in alerts)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": source,
        "events_parsed": event_count,
        "alert_count": len(alerts),
        "severity_counts": dict(counts),
        "config": config,
        "alerts": [alert.to_dict() for alert in alerts],
    }


def to_markdown(report: Dict[str, Any]) -> str:
    alerts = report["alerts"]
    out = [f"# SSH auth triage: `{report['source']}`", "",
           f"Generated {report['generated_at']} | {report['events_parsed']} events parsed "
           f"| {report['alert_count']} alert(s)", "", "## Summary", ""]
    if not alerts:
        return "\n".join(out + [_EMPTY, ""])

    out += ["| # | Severity | Rule | Source IP | Observed | Threshold | First seen |",
            "|---|---|---|---|---|---|---|"]
    out += [f"| {i} | {a['severity'].upper()} | {a['rule']} | {a['source_ip']} | "
            f"{a['observed']} | {a['threshold']} | {a['first_seen']} |"
            for i, a in enumerate(alerts, 1)]
    out += ["", "## Alerts"]
    for index, alert in enumerate(alerts, 1):
        out += [
            "", f"### {index}. {alert['rule']} from {alert['source_ip']} "
                f"[{alert['severity'].upper()}]",
            "", alert["description"], "",
            f"- Window: {alert['first_seen']} to {alert['last_seen']} "
            f"({alert['window_seconds']}s rule window)",
            f"- Usernames: {', '.join(alert['usernames']) or 'none recorded'}",
            "", "Evidence:", "", "```", *alert["evidence"], "```", "",
            "Suggested response (text only, nothing is executed by this tool):", "",
        ]
        out += [f"{n}. {text}" for n, text in enumerate(RESPONSES.get(alert["rule"], []), 1)]
    return "\n".join(out + [""])
