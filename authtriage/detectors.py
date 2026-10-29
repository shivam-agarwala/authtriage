"""The three detection rules.

Sliding windows, not fixed buckets: bucketing splits an attack that straddles a
boundary and halves it. Overlapping hits merge into one burst per attack.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Sequence

from .parser import Event

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


@dataclass
class Alert:
    rule: str
    severity: str
    source_ip: str
    usernames: List[str]
    first_seen: str
    last_seen: str
    observed: int
    threshold: int
    window_seconds: int
    description: str
    evidence: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.index(self.severity)


def _escalate(base: str, observed: int, threshold: int) -> str:
    """Bump severity when volume runs well past the threshold."""
    ratio = observed / threshold
    index = SEVERITY_ORDER.index(base) + (2 if ratio >= 3 else 1 if ratio >= 1.75 else 0)
    return SEVERITY_ORDER[min(index, len(SEVERITY_ORDER) - 1)]


def _evidence(events: Sequence[Event], cap: int) -> List[str]:
    """Line-numbered raw log lines; long bursts are elided in the middle."""
    if len(events) <= cap or cap < 4:
        return [f"L{e.line_no}: {e.raw}" for e in events[:cap]]
    head, tail = cap - 3, 2  # the elision line itself counts against the cap
    lines = [f"L{e.line_no}: {e.raw}" for e in list(events[:head]) + list(events[-tail:])]
    lines.insert(head, f"... {len(events) - head - tail} further lines omitted ...")
    return lines


def _bursts(events: Sequence[Event], threshold: int, window: int,
            distinct: bool = False) -> List[Sequence[Event]]:
    """Index ranges where `window` seconds hold >= threshold events.

    distinct=True counts unique usernames instead of raw events, which is what
    separates enumeration from a password spray against one account.
    """
    out: List[List[int]] = []
    current: List[int] | None = None
    seen, start = Counter(), 0
    for index, event in enumerate(events):
        seen[event.user] += 1
        while (event.ts - events[start].ts).total_seconds() > window:
            seen[events[start].user] -= 1
            if seen[events[start].user] <= 0:
                del seen[events[start].user]
            start += 1
        if (len(seen) if distinct else index - start + 1) >= threshold:
            # start <= current[1] means the windows overlap, so it is the same
            # burst. Merely adjacent indices hours apart are two separate bursts.
            if current and start <= current[1]:
                current[1] = index
            else:
                if current:
                    out.append(current)
                current = [start, index]
    if current:
        out.append(current)
    return [events[a:b + 1] for a, b in out]


def _users(events: Sequence[Event]) -> List[str]:
    return sorted({e.user for e in events if e.user})


def _span(events: Sequence[Event]) -> int:
    return int((events[-1].ts - events[0].ts).total_seconds())


def _make(rule, severity, ip, events, observed, threshold, window, description, cap) -> Alert:
    return Alert(
        rule=rule, severity=_escalate(severity, observed, threshold), source_ip=ip,
        usernames=_users(events), first_seen=events[0].ts.isoformat(sep=" "),
        last_seen=events[-1].ts.isoformat(sep=" "), observed=observed, threshold=threshold,
        window_seconds=window, description=description, evidence=_evidence(events, cap))


def detect(events: Sequence[Event], config: Dict[str, Any]) -> List[Alert]:
    """Run every rule; alerts come back sorted by severity, then time."""
    cap, ignored = config["max_evidence_lines"], set(config["ignore_ips"])
    failure_kinds = set(config["failure_kinds"])
    brute, enum = config["brute_force"], config["user_enumeration"]
    after = config["success_after_failures"]
    by_ip: Dict[str, List[Event]] = defaultdict(list)
    for event in events:
        if event.ip and event.ip not in ignored:
            by_ip[event.ip].append(event)

    alerts: List[Alert] = []
    for ip, bucket in by_ip.items():  # one IP at a time; rules never cross sources
        bucket.sort(key=lambda e: (e.ts, e.line_no))
        failures = [e for e in bucket if e.kind in failure_kinds]
        invalids = [e for e in bucket if e.kind == "invalid_user" and e.user]
        # Rule 1: many failed logins from one IP inside the window.
        for burst in _bursts(failures, brute["min_failures"], brute["window_seconds"]):
            alerts.append(_make(
                "brute_force", "medium", ip, burst, len(burst), brute["min_failures"],
                brute["window_seconds"],
                f"{len(burst)} failed SSH authentications from {ip} over {_span(burst)}s "
                f"(threshold {brute['min_failures']} in {brute['window_seconds']}s), "
                f"targeting {len(_users(burst))} account(s).", cap))
        # Rule 2: repeated attempts against accounts that do not exist.
        for burst in _bursts(invalids, enum["min_distinct_users"],
                             enum["window_seconds"], distinct=True):
            distinct = len(_users(burst))
            alerts.append(_make(
                "user_enumeration", "medium", ip, burst, distinct,
                enum["min_distinct_users"], enum["window_seconds"],
                f"{distinct} distinct non-existent usernames from {ip} over {_span(burst)}s "
                f"(threshold {enum['min_distinct_users']} in {enum['window_seconds']}s). "
                f"Consistent with account discovery.", cap))
        # Rule 3: a success from an IP that was failing moments earlier.
        for success in (e for e in bucket if e.kind == "accepted"):
            window = after["lookback_seconds"]
            prior = [e for e in failures if 0 <= (success.ts - e.ts).total_seconds() <= window]
            if len(prior) < after["min_failures"]:
                continue
            alerts.append(_make(
                "success_after_failures", "high", ip, prior + [success], len(prior),
                after["min_failures"], window,
                f"Successful login as '{success.user}' from {ip} after {len(prior)} failed "
                f"attempts in the preceding {window}s. Treat as a possible credential "
                f"compromise until the account owner confirms otherwise.", cap))

    alerts.sort(key=lambda a: (-a.severity_rank, a.first_seen, a.rule))
    return alerts
