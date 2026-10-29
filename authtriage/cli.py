"""authtriage command line interface."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import load_config
from .detectors import SEVERITY_ORDER, detect
from .parser import parse_lines
from .report import build_report, to_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="authtriage", description=(
        "Triage sshd auth logs for brute force, user enumeration and successful "
        "logins that follow a failure run."))
    add = parser.add_argument
    add("logfile", nargs="?", help="path to the auth log, or - for stdin")
    add("-c", "--config", help="JSON config file overriding thresholds")
    add("--json-out", help="write the JSON report here (default: stdout)")
    add("--md-out", help="write the markdown incident summary here")
    add("--min-severity", choices=SEVERITY_ORDER, default="info", help="drop alerts below this")
    add("--year", type=int, help="year for syslog timestamps, which omit it (default: now)")
    add("--brute-failures", type=int, help="override brute_force.min_failures")
    add("--brute-window", type=int, help="override brute_force.window_seconds")
    add("--enum-users", type=int, help="override user_enumeration.min_distinct_users")
    add("--ignore-ip", action="append", default=None, help="source IP to skip; repeatable")
    add("--fail-on-alert", action="store_true", help="exit 2 when any alert is reported")
    add("--print-config", action="store_true", help="print the effective config and exit")
    add("-q", "--quiet", action="store_true", help="suppress the console summary")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(
            args.config,
            **{"brute_force.min_failures": args.brute_failures,
               "brute_force.window_seconds": args.brute_window,
               "user_enumeration.min_distinct_users": args.enum_users,
               "ignore_ips": args.ignore_ip})
    except (ValueError, OSError, json.JSONDecodeError) as error:
        print(f"authtriage: config error: {error}", file=sys.stderr)
        return 1

    if args.print_config:
        print(json.dumps(config, indent=2))
        return 0
    if not args.logfile:
        print("authtriage: a logfile (or -) is required", file=sys.stderr)
        return 1
    source = "<stdin>" if args.logfile == "-" else args.logfile
    try:
        handle = sys.stdin if args.logfile == "-" else open(
            source, "r", encoding="utf-8", errors="replace")
    except OSError as error:
        print(f"authtriage: cannot read {source}: {error}", file=sys.stderr)
        return 1
    with handle:
        events = list(parse_lines(handle, year=args.year))

    floor = SEVERITY_ORDER.index(args.min_severity)
    alerts = [a for a in detect(events, config) if a.severity_rank >= floor]
    report = build_report(alerts, source, config, len(events))
    payload = json.dumps(report, indent=2)
    if args.json_out:
        Path(args.json_out).write_text(payload + "\n", encoding="utf-8")
    if args.md_out:
        Path(args.md_out).write_text(to_markdown(report), encoding="utf-8")
    if not (args.json_out or args.md_out):
        print(payload)
    elif not args.quiet:
        counts = ", ".join(f"{k}={v}" for k, v in report["severity_counts"].items()) or "none"
        print(f"{len(events)} events parsed, {len(alerts)} alert(s) [{counts}]")

    return 2 if (alerts and args.fail_on_alert) else 0


if __name__ == "__main__":
    raise SystemExit(main())
