#!/usr/bin/env python3
"""Score authtriage against the hand-labelled sample.

Match key is (rule, source_ip). Run it after any threshold or rule change:
precision tells you whether you are about to drown an analyst in noise,
recall tells you what you stopped catching.

    python eval/evaluate.py [--labels eval/labels.json] [--min-f1 1.0]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from authtriage import detect, load_config, parse_file  # noqa: E402


def score(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return precision, recall, f1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labels", default=str(Path(__file__).parent / "labels.json"))
    parser.add_argument("--min-f1", type=float, default=1.0,
                        help="fail if overall F1 drops below this")
    args = parser.parse_args()

    labels_path = Path(args.labels)
    labels = json.loads(labels_path.read_text(encoding="utf-8"))
    log_path = labels_path.parent / labels["log"]
    config = load_config(labels.get("config"))

    events = parse_file(str(log_path), year=2026)
    alerts = detect(events, config)

    expected = {(item["rule"], item["source_ip"]) for item in labels["expected"]}
    actual = {(alert.rule, alert.source_ip) for alert in alerts}
    rules = sorted({rule for rule, _ in expected | actual})

    print(f"log: {log_path.name}  events parsed: {len(events)}  alerts: {len(alerts)}\n")
    print(f"{'rule':<24}{'TP':>4}{'FP':>4}{'FN':>4}{'prec':>8}{'rec':>8}{'F1':>8}")
    print("-" * 60)

    totals = [0, 0, 0]
    for rule in rules:
        exp = {key for key in expected if key[0] == rule}
        act = {key for key in actual if key[0] == rule}
        tp, fp, fn = len(exp & act), len(act - exp), len(exp - act)
        totals = [totals[0] + tp, totals[1] + fp, totals[2] + fn]
        precision, recall, f1 = score(tp, fp, fn)
        print(f"{rule:<24}{tp:>4}{fp:>4}{fn:>4}{precision:>8.2f}{recall:>8.2f}{f1:>8.2f}")

    precision, recall, f1 = score(*totals)
    print("-" * 60)
    print(f"{'OVERALL':<24}{totals[0]:>4}{totals[1]:>4}{totals[2]:>4}"
          f"{precision:>8.2f}{recall:>8.2f}{f1:>8.2f}")

    for key in sorted(actual - expected):
        print(f"\nFALSE POSITIVE: {key[0]} on {key[1]}")
    for key in sorted(expected - actual):
        print(f"\nMISSED: {key[0]} on {key[1]}")

    benign = {item["source_ip"] for item in labels.get("known_benign", [])}
    noisy = sorted(ip for _, ip in actual if ip in benign)
    if noisy:
        print(f"\nAlerted on IPs labelled benign: {', '.join(noisy)}")

    if f1 < args.min_f1:
        print(f"\nFAIL: overall F1 {f1:.2f} below required {args.min_f1:.2f}")
        return 1
    print(f"\nPASS: overall F1 {f1:.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
