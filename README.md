# authtriage

A small Python CLI that reads Linux `sshd` authentication logs and reports three
things an on-call engineer actually cares about: brute force bursts, username
enumeration, and a successful login that lands right after a run of failures.

Output is a JSON alert document for pipelines and a markdown incident summary for
humans. The summary includes a suggested response, which is advisory text only.
**authtriage reads logs. It does not block, firewall, disable accounts or run any
remediation.**

Standard library only. No runtime dependencies.

## Install

```bash
git clone <your-fork> && cd authtriage
pip install -e ".[dev]"      # dev extras are pytest and ruff
```

## Usage

```bash
# JSON to stdout
authtriage /var/log/auth.log

# both artefacts on disk
authtriage /var/log/auth.log --json-out report.json --md-out report.md

# tighter thresholds, ignore a known scanner, read from a pipe
zcat /var/log/auth.log.1.gz | authtriage - --brute-failures 5 --ignore-ip 10.0.0.9

# only show me the bad news
authtriage /var/log/auth.log --min-severity high

# effective config after file and flag overrides
authtriage --print-config -c config.example.json
```

Exit codes: `0` normal, `1` on a config or IO error, `2` when alerts were found
and `--fail-on-alert` was passed.

## Rules

| Rule | Fires when | Default | Base severity |
|---|---|---|---|
| `brute_force` | failures from one IP inside a sliding window | 8 in 120s | medium |
| `user_enumeration` | distinct non-existent usernames from one IP | 5 in 300s | medium |
| `success_after_failures` | an `Accepted` line preceded by failures from the same IP | 5 in 600s | high |

Severity escalates one level at 1.75x the threshold and two at 3x, so a 40-failure
flood reports as critical while a 9-failure one does not.

### Two design decisions worth knowing

**Sliding windows, not fixed buckets.** Bucketing by minute splits an attack that
straddles a boundary and can halve the observed count, which is exactly how a
burst slips under a threshold. Every rule scans a window that moves with the
events. Overlapping window hits are merged, so a 50-failure run produces one alert
with `observed: 50`, not 43 near-identical alerts.

**One attempt is counted once.** A single failed password typically writes three
lines:

```
pam_unix(sshd:auth): authentication failure; ... rhost=203.0.113.5  user=root
Failed password for root from 203.0.113.5 port 44001 ssh2
Connection closed by authenticating user root 203.0.113.5 port 44001 [preauth]
```

Counting all three inflates every rate by roughly 3x and makes thresholds
meaningless. Only `failed_password` counts by default; the rest are parsed and
retained as evidence. Change this with `failure_kinds` if your distribution logs
differently.

## Configuration

Precedence is CLI flags, then the JSON file, then the built-in defaults. Unknown
keys and non-positive thresholds are rejected at load time rather than producing a
detector that alerts on silence.

```bash
cp config.example.json my.json
authtriage /var/log/auth.log -c my.json
```

| Key | Meaning |
|---|---|
| `brute_force.min_failures` / `.window_seconds` | rule 1 threshold and window |
| `user_enumeration.min_distinct_users` / `.window_seconds` | rule 2 threshold and window |
| `success_after_failures.min_failures` / `.lookback_seconds` | rule 3 threshold and lookback |
| `failure_kinds` | which parsed event kinds count as a failure |
| `max_evidence_lines` | evidence lines per alert, elided in the middle when longer |
| `ignore_ips` | sources to skip entirely, such as your jump host or CI runner |

## Log formats

Both of these parse, including the space-padded single-digit day and a year
rollover from December to January:

```
Oct 29 10:11:12 web-01 sshd[4001]: Failed password for root from 203.0.113.5 port 44001 ssh2
2026-10-29T10:11:12+05:30 web-01 sshd[4001]: Accepted password for alice from 198.51.100.9 port 1 ssh2
```

Traditional syslog has no year, so pass `--year` when triaging an old file.
Offsets on ISO timestamps are normalised to UTC. Non-sshd lines and lines that
match no known message are skipped silently, because an auth log is a shared file
and unrelated noise is normal rather than an error.

## Tests and evaluation

```bash
pytest -q                  # 30 unit tests over synthetic logs
python eval/evaluate.py    # detection quality against a hand-labelled sample
```

The unit tests cover both directions: that each rule fires at its threshold, and
that it stays silent one attempt below it, when the same volume is spread past the
window, and when the three lines of a single attempt could be double counted.

`eval/sample_auth.log` is hand-labelled in `eval/labels.json`. The evaluation
matches each detection on `(rule, source_ip)` and reports precision, recall and F1
per rule. The sample is built to punish the specific ways this tool could be
wrong:

| Source | Shape | Must produce |
|---|---|---|
| 203.0.113.5 | 12 root failures in 88s, each with pam and preauth lines | `brute_force` only |
| 203.0.113.77 | 7 distinct invalid users in 150s, 7 failures total | `user_enumeration` only, since 7 is below the brute force threshold |
| 192.0.2.44 | 6 failures over 200s, then a success | `success_after_failures` only, since the rate is too slow for a 120s window |
| 198.51.100.9 | real user mistypes 3 times, then succeeds | nothing at all |

CI runs the evaluation with `--min-f1 1.0`, so a threshold change that starts
missing attacks or alerting on the benign user fails the build.

```
rule                      TP  FP  FN    prec     rec      F1
------------------------------------------------------------
brute_force                1   0   0    1.00    1.00    1.00
success_after_failures     1   0   0    1.00    1.00    1.00
user_enumeration           1   0   0    1.00    1.00    1.00
------------------------------------------------------------
OVERALL                    3   0   0    1.00    1.00    1.00
```

## JSON shape

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-10-29T14:42:50+00:00",
  "source": "eval/sample_auth.log",
  "events_parsed": 72,
  "alert_count": 3,
  "severity_counts": { "high": 1, "medium": 2 },
  "config": { "...": "the effective config, so a report is reproducible" },
  "alerts": [
    {
      "rule": "success_after_failures",
      "severity": "high",
      "source_ip": "192.0.2.44",
      "usernames": ["backup"],
      "first_seen": "2026-10-29 10:40:00",
      "last_seen": "2026-10-29 10:44:00",
      "observed": 6,
      "threshold": 5,
      "window_seconds": 600,
      "description": "Successful login as 'backup' from 192.0.2.44 after 6 failed attempts ...",
      "evidence": ["L70: Oct 29 10:40:00 web-01 sshd[6000]: Failed password for backup ..."]
    }
  ]
}
```

The effective config travels inside every report, so an alert can be reproduced
later without guessing which thresholds were in force.

## Limitations

1. Thresholds are global. A host with one legitimate noisy client needs that IP in
   `ignore_ips` or its own config file, not a lowered global threshold.
2. There is no state between runs. A brute force spanning two log files is counted
   per file. Concatenate before triaging if that matters.
3. Distributed attacks are not caught. Every rule groups by a single source IP, so
   one attempt each from 500 addresses looks like nothing. A sibling rule keyed on
   the targeted username rather than the source IP is the natural next addition.
4. A single evaluation sample proves the rules behave as specified, not that the
   defaults suit your environment. Baseline against your own logs before trusting
   the numbers.
5. Timestamps without a year rely on `--year` and on the log being in chronological
   order for rollover detection.

## Layout

```
authtriage/
  config.py      defaults, JSON override, validation
  parser.py      log lines to Event records
  detectors.py   the three rules and the sliding window scan
  report.py      JSON document and markdown summary
  cli.py         argparse entrypoint
tests/           unit tests over synthetic logs
eval/            hand-labelled sample, labels, scoring script
```

Source is 497 lines.
