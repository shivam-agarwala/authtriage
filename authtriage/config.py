"""Detection thresholds: built-in defaults, JSON file override, CLI override."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict

# Every number here is tunable. Defaults are deliberately conservative, tuned to
# stay quiet on a normal host where real users fat-finger passwords.
DEFAULTS: Dict[str, Any] = {
    "brute_force": {"min_failures": 8, "window_seconds": 120},
    "user_enumeration": {"min_distinct_users": 5, "window_seconds": 300},
    "success_after_failures": {"min_failures": 5, "lookback_seconds": 600},
    # sshd emits up to 3 lines per failed attempt (pam_unix, Failed password,
    # preauth disconnect). Counting all of them inflates every rate ~3x, so only
    # the canonical line counts; the rest stay as evidence. See README.
    "failure_kinds": ["failed_password"],
    "max_evidence_lines": 6,
    "ignore_ips": [],  # known scanners, your own jump host, CI runners
}


def _merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursive merge; override wins, unknown keys are rejected loudly."""
    out = copy.deepcopy(base)
    for key, value in override.items():
        if key not in out:
            raise ValueError(f"unknown config key: {key}")
        out[key] = _merge(out[key], value) if isinstance(out[key], dict) and \
            isinstance(value, dict) else value
    return out


def validate(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Every threshold must be a positive int. A zero threshold alerts on silence."""
    for section, values in cfg.items():
        if not isinstance(values, dict):
            continue
        for key, number in values.items():
            if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
                raise ValueError(f"{section}.{key} must be a positive integer, got {number!r}")
    if not cfg["failure_kinds"]:
        raise ValueError("failure_kinds must list at least one event kind")
    if cfg["max_evidence_lines"] < 1:
        raise ValueError("max_evidence_lines must be >= 1")
    return cfg


def load_config(path: str | Path | None = None, **overrides: Any) -> Dict[str, Any]:
    """Effective config, CLI over file over defaults. Overrides use dotted keys,
    e.g. load_config(**{"brute_force.min_failures": 5})."""
    cfg = copy.deepcopy(DEFAULTS)
    if path:
        cfg = _merge(cfg, json.loads(Path(path).read_text(encoding="utf-8")))
    for dotted, value in ((k, v) for k, v in overrides.items() if v is not None):
        section, _, key = dotted.partition(".")
        if section not in cfg:
            raise ValueError(f"unknown config key: {dotted}")
        if key:
            cfg[section][key] = value
        else:
            cfg[section] = value
    return validate(cfg)
