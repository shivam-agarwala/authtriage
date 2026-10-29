"""authtriage: defensive triage of OpenSSH authentication logs."""
from .config import DEFAULTS, load_config
from .detectors import Alert, detect
from .parser import Event, parse_file, parse_lines
from .report import build_report, to_markdown

__version__ = "0.1.0"
__all__ = ["DEFAULTS", "load_config", "Alert", "detect", "Event", "parse_file",
           "parse_lines", "build_report", "to_markdown"]
