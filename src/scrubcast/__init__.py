"""scrubcast — redact secrets from terminal recordings and ANSI logs.

The public API mirrors the CLI:

* :func:`scrub_text` / :func:`scan_text` — one chunk of terminal output;
* :func:`scrub_log` — a log file, findings annotated with line/column;
* :func:`scrub_cast` / :func:`scan_cast` — an asciicast v2 document,
  findings annotated with event index and timestamp;
* :class:`RuleSet`, :func:`default_ruleset`, :func:`load_rules_file` —
  detection configuration;
* :class:`ScrubOptions` — replacement style (``label``, ``hash``, ``mask``).

Everything is pure standard library and fully offline.
"""

from .ansi import Token, plain_view, strip_escapes, tokenize
from .cast import Cast, looks_like_cast, parse_cast, scan_cast, scrub_cast
from .config import RuleSet, default_ruleset, load_rules_file
from .detectors import BUILTIN_RULES, Rule
from .engine import (
    Finding,
    ScrubOptions,
    ScrubResult,
    scan_text,
    scrub_log,
    scrub_text,
)
from .entropy import EntropyConfig, shannon_entropy
from .errors import CastParseError, ConfigError, ScrubcastError

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # engine
    "Finding",
    "ScrubOptions",
    "ScrubResult",
    "scrub_text",
    "scan_text",
    "scrub_log",
    # cast
    "Cast",
    "parse_cast",
    "looks_like_cast",
    "scrub_cast",
    "scan_cast",
    # configuration
    "RuleSet",
    "Rule",
    "BUILTIN_RULES",
    "EntropyConfig",
    "default_ruleset",
    "load_rules_file",
    "shannon_entropy",
    # ANSI helpers
    "Token",
    "tokenize",
    "plain_view",
    "strip_escapes",
    # errors
    "ScrubcastError",
    "CastParseError",
    "ConfigError",
]
