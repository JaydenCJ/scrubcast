"""Exception hierarchy for scrubcast.

Every error raised on purpose by this package derives from
:class:`ScrubcastError`, so callers can catch one type at the boundary.
"""

from __future__ import annotations

__all__ = ["ScrubcastError", "CastParseError", "ConfigError"]


class ScrubcastError(Exception):
    """Base class for all scrubcast errors."""


class CastParseError(ScrubcastError):
    """Raised when an input claims to be an asciicast but cannot be parsed.

    The message always names the offending line number so the user can
    inspect the file directly.
    """


class ConfigError(ScrubcastError):
    """Raised when a rules file is malformed (bad JSON, bad regex, ...)."""
