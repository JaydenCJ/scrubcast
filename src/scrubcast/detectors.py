"""Built-in secret detection rules.

Each rule is a compiled regex applied to the *plain view* of the input (see
:mod:`scrubcast.ansi`), so a token split by color codes still matches. When a
rule defines a ``secret`` named group, only that group is redacted — the
surrounding context (``Authorization:``, ``password=``) is kept, which is
what makes scrubbed logs still readable.

Rules that match *assignments* rather than token shapes set
``skip_placeholder_values``: an already-scrubbed value (``[REDACTED:...]``,
``<your-key-here>``, ``${VAR}``, ``*****``) is not re-redacted, which makes
scrubbing idempotent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Pattern

__all__ = ["Rule", "BUILTIN_RULES", "looks_like_placeholder"]


@dataclass(frozen=True)
class Rule:
    """A named detection rule.

    ``pattern`` runs against plain text; if it defines a ``(?P<secret>...)``
    group, only that group's span is redacted.
    """

    name: str
    description: str
    pattern: Pattern[str] = field(repr=False)
    skip_placeholder_values: bool = False

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", self.name):
            raise ValueError(f"rule name must be kebab-case: {self.name!r}")


_PLACEHOLDER_VALUES = frozenset(
    {"true", "false", "null", "none", "redacted", "changeme", "xxxxxx", "hunter2"}
)


def looks_like_placeholder(value: str) -> bool:
    """Heuristic: is ``value`` already a stand-in rather than a live secret?

    Applied only by rules with ``skip_placeholder_values`` (assignment-style
    rules whose value group is open-ended). Shape-based rules such as the
    AWS key id never hit this path — a real ``AKIA...`` is redacted even if
    it is all one repeated character.
    """
    if not value:
        return True
    if value.startswith(("[REDACTED", "<", "$", "{", "%")):
        return True
    if len(set(value)) == 1:  # ******, xxxxxx, ------
        return True
    return value.lower() in _PLACEHOLDER_VALUES


def _r(pattern: str, flags: int = 0) -> Pattern[str]:
    return re.compile(pattern, flags)


#: The built-in rule set, ordered from most to least specific. Order matters
#: only for overlapping matches: the engine keeps the leftmost-longest span
#: and, on ties, the earlier rule.
BUILTIN_RULES: List[Rule] = [
    Rule(
        "private-key-block",
        "PEM-encoded private key block (RSA, EC, OpenSSH, PGP, ...)",
        _r(
            r"-----BEGIN (?:[A-Z][A-Z ]*)?PRIVATE KEY(?: BLOCK)?-----"
            r"[\s\S]*?"
            r"(?:-----END (?:[A-Z][A-Z ]*)?PRIVATE KEY(?: BLOCK)?-----|\Z)"
        ),
    ),
    Rule(
        "aws-access-key-id",
        "AWS access key id (AKIA/ASIA/ABIA/ACCA + 16 chars)",
        _r(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    ),
    Rule(
        "aws-secret-access-key",
        "AWS secret access key assigned to an aws_secret_access_key-like name",
        _r(
            r"(?i)\baws_?secret_?(?:access_?)?key\b[^\S\n]*[:=][^\S\n]*[\"']?"
            r"(?P<secret>[A-Za-z0-9/+=]{40})\b"
        ),
        skip_placeholder_values=True,
    ),
    Rule(
        "github-token",
        "GitHub personal/app token (ghp_, gho_, ghu_, ghs_, ghr_, github_pat_)",
        _r(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
    ),
    Rule(
        "gitlab-token",
        "GitLab personal access token (glpat-)",
        _r(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    ),
    Rule(
        "slack-token",
        "Slack bot/user/app token (xoxb-, xoxp-, xoxa-, xoxr-, xoxs-)",
        _r(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    Rule(
        "slack-webhook",
        "Slack incoming-webhook URL",
        _r(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_/]{8,}"),
    ),
    Rule(
        "stripe-key",
        "Stripe secret/restricted key (sk_live_, sk_test_, rk_live_, rk_test_)",
        _r(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    ),
    Rule(
        "sk-api-key",
        "sk-prefixed model-provider API key (sk-..., sk-proj-..., sk-ant-...)",
        _r(r"\bsk-(?:[A-Za-z0-9]+-)*[A-Za-z0-9_\-]{20,}\b"),
    ),
    Rule(
        "google-api-key",
        "Google API key (AIza + 35 chars)",
        _r(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ),
    Rule(
        "npm-token",
        "npm granular/classic automation token (npm_)",
        _r(r"\bnpm_[A-Za-z0-9]{36}\b"),
    ),
    Rule(
        "pypi-token",
        "PyPI upload token (pypi- + macaroon)",
        _r(r"\bpypi-AgE[A-Za-z0-9_\-]{50,}\b"),
    ),
    Rule(
        "sendgrid-key",
        "SendGrid API key (SG.xxx.yyy)",
        _r(r"\bSG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{16,64}\b"),
    ),
    Rule(
        "age-secret-key",
        "age file-encryption identity (AGE-SECRET-KEY-1...)",
        _r(r"\bAGE-SECRET-KEY-1[A-Z0-9]{50,}\b"),
    ),
    Rule(
        "jwt",
        "JSON Web Token (three base64url segments, header starting with eyJ)",
        _r(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    ),
    Rule(
        "authorization-header",
        "Authorization / Proxy-Authorization header value (Bearer, Basic, token)",
        _r(
            r"(?i)\b(?:proxy-)?authorization[^\S\n]*:[^\S\n]*(?:bearer|basic|token)[^\S\n]+"
            r"(?P<secret>[A-Za-z0-9._+/=\-]{8,})"
        ),
        skip_placeholder_values=True,
    ),
    Rule(
        "url-userinfo",
        "Password embedded in a URL (scheme://user:password@host)",
        _r(r"\b[a-z][a-z0-9+.\-]*://[^/\s:@\x1b]+:(?P<secret>[^/\s@\x1b]+)@"),
        skip_placeholder_values=True,
    ),
    Rule(
        "secret-assignment",
        "Generic KEY=value assignment where KEY names a credential",
        # The key may carry a prefix (API_SECRET, DB_PASSWORD) but the
        # credential word must start the identifier or follow a separator,
        # so "monkey=" and "sshkey=" never trigger.
        _r(
            r"(?i)\b(?:[a-z0-9_.\-]*[_.\-])?"
            r"(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|"
            r"auth[_-]?token|token|credentials?)\b[^\S\n]*[:=][^\S\n]*[\"']?"
            r"(?P<secret>[^\s\"'\x1b]{6,})"
        ),
        skip_placeholder_values=True,
    ),
]

_BY_NAME = {rule.name: rule for rule in BUILTIN_RULES}
assert len(_BY_NAME) == len(BUILTIN_RULES), "duplicate rule name"


def builtin_rule(name: str) -> Rule:
    """Look up one built-in rule by name (raises ``KeyError`` if unknown)."""
    return _BY_NAME[name]
