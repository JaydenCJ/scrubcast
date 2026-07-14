"""asciicast v2 reading, scrubbing, and writing.

An asciicast v2 file is newline-delimited JSON: a header object on the first
line, then one ``[time, code, data]`` event per line. Two properties make a
naive line-by-line scrub wrong:

* a secret is frequently **split across events** — echoed keystroke by
  keystroke, or flushed in arbitrary chunks by the program that printed it;
* an escape sequence can *itself* be split across events, so per-event
  tokenization would misparse.

scrubcast therefore joins each stream (all ``"o"`` events in order; ``"i"``
separately) into one logical string, scans and plans replacements on that,
then rebuilds every event from its slice of the emission table. Event
count, order, timestamps, and every escape byte survive — the recording
plays back exactly as before, minus the secrets.
"""

from __future__ import annotations

import json
from bisect import bisect_right
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .config import RuleSet, default_ruleset
from .engine import Finding, ScrubOptions, placeholder_for, plan_emissions, scan_plain
from .errors import CastParseError

__all__ = ["Cast", "parse_cast", "looks_like_cast", "scrub_cast", "scan_cast"]

#: Event codes whose payload is terminal data worth scrubbing.
_SCRUBBED_CODES = ("o", "i")

#: Header string fields that may carry secrets (shell command lines, titles).
_HEADER_TEXT_FIELDS = ("title", "command")


@dataclass
class Cast:
    """A parsed asciicast v2 document."""

    header: Dict[str, Any]
    events: List[List[Any]] = field(default_factory=list)

    def dumps(self) -> str:
        """Serialize back to newline-delimited JSON (asciicast v2)."""
        lines = [json.dumps(self.header, ensure_ascii=False, separators=(", ", ": "))]
        for event in self.events:
            lines.append(json.dumps(event, ensure_ascii=False, separators=(", ", ": ")))
        return "\n".join(lines) + "\n"


def looks_like_cast(text: str) -> bool:
    """Cheap format sniff: is the first non-empty line an asciicast header?"""
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            head = json.loads(line)
        except json.JSONDecodeError:
            return False
        return isinstance(head, dict) and "version" in head
    return False


def parse_cast(text: str) -> Cast:
    """Parse asciicast v2 text, validating shape line by line."""
    header: Optional[Dict[str, Any]] = None
    events: List[List[Any]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise CastParseError(f"line {lineno}: not valid JSON: {exc}") from None
        if header is None:
            if not isinstance(value, dict) or "version" not in value:
                raise CastParseError(
                    f"line {lineno}: expected an asciicast header object with a"
                    ' "version" key'
                )
            if value.get("version") != 2:
                raise CastParseError(
                    f"line {lineno}: unsupported asciicast version"
                    f" {value.get('version')!r} (only v2 is supported)"
                )
            header = value
            continue
        if (
            not isinstance(value, list)
            or len(value) < 3
            or not isinstance(value[0], (int, float))
            or not isinstance(value[1], str)
        ):
            raise CastParseError(
                f"line {lineno}: expected an event array [time, code, data]"
            )
        events.append(value)
    if header is None:
        raise CastParseError("empty input: no asciicast header found")
    return Cast(header=header, events=events)


def _scrub_stream(
    cast: Cast,
    code: str,
    ruleset: RuleSet,
    options: ScrubOptions,
) -> List[Finding]:
    """Scrub every ``code`` event in place, treating them as one stream."""
    indices = [
        i
        for i, event in enumerate(cast.events)
        if event[1] == code and isinstance(event[2], str)
    ]
    if not indices:
        return []
    joined = "".join(cast.events[i][2] for i in indices)
    emissions, findings = plan_emissions(joined, ruleset, options)

    # offsets[k] = start offset of the k-th participating event in `joined`.
    offsets: List[int] = []
    total = 0
    for i in indices:
        offsets.append(total)
        total += len(cast.events[i][2])

    for k, i in enumerate(indices):
        lo = offsets[k]
        hi = offsets[k + 1] if k + 1 < len(offsets) else total
        cast.events[i][2] = "".join(emissions[lo:hi])

    for finding in findings:
        k = bisect_right(offsets, finding.anchor) - 1
        event_index = indices[k]
        finding.location = {
            "stream": code,
            "event": event_index,
            "time": cast.events[event_index][0],
        }
    return findings


def _scrub_header(
    cast: Cast, ruleset: RuleSet, options: ScrubOptions
) -> List[Finding]:
    """Scrub free-text header fields and every env value."""
    findings: List[Finding] = []

    def scrub_value(value: str, where: str) -> str:
        value_findings = scan_plain(value, ruleset)
        if not value_findings:
            return value
        out: List[str] = list(value)
        for finding in value_findings:
            finding.origin = "header"
            finding.location = {"field": where}
            if options.style == "mask":
                for p in range(finding.start, finding.end):
                    out[p] = options.mask_char
            else:
                replacement = placeholder_for(finding, options)
                for offset, p in enumerate(range(finding.start, finding.end)):
                    out[p] = replacement if offset == 0 else ""
        findings.extend(value_findings)
        return "".join(out)

    for key in _HEADER_TEXT_FIELDS:
        if isinstance(cast.header.get(key), str):
            cast.header[key] = scrub_value(cast.header[key], key)
    env = cast.header.get("env")
    if isinstance(env, dict):
        for key, value in list(env.items()):
            if isinstance(value, str):
                env[key] = scrub_value(value, f"env.{key}")
    return findings


def scrub_cast(
    text: str,
    ruleset: Optional[RuleSet] = None,
    options: Optional[ScrubOptions] = None,
) -> Tuple[str, List[Finding]]:
    """Scrub an asciicast v2 document; return ``(new_text, findings)``.

    Output and input events correspond one to one: same count, same order,
    same timestamps and codes. Only string payloads change.
    """
    ruleset = ruleset if ruleset is not None else default_ruleset()
    options = options if options is not None else ScrubOptions()
    cast = parse_cast(text)
    findings: List[Finding] = []
    findings.extend(_scrub_header(cast, ruleset, options))
    for code in _SCRUBBED_CODES:
        findings.extend(_scrub_stream(cast, code, ruleset, options))
    return cast.dumps(), findings


def scan_cast(text: str, ruleset: Optional[RuleSet] = None) -> List[Finding]:
    """Detect secrets in an asciicast without rewriting it."""
    _, findings = scrub_cast(text, ruleset, ScrubOptions())
    return findings
