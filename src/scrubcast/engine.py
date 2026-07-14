"""The scrubbing engine: scan the plain view, rewrite the original bytes.

The pipeline for a chunk of terminal output:

1. tokenize into text and escape sequences (:mod:`scrubcast.ansi`);
2. project the *plain view* (text only) with an index map back to the
   original string;
3. run rules and the entropy detector against the plain view;
4. plan a per-original-character emission table: escape sequences pass
   through verbatim, matched text characters become the placeholder (emitted
   once, at the first matched character) or a mask character;
5. scan OSC payloads (window titles, hyperlink URIs) separately, since those
   live *inside* escape sequences and never reach the plain view.

The emission table — one output string per original character — is the trick
that lets :mod:`scrubcast.cast` redact a secret spanning several asciicast
events while keeping every event, timestamp, and escape sequence in place.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .ansi import KIND_OSC, osc_payload_span, plain_view, tokenize
from .config import RuleSet, default_ruleset
from .detectors import looks_like_placeholder
from .entropy import iter_entropy_candidates

__all__ = ["Finding", "ScrubOptions", "ScrubResult", "scrub_text", "scan_text", "scrub_log"]

#: Placeholder styles. ``label`` is readable, ``hash`` correlates repeated
#: occurrences of the same secret, ``mask`` preserves character count so
#: column-aligned output stays aligned.
STYLES = ("label", "hash", "mask")


@dataclass
class Finding:
    """One detected secret.

    ``start``/``end`` are plain-view offsets (or payload offsets for OSC
    findings); ``anchor`` is the offset of the first matched character in the
    *original* string, which is what location reporting is based on.
    """

    rule: str
    start: int
    end: int
    secret: str
    anchor: int
    origin: str = "text"  # "text" | "osc" | "header"
    location: Optional[Dict[str, object]] = None

    def preview(self) -> str:
        """A safe, non-reversible preview: first 4 chars + length."""
        head = self.secret[:4]
        return f"{head}… ({len(self.secret)} chars)"


@dataclass(frozen=True)
class ScrubOptions:
    """How replacements are rendered."""

    style: str = "label"
    mask_char: str = "*"

    def __post_init__(self) -> None:
        if self.style not in STYLES:
            raise ValueError(f"unknown style {self.style!r}; choose from {STYLES}")
        if len(self.mask_char) != 1:
            raise ValueError("mask_char must be a single character")


@dataclass
class ScrubResult:
    """Scrubbed text plus everything that was found."""

    text: str
    findings: List[Finding] = field(default_factory=list)


def placeholder_for(finding: Finding, options: ScrubOptions) -> str:
    """Render the replacement string for one finding."""
    if options.style == "hash":
        digest = hashlib.sha256(finding.secret.encode("utf-8")).hexdigest()[:8]
        return f"[REDACTED:{finding.rule}:{digest}]"
    return f"[REDACTED:{finding.rule}]"


def scan_plain(plain: str, ruleset: RuleSet) -> List[Finding]:
    """Run every rule, then entropy, over an escape-free string.

    Overlaps resolve leftmost-longest, rules beating entropy: rule findings
    are collected first, merged, and entropy candidates that touch a rule
    span are dropped.
    """
    raw: List[Finding] = []
    for rule in ruleset.rules:
        for match in rule.pattern.finditer(plain):
            if "secret" in rule.pattern.groupindex and match.group("secret") is not None:
                start, end = match.span("secret")
            else:
                start, end = match.span()
            if start == end:
                continue
            secret = plain[start:end]
            if rule.skip_placeholder_values and looks_like_placeholder(secret):
                continue
            if ruleset.allows(secret):
                continue
            raw.append(Finding(rule.name, start, end, secret, anchor=start))
    merged = _merge_overlaps(raw)
    if ruleset.entropy.enabled:
        for start, end, _entropy in iter_entropy_candidates(plain, ruleset.entropy):
            if _overlaps_any(start, end, merged):
                continue
            secret = plain[start:end]
            if ruleset.allows(secret):
                continue
            merged.append(Finding("entropy", start, end, secret, anchor=start))
        merged.sort(key=lambda f: f.start)
    return merged


def _merge_overlaps(findings: List[Finding]) -> List[Finding]:
    """Keep leftmost-longest non-overlapping findings (stable for ties)."""
    ordered = sorted(findings, key=lambda f: (f.start, -(f.end - f.start)))
    kept: List[Finding] = []
    last_end = -1
    for finding in ordered:
        if finding.start < last_end:
            continue
        kept.append(finding)
        last_end = finding.end
    return kept


def _overlaps_any(start: int, end: int, findings: List[Finding]) -> bool:
    return any(start < f.end and end > f.start for f in findings)


def plan_emissions(
    s: str,
    ruleset: Optional[RuleSet] = None,
    options: Optional[ScrubOptions] = None,
) -> Tuple[List[str], List[Finding]]:
    """Compute the per-original-character emission table for ``s``.

    Returns ``(emissions, findings)`` where ``emissions[i]`` is the output
    text for original character ``i`` — the identity character when
    untouched, a mask character or placeholder when redacted, ``""`` when
    swallowed by a placeholder. ``"".join(emissions)`` is the scrubbed
    string; slicing the table is how cast events are rebuilt individually.
    """
    ruleset = ruleset if ruleset is not None else default_ruleset()
    options = options if options is not None else ScrubOptions()

    tokens = tokenize(s)
    plain, index_map = plain_view(s, tokens)
    findings = scan_plain(plain, ruleset)

    emissions: List[str] = list(s)
    for finding in findings:
        finding.anchor = index_map[finding.start]
        if options.style == "mask":
            for p in range(finding.start, finding.end):
                emissions[index_map[p]] = options.mask_char
        else:
            replacement = placeholder_for(finding, options)
            for offset, p in enumerate(range(finding.start, finding.end)):
                emissions[index_map[p]] = replacement if offset == 0 else ""

    # Second pass: OSC payloads (titles, OSC 8 hyperlink URIs) live inside
    # escape sequences and are invisible to the plain view.
    for token in tokens:
        if token.kind != KIND_OSC:
            continue
        pay_start, pay_end = osc_payload_span(s, token)
        payload = s[pay_start:pay_end]
        if not payload:
            continue
        payload_findings = scan_plain(payload, ruleset)
        for finding in payload_findings:
            finding.origin = "osc"
            finding.anchor = pay_start + finding.start
            if options.style == "mask":
                for p in range(finding.start, finding.end):
                    emissions[pay_start + p] = options.mask_char
            else:
                replacement = placeholder_for(finding, options)
                for offset, p in enumerate(range(finding.start, finding.end)):
                    emissions[pay_start + p] = replacement if offset == 0 else ""
        findings.extend(payload_findings)

    findings.sort(key=lambda f: f.anchor)
    return emissions, findings


def scrub_text(
    s: str,
    ruleset: Optional[RuleSet] = None,
    options: Optional[ScrubOptions] = None,
) -> ScrubResult:
    """Scrub one string of terminal output (escape-sequence aware)."""
    emissions, findings = plan_emissions(s, ruleset, options)
    return ScrubResult("".join(emissions), findings)


def scan_text(s: str, ruleset: Optional[RuleSet] = None) -> List[Finding]:
    """Detect without rewriting (the ``scan`` subcommand / CI gate)."""
    _, findings = plan_emissions(s, ruleset, ScrubOptions())
    return findings


def scrub_log(
    s: str,
    ruleset: Optional[RuleSet] = None,
    options: Optional[ScrubOptions] = None,
) -> ScrubResult:
    """Scrub a log file and attach ``line``/``column`` locations.

    Line and column are 1-based positions of the finding's first character
    in the *original* file, so they line up with what an editor shows.
    """
    result = scrub_text(s, ruleset, options)
    for finding in result.findings:
        line = s.count("\n", 0, finding.anchor) + 1
        line_start = s.rfind("\n", 0, finding.anchor) + 1
        finding.location = {"line": line, "column": finding.anchor - line_start + 1}
    return result
