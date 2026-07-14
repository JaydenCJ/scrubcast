"""Entropy-based detection of secrets that no shape rule knows about.

Rules catch the well-known prefixes; entropy catches the rest: hex session
ids, random base64 blobs, home-grown API keys. The detector is deliberately
conservative — terminal output is full of high-entropy strings that are
*not* secrets (git SHAs, docker digests, cache-busted filenames) — and every
heuristic here exists to keep a specific class of false positive out:

* pure-hex candidates (git SHAs, digests) are flagged **only** when a
  credential keyword appears shortly before them;
* non-hex candidates must mix letters and digits (English words never do);
* path-shaped candidates (three or more ``/`` and no base64 padding) are
  skipped;
* UUID-shaped candidates classify as hex after separator stripping, so bare
  UUIDs in logs also require keyword context.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Iterator, List, Tuple

__all__ = [
    "EntropyConfig",
    "shannon_entropy",
    "iter_entropy_candidates",
]

#: Words that, appearing within ``context_window`` chars before a candidate,
#: mark it as credential-adjacent (lower threshold, hex allowed).
CONTEXT_KEYWORDS = (
    "token",
    "secret",
    "key",
    "password",
    "passwd",
    "pwd",
    "auth",
    "credential",
    "bearer",
    "signature",
    "session",
)

_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/=_\-]+")
_HEX_RE = re.compile(r"[0-9a-fA-F]+\Z")
_KEYWORD_RE = re.compile("|".join(CONTEXT_KEYWORDS), re.IGNORECASE)


@dataclass(frozen=True)
class EntropyConfig:
    """Tunables for the entropy detector.

    ``threshold`` applies to mixed-alphabet candidates; hex candidates use
    ``hex_threshold`` and additionally require keyword context. A keyword
    within ``context_window`` chars relaxes ``threshold`` by
    ``context_bonus`` bits.
    """

    enabled: bool = True
    min_length: int = 20
    threshold: float = 4.0
    hex_threshold: float = 3.0
    context_window: int = 40
    context_bonus: float = 0.5


def shannon_entropy(s: str) -> float:
    """Shannon entropy of ``s`` in bits per character (0.0 for empty)."""
    if not s:
        return 0.0
    counts: dict = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _classify(candidate: str) -> str:
    """Classify a candidate's alphabet: ``hex`` or ``mixed``.

    Separators are stripped first so UUIDs (hex + hyphens) and
    underscore-grouped hex ids land in the hex class, where the
    keyword-context requirement protects git SHAs and friends.
    """
    core = candidate.replace("-", "").replace("_", "")
    if core and _HEX_RE.match(core):
        return "hex"
    return "mixed"


def _has_context(plain: str, start: int, window: int) -> bool:
    lo = max(0, start - window)
    return _KEYWORD_RE.search(plain, lo, start) is not None


def _is_path_like(candidate: str) -> bool:
    """Skip filesystem-path-shaped runs (`/opt/tool/bin/run-2024`)."""
    return candidate.count("/") >= 3 and "+" not in candidate and "=" not in candidate


def iter_entropy_candidates(
    plain: str, config: EntropyConfig
) -> Iterator[Tuple[int, int, float]]:
    """Yield ``(start, end, entropy)`` for spans that look like raw secrets.

    ``plain`` must be the escape-free projection of the input (see
    :func:`scrubcast.ansi.plain_view`); offsets are plain-view offsets.
    """
    if not config.enabled:
        return
    for start, candidate in _split_candidates(plain):
        if len(candidate) < config.min_length:
            continue
        if _is_path_like(candidate):
            continue
        if len(set(candidate)) == 1:
            continue
        entropy = shannon_entropy(candidate)
        kind = _classify(candidate)
        has_context = _has_context(plain, start, config.context_window)
        if kind == "hex":
            # Hex needs a credential keyword nearby: bare SHAs and digests
            # are everywhere in terminal output and are not secrets.
            if not has_context:
                continue
            if entropy < config.hex_threshold:
                continue
        else:
            if not _has_digit_and_alpha(candidate):
                continue
            threshold = config.threshold
            if has_context:
                threshold -= config.context_bonus
            if entropy < threshold:
                continue
        yield start, start + len(candidate), entropy


def _split_candidates(plain: str) -> Iterator[Tuple[int, str]]:
    """Yield ``(start, candidate)`` runs, splitting KEY=value at interior '='.

    In base64, '=' only pads the tail; an '=' in the middle of a run means an
    assignment, and treating ``API_SECRET=Zq3x...`` as one candidate would
    redact the variable name along with the value. Trailing '=' padding stays
    attached to its segment.
    """
    for match in _CANDIDATE_RE.finditer(plain):
        run = match.group(0)
        base = match.start()
        offset = 0
        while offset < len(run):
            eq = run.find("=", offset)
            if eq == -1:
                yield base + offset, run[offset:]
                break
            end = eq
            while end < len(run) and run[end] == "=":
                end += 1
            if end == len(run):  # trailing padding: keep it on the segment
                yield base + offset, run[offset:]
                break
            if eq > offset:
                yield base + offset, run[offset:eq]
            offset = end


def _has_digit_and_alpha(candidate: str) -> bool:
    return any(c.isdigit() for c in candidate) and any(c.isalpha() for c in candidate)


def entropy_spans(plain: str, config: EntropyConfig) -> List[Tuple[int, int, float]]:
    """Eager list form of :func:`iter_entropy_candidates` (test convenience)."""
    return list(iter_entropy_candidates(plain, config))
