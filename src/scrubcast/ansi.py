"""ANSI escape-sequence tokenizer.

The whole point of scrubcast is that a secret printed to a terminal is often
*not* contiguous in the byte stream: prompts inject SGR color codes into the
middle of tokens, progress redraws interleave cursor movement with text, and
OSC sequences carry their own payloads (window titles, hyperlink targets).

This module splits a string into tokens of two families:

* **text** — characters the terminal would render (including ``\\n``, ``\\r``,
  ``\\t`` and other bare C0 controls, which are kept in the text stream so a
  pattern can never falsely match "across" a carriage return), and
* **escape sequences** — CSI, OSC, DCS/SOS/PM/APC and the short two- and
  three-byte ``ESC``-prefixed forms.

From the tokens it derives a *plain view*: the concatenated text content plus
an index map back into the original string, so a match found on the plain
view can be surgically replaced in the original without touching a single
escape byte. That is what keeps scrubbed recordings playable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

__all__ = ["Token", "tokenize", "plain_view", "strip_escapes"]

ESC = "\x1b"
CSI_8BIT = "\x9b"  # single-byte CSI introducer (C1), seen in some captures
BEL = "\x07"
ST = "\x1b\\"  # string terminator

#: Token kinds. ``osc`` is separated from other escapes because its payload
#: (title text, hyperlink URI) is itself scannable content.
KIND_TEXT = "text"
KIND_CSI = "csi"
KIND_OSC = "osc"
KIND_ESC = "esc"


@dataclass(frozen=True)
class Token:
    """A half-open slice ``[start, end)`` of the original string."""

    kind: str
    start: int
    end: int


def _scan_csi(s: str, i: int) -> int:
    """Consume a CSI body starting after the introducer; return end index.

    Grammar: parameter bytes 0x30-0x3F, intermediate bytes 0x20-0x2F, one
    final byte 0x40-0x7E. A truncated sequence (end of chunk) consumes to the
    end of the string, which keeps the tokenizer total.
    """
    n = len(s)
    while i < n and "\x30" <= s[i] <= "\x3f":
        i += 1
    while i < n and "\x20" <= s[i] <= "\x2f":
        i += 1
    if i < n and "\x40" <= s[i] <= "\x7e":
        i += 1
    return i


def _scan_string_sequence(s: str, i: int) -> int:
    """Consume an OSC/DCS/SOS/PM/APC body; return index past the terminator.

    Terminated by BEL or ST (ESC ``\\``); a truncated sequence consumes to the
    end of the string.
    """
    n = len(s)
    while i < n:
        ch = s[i]
        if ch == BEL:
            return i + 1
        if ch == ESC:
            if i + 1 < n and s[i + 1] == "\\":
                return i + 2
            # A bare ESC inside a string sequence aborts it; do not swallow
            # the following sequence into this token.
            return i
        i += 1
    return i


def tokenize(s: str) -> List[Token]:
    """Split ``s`` into a lossless sequence of text and escape tokens.

    The concatenation of ``s[t.start:t.end]`` over all tokens is exactly
    ``s`` — nothing is dropped, reordered, or normalized.
    """
    tokens: List[Token] = []
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch == CSI_8BIT:
            end = _scan_csi(s, i + 1)
            tokens.append(Token(KIND_CSI, i, end))
            i = end
            continue
        if ch != ESC:
            start = i
            while i < n and s[i] != ESC and s[i] != CSI_8BIT:
                i += 1
            tokens.append(Token(KIND_TEXT, start, i))
            continue
        # ESC-introduced sequence.
        start = i
        i += 1
        if i >= n:
            tokens.append(Token(KIND_ESC, start, n))  # lone trailing ESC
            break
        c = s[i]
        if c == "[":
            end = _scan_csi(s, i + 1)
            tokens.append(Token(KIND_CSI, start, end))
        elif c == "]":
            end = _scan_string_sequence(s, i + 1)
            tokens.append(Token(KIND_OSC, start, end))
        elif c in "PX^_":
            end = _scan_string_sequence(s, i + 1)
            tokens.append(Token(KIND_ESC, start, end))
        elif "\x20" <= c <= "\x2f":
            # nF sequences such as charset designation ESC ( B.
            i += 1
            while i < n and "\x20" <= s[i] <= "\x2f":
                i += 1
            end = i + 1 if i < n else i
            tokens.append(Token(KIND_ESC, start, end))
        else:
            # Fp/Fe/Fs two-byte sequences: ESC 7, ESC =, ESC M, ...
            end = i + 1
            tokens.append(Token(KIND_ESC, start, end))
        i = tokens[-1].end
    return tokens


def plain_view(s: str, tokens: List[Token]) -> Tuple[str, List[int]]:
    """Return the rendered-text projection of ``s`` and its index map.

    ``plain[i]`` corresponds to ``s[index_map[i]]``. Escape sequences are
    absent from ``plain``, which is why a secret interleaved with SGR codes
    becomes contiguous here and matchable by an ordinary regex.
    """
    parts: List[str] = []
    index_map: List[int] = []
    for tok in tokens:
        if tok.kind != KIND_TEXT:
            continue
        parts.append(s[tok.start : tok.end])
        index_map.extend(range(tok.start, tok.end))
    return "".join(parts), index_map


def strip_escapes(s: str) -> str:
    """Convenience: ``s`` with every escape sequence removed."""
    plain, _ = plain_view(s, tokenize(s))
    return plain


def osc_payload_span(s: str, token: Token) -> Tuple[int, int]:
    """Return the ``[start, end)`` span of an OSC token's payload in ``s``.

    The payload excludes the two-byte introducer ``ESC ]`` and the trailing
    BEL / ST terminator (whichever is present).
    """
    start = token.start + 2  # skip ESC ]
    end = token.end
    body = s[start:end]
    if body.endswith(ST):
        end -= 2
    elif body.endswith(BEL):
        end -= 1
    return start, min(max(start, end), token.end)
