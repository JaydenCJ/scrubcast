"""ANSI tokenizer: lossless splitting and the plain-view index map."""

from __future__ import annotations

from scrubcast.ansi import (
    KIND_CSI,
    KIND_ESC,
    KIND_OSC,
    KIND_TEXT,
    osc_payload_span,
    plain_view,
    strip_escapes,
    tokenize,
)


def kinds(s: str):
    return [t.kind for t in tokenize(s)]


def reassemble(s: str) -> str:
    return "".join(s[t.start : t.end] for t in tokenize(s))


def test_text_and_csi_sequences_are_classified():
    assert kinds("hello world") == [KIND_TEXT]
    assert kinds("a\x1b[31mred\x1b[0mb") == [
        KIND_TEXT,
        KIND_CSI,
        KIND_TEXT,
        KIND_CSI,
        KIND_TEXT,
    ]
    # Private params (DECSET) and intermediate bytes are part of one CSI.
    assert kinds("\x1b[?2004h") == [KIND_CSI]
    assert kinds("\x1b[0 q") == [KIND_CSI]


def test_osc_terminated_by_bel_and_by_st():
    assert kinds("\x1b]0;title\x07after") == [KIND_OSC, KIND_TEXT]
    assert kinds("\x1b]8;;https://example.test\x1b\\after") == [KIND_OSC, KIND_TEXT]


def test_dcs_apc_pm_sos_are_swallowed_as_escape_tokens():
    for intro in ("P", "X", "^", "_"):
        s = f"\x1b{intro}payload\x1b\\tail"
        toks = tokenize(s)
        assert [t.kind for t in toks] == [KIND_ESC, KIND_TEXT]
        assert s[toks[1].start :] == "tail"


def test_short_and_truncated_sequences_are_consumed_not_leaked():
    # ESC 7 (save cursor), ESC = (keypad), ESC ( B (charset designation).
    assert kinds("\x1b7\x1b=\x1b(Btext") == [KIND_ESC, KIND_ESC, KIND_ESC, KIND_TEXT]
    # A lone trailing ESC and a CSI cut off mid-sequence (chunked flush)
    # must become escape tokens, never text.
    assert kinds("abc\x1b") == [KIND_TEXT, KIND_ESC]
    assert kinds("x\x1b[3") == [KIND_TEXT, KIND_CSI]


def test_8bit_csi_introducer_is_recognized():
    assert kinds("a\x9b31mb") == [KIND_TEXT, KIND_CSI, KIND_TEXT]


def test_tokenization_is_lossless_contiguous_and_total():
    s = "a\x1b[1mBold\x1b]2;t\x07 \x1b(0line\x1b(B \r\npلain\x1b[0m\x1b7d"
    toks = tokenize(s)
    assert reassemble(s) == s
    assert toks[0].start == 0 and toks[-1].end == len(s)
    for prev, nxt in zip(toks, toks[1:]):
        assert prev.end == nxt.start
    assert tokenize("") == []


def test_control_characters_stay_in_the_text_stream():
    # \r and \b are text, so a pattern can never match "across" them.
    plain, _ = plain_view("ab\rcd\be", tokenize("ab\rcd\be"))
    assert plain == "ab\rcd\be"


def test_plain_view_index_map_points_at_original_positions():
    s = "AB\x1b[32mCD\x1b[0mEF"
    plain, imap = plain_view(s, tokenize(s))
    assert plain == "ABCDEF"
    for i, ch in enumerate(plain):
        assert s[imap[i]] == ch
    assert strip_escapes("\x1b[31mred\x1b[0m \x1b]0;t\x07plain\x9b1mX") == "red plainX"


def test_osc_payload_span_excludes_intro_and_terminator():
    s = "\x1b]0;my title\x07"
    (tok,) = tokenize(s)
    lo, hi = osc_payload_span(s, tok)
    assert s[lo:hi] == "0;my title"
    s2 = "\x1b]8;;https://example.test\x1b\\"
    (tok2,) = tokenize(s2)
    lo2, hi2 = osc_payload_span(s2, tok2)
    assert s2[lo2:hi2] == "8;;https://example.test"
