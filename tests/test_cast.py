"""asciicast v2: parsing, cross-event redaction, playable output."""

from __future__ import annotations

import json

import pytest

from scrubcast import (
    CastParseError,
    ScrubOptions,
    looks_like_cast,
    parse_cast,
    scan_cast,
    scrub_cast,
)

from conftest import FAKE_GITHUB, make_cast


def events_of(text: str):
    lines = [ln for ln in text.splitlines() if ln.strip()]
    return json.loads(lines[0]), [json.loads(ln) for ln in lines[1:]]


def test_parse_roundtrip_preserves_header_and_events():
    text = make_cast([[0.5, "o", "hello\r\n"], [1.0, "o", "world\r\n"]])
    cast = parse_cast(text)
    assert cast.header["version"] == 2
    header, events = events_of(cast.dumps())
    assert header["width"] == 80
    assert events == [[0.5, "o", "hello\r\n"], [1.0, "o", "world\r\n"]]


def test_parse_rejects_missing_header_and_wrong_version():
    with pytest.raises(CastParseError, match="header"):
        parse_cast('[0.1, "o", "hi"]\n')
    with pytest.raises(CastParseError, match="version"):
        parse_cast('{"version": 1, "width": 80}\n')


def test_parse_rejects_bad_json_and_malformed_events_with_line_numbers():
    with pytest.raises(CastParseError, match="line 2"):
        parse_cast('{"version": 2}\nnot json\n')
    with pytest.raises(CastParseError, match="line 2"):
        parse_cast('{"version": 2}\n{"time": 1}\n')


def test_looks_like_cast_sniffs_correctly():
    assert looks_like_cast(make_cast([]))
    assert not looks_like_cast("plain log line\n")
    assert not looks_like_cast('["not", "a", "header"]\n')
    assert not looks_like_cast("")


def test_secret_inside_one_event_is_replaced_with_location():
    text = make_cast([[0.1, "o", f"token {FAKE_GITHUB}\r\n"]])
    out, findings = scrub_cast(text)
    _, events = events_of(out)
    assert events[0][2] == "token [REDACTED:github-token]\r\n"
    assert findings[0].location == {"stream": "o", "event": 0, "time": 0.1}
    assert [f.rule for f in scan_cast(text)] == ["github-token"]
    # Multibyte payloads around the secret survive untouched.
    jp = make_cast([[0.1, "o", f"日本語 {FAKE_GITHUB} テスト\r\n"]])
    _, jp_events = events_of(scrub_cast(jp)[0])
    assert jp_events[0][2] == "日本語 [REDACTED:github-token] テスト\r\n"


def test_secret_split_across_events_is_caught():
    # The reason scrubcast exists: output flushed in arbitrary chunks.
    text = make_cast(
        [
            [0.1, "o", f"key: {FAKE_GITHUB[:12]}"],
            [0.2, "o", FAKE_GITHUB[12:25]],
            [0.3, "o", f"{FAKE_GITHUB[25:]} done\r\n"],
        ]
    )
    out, findings = scrub_cast(text)
    _, events = events_of(out)
    joined = "".join(e[2] for e in events)
    assert FAKE_GITHUB[:12] not in joined
    assert joined == "key: [REDACTED:github-token] done\r\n"
    assert len(findings) == 1


def test_event_count_order_times_and_codes_are_preserved():
    original = [
        [0.1, "o", f"a {FAKE_GITHUB[:20]}"],
        [0.15, "r", "80x24"],
        [0.2, "o", f"{FAKE_GITHUB[20:]} b"],
        [0.3, "m", "marker"],
    ]
    out, _ = scrub_cast(make_cast(original))
    _, events = events_of(out)
    assert [(e[0], e[1]) for e in events] == [(e[0], e[1]) for e in original]
    assert events[1][2] == "80x24"  # non-o/i payloads untouched
    assert events[3][2] == "marker"


def test_escape_sequence_split_across_events_is_not_misparsed():
    # ESC in one event, the rest of the SGR sequence in the next: the joined
    # stream parses it as one sequence and the secret around it still matches.
    text = make_cast(
        [
            [0.1, "o", f"{FAKE_GITHUB[:8]}\x1b"],
            [0.2, "o", f"[31m{FAKE_GITHUB[8:]}\x1b[0m"],
        ]
    )
    out, findings = scrub_cast(text)
    _, events = events_of(out)
    joined = "".join(e[2] for e in events)
    assert "[REDACTED:github-token]" in joined
    assert "\x1b[31m" in joined and "\x1b[0m" in joined
    assert len(findings) == 1


def test_mask_style_keeps_stream_length_identical():
    text = make_cast(
        [[0.1, "o", FAKE_GITHUB[:15]], [0.2, "o", FAKE_GITHUB[15:] + "\r\n"]]
    )
    out, _ = scrub_cast(text, options=ScrubOptions(style="mask"))
    _, events = events_of(out)
    assert len(events[0][2]) == 15
    assert len(events[1][2]) == len(FAKE_GITHUB) - 15 + 2
    assert set(events[0][2]) == {"*"}


def test_input_events_are_scrubbed_separately_from_output():
    # A password typed (i) and locally echoed (o) must both go, and the i/o
    # streams must not bleed into each other when matching.
    text = make_cast(
        [
            [0.1, "i", f"login --password {FAKE_GITHUB}\r"],
            [0.2, "o", f"using {FAKE_GITHUB}\r\n"],
        ]
    )
    out, findings = scrub_cast(text)
    _, events = events_of(out)
    assert FAKE_GITHUB not in events[0][2]
    assert FAKE_GITHUB not in events[1][2]
    assert sorted(f.location["stream"] for f in findings) == ["i", "o"]


def test_typed_secret_one_keystroke_per_event():
    keystrokes = [[round(0.1 * i, 1), "i", ch] for i, ch in enumerate(FAKE_GITHUB)]
    out, findings = scrub_cast(make_cast(keystrokes))
    _, events = events_of(out)
    assert len(events) == len(FAKE_GITHUB)  # every keystroke event survives
    assert "".join(e[2] for e in events) == "[REDACTED:github-token]"
    assert len(findings) == 1
    assert findings[0].location["event"] == 0  # anchored at the first key


def test_header_title_and_env_are_scrubbed():
    header = {
        "title": f"demo {FAKE_GITHUB}",
        "env": {"SHELL": "/bin/bash", "API_TOKEN": FAKE_GITHUB},
    }
    out, findings = scrub_cast(make_cast([[0.1, "o", "hi"]], header=header))
    new_header, _ = events_of(out)
    assert FAKE_GITHUB not in json.dumps(new_header)
    assert new_header["env"]["SHELL"] == "/bin/bash"
    assert sorted(f.location["field"] for f in findings) == ["env.API_TOKEN", "title"]


def test_scrubbed_output_is_valid_asciicast_and_clean_input_passes_through():
    text = make_cast([[0.1, "o", f"x {FAKE_GITHUB}\r\n"], [0.2, "i", "y"]])
    out, _ = scrub_cast(text)
    assert len(parse_cast(out).events) == 2  # must reparse cleanly
    clean = make_cast([[0.1, "o", "\x1b[32m$ make test\x1b[0m\r\n"]])
    out2, findings2 = scrub_cast(clean)
    assert findings2 == []
    _, events2 = events_of(out2)
    assert events2[0][2] == "\x1b[32m$ make test\x1b[0m\r\n"
