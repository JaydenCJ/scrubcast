"""The scrubbing engine: escape-aware replacement, styles, OSC payloads."""

from __future__ import annotations

import pytest

from scrubcast import (
    RuleSet,
    ScrubOptions,
    scan_text,
    scrub_log,
    scrub_text,
    strip_escapes,
)
from scrubcast.entropy import EntropyConfig

from conftest import FAKE_GITHUB, FAKE_HIGH_ENTROPY


def test_plain_secret_is_replaced_with_labelled_placeholder():
    result = scrub_text(f"token {FAKE_GITHUB} end")
    assert result.text == "token [REDACTED:github-token] end"
    assert [f.rule for f in result.findings] == ["github-token"]


def test_secret_split_by_sgr_codes_matches_and_escapes_survive():
    # The flagship case: color codes injected mid-token by a highlighter.
    styled = f"\x1b[1m{FAKE_GITHUB[:10]}\x1b[33m{FAKE_GITHUB[10:]}\x1b[0m"
    result = scrub_text(f"pull {styled}\n")
    assert FAKE_GITHUB[:10] not in result.text
    assert FAKE_GITHUB[10:] not in result.text
    assert "[REDACTED:github-token]" in result.text
    # Every SGR sequence is still present, in the original order.
    for seq in ("\x1b[1m", "\x1b[33m", "\x1b[0m"):
        assert seq in result.text
    assert strip_escapes(result.text) == "pull [REDACTED:github-token]\n"


def test_mask_style_preserves_length_and_escape_positions():
    s = f"x \x1b[31m{FAKE_GITHUB}\x1b[0m y"
    result = scrub_text(s, options=ScrubOptions(style="mask"))
    assert len(result.text) == len(s)
    assert result.text.startswith("x \x1b[31m")
    assert result.text.endswith("\x1b[0m y")
    assert "*" * len(FAKE_GITHUB) in result.text
    hashed = scrub_text(FAKE_GITHUB, options=ScrubOptions(style="mask", mask_char="#"))
    assert hashed.text == "#" * len(FAKE_GITHUB)


def test_hash_style_correlates_same_secret_distinguishes_different():
    s = f"first {FAKE_GITHUB} second {FAKE_GITHUB}"
    result = scrub_text(s, options=ScrubOptions(style="hash"))
    tags = [part for part in result.text.split() if part.startswith("[REDACTED")]
    assert len(tags) == 2 and tags[0] == tags[1]
    assert tags[0].startswith("[REDACTED:github-token:")
    other = "ghp_" + "Zx9" * 12
    result2 = scrub_text(f"{FAKE_GITHUB} vs {other}", options=ScrubOptions(style="hash"))
    tags2 = [p for p in result2.text.split() if p.startswith("[REDACTED")]
    assert len(tags2) == 2 and tags2[0] != tags2[1]


def test_invalid_style_and_mask_char_are_rejected():
    with pytest.raises(ValueError):
        ScrubOptions(style="blur")
    with pytest.raises(ValueError):
        ScrubOptions(mask_char="**")


def test_overlapping_findings_resolve_to_one_replacement():
    # `export GITHUB_TOKEN=ghp_...` matches both the assignment rule and the
    # GitHub shape rule on the same span; exactly one placeholder appears,
    # and rules always beat entropy on the same span.
    result = scrub_text(f"export GITHUB_TOKEN={FAKE_GITHUB}")
    assert result.text.count("[REDACTED") == 1
    assert [f.rule for f in result.findings] == ["github-token"]


def test_clean_input_is_byte_identical_and_scrubbing_is_idempotent():
    s = "\x1b[32m$ ls -la\x1b[0m\r\ntotal 0\r\n"
    untouched = scrub_text(s)
    assert untouched.text == s and untouched.findings == []
    once = scrub_text(f"password={FAKE_HIGH_ENTROPY}").text
    twice = scrub_text(once)
    assert twice.text == once
    assert twice.findings == []


def test_osc_window_title_payload_is_scrubbed():
    s = f"\x1b]0;deploy token={FAKE_HIGH_ENTROPY}\x07prompt$ "
    result = scrub_text(s)
    assert FAKE_HIGH_ENTROPY not in result.text
    assert result.text.startswith("\x1b]0;deploy ")
    assert result.text.endswith("\x07prompt$ ")
    assert any(f.origin == "osc" for f in result.findings)


def test_osc8_hyperlink_uri_with_credentials_is_scrubbed():
    s = "\x1b]8;;https://bot:p4ssw0rdX@example.test/\x1b\\link\x1b]8;;\x1b\\"
    result = scrub_text(s)
    assert "p4ssw0rdX" not in result.text
    assert result.text.endswith("\x1b\\link\x1b]8;;\x1b\\")


def test_secret_on_screen_and_in_title_are_both_caught():
    s = f"\x1b]2;{FAKE_GITHUB}\x07echo {FAKE_GITHUB}"
    result = scrub_text(s)
    assert FAKE_GITHUB not in result.text
    assert sorted(f.origin for f in result.findings) == ["osc", "text"]


def test_scan_text_reports_with_safe_previews_only():
    (finding,) = scan_text(f"key {FAKE_GITHUB}")
    assert finding.secret == FAKE_GITHUB
    assert FAKE_GITHUB not in finding.preview()
    assert finding.preview().startswith(FAKE_GITHUB[:4])


def test_allowlist_drops_findings():
    ruleset = RuleSet()
    ruleset.add_allow([r"^ghp_Ab3"])
    result = scrub_text(f"use {FAKE_GITHUB}", ruleset)
    assert result.text == f"use {FAKE_GITHUB}"
    assert result.findings == []


def test_disabling_a_rule_removes_its_findings():
    ruleset = RuleSet()
    ruleset.entropy = EntropyConfig(enabled=False)
    ruleset.disable(["github-token"])
    assert scrub_text(f"use {FAKE_GITHUB}").findings  # default set finds it
    assert scrub_text(f"use {FAKE_GITHUB}", ruleset).findings == []


def test_custom_rule_is_applied():
    ruleset = RuleSet()
    ruleset.add_rule("corp-token", r"CORP-[0-9]{10}", "internal token")
    result = scrub_text("id CORP-0123456789 ok", ruleset)
    assert result.text == "id [REDACTED:corp-token] ok"


def test_scrub_log_attaches_line_and_column_of_the_original():
    text = f"line one\nline two {FAKE_GITHUB}\n"
    (finding,) = scrub_log(text).findings
    assert finding.location == {"line": 2, "column": 10}
    # Columns count original characters, escape bytes included.
    styled = f"\x1b[31mred\x1b[0m {FAKE_GITHUB}\n"
    (finding2,) = scrub_log(styled).findings
    assert finding2.location == {"line": 1, "column": styled.index(FAKE_GITHUB) + 1}


def test_multiple_secrets_on_one_line_all_replaced():
    other = "AKIA" + "IOSFODNN7EXAMPLE"
    result = scrub_text(f"{other} and {FAKE_GITHUB}")
    assert result.text == "[REDACTED:aws-access-key-id] and [REDACTED:github-token]"
