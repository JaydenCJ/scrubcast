"""The shipped example files behave exactly as the README advertises."""

from __future__ import annotations

import json
from pathlib import Path

from scrubcast import parse_cast, scrub_cast, scrub_log

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_demo_cast_scrubs_all_four_leaks_and_stays_playable():
    text = (EXAMPLES / "demo.cast").read_text(encoding="utf-8")
    out, findings = scrub_cast(text)
    assert sorted(f.rule for f in findings) == [
        "aws-access-key-id",
        "aws-secret-access-key",
        "github-token",
        "jwt",
    ]
    # No secret material survives anywhere in the output document.
    for finding in findings:
        assert finding.secret not in out
    # Still a valid asciicast: same event count, same timestamps, and the
    # bold SGR pair around the AWS key id is intact.
    before, after = parse_cast(text), parse_cast(out)
    assert [e[0] for e in after.events] == [e[0] for e in before.events]
    styled = after.events[9][2]
    assert "\x1b[1m" in styled and "\x1b[0m" in styled
    assert "[REDACTED:aws-access-key-id]" in styled
    # The JWT is split across events 4 and 5: the placeholder lands in the
    # event where the secret starts and the follow-on event survives, empty,
    # so playback timing is untouched — exactly what the README shows.
    (jwt,) = [f for f in findings if f.rule == "jwt"]
    assert jwt.location["event"] == 4
    assert after.events[4][2] == "[REDACTED:jwt]"
    assert after.events[5][2] == ""


def test_ci_log_scrubs_rule_and_entropy_hits_keeping_colors():
    text = (EXAMPLES / "ci-log.txt").read_text(encoding="utf-8")
    result = scrub_log(text)
    rules = sorted(f.rule for f in result.findings)
    assert rules == ["aws-access-key-id", "entropy", "slack-webhook"]
    for finding in result.findings:
        assert finding.secret not in result.text
    # Colors and layout survive: same line count, SGR sequences intact.
    assert result.text.count("\n") == text.count("\n")
    assert "\x1b[32m" in result.text and "\x1b[31m" in result.text
    # The rules file example parses and is applied cleanly.
    from scrubcast import load_rules_file, scrub_text

    ruleset = load_rules_file(EXAMPLES / "scrubcast-rules.json")
    assert "jwt" not in ruleset.rule_names()
    assert scrub_text("CORP-1234567890", ruleset).text == "[REDACTED:corp-build-token]"
    assert json.loads((EXAMPLES / "scrubcast-rules.json").read_text())["disable"] == ["jwt"]
