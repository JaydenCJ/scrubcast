"""Rules files and rule-set assembly: happy paths and every failure mode."""

from __future__ import annotations

import json

import pytest

from scrubcast import ConfigError, load_rules_file, scrub_text
from scrubcast.config import RuleSet, default_ruleset


def write_rules(tmp_path, payload) -> str:
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def test_default_ruleset_is_a_fresh_copy_each_time():
    a, b = default_ruleset(), default_ruleset()
    a.disable(["jwt"])
    assert "jwt" in b.rule_names()  # b unaffected


def test_load_adds_custom_rules(tmp_path):
    path = write_rules(
        tmp_path, {"rules": [{"name": "corp-token", "pattern": "CORP-[0-9]{10}"}]}
    )
    ruleset = load_rules_file(path)
    assert scrub_text("CORP-1234567890", ruleset).text == "[REDACTED:corp-token]"


def test_load_disable_and_allow(tmp_path):
    path = write_rules(
        tmp_path, {"disable": ["jwt"], "allow": ["EXAMPLE_[A-Z0-9]+"]}
    )
    ruleset = load_rules_file(path)
    assert "jwt" not in ruleset.rule_names()
    assert ruleset.allows("EXAMPLE_ABC123")
    assert not ruleset.allows("other-value")


def test_load_entropy_overrides_keep_untouched_defaults(tmp_path):
    path = write_rules(tmp_path, {"entropy": {"min_length": 30, "threshold": 4.5}})
    ruleset = load_rules_file(path)
    assert ruleset.entropy.min_length == 30
    assert ruleset.entropy.threshold == 4.5
    assert ruleset.entropy.enabled is True


def test_unreadable_inputs_raise_config_error(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        load_rules_file(tmp_path / "nope.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid JSON"):
        load_rules_file(bad)
    top = tmp_path / "list.json"
    top.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ConfigError, match="JSON object"):
        load_rules_file(top)


def test_unknown_keys_rejected_at_top_level_and_in_entropy(tmp_path):
    path = write_rules(tmp_path, {"rulez": []})
    with pytest.raises(ConfigError, match="unknown keys"):
        load_rules_file(path)
    entropy = write_rules(tmp_path, {"entropy": {"strictness": 11}})
    with pytest.raises(ConfigError, match="unknown entropy settings"):
        load_rules_file(entropy)


def test_incomplete_and_duplicate_rules_rejected(tmp_path):
    path = write_rules(tmp_path, {"rules": [{"name": "x"}]})
    with pytest.raises(ConfigError, match='"name" and "pattern"'):
        load_rules_file(path)
    dup = write_rules(tmp_path, {"rules": [{"name": "jwt", "pattern": "x"}]})
    with pytest.raises(ConfigError, match="duplicate rule name"):
        load_rules_file(dup)


def test_bad_regexes_rejected_with_context(tmp_path):
    path = write_rules(tmp_path, {"rules": [{"name": "broken", "pattern": "["}]})
    with pytest.raises(ConfigError, match="invalid regex"):
        load_rules_file(path)
    allow = write_rules(tmp_path, {"allow": ["("]})
    with pytest.raises(ConfigError, match="allow pattern"):
        load_rules_file(allow)


def test_disable_unknown_rule_lists_known_ones():
    ruleset = RuleSet()
    with pytest.raises(ConfigError, match="unknown rule 'nope'"):
        ruleset.disable(["nope"])
