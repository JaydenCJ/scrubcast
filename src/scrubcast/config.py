"""Rule-set assembly: built-ins, user rules files, allowlists.

A rules file is plain JSON (an example ships in ``examples/``):

.. code-block:: json

    {
      "rules":  [{"name": "corp-token", "pattern": "CORP-[0-9]{10}"}],
      "disable": ["jwt"],
      "allow":  ["EXAMPLE_[A-Z0-9]+"],
      "entropy": {"min_length": 24, "threshold": 4.2}
    }

``rules`` adds detectors, ``disable`` removes built-ins by name, ``allow``
drops any finding whose secret matches one of the regexes, and ``entropy``
overrides fields of :class:`scrubcast.entropy.EntropyConfig`.
"""

from __future__ import annotations

import dataclasses
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Pattern, Union

from .detectors import BUILTIN_RULES, Rule
from .entropy import EntropyConfig
from .errors import ConfigError

__all__ = ["RuleSet", "default_ruleset", "load_rules_file"]

_ENTROPY_FIELDS = {f.name for f in dataclasses.fields(EntropyConfig)}


@dataclass
class RuleSet:
    """The complete detection configuration used by the engine."""

    rules: List[Rule] = field(default_factory=lambda: list(BUILTIN_RULES))
    allow: List[Pattern[str]] = field(default_factory=list)
    entropy: EntropyConfig = field(default_factory=EntropyConfig)

    def allows(self, secret: str) -> bool:
        """True if ``secret`` matches an allowlist pattern (drop finding)."""
        return any(p.search(secret) for p in self.allow)

    def rule_names(self) -> List[str]:
        return [rule.name for rule in self.rules]

    def disable(self, names: Iterable[str]) -> None:
        """Remove rules by name; unknown names raise :class:`ConfigError`."""
        wanted = list(names)
        known = set(self.rule_names())
        for name in wanted:
            if name not in known:
                raise ConfigError(
                    f"cannot disable unknown rule {name!r}; "
                    f"known rules: {', '.join(sorted(known))}"
                )
        drop = set(wanted)
        self.rules = [rule for rule in self.rules if rule.name not in drop]

    def add_allow(self, patterns: Iterable[str]) -> None:
        for raw in patterns:
            self.allow.append(_compile(raw, where="allow pattern"))

    def add_rule(self, name: str, pattern: str, description: str = "") -> None:
        if name in self.rule_names():
            raise ConfigError(f"duplicate rule name {name!r}")
        try:
            rule = Rule(name, description or "user-defined rule", _compile(pattern, where=f"rule {name!r}"))
        except ValueError as exc:
            raise ConfigError(str(exc)) from None
        self.rules.append(rule)


def _compile(raw: str, *, where: str) -> Pattern[str]:
    try:
        return re.compile(raw)
    except re.error as exc:
        raise ConfigError(f"invalid regex in {where}: {exc}") from None


def default_ruleset() -> RuleSet:
    """A fresh rule set with every built-in rule and default entropy config."""
    return RuleSet()


def load_rules_file(path: Union[str, Path], base: Optional[RuleSet] = None) -> RuleSet:
    """Load a JSON rules file on top of ``base`` (default: the built-ins)."""
    ruleset = base if base is not None else default_ruleset()
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read rules file {path}: {exc}") from None
    except json.JSONDecodeError as exc:
        raise ConfigError(f"rules file {path} is not valid JSON: {exc}") from None
    if not isinstance(data, dict):
        raise ConfigError(f"rules file {path} must contain a JSON object")
    unknown = set(data) - {"rules", "disable", "allow", "entropy"}
    if unknown:
        raise ConfigError(f"unknown keys in rules file {path}: {', '.join(sorted(unknown))}")

    for entry in _expect_list(data, "rules", path):
        if not isinstance(entry, dict) or "name" not in entry or "pattern" not in entry:
            raise ConfigError(f'each rule in {path} needs "name" and "pattern"')
        ruleset.add_rule(
            str(entry["name"]), str(entry["pattern"]), str(entry.get("description", ""))
        )
    disable = [str(name) for name in _expect_list(data, "disable", path)]
    if disable:
        ruleset.disable(disable)
    ruleset.add_allow(str(p) for p in _expect_list(data, "allow", path))

    entropy_overrides = data.get("entropy", {})
    if entropy_overrides:
        if not isinstance(entropy_overrides, dict):
            raise ConfigError(f'"entropy" in {path} must be an object')
        bad = set(entropy_overrides) - _ENTROPY_FIELDS
        if bad:
            raise ConfigError(
                f"unknown entropy settings in {path}: {', '.join(sorted(bad))}"
            )
        ruleset.entropy = dataclasses.replace(ruleset.entropy, **entropy_overrides)
    return ruleset


def _expect_list(data: dict, key: str, path: Path) -> list:
    value = data.get(key, [])
    if not isinstance(value, list):
        raise ConfigError(f'"{key}" in {path} must be an array')
    return value
