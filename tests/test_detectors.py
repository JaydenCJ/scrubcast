"""Built-in rules: each detector hits its target and spares its near-miss."""

from __future__ import annotations

import re

import pytest

from scrubcast import scan_text
from scrubcast.config import RuleSet
from scrubcast.detectors import BUILTIN_RULES, Rule, looks_like_placeholder
from scrubcast.entropy import EntropyConfig

from conftest import FAKE_AWS_ID, FAKE_GITHUB, FAKE_JWT, FAKE_SLACK, FAKE_STRIPE


def rules_only():
    """A rule set with entropy off, to isolate rule behavior."""
    rs = RuleSet()
    rs.entropy = EntropyConfig(enabled=False)
    return rs


def found(text: str):
    return [(f.rule, f.secret) for f in scan_text(text, rules_only())]


def test_aws_access_key_id_and_secret_key():
    assert found(f"key is {FAKE_AWS_ID} ok") == [("aws-access-key-id", FAKE_AWS_ID)]
    assert found("AKIA too short AKIA123") == []
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert found(f"aws_secret_access_key = {secret}") == [
        ("aws-secret-access-key", secret)
    ]


def test_github_tokens_classic_and_fine_grained():
    assert found(f"push with {FAKE_GITHUB}")[0][0] == "github-token"
    assert found("github_pat_" + "1a" * 15)[0][0] == "github-token"
    assert found("ghp_tooshort") == []


def test_gitlab_slack_tokens_and_webhooks():
    assert found("glpat-" + "x1" * 12)[0][0] == "gitlab-token"
    assert found(FAKE_SLACK)[0][0] == "slack-token"
    assert found("xoxz-0000000000-bad") == []  # unknown token family
    url = "https://hooks.slack.com/services/T0000000/B0000000/XXXXXXXX"
    assert found(f"curl {url}")[0][0] == "slack-webhook"


def test_stripe_and_sk_api_keys():
    assert found(FAKE_STRIPE)[0][0] == "stripe-key"
    assert found("sk-proj-" + "aB1" * 8)[0][0] == "sk-api-key"
    assert found("sk-" + "z9X" * 8)[0][0] == "sk-api-key"
    # "task-..." must not tempt the sk- rule via a mid-word boundary.
    assert found("task-runner-with-a-long-name") == []


def test_google_npm_pypi_sendgrid_age_shapes():
    assert found("AIza" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r")[0][0] == "google-api-key"
    assert found("npm_" + "a1B2" * 9)[0][0] == "npm-token"
    assert found("pypi-AgE" + "Ab1" * 20)[0][0] == "pypi-token"
    assert found("SG." + "a1" * 10 + "." + "b2" * 16)[0][0] == "sendgrid-key"
    assert found("AGE-SECRET-KEY-1" + "Q2" * 29)[0][0] == "age-secret-key"


def test_jwt_three_segments_required():
    assert found(f"jwt {FAKE_JWT}")[0][0] == "jwt"
    assert found("eyJhbGciOiJIUzI1NiJ9.only-two-segments") == []


def test_private_key_block_spans_lines_even_unterminated():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\nAB12==\n-----END RSA PRIVATE KEY-----"
    assert found(f"before\n{pem}\nafter") == [("private-key-block", pem)]
    # A recording cut off mid-key must not leak the beginning of it.
    cut = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA=="
    hits = found(cut)
    assert hits and hits[0][0] == "private-key-block"


def test_authorization_header_redacts_only_the_value():
    hits = found("Authorization: Bearer abc123DEF456ghi789")
    assert hits == [("authorization-header", "abc123DEF456ghi789")]
    assert found("Authorization: Bearer") == []


def test_url_userinfo_password():
    hits = found("fetch https://alice:s3cr3tPW@example.test/repo.git")
    assert hits == [("url-userinfo", "s3cr3tPW")]
    assert found("https://example.test/no-credentials") == []


def test_secret_assignment_env_prefixes_yes_lookalikes_no():
    assert found("export API_SECRET=Zq3xVb9T") == [("secret-assignment", "Zq3xVb9T")]
    assert found("DB_PASSWORD: 'p4ssw0rd!'") == [("secret-assignment", "p4ssw0rd!")]
    assert found("monkey=banana123456") == []  # keyword must follow a separator
    assert found("token=short") == []  # under 6 chars


def test_placeholder_values_are_not_re_redacted():
    assert found("password=[REDACTED:secret-assignment]") == []
    assert found("password=<your-password-here>") == []
    assert found("password=${DB_PASSWORD}") == []
    assert found("password=********") == []
    assert looks_like_placeholder("") and looks_like_placeholder("ChangeMe")
    assert not looks_like_placeholder("Zq3xVb9T")


def test_rule_names_are_unique_kebab_case_and_validated():
    names = [rule.name for rule in BUILTIN_RULES]
    assert len(names) == len(set(names))
    for name in names:
        assert re.fullmatch(r"[a-z0-9][a-z0-9-]*", name)
    with pytest.raises(ValueError):
        Rule("Bad Name", "x", re.compile("x"))
