"""Entropy detector: catches raw randomness, spares everyday terminal noise."""

from __future__ import annotations

import pytest

from scrubcast.entropy import (
    EntropyConfig,
    entropy_spans,
    iter_entropy_candidates,
    shannon_entropy,
)

from conftest import FAKE_HIGH_ENTROPY

CFG = EntropyConfig()


def hits(text: str, config: EntropyConfig = CFG):
    return [text[a:b] for a, b, _ in iter_entropy_candidates(text, config)]


def test_shannon_entropy_math():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abababab") == pytest.approx(1.0)
    assert shannon_entropy("abcdefgh") == pytest.approx(3.0)  # log2(8)


def test_random_mixed_token_is_flagged_with_offsets():
    text = f"generated value {FAKE_HIGH_ENTROPY} ok"
    ((start, end, bits),) = entropy_spans(text, CFG)
    assert text[start:end] == FAKE_HIGH_ENTROPY
    assert bits > 4.0


def test_base64_blob_is_flagged_with_padding_attached():
    blob = "QmFzZTY0IHNlY3JldCBkYXRhIGhlcmU9PQ=="
    assert hits(f"payload {blob}") == [blob]
    padded = "Zq3xVb9TkLm2Pw8RsYd4Jf6H=="
    assert hits(f"data {padded}") == [padded]


def test_short_candidates_are_ignored_and_min_length_is_configurable():
    assert hits("id Zq3xVb9TkLm2Pw8R") == []  # 16 chars < min_length 20
    cfg = EntropyConfig(min_length=40)
    assert hits(f"x {FAKE_HIGH_ENTROPY}", cfg) == []  # 32 < 40


def test_prose_and_digitless_identifiers_never_flag():
    assert hits("internationalization-configuration-management pipeline done") == []
    # High-entropy letters but no digit: long camelCase identifiers survive.
    assert hits("call QzWxEcRvTbYnUmIoPaSdFgHj now") == []


def test_bare_hex_digests_are_not_flagged():
    # git SHAs and docker digests are everywhere in terminal output.
    assert hits("commit 8f14e45fceea167a5a36dedd4bea254345678901") == []
    digest = "a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
    assert hits(f"pulled sha256 {digest} done") == []


def test_hex_with_credential_keyword_context_is_flagged():
    sha_like = "8f14e45fceea167a5a36dedd4bea254345678901"
    assert hits(f"session token {sha_like}") == [sha_like]


def test_uuid_requires_context_too():
    uuid = "550e8400-e29b-41d4-a716-446655440000"
    assert hits(f"request id {uuid}") == []
    assert hits(f"api key {uuid}") == [uuid]


def test_structural_skips_paths_and_repeats():
    assert hits("ran /opt/example/bin/build-2024/artifact9 fine") == []
    assert hits("pad " + "A" * 32) == []


def test_key_equals_value_run_only_flags_the_value():
    text = f"CUSTOM_BLOB={FAKE_HIGH_ENTROPY}"
    assert hits(text) == [FAKE_HIGH_ENTROPY]


def test_disabled_config_yields_nothing():
    cfg = EntropyConfig(enabled=False)
    assert hits(f"x {FAKE_HIGH_ENTROPY}", cfg) == []


def test_context_bonus_lowers_the_threshold():
    # A borderline candidate that misses the threshold cold but passes once
    # a credential keyword appears just before it.
    borderline = "abcdefghij0123456789"  # 20 distinct chars: log2(20) ≈ 4.32
    cfg = EntropyConfig(threshold=4.4, context_bonus=0.5)
    assert hits(f"see {borderline}", cfg) == []
    assert hits(f"secret {borderline}", cfg) == [borderline]
