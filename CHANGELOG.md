# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-13

### Added

- Escape-sequence-aware scrubbing engine: input is tokenized into text and
  ANSI escape sequences (CSI incl. 8-bit `0x9B`, OSC with BEL/ST terminators,
  DCS/SOS/PM/APC, short `ESC x` and nF forms, truncated sequences), detection
  runs on the escape-free plain view, and replacement is applied back through
  an index map so escape bytes are never modified.
- 18 built-in detection rules: AWS key id/secret, GitHub, GitLab, Slack
  (tokens and webhooks), Stripe, `sk-` model-provider keys, Google, npm,
  PyPI, SendGrid, age, JWTs, multi-line PEM private-key blocks (including
  recordings cut off mid-key), `Authorization:` header values, URL userinfo
  passwords, and generic `KEY=value` credential assignments.
- Entropy detector for unknown secret shapes: ≥20-char candidates split at
  interior `=`, letter+digit requirement, ≥4.0 bits/char for mixed alphabets,
  and a keyword-context requirement for pure-hex candidates so git SHAs,
  docker digests, and UUIDs in ordinary output stay quiet.
- asciicast v2 support: `"o"` and `"i"` streams are each scrubbed as one
  logical string, so secrets and escape sequences split across events are
  caught; event count, order, codes, and timestamps are preserved and the
  output remains playable. Header `title`, `command`, and `env` values are
  scrubbed too, and OSC payloads (window titles, `OSC 8` hyperlink URIs)
  get their own pass.
- Three replacement styles: `label` (`[REDACTED:rule]`), `hash` (stable
  truncated-digest tag for grep-able correlation), and `mask`
  (length-preserving, keeps column alignment). Scrubbing is idempotent —
  placeholders are never re-redacted.
- JSON rules files: custom rules, disabling built-ins, allowlist regexes,
  and entropy overrides, all validated with precise error messages.
- `scrubcast` CLI: `scrub` (stdout, `-o`, or `--in-place`; findings summary
  on stderr), `scan` (exit 1 on findings — a CI/pre-share gate), and `rules`;
  `--format auto|cast|log` sniffing, `--json` reports that never contain
  secret material, and per-finding locations (line/column for logs, event
  and timestamp for casts).
- Runnable examples (`examples/`): a leaky recording, a colored CI log, and
  a rules file, all exercised verbatim by the tests and the smoke script.
- 91 offline deterministic tests plus `scripts/smoke.sh` (prints `SMOKE OK`).

### Notes

- The repository ships no CI workflow; verification is local —
  `pip install -e '.[dev]' && pytest && bash scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/scrubcast/releases/tag/v0.1.0
