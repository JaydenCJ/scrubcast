# Contributing to scrubcast

Thanks for your interest in contributing. Issues, discussions, and pull
requests are all welcome.

## Development setup

Python ≥ 3.9, nothing else — the runtime has zero dependencies.

```bash
git clone https://github.com/JaydenCJ/scrubcast
cd scrubcast
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Running the checks

```bash
pytest                 # 91 unit + integration tests, fully offline
bash scripts/smoke.sh  # end-to-end: scrub, playability check, CI gate
```

Both must pass before a pull request is reviewed; `scripts/smoke.sh` must
print `SMOKE OK`. Everything runs offline and needs no credentials of any
kind — every "secret" in the tree is a fake assembled at runtime.

## Before you open a pull request

1. Format and lint if you have the tools handy (`ruff format`, `ruff check`);
   keep the code PEP 8-shaped either way.
2. `pytest` must pass.
3. `bash scripts/smoke.sh` must print `SMOKE OK`.
4. Add tests for behavior changes; keep logic in pure, unit-testable modules.
5. New detection rules need a hit case, a near-miss case, and a one-line
   description shown by `scrubcast rules`.

## Ground rules

- **No new runtime dependencies.** The package is standard-library only;
  that is a feature. Test-only dependencies belong in the `dev` extra.
- **No network calls, ever.** scrubcast handles secret material; it must be
  auditable at a glance as a tool that sends nothing anywhere.
- **Never weaken playability.** Any change to replacement must keep the
  invariants in `docs/redaction-model.md`: escape bytes untouched, cast
  event count/timestamps preserved, `mask` style length-preserving.
- **No real secrets in tests or fixtures** — assemble fakes at runtime or
  use documented example values, as `tests/conftest.py` does.
- Code comments and doc comments are written in English.

## Reporting bugs

Include the scrubcast version (`scrubcast --version`), the exact command,
and a minimal input that reproduces the issue — after running it through
`scrubcast scrub` so you do not paste the very secret you found. False
positives and false negatives of specific rules are bugs too; name the rule.

## Security

Do not report vulnerabilities in public issues. Use GitHub private
vulnerability reporting on this repository instead.
