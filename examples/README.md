# scrubcast examples

Everything here is fake: tokens are made-up strings in real-world *shapes*
(the AWS values are the official documentation examples). The files exist so
you can try every code path without recording anything yourself.

| File | What it shows |
|---|---|
| `demo.cast` | An asciicast v2 recording that leaks a GitHub token, a JWT split across two events, an AWS secret key inside an OSC window title, and an AWS key id wrapped in bold SGR codes |
| `ci-log.txt` | A colored CI log leaking an AWS key id, a Slack webhook URL, and a hex session token (caught by entropy + keyword context) |
| `scrubcast-rules.json` | A rules file: one custom rule, one disabled built-in, an allowlist entry, entropy overrides |

## Try it

From the repository root (no install needed, zero dependencies):

```bash
export PYTHONPATH=src

# Scrub the recording; the output plays back fine in any asciicast player.
python3 -m scrubcast scrub examples/demo.cast -o /tmp/clean.cast

# Gate a CI log: exit code 1 because it leaks.
python3 -m scrubcast scan examples/ci-log.txt; echo "exit: $?"

# Length-preserving masking keeps column alignment intact.
python3 -m scrubcast scrub examples/ci-log.txt --style mask

# Apply the custom rules file.
python3 -m scrubcast scan examples/ci-log.txt --rules examples/scrubcast-rules.json
```

Both example files are also exercised verbatim by
`tests/test_readme_examples.py` and `scripts/smoke.sh`, so they can never
drift from what the README claims.
