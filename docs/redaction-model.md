# The scrubcast redaction model

This document explains *how* scrubcast rewrites terminal data without
breaking it. It is the design contract behind the "scrubbed recordings stay
playable" claim; the test suite enforces every property stated here.

## 1. Two views of the same bytes

Terminal output is a mixture of **text** (what the terminal renders) and
**escape sequences** (how it renders it: SGR colors, cursor movement, OSC
window titles and hyperlinks). scrubcast tokenizes the input into exactly
those two families (`src/scrubcast/ansi.py`), recognizing:

| Family | Forms |
|---|---|
| CSI | `ESC [ params intermediates final`, plus the 8-bit `0x9B` introducer |
| OSC | `ESC ] payload` terminated by `BEL` or `ESC \` |
| DCS / SOS / PM / APC | `ESC P/X/^/_ ... ESC \` |
| Short escapes | `ESC 7`, `ESC =`, `ESC ( B`, other nF/Fp/Fe/Fs forms |
| Text | everything else, **including** bare `\r`, `\n`, `\b` |

Bare control characters stay in the text stream deliberately: a carriage
return between two runs of characters means they were rendered at different
screen positions, and a secret pattern must never match "across" one.
Truncated sequences (a chunk that ends mid-`ESC [`) are consumed as escape
tokens, never leaked into text.

From the tokens scrubcast derives the **plain view**: the concatenated text
content plus an index map `plain[i] -> original[j]`. Detection runs on the
plain view — so a token interrupted by `\x1b[33m` is contiguous and
matchable — and replacement is applied back through the map, so escape
bytes are never touched.

## 2. Detection: rules, then entropy

1. Every rule regex (built-in + user rules) runs over the plain view. A rule
   with a `(?P<secret>...)` group redacts only that group, keeping context
   like `Authorization:` readable. Overlaps resolve leftmost-longest.
2. The entropy detector proposes candidates that no rule claimed: runs of
   base64-ish characters at least 20 chars long, split at interior `=` so a
   `KEY=value` run only flags the value. Mixed-alphabet candidates need
   letters *and* digits plus ≥4.0 bits/char; pure-hex candidates (git SHAs,
   docker digests, UUIDs) additionally require a credential keyword within
   the previous 40 chars, which is what keeps ordinary build output quiet.
3. Findings matching an allowlist pattern are dropped. Assignment-style
   rules skip values that are already placeholders (`[REDACTED:...]`,
   `<...>`, `${...}`, `*****`), which makes scrubbing idempotent.

## 3. Replacement: the emission table

The engine builds one output string *per original character*
(`plan_emissions` in `src/scrubcast/engine.py`):

- untouched characters emit themselves;
- with `--style mask`, every matched text character emits the mask
  character — byte length and column alignment are preserved exactly;
- with `label`/`hash`, the *first* matched text character emits the
  placeholder and the rest emit nothing — escape sequences between them are
  left in place, so the terminal's styling state stays correct.

OSC payloads (window titles, `OSC 8` hyperlink URIs) never reach the plain
view, so they get their own scan-and-replace pass inside the token.

## 4. Why casts stay playable

An asciicast v2 event stream is scrubbed as **one logical string per
stream** (`"o"` and `"i"` joined separately, in order). That solves both
split-secret cases at once: a token echoed keystroke by keystroke and an
escape sequence flushed across two events are each whole in the joined
stream. The emission table is then sliced back per event:

- event **count, order, codes, and timestamps** are byte-identical;
- an event whose payload was entirely swallowed by a placeholder becomes
  `""` but still exists, so timing is unchanged;
- header `title`, `command`, and `env` values are scrubbed field by field.

The result parses as asciicast v2 and plays back exactly like the original,
minus the secrets.

## 5. Placeholder styles

| Style | Output | Property |
|---|---|---|
| `label` (default) | `[REDACTED:github-token]` | readable, explains what was removed |
| `hash` | `[REDACTED:github-token:1a2b3c4d]` | same secret ⇒ same tag: grep-able correlation across a log. The tag is the first 8 hex chars of an unsalted SHA-256, so treat it as a correlation id, not as encryption |
| `mask` | `****************` | length-preserving: column alignment and cast byte-timing layout survive |
