# Detection channels

coalmine's detection is deterministic and rule-based. A canary token is a
20-character string (`CM` + 16 Crockford-base32 payload characters +
2 checksum characters) carrying 80 bits of entropy, so any match is a real
leak rather than a coincidence. This document explains exactly what the
scanner looks for and why each channel exists.

## Haystack views

Before matching, each document is projected into three views. Needles are
searched in whichever view makes their channel robust; every view keeps a
byte-accurate offset map back to the original text so findings report true
`line:col` locations.

| View | Transformation | Purpose |
|---|---|---|
| `raw` | none | case-sensitive base64 needles |
| `folded` | strip zero-width chars, map homoglyphs and fullwidth forms to ASCII, uppercase, fold Crockford-ambiguous `I`/`L`→`1` and `O`→`0` | case, Unicode, and glyph obfuscation |
| `condensed` | `folded`, then strip whitespace and separator punctuation | tokens spelled out with spaces or hyphens |

## Channels

Each planted canary is expanded once into a fixed set of literal needles;
scanning is then a plain substring search, so adding channels never slows
the hot path.

| Channel | What it catches | Example (token `CM7Q3KXN4TP2A9ZR6WB0`) | Confidence |
|---|---|---|---|
| `exact` | the token verbatim, tolerant of case, zero-width padding, homoglyphs, and Crockford ambiguity | `...marker is CM7Q3KXN4TP2A9ZR6WB0.` | high |
| `exact` (condensed) | the token spelled out with separators | `C M 7 Q 3 K X N ...` | medium |
| `base64` | the token inside any base64 or URL-safe base64 stream, at every byte offset | `Q003UTNLWE40...` | high |
| `hex` | hex-encoded bytes, upper or lower case | `434d3751334b...` | high |
| `rot13` | the classic "rotate the letters" trick | `PZ7D3XKA4GC2...` | high |
| `reversed` | the token spelled backwards | `0BW6RZ9A2PT4...` | high |
| `percent` | URL percent-encoding of every byte | `%43%4D%37%51...` | high |
| `fragment` | a contiguous partial leak of at least `--min-fragment` characters (default 12) | `...starts with CM7Q3KXN4TP2A9` | medium |

### base64 at every offset

A token embedded inside a larger base64 blob starts at byte offset 0, 1, or
2 relative to the encoding's 3-byte groups. For each offset coalmine encodes
the token with that many leading pad bytes and slices out the characters
that are fully determined by the token itself — three ~26-character needles
that match no matter what surrounds the token. Because token bytes are
alphanumeric ASCII, the needles never contain `+` or `/`, so the same three
literals also match URL-safe base64.

### Fragments

Full-token channels miss a model that leaks only the first half of the
prompt. The fragment channel finds the longest contiguous run of the
document that is a substring of the folded token, reporting it as a
medium-confidence finding annotated with how many characters were
recovered. The `--min-fragment` floor (default 12, minimum 8) keeps short
coincidental runs out of the results; `--min-fragment 0` disables the
channel entirely.

## Confidence and gating

`high` findings come from unambiguous whole-token transformations; `medium`
findings come from aggressive normalization (separator stuffing) or partial
recovery (fragments). `coalmine scan --fail-on high` gates CI on high-
confidence leaks only, while still printing the medium ones for review.

## What coalmine does not do

- It never inspects code *content* or guesses — every finding quotes the
  exact text that matched.
- It does not attempt semantic paraphrase detection; a model that describes
  its instructions in its own words without reproducing the token is out of
  scope by design (that is what the token is *for*).
- It sends nothing anywhere. The only files it reads are the ones you name.
