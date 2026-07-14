# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-12

### Added

- Canary token format: `CM` prefix + 80-bit Crockford-base32 payload +
  2-character checksum, with generation from an injectable randomness
  source and validation that rejects single-character substitutions and
  adjacent transpositions.
- `plant` subcommand: embeds a canary into a system prompt via the `rule`,
  `comment`, `bare`, or a custom `{token}` template, at the start or end,
  and registers it in an atomically-written, 0600 JSON registry keyed by a
  stable 8-character id and prompt SHA-256.
- `scan` subcommand: detection across obfuscation channels — exact
  (case/zero-width/homoglyph/fullwidth/Crockford-ambiguity tolerant),
  separator-stuffed, base64 (every byte offset, incl. URL-safe), hex,
  ROT13, reversed, percent-encoding, and contiguous partial fragments — with
  exact `line:col` locations, quoted excerpts, and text or JSON
  (`schema_version: 1`) output.
- Three normalized haystack views (raw, folded, condensed) with
  byte-accurate offset maps, so obfuscated matches still report true source
  locations.
- `--fail-on any|high|never` exit-code gate, `--min-fragment` control,
  `--all` to include revoked canaries, `--max-file-size`, binary and `.git`
  skipping, and self-exclusion of the registry file.
- `list`, `revoke`, `gen`, and `version` subcommands.
- Runnable examples (`examples/plant-and-scan.sh`, `examples/ci-gate.sh`), a
  detection-channel reference (`docs/detection.md`), and `scripts/smoke.sh`.
- 90 deterministic offline tests (unit + in-process CLI integration against
  fabricated prompts and logs).

[0.1.0]: https://github.com/JaydenCJ/coalmine/releases/tag/v0.1.0
