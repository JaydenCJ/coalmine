# Contributing to coalmine

Issues, discussions and pull requests are all welcome.

## Getting started

You need Go ≥1.22 and a POSIX shell for the smoke script; nothing else.

```bash
git clone https://github.com/JaydenCJ/coalmine && cd coalmine
go build ./...
go test ./...
bash scripts/smoke.sh
```

`scripts/smoke.sh` builds the binary, plants a canary in a real system
prompt, fabricates leaky and clean logs, and asserts on the CLI output and
exit codes across every subcommand; it must finish by printing `SMOKE OK`.

## Before you open a pull request

1. `gofmt -l .` reports nothing (formatting is enforced).
2. `go vet ./...` passes with no findings.
3. `go test ./...` passes (90 deterministic tests, no network).
4. `bash scripts/smoke.sh` prints `SMOKE OK`.
5. Add tests for behavior changes; keep logic in pure, unit-testable
   modules (token, normalize, variant, scan, store never talk to a terminal
   — only the `cli` package does).

## Ground rules

- Keep dependencies at zero; adding one needs strong justification in the PR.
- No network calls, ever — coalmine reads only the files you name and sends
  nothing anywhere. No telemetry.
- Detection channels are data: a new obfuscation channel adds a needle in
  `internal/variant/variant.go` with a test proving the transformed token
  actually matches, and a row in `docs/detection.md`.
- Code comments and doc comments are written in English.
- Determinism first: identical input must produce byte-identical reports,
  including all orderings.

## Reporting bugs

Include the output of `coalmine version`, the exact command you ran, and —
for a missed leak or a false positive — a minimal snippet of the scanned
text and the canary token shape (never a live token from production). A
misclassification report is only actionable with the input the scanner saw.

## Security

Please do not open public issues for security problems; use GitHub's private
vulnerability reporting on this repository instead. Note that a real
`coalmine.json` registry contains live canary tokens — treat it as a secret
and never attach one to an issue.
