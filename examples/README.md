# coalmine examples

Runnable scripts that exercise the two-command loop end to end. Each builds
`coalmine` from source into a temp dir, so they never touch your `$PATH` or
leave a registry behind.

| Script | What it shows |
|---|---|
| `plant-and-scan.sh` | The canonical flow: plant a canary in a prompt, then catch it leaking in a fabricated log across several obfuscation channels. |
| `ci-gate.sh` | Using `coalmine scan` as a policy gate whose exit code fails a CI job when a system prompt leaks. |

```bash
bash examples/plant-and-scan.sh
bash examples/ci-gate.sh
```

Both print their own steps and finish quickly with no network access.
