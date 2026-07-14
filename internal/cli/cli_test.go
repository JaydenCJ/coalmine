// In-process CLI integration tests: every subcommand is driven through
// Run() with injected streams, a temp working area, and pinned randomness,
// so the full plant→scan→gate loop is exercised without a real terminal.
package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JaydenCJ/coalmine/internal/token"
	"github.com/JaydenCJ/coalmine/internal/version"
)

const (
	tok  = "CM7Q3KXN4TP2A9ZR6WB0"
	tok2 = "CM4TQ7XKN2P9A3ZR6WWG"
)

// run invokes the CLI in-process and captures both streams.
func run(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code = Run(args, strings.NewReader(stdin), &out, &errBuf)
	return code, out.String(), errBuf.String()
}

// pinRandomness makes gen/plant deterministic for one test.
func pinRandomness(t *testing.T) {
	t.Helper()
	prev := randReader
	seed := make([]byte, 256)
	for i := range seed {
		seed[i] = byte(i*13 + 7)
	}
	randReader = bytes.NewReader(seed)
	t.Cleanup(func() { randReader = prev })
}

// pinClock freezes timestamps for one test.
func pinClock(t *testing.T) {
	t.Helper()
	prev := now
	now = func() time.Time { return time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { now = prev })
}

// storeIn returns a store path inside a fresh temp dir.
func storeIn(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "coalmine.json")
}

func plantFixture(t *testing.T, storePath, tk, label string) string {
	t.Helper()
	code, out, stderr := run(t, "You are a helpful bot.\n",
		"plant", "--store", storePath, "--label", label, "--token", tk, "-")
	if code != ExitOK {
		t.Fatalf("plant failed (%d): %s", code, stderr)
	}
	return out
}

func TestVersionSubcommandAndFlag(t *testing.T) {
	for _, argv := range [][]string{{"version"}, {"--version"}, {"-v"}} {
		code, out, _ := run(t, "", argv...)
		if code != ExitOK || out != "coalmine "+version.Version+"\n" {
			t.Errorf("%v -> (%d, %q)", argv, code, out)
		}
	}
}

func TestUsageSurface(t *testing.T) {
	code, out, _ := run(t, "", "help")
	if code != ExitOK || !strings.Contains(out, "plant") || !strings.Contains(out, "scan") {
		t.Fatalf("help = (%d, %q)", code, out)
	}
	code, _, stderr := run(t, "")
	if code != ExitUsage || !strings.Contains(stderr, "usage") {
		t.Fatalf("empty argv = (%d, %q)", code, stderr)
	}
	code, _, stderr = run(t, "", "explode")
	if code != ExitUsage || !strings.Contains(stderr, "explode") {
		t.Fatalf("unknown command = (%d, %q)", code, stderr)
	}
	// Explicitly requested help is success, not a usage error — matching
	// the flag package's own ExitOnError convention.
	code, _, stderr = run(t, "", "scan", "-h")
	if code != ExitOK || !strings.Contains(stderr, "-fail-on") {
		t.Fatalf("scan -h = (%d, %q)", code, stderr)
	}
	// An actually unknown flag is still a usage error.
	if code, _, _ := run(t, "", "scan", "--bogus"); code != ExitUsage {
		t.Fatalf("scan --bogus exit %d, want %d", code, ExitUsage)
	}
}

func TestGenEmitsValidDistinctTokens(t *testing.T) {
	pinRandomness(t)
	code, out, _ := run(t, "", "gen", "--count", "3")
	if code != ExitOK {
		t.Fatalf("gen exit %d", code)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("gen printed %d lines", len(lines))
	}
	seen := map[string]bool{}
	for _, l := range lines {
		if !token.Valid(l) {
			t.Errorf("invalid token %q", l)
		}
		if seen[l] {
			t.Errorf("duplicate token %q", l)
		}
		seen[l] = true
	}
	if code, _, _ := run(t, "", "gen", "--count", "0"); code != ExitUsage {
		t.Errorf("gen --count 0 exit %d, want %d", code, ExitUsage)
	}
}

func TestPlantStdinToStdoutRegistersCanary(t *testing.T) {
	pinClock(t)
	storePath := storeIn(t)
	out := plantFixture(t, storePath, tok, "prod-bot")
	if !strings.Contains(out, "You are a helpful bot.") || !strings.Contains(out, tok) {
		t.Fatalf("instrumented prompt wrong:\n%s", out)
	}
	data, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("store not written: %v", err)
	}
	var reg struct {
		Canaries []struct {
			Token, Label, Status, Created string
		} `json:"canaries"`
	}
	if err := json.Unmarshal(data, &reg); err != nil {
		t.Fatalf("store not JSON: %v", err)
	}
	c := reg.Canaries[0]
	if c.Token != tok || c.Label != "prod-bot" || c.Status != "active" {
		t.Fatalf("registered canary wrong: %+v", c)
	}
	if c.Created != "2026-07-12T12:00:00Z" {
		t.Fatalf("created = %q, clock not honored", c.Created)
	}
}

func TestPlantFileToFile(t *testing.T) {
	dir := t.TempDir()
	promptPath := filepath.Join(dir, "prompt.txt")
	outPath := filepath.Join(dir, "instrumented.txt")
	if err := os.WriteFile(promptPath, []byte("Be terse.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run(t, "",
		"plant", "--store", filepath.Join(dir, "coalmine.json"),
		"--token", tok, "-o", outPath, promptPath)
	if code != ExitOK {
		t.Fatalf("plant exit %d: %s", code, stderr)
	}
	if stdout != "" {
		t.Fatalf("plant -o should not write the prompt to stdout, got %q", stdout)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "Be terse.") || !strings.Contains(string(data), tok) {
		t.Fatalf("instrumented file wrong:\n%s", data)
	}
	if !strings.Contains(stderr, "planted canary") {
		t.Fatalf("plant notice missing: %q", stderr)
	}
}

func TestFlagsMayFollowPositionalArguments(t *testing.T) {
	// The README quickstart writes `plant --label x prompt.txt -o out.txt`,
	// with a flag after the positional file. Stock flag parsing would treat
	// `-o out.txt` as two extra positionals and reject the command.
	dir := t.TempDir()
	storePath := filepath.Join(dir, "coalmine.json")
	promptPath := filepath.Join(dir, "prompt.txt")
	outPath := filepath.Join(dir, "system.txt")
	if err := os.WriteFile(promptPath, []byte("Answer briefly.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := run(t, "",
		"plant", "--store", storePath,
		"--label", "support-prod", "--token", tok, promptPath, "-o", outPath)
	if code != ExitOK {
		t.Fatalf("interleaved plant exit %d: %s", code, stderr)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), tok) {
		t.Fatalf("instrumented file missing token:\n%s", data)
	}
	// scan too: `scan <path> --format json` must parse the trailing flag.
	logPath := filepath.Join(dir, "app.log")
	if err := os.WriteFile(logPath, []byte("leak "+tok+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run(t, "", "scan", "--store", storePath, logPath, "--format", "json")
	if code != ExitLeak || !strings.Contains(out, `"leaks": 1`) {
		t.Fatalf("interleaved scan = (%d, %q)", code, out)
	}
	// An explicit `--` still protects flag-looking paths from re-parsing.
	code, _, stderr = run(t, "", "scan", "--store", storePath, "--", "-not-a-flag")
	if code != ExitRuntime || !strings.Contains(stderr, "-not-a-flag") {
		t.Fatalf("post-`--` path was re-parsed as a flag: (%d, %q)", code, stderr)
	}
}

func TestPlantGeneratesTokenWhenNotGiven(t *testing.T) {
	pinRandomness(t)
	storePath := storeIn(t)
	code, out, stderr := run(t, "prompt body\n", "plant", "--store", storePath, "-")
	if code != ExitOK {
		t.Fatalf("plant exit %d: %s", code, stderr)
	}
	if !strings.Contains(out, token.Prefix) {
		t.Fatalf("no token embedded:\n%s", out)
	}
}

func TestPlantRejectsInvalidAndDuplicateTokens(t *testing.T) {
	storePath := storeIn(t)
	code, _, stderr := run(t, "x\n", "plant", "--store", storePath, "--token", "CMBOGUS", "-")
	if code != ExitUsage || !strings.Contains(stderr, "not a valid") {
		t.Fatalf("invalid token = (%d, %q)", code, stderr)
	}
	plantFixture(t, storePath, tok, "first")
	code, _, stderr = run(t, "y\n", "plant", "--store", storePath, "--token", tok, "-")
	if code != ExitRuntime || !strings.Contains(stderr, "already planted") {
		t.Fatalf("duplicate plant = (%d, %q)", code, stderr)
	}
}

func TestPlantCustomTemplateAndPosition(t *testing.T) {
	storePath := storeIn(t)
	code, out, stderr := run(t, "Body.\n",
		"plant", "--store", storePath, "--token", tok,
		"--template", "<!-- {token} -->", "--at", "start", "-")
	if code != ExitOK {
		t.Fatalf("plant exit %d: %s", code, stderr)
	}
	if !strings.HasPrefix(out, "<!-- "+tok+" -->\n\nBody.") {
		t.Fatalf("custom start marker wrong:\n%s", out)
	}
}

func TestScanFindsLeakAndExitsOne(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "coalmine.json")
	plantFixture(t, storePath, tok, "prod-bot")
	logPath := filepath.Join(dir, "app.log")
	if err := os.WriteFile(logPath, []byte("the model said "+tok+" today\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run(t, "", "scan", "--store", storePath, logPath)
	if code != ExitLeak {
		t.Fatalf("scan exit %d, want %d", code, ExitLeak)
	}
	for _, want := range []string{"LEAK", "prod-bot", "exact", "scan: LEAK"} {
		if !strings.Contains(out, want) {
			t.Errorf("scan output missing %q:\n%s", want, out)
		}
	}
	// The same store over an innocent file exits 0 and says CLEAN.
	if err := os.WriteFile(logPath, []byte("nothing to see here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ = run(t, "", "scan", "--store", storePath, logPath)
	if code != ExitOK || !strings.Contains(out, "scan: CLEAN") {
		t.Fatalf("clean scan = (%d, %q)", code, out)
	}
}

func TestScanJSONFormat(t *testing.T) {
	storePath := storeIn(t)
	plantFixture(t, storePath, tok, "prod-bot")
	code, out, _ := run(t, "leak "+tok+"\n", "scan", "--store", storePath, "--format", "json", "-")
	if code != ExitLeak {
		t.Fatalf("scan exit %d", code)
	}
	var env struct {
		Tool     string `json:"tool"`
		Leaks    int    `json:"leaks"`
		Findings []struct {
			File, Label, Variant string
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("scan --format json emitted invalid JSON: %v\n%s", err, out)
	}
	if env.Tool != "coalmine" || env.Leaks != 1 || env.Findings[0].Variant != "exact" {
		t.Fatalf("json envelope wrong: %+v", env)
	}
	if env.Findings[0].File != "<stdin>" {
		t.Fatalf("stdin input should be reported as <stdin>, got %q", env.Findings[0].File)
	}
}

func TestScanFailOnPolicies(t *testing.T) {
	storePath := storeIn(t)
	plantFixture(t, storePath, tok, "prod-bot")
	// A 14-char fragment is a medium-confidence finding.
	partial := "prefix " + tok[:14] + " suffix\n"
	code, out, _ := run(t, partial, "scan", "--store", storePath, "--fail-on", "high", "-")
	if code != ExitOK {
		t.Fatalf("--fail-on high exit %d, want 0", code)
	}
	if !strings.Contains(out, "fragment") {
		t.Fatalf("medium finding should still be reported:\n%s", out)
	}
	// The same input with the default policy gates.
	code, _, _ = run(t, partial, "scan", "--store", storePath, "-")
	if code != ExitLeak {
		t.Fatalf("default --fail-on exit %d, want 1", code)
	}
	// --fail-on never reports but never gates, even on a full leak.
	code, _, _ = run(t, tok+"\n", "scan", "--store", storePath, "--fail-on", "never", "-")
	if code != ExitOK {
		t.Fatalf("--fail-on never exit %d", code)
	}
}

func TestScanWithoutCanariesIsRuntimeError(t *testing.T) {
	code, _, stderr := run(t, "text\n", "scan", "--store", storeIn(t), "-")
	if code != ExitRuntime || !strings.Contains(stderr, "no active canaries") {
		t.Fatalf("empty-store scan = (%d, %q)", code, stderr)
	}
}

func TestScanUsageErrors(t *testing.T) {
	storePath := storeIn(t)
	plantFixture(t, storePath, tok, "prod-bot")
	cases := [][]string{
		{"scan", "--store", storePath},                                // no paths
		{"scan", "--store", storePath, "--format", "yaml", "-"},       // bad format
		{"scan", "--store", storePath, "--fail-on", "sometimes", "-"}, // bad policy
		{"scan", "--store", storePath, "--min-fragment", "3", "-"},    // below floor
	}
	for _, argv := range cases {
		if code, _, _ := run(t, "", argv...); code != ExitUsage {
			t.Errorf("%v exit %d, want %d", argv, code, ExitUsage)
		}
	}
}

func TestScanMinFragmentZeroDisablesPartialDetection(t *testing.T) {
	storePath := storeIn(t)
	plantFixture(t, storePath, tok, "prod-bot")
	code, out, _ := run(t, "partial "+tok[:14]+"\n",
		"scan", "--store", storePath, "--min-fragment", "0", "-")
	if code != ExitOK || !strings.Contains(out, "scan: CLEAN") {
		t.Fatalf("fragment channel not disabled: (%d, %q)", code, out)
	}
}

func TestListShowsPlantedCanaries(t *testing.T) {
	storePath := storeIn(t)
	plantFixture(t, storePath, tok, "prod-bot")
	plantFixture(t, storePath, tok2, "staging-bot")
	code, out, _ := run(t, "", "list", "--store", storePath)
	if code != ExitOK {
		t.Fatalf("list exit %d", code)
	}
	for _, want := range []string{"prod-bot", "staging-bot", "active"} {
		if !strings.Contains(out, want) {
			t.Errorf("list missing %q:\n%s", want, out)
		}
	}
}

func TestRevokeLifecycle(t *testing.T) {
	storePath := storeIn(t)
	plantFixture(t, storePath, tok, "prod-bot")
	plantFixture(t, storePath, tok2, "staging-bot")
	code, out, stderr := run(t, "", "revoke", "--store", storePath, "prod-bot")
	if code != ExitOK || !strings.Contains(out, "revoked 1") {
		t.Fatalf("revoke = (%d, %q, %q)", code, out, stderr)
	}
	// The revoked token no longer gates; the active one still does.
	code, _, _ = run(t, tok+"\n", "scan", "--store", storePath, "-")
	if code != ExitOK {
		t.Fatalf("scan after revoke exit %d, want 0", code)
	}
	code, _, _ = run(t, tok2+"\n", "scan", "--store", storePath, "-")
	if code != ExitLeak {
		t.Fatalf("active canary must still gate, exit %d", code)
	}
	// --all hunts revoked canaries too (forensics on old logs).
	code, out, _ = run(t, tok+"\n", "scan", "--store", storePath, "--all", "-")
	if code != ExitLeak || !strings.Contains(out, "prod-bot") {
		t.Fatalf("--all scan = (%d, %q)", code, out)
	}
	// Revoking something that does not exist fails loudly.
	code, _, stderr = run(t, "", "revoke", "--store", storePath, "ghost")
	if code != ExitRuntime || !strings.Contains(stderr, "ghost") {
		t.Fatalf("revoke ghost = (%d, %q)", code, stderr)
	}
}

func TestPlantThenScanRoundTripThroughInstrumentedPrompt(t *testing.T) {
	// The canonical two-command loop: the instrumented prompt itself must
	// trip the scanner (that is the whole point of planting).
	storePath := storeIn(t)
	instrumented := plantFixture(t, storePath, tok, "prod-bot")
	code, out, _ := run(t, instrumented, "scan", "--store", storePath, "-")
	if code != ExitLeak || !strings.Contains(out, "exact") {
		t.Fatalf("instrumented prompt did not scan as a leak: (%d, %q)", code, out)
	}
}
