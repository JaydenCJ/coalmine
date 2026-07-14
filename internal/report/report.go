// Package report renders scan results and canary listings for humans
// (aligned text) and machines (stable JSON, schema_version 1). Rendering is
// deterministic: identical input produces byte-identical output.
package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/JaydenCJ/coalmine/internal/scan"
	"github.com/JaydenCJ/coalmine/internal/store"
)

// SchemaVersion identifies the JSON report format.
const SchemaVersion = 1

// ScanText writes the human-readable scan report.
func ScanText(w io.Writer, res scan.Result) {
	if res.Clean() {
		fmt.Fprintf(w, "coalmine scan — no leaks detected\n")
	} else {
		fmt.Fprintf(w, "coalmine scan — %s in %s\n",
			plural(len(res.Findings), "leak"), plural(res.FilesAffected(), "file"))
	}
	fmt.Fprintln(w)
	for _, f := range res.Findings {
		detail := ""
		if f.MatchedChars < f.TokenChars {
			detail = fmt.Sprintf("  (%d/%d chars)", f.MatchedChars, f.TokenChars)
		}
		fmt.Fprintf(w, "LEAK  %s:%d:%d\n", f.File, f.Line, f.Col)
		fmt.Fprintf(w, "      canary %s (%s)  ·  %s  ·  %s%s\n",
			f.CanaryID, f.Label, f.Variant, f.Confidence, detail)
		fmt.Fprintf(w, "      └─ %s\n", f.Excerpt)
	}
	if !res.Clean() {
		fmt.Fprintln(w)
	}
	verdict := "CLEAN"
	if !res.Clean() {
		verdict = "LEAK"
	}
	fmt.Fprintf(w, "%s · %s affected · %s scanned · %d skipped\n",
		plural(len(res.Findings), "leak"), plural(res.FilesAffected(), "file"),
		plural(res.FilesScanned, "file"), res.FilesSkipped)
	fmt.Fprintf(w, "scan: %s\n", verdict)
}

// jsonEnvelope is the machine-readable scan report.
type jsonEnvelope struct {
	Tool          string         `json:"tool"`
	SchemaVersion int            `json:"schema_version"`
	FilesScanned  int            `json:"files_scanned"`
	FilesSkipped  int            `json:"files_skipped"`
	FilesAffected int            `json:"files_affected"`
	Leaks         int            `json:"leaks"`
	Clean         bool           `json:"clean"`
	Findings      []scan.Finding `json:"findings"`
}

// ScanJSON writes the machine-readable scan report.
func ScanJSON(w io.Writer, res scan.Result) error {
	env := jsonEnvelope{
		Tool:          "coalmine",
		SchemaVersion: SchemaVersion,
		FilesScanned:  res.FilesScanned,
		FilesSkipped:  res.FilesSkipped,
		FilesAffected: res.FilesAffected(),
		Leaks:         len(res.Findings),
		Clean:         res.Clean(),
		Findings:      res.Findings,
	}
	if env.Findings == nil {
		env.Findings = []scan.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(env)
}

// ListText writes the canary registry as an aligned table.
func ListText(w io.Writer, canaries []store.Canary) {
	if len(canaries) == 0 {
		fmt.Fprintln(w, "no canaries planted")
		return
	}
	labelW := len("label")
	for _, c := range canaries {
		if len(c.Label) > labelW {
			labelW = len(c.Label)
		}
	}
	fmt.Fprintf(w, "%-8s  %-*s  %-8s  %-20s  %s\n", "id", labelW, "label", "status", "created", "source")
	for _, c := range canaries {
		src := c.Source
		if src == "" {
			src = "-"
		}
		fmt.Fprintf(w, "%-8s  %-*s  %-8s  %-20s  %s\n", c.ID, labelW, c.Label, c.Status, c.Created, src)
	}
}

// listEnvelope is the machine-readable registry listing.
type listEnvelope struct {
	Tool          string         `json:"tool"`
	SchemaVersion int            `json:"schema_version"`
	Canaries      []store.Canary `json:"canaries"`
}

// ListJSON writes the canary registry as JSON. Tokens are included: the
// registry file already holds them and `list --format json` is how other
// tooling looks them up.
func ListJSON(w io.Writer, canaries []store.Canary) error {
	env := listEnvelope{Tool: "coalmine", SchemaVersion: SchemaVersion, Canaries: canaries}
	if env.Canaries == nil {
		env.Canaries = []store.Canary{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(env)
}

// plural renders "1 leak" / "3 leaks" without a dependency.
func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
