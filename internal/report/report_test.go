// Tests for report rendering: verdict lines, location formatting, JSON
// envelope stability, and registry listings — all byte-deterministic.
package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/JaydenCJ/coalmine/internal/scan"
	"github.com/JaydenCJ/coalmine/internal/store"
)

func sampleResult() scan.Result {
	return scan.Result{
		FilesScanned: 3,
		FilesSkipped: 1,
		Findings: []scan.Finding{
			{
				CanaryID: "8baf53a9", Label: "prod-bot", Variant: "exact",
				Confidence: "high", File: "logs/app.log", Line: 2, Col: 15,
				MatchedChars: 20, TokenChars: 20, Excerpt: "marker CM… here",
			},
			{
				CanaryID: "8baf53a9", Label: "prod-bot", Variant: "fragment",
				Confidence: "medium", File: "logs/ticket.txt", Line: 9, Col: 1,
				MatchedChars: 14, TokenChars: 20, Excerpt: "partial…",
			},
		},
	}
}

func TestTextReportCleanVerdict(t *testing.T) {
	var b bytes.Buffer
	ScanText(&b, scan.Result{FilesScanned: 2})
	out := b.String()
	for _, want := range []string{"no leaks detected", "scan: CLEAN", "2 files scanned"} {
		if !strings.Contains(out, want) {
			t.Errorf("clean report missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "LEAK") && !strings.Contains(out, "CLEAN") {
		t.Errorf("clean report claims a leak:\n%s", out)
	}
}

func TestTextReportListsFindingsWithLocations(t *testing.T) {
	var b bytes.Buffer
	ScanText(&b, sampleResult())
	out := b.String()
	for _, want := range []string{
		"2 leaks in 2 files",
		"LEAK  logs/app.log:2:15",
		"canary 8baf53a9 (prod-bot)",
		"exact  ·  high",
		"scan: LEAK",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
}

func TestTextReportFragmentCountsAndSingularForms(t *testing.T) {
	var b bytes.Buffer
	ScanText(&b, sampleResult())
	if !strings.Contains(b.String(), "(14/20 chars)") {
		t.Fatalf("fragment char counts missing:\n%s", b.String())
	}
	res := sampleResult()
	res.Findings = res.Findings[:1]
	b.Reset()
	ScanText(&b, res)
	if !strings.Contains(b.String(), "1 leak in 1 file\n") {
		t.Fatalf("singular form wrong:\n%s", b.String())
	}
}

func TestJSONReportEnvelope(t *testing.T) {
	var b bytes.Buffer
	if err := ScanJSON(&b, sampleResult()); err != nil {
		t.Fatalf("ScanJSON: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(b.Bytes(), &env); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if env["tool"] != "coalmine" || env["schema_version"] != float64(1) {
		t.Fatalf("envelope wrong: %v", env)
	}
	if env["leaks"] != float64(2) || env["clean"] != false || env["files_affected"] != float64(2) {
		t.Fatalf("counts wrong: %v", env)
	}
	findings := env["findings"].([]any)
	first := findings[0].(map[string]any)
	if first["file"] != "logs/app.log" || first["line"] != float64(2) {
		t.Fatalf("finding serialization wrong: %v", first)
	}
	// Rendering the same result twice must be byte-identical.
	var again bytes.Buffer
	if err := ScanJSON(&again, sampleResult()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b.Bytes(), again.Bytes()) {
		t.Fatal("identical input produced different JSON bytes")
	}
}

func TestJSONReportCleanHasEmptyFindingsArray(t *testing.T) {
	var b bytes.Buffer
	if err := ScanJSON(&b, scan.Result{FilesScanned: 1}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"findings": []`) {
		t.Fatalf("findings should be [], not null:\n%s", b.String())
	}
	if !strings.Contains(b.String(), `"clean": true`) {
		t.Fatalf("clean flag missing:\n%s", b.String())
	}
}

func TestListTextTable(t *testing.T) {
	var b bytes.Buffer
	ListText(&b, []store.Canary{
		{ID: "8baf53a9", Label: "prod-bot", Status: "active", Created: "2026-07-12T00:00:00Z", Source: "prompt.txt"},
		{ID: "0d3adb11", Label: "staging", Status: "revoked", Created: "2026-07-12T00:00:00Z"},
	})
	out := b.String()
	for _, want := range []string{"id", "prod-bot", "active", "revoked", "prompt.txt"} {
		if !strings.Contains(out, want) {
			t.Errorf("listing missing %q:\n%s", want, out)
		}
	}
	// A canary without a source shows a dash, not an empty cell.
	if !strings.Contains(out, "-") {
		t.Errorf("empty source not dashed:\n%s", out)
	}
	// And an empty registry says so instead of printing a bare header.
	b.Reset()
	ListText(&b, nil)
	if !strings.Contains(b.String(), "no canaries planted") {
		t.Fatalf("empty listing = %q", b.String())
	}
}

func TestListJSONRoundTrips(t *testing.T) {
	var b bytes.Buffer
	in := []store.Canary{{ID: "x", Token: "CM7Q3KXN4TP2A9ZR6WB0", Label: "l", Status: "active"}}
	if err := ListJSON(&b, in); err != nil {
		t.Fatal(err)
	}
	var env struct {
		Tool     string         `json:"tool"`
		Canaries []store.Canary `json:"canaries"`
	}
	if err := json.Unmarshal(b.Bytes(), &env); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if env.Tool != "coalmine" || len(env.Canaries) != 1 || env.Canaries[0].Token != in[0].Token {
		t.Fatalf("round trip wrong: %+v", env)
	}
}
