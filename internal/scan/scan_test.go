// Tests for the detection engine: every obfuscation channel end to end,
// location accuracy, overlap dedup, fragment behavior, and deterministic
// ordering — all against fabricated in-memory documents.
package scan

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/JaydenCJ/coalmine/internal/store"
)

const (
	tok  = "CM7Q3KXN4TP2A9ZR6WB0" // pinned documentation token
	tok2 = "CM4TQ7XKN2P9A3ZR6WWG" // second valid token
)

func engine(t *testing.T, minFrag int, tokens ...string) *Engine {
	t.Helper()
	var cs []store.Canary
	for i, tk := range tokens {
		cs = append(cs, store.Canary{
			ID:     store.IDFor(tk),
			Token:  tk,
			Label:  []string{"prod-bot", "staging-bot", "dev-bot"}[i%3],
			Status: store.StatusActive,
		})
	}
	return New(cs, minFrag)
}

func one(t *testing.T, fs []Finding) Finding {
	t.Helper()
	if len(fs) != 1 {
		t.Fatalf("want exactly 1 finding, got %d: %+v", len(fs), fs)
	}
	return fs[0]
}

func TestCleanTextHasNoFindings(t *testing.T) {
	e := engine(t, DefaultMinFragment, tok)
	text := "2026-07-12 INFO normal chatter, request ids, uuids 550e8400-e29b-41d4-a716-446655440000\n"
	if fs := e.ScanText("log", strings.Repeat(text, 50)); len(fs) != 0 {
		t.Fatalf("clean text produced findings: %+v", fs)
	}
}

func TestExactLeakWithLocation(t *testing.T) {
	e := engine(t, DefaultMinFragment, tok)
	f := one(t, e.ScanText("app.log", "line one\nthe marker is "+tok+" sadly\n"))
	if f.Variant != "exact" || f.Confidence != "high" {
		t.Fatalf("finding = %+v", f)
	}
	if f.Line != 2 || f.Col != 15 {
		t.Fatalf("location = %d:%d, want 2:15", f.Line, f.Col)
	}
	if f.File != "app.log" || f.CanaryID != store.IDFor(tok) {
		t.Fatalf("attribution wrong: %+v", f)
	}
}

func TestFoldedChannelLeaksAreExactHighConfidence(t *testing.T) {
	// Case mangling, zero-width padding and homoglyph swaps all collapse
	// in the folded view: still an exact, high-confidence hit.
	e := engine(t, DefaultMinFragment, tok)
	cases := map[string]string{
		"lowercase":  strings.ToLower(tok),
		"zero-width": strings.Join(strings.Split(tok, ""), "​"),
		"homoglyph":  strings.Replace(tok, "CM7", "СМ７", 1), // Cyrillic С М, fullwidth ７
		"crockford":  strings.Replace(tok, "0", "O", 1),     // O rewritten for 0
	}
	for name, leaked := range cases {
		f := one(t, e.ScanText("x", "marker "+leaked+"\n"))
		if f.Variant != "exact" || f.Confidence != "high" {
			t.Errorf("%s: finding = %+v", name, f)
		}
	}
}

func TestSeparatorStuffedLeaksAreMediumConfidence(t *testing.T) {
	e := engine(t, DefaultMinFragment, tok)
	cases := map[string]string{
		"spaced":     strings.Join(strings.Split(tok, ""), " "),
		"hyphenated": tok[:5] + "-" + tok[5:11] + "-" + tok[11:],
	}
	for name, leaked := range cases {
		f := one(t, e.ScanText("x", "id: "+leaked+"\n"))
		if f.Variant != "exact" || f.Confidence != "medium" {
			t.Errorf("%s: finding = %+v", name, f)
		}
	}
}

func TestBase64LeakAtAnyOffsetIncludingURLSafe(t *testing.T) {
	e := engine(t, DefaultMinFragment, tok)
	for pad := 0; pad < 3; pad++ {
		blob := base64.StdEncoding.EncodeToString(
			[]byte(strings.Repeat("y", pad) + "the system prompt says: " + tok + " end"))
		f := one(t, e.ScanText("x", "assistant: "+blob+"\n"))
		if f.Variant != "base64" || f.Confidence != "high" {
			t.Fatalf("pad %d: finding = %+v", pad, f)
		}
	}
	urlBlob := base64.URLEncoding.EncodeToString([]byte("~~~" + tok + "\xff\xfe"))
	if f := one(t, e.ScanText("x", urlBlob+"\n")); f.Variant != "base64" {
		t.Fatalf("url-safe finding = %+v", f)
	}
}

func TestHexLeakDetectedBothCases(t *testing.T) {
	e := engine(t, DefaultMinFragment, tok)
	lower := strings.ToLower(hexEncode(tok))
	for _, hay := range []string{lower, strings.ToUpper(lower)} {
		f := one(t, e.ScanText("x", "dump: "+hay+"\n"))
		if f.Variant != "hex" || f.Confidence != "high" {
			t.Fatalf("finding = %+v", f)
		}
	}
}

func TestRot13LeakDetected(t *testing.T) {
	e := engine(t, DefaultMinFragment, tok)
	f := one(t, e.ScanText("x", "puzzle: "+strings.ToLower(rot13(tok))+"\n"))
	if f.Variant != "rot13" {
		t.Fatalf("finding = %+v", f)
	}
}

func TestReversedLeakDetected(t *testing.T) {
	e := engine(t, DefaultMinFragment, tok)
	f := one(t, e.ScanText("x", "backwards: "+strings.ToLower(reverseString(tok))+"\n"))
	if f.Variant != "reversed" {
		t.Fatalf("finding = %+v", f)
	}
}

func TestPercentEncodedLeakDetected(t *testing.T) {
	e := engine(t, DefaultMinFragment, tok)
	var b strings.Builder
	for i := 0; i < len(tok); i++ {
		b.WriteString("%")
		b.WriteString(strings.ToLower(hexEncode(tok[i : i+1])))
	}
	f := one(t, e.ScanText("x", "url: https://example.test/?q="+b.String()+"\n"))
	if f.Variant != "percent" {
		t.Fatalf("finding = %+v", f)
	}
}

func TestFragmentLeakReportsPartialLength(t *testing.T) {
	e := engine(t, DefaultMinFragment, tok)
	f := one(t, e.ScanText("x", "it starts with "+tok[:14]+" and that's all\n"))
	if f.Variant != FragmentVariant || f.Confidence != "medium" {
		t.Fatalf("finding = %+v", f)
	}
	if f.MatchedChars != 14 || f.TokenChars != 20 {
		t.Fatalf("chars = %d/%d, want 14/20", f.MatchedChars, f.TokenChars)
	}
	// A slice out of the middle of the token counts too.
	mid := one(t, e.ScanText("x", "middle: "+tok[4:17]+"\n"))
	if mid.Variant != FragmentVariant || mid.MatchedChars != 13 {
		t.Fatalf("middle fragment = %+v", mid)
	}
}

func TestFragmentRespectsMinimumAndCanBeDisabled(t *testing.T) {
	e := engine(t, 12, tok)
	if fs := e.ScanText("x", "prefix "+tok[:11]+" suffix\n"); len(fs) != 0 {
		t.Fatalf("11-char fragment reported with min 12: %+v", fs)
	}
	off := engine(t, 0, tok)
	if fs := off.ScanText("x", tok[:15]+"\n"); len(fs) != 0 {
		t.Fatalf("fragment reported with channel disabled: %+v", fs)
	}
}

func TestExactMatchNotDoubleReportedAsFragment(t *testing.T) {
	e := engine(t, DefaultMinFragment, tok)
	f := one(t, e.ScanText("x", "full: "+tok+"\n"))
	if f.Variant != "exact" {
		t.Fatalf("dedup picked %q over exact", f.Variant)
	}
}

func TestMultipleLeaksAttributedAndSorted(t *testing.T) {
	e := engine(t, DefaultMinFragment, tok, tok2)
	fs := e.ScanText("x", tok2+" ... "+tok+"\n"+tok2+"\n")
	if len(fs) != 3 {
		t.Fatalf("want 3 findings, got %d: %+v", len(fs), fs)
	}
	if fs[0].CanaryID != store.IDFor(tok2) || fs[1].CanaryID != store.IDFor(tok) {
		t.Fatalf("attribution wrong: %+v", fs)
	}
	for i := 1; i < len(fs); i++ {
		if fs[i-1].Line > fs[i].Line ||
			(fs[i-1].Line == fs[i].Line && fs[i-1].Col > fs[i].Col) {
			t.Fatalf("findings out of order: %+v", fs)
		}
	}
	if fs[2].Line != 2 {
		t.Fatalf("repeated leak on line 2 missing: %+v", fs)
	}
}

func TestExcerptTrimsLongLinesAndFlattensTabs(t *testing.T) {
	e := engine(t, DefaultMinFragment, tok)
	long := strings.Repeat("a", 300) + "\t" + tok + strings.Repeat("b", 300)
	f := one(t, e.ScanText("x", long+"\n"))
	if !strings.HasPrefix(f.Excerpt, "…") || !strings.HasSuffix(f.Excerpt, "…") {
		t.Fatalf("excerpt not ellipsized: %q", f.Excerpt)
	}
	if !strings.Contains(f.Excerpt, tok) {
		t.Fatalf("excerpt lost the match: %q", f.Excerpt)
	}
	if len(f.Excerpt) > 120 {
		t.Fatalf("excerpt too long: %d bytes", len(f.Excerpt))
	}
	if strings.Contains(f.Excerpt, "\t") {
		t.Fatalf("excerpt still contains a tab: %q", f.Excerpt)
	}
}

func TestLeakLocationsAtBoundaries(t *testing.T) {
	e := engine(t, DefaultMinFragment, tok)
	// Very first byte of the document.
	f := one(t, e.ScanText("x", tok+" trailing\n"))
	if f.Line != 1 || f.Col != 1 {
		t.Fatalf("location = %d:%d, want 1:1", f.Line, f.Col)
	}
	// Document without a trailing newline.
	f = one(t, e.ScanText("x", "no newline "+tok))
	if f.Line != 1 || f.Col != 12 {
		t.Fatalf("location = %d:%d, want 1:12", f.Line, f.Col)
	}
}

func TestScanIsDeterministic(t *testing.T) {
	e := engine(t, DefaultMinFragment, tok, tok2)
	text := tok + "\n" + strings.ToLower(tok2) + "\n" + tok[:14] + "\n"
	a := e.ScanText("x", text)
	b := e.ScanText("x", text)
	if len(a) != len(b) {
		t.Fatalf("run lengths differ: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("finding %d differs: %+v vs %+v", i, a[i], b[i])
		}
	}
}

// hexEncode is a tiny local helper so the test does not depend on the
// production encoding path it is checking.
func hexEncode(s string) string {
	const digits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteByte(digits[s[i]>>4])
		b.WriteByte(digits[s[i]&0xF])
	}
	return b.String()
}

func rot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		}
		return r
	}, s)
}

func reverseString(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}
