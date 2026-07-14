// Tests for the haystack views: folding semantics, separator condensing,
// and — critically — that every view position maps back to the correct
// byte offset in the original text, because reported line:col locations
// are only as good as these maps.
package normalize

import (
	"strings"
	"testing"
)

func TestFoldNormalizesEveryObfuscationChannel(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"lowercase":  {"cm7q3kxn", "CM7Q3KXN"},
		"zero-width": {"C\u200bM\u200c7\u200dQ\u20603\ufeffK\u00adX\u200fN", "CM7Q3KXN"},
		"bidi":       {"A\u202eB\u202aC", "ABC"},
		"cyrillic":   {"СМАВЕКНОРТХУ", "CMABEKH0PTXY"},
		"greek":      {"ΑΒΕΗΚΜΝΡΤΧ", "ABEHKMNPTX"},
		"fullwidth":  {"ＣＭ７Ｑ３ｋｘｎ", "CM7Q3KXN"},
		// I and L decode as 1, O as 0 in Crockford base32: an attacker
		// rewriting CM0… as CMO… must still match.
		"crockford": {"IlO0o1L", "1100011"},
		"unrelated": {"hey there, 世界! 123", "HEY THERE, 世界! 123"},
	}
	for name, c := range cases {
		if got := Fold(c.in).Text; got != c.want {
			t.Errorf("%s: Fold(%q) = %q, want %q", name, c.in, got, c.want)
		}
	}
}

func TestFoldOffsetMapPointsIntoOriginal(t *testing.T) {
	in := "x\u200by\u200bZ" // bytes: x(0) zwsp(1-3) y(4) zwsp(5-7) Z(8)
	v := Fold(in)
	if v.Text != "XYZ" {
		t.Fatalf("Fold = %q", v.Text)
	}
	for i, want := range []int{0, 4, 8} {
		if got := v.OrigOffset(i); got != want {
			t.Errorf("OrigOffset(%d) = %d, want %d", i, got, want)
		}
	}
	if got := v.OrigOffset(3); got != len(in) {
		t.Errorf("OrigOffset past end = %d, want original length %d", got, len(in))
	}
}

func TestCondenseDropsSeparatorsAndWhitespace(t *testing.T) {
	v := Condense(Fold("C M-7_Q.3,K:X;N|4/T\\P+2*A=9'Z\"R(6)W[B]0"))
	if v.Text != "CM7Q3KXN4TP2A9ZR6WB0" {
		t.Fatalf("Condense = %q", v.Text)
	}
	if got := Condense(Fold("CM7\n\tQ3K")).Text; got != "CM7Q3K" {
		t.Fatalf("Condense over newlines/tabs = %q", got)
	}
}

func TestCondenseOffsetMapComposesThroughFold(t *testing.T) {
	in := "a - b" // a(0) sp(1) -(2) sp(3) b(4)
	v := Condense(Fold(in))
	if v.Text != "AB" {
		t.Fatalf("Condense = %q", v.Text)
	}
	if got := v.OrigOffset(0); got != 0 {
		t.Errorf("OrigOffset(0) = %d, want 0", got)
	}
	if got := v.OrigOffset(1); got != 4 {
		t.Errorf("OrigOffset(1) = %d, want 4", got)
	}
}

func TestRawViewIsIdentity(t *testing.T) {
	in := "unchanged TEXT with Ünïcode"
	v := Raw(in)
	if v.Text != in {
		t.Fatalf("Raw changed the text: %q", v.Text)
	}
	for _, i := range []int{0, 5, len(in)} {
		if got := v.OrigOffset(i); got != i {
			t.Errorf("Raw OrigOffset(%d) = %d", i, got)
		}
	}
}

func TestFoldStringMatchesFoldAndIsIdempotent(t *testing.T) {
	// Needles are folded once at compile time and haystacks at scan time;
	// FoldString must agree with Fold and double-folding must be a no-op.
	in := "СМ7q\u200b3kxnＩＬＯ"
	once := FoldString(in)
	if once != Fold(in).Text {
		t.Fatal("FoldString diverged from Fold().Text")
	}
	if twice := FoldString(once); twice != once {
		t.Fatalf("Fold not idempotent: %q -> %q", once, twice)
	}
}

func TestCondenseKeepsOnlyScannableCharactersAtScale(t *testing.T) {
	// A folded-then-condensed round trip over a synthetic log line keeps
	// only the characters the scanner needs.
	line := strings.Repeat("ab 12-", 100)
	v := Condense(Fold(line))
	if len(v.Text) != 400 {
		t.Fatalf("condensed length = %d, want 400", len(v.Text))
	}
}
