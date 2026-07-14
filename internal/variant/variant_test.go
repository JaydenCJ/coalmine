// Tests for needle expansion: every encoding channel must produce a
// literal that actually appears when the token is transformed the way an
// exfiltrating model would transform it — including base64 at every byte
// offset and URL-safe base64 with the same needles.
package variant

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/JaydenCJ/coalmine/internal/normalize"
)

// tok is the pinned documentation token; any valid token shape works here.
const tok = "CM7Q3KXN4TP2A9ZR6WB0"

func needlesByName(t *testing.T, name string) []Needle {
	t.Helper()
	var out []Needle
	for _, n := range Needles(tok) {
		if n.Name == name {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no %q needles generated", name)
	}
	return out
}

func TestExactNeedleTargetsFoldedAndCondensedViews(t *testing.T) {
	exact := needlesByName(t, "exact")
	views := map[string]string{}
	for _, n := range exact {
		views[n.View] = n.Confidence
		if n.Text != normalize.FoldString(tok) {
			t.Errorf("exact needle text %q not the folded token", n.Text)
		}
	}
	if views["folded"] != High {
		t.Errorf("folded exact needle confidence = %q, want high", views["folded"])
	}
	if views["condensed"] != Medium {
		t.Errorf("condensed exact needle confidence = %q, want medium", views["condensed"])
	}
}

func TestBase64NeedlesCoverEveryByteOffset(t *testing.T) {
	// Embed the token after 0..8 prefix bytes inside a larger sentence;
	// exactly one of the three offset needles must match each encoding,
	// and each needle must be wide enough that a hit is unambiguous.
	needles := needlesByName(t, "base64")
	for _, n := range needles {
		if len(n.Text) < 25 || len(n.Text) > 27 {
			t.Errorf("needle width %d outside [25,27]", len(n.Text))
		}
	}
	for pad := 0; pad <= 8; pad++ {
		plain := strings.Repeat("x", pad) + tok + " and more trailing text."
		enc := base64.StdEncoding.EncodeToString([]byte(plain))
		hits := 0
		for _, n := range needles {
			if strings.Contains(enc, n.Text) {
				hits++
			}
		}
		if hits != 1 {
			t.Errorf("pad %d: %d base64 needles matched, want exactly 1", pad, hits)
		}
	}
}

func TestBase64NeedlesAlsoMatchURLSafeEncoding(t *testing.T) {
	// Token bytes are alphanumeric, so needles contain no '+' or '/'; the
	// same literals must hit URL-safe base64 streams too.
	needles := needlesByName(t, "base64")
	for _, n := range needles {
		if strings.ContainsAny(n.Text, "+/") {
			t.Errorf("base64 needle %q contains + or /, breaking URL-safe coverage", n.Text)
		}
		if n.View != "raw" {
			t.Errorf("base64 needle must search the raw view, got %q", n.View)
		}
	}
	for pad := 0; pad <= 2; pad++ {
		plain := strings.Repeat("\xfb", pad) + tok + "\xfe\xff" // URL-unsafe surroundings
		enc := base64.URLEncoding.EncodeToString([]byte(plain))
		hit := false
		for _, n := range needles {
			if strings.Contains(enc, n.Text) {
				hit = true
			}
		}
		if !hit {
			t.Errorf("pad %d: no needle matched URL-safe encoding %q", pad, enc)
		}
	}
}

func TestHexNeedleMatchesLowerAndUpperHexViaFolding(t *testing.T) {
	n := needlesByName(t, "hex")[0]
	lower := hex.EncodeToString([]byte(tok)) // lowercase by definition
	upper := strings.ToUpper(lower)
	for _, hay := range []string{lower, upper} {
		if !strings.Contains(normalize.FoldString(hay), n.Text) {
			t.Errorf("hex needle missed %q after folding", hay)
		}
	}
}

func TestRot13NeedleMatchesRotatedToken(t *testing.T) {
	n := needlesByName(t, "rot13")[0]
	rotated := rot13(tok) // digits unchanged, letters rotated
	if !strings.Contains(normalize.FoldString(rotated), n.Text) {
		t.Fatalf("rot13 needle %q missed %q", n.Text, rotated)
	}
	// And the round trip really is ROT13: applying it twice restores tok.
	if rot13(rotated) != tok {
		t.Fatal("rot13 helper is not an involution")
	}
}

func TestReversedNeedleMatchesBackwardsToken(t *testing.T) {
	n := needlesByName(t, "reversed")[0]
	backwards := reverse(tok)
	if !strings.Contains(normalize.FoldString(backwards), n.Text) {
		t.Fatalf("reversed needle %q missed %q", n.Text, backwards)
	}
}

func TestPercentNeedleMatchesBothHexDigitCases(t *testing.T) {
	n := needlesByName(t, "percent")[0]
	upper := percentEncode(tok)
	lower := strings.ToLower(upper)
	for _, hay := range []string{upper, lower} {
		if !strings.Contains(normalize.FoldString(hay), n.Text) {
			t.Errorf("percent needle missed %q", hay)
		}
	}
}

func TestNeedleSetHasNoDuplicatesAndCarriesEnoughEntropy(t *testing.T) {
	seen := map[string]bool{}
	for _, n := range Needles(tok) {
		key := n.View + "\x00" + n.Text
		if seen[key] {
			t.Errorf("duplicate needle %q in view %s", n.Text, n.View)
		}
		seen[key] = true
		// Every needle must be long enough that a match is a leak, not
		// luck: nothing shorter than the 20-char token itself.
		if len(n.Text) < 20 {
			t.Errorf("needle %s/%q is only %d chars", n.Name, n.Text, len(n.Text))
		}
	}
}
