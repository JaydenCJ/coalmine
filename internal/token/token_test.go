// Tests for token generation and validation: format guarantees, checksum
// strength, and deterministic behavior under an injected randomness source.
package token

import (
	"bytes"
	"strings"
	"testing"
)

// fixedReader yields a repeating byte pattern so token generation is
// reproducible in tests without touching crypto/rand.
func fixedReader(seed byte) *bytes.Reader {
	b := make([]byte, 32)
	for i := range b {
		b[i] = seed + byte(i)*7
	}
	return bytes.NewReader(b)
}

func TestGenerateProducesValidToken(t *testing.T) {
	tok, err := Generate(fixedReader(1))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !Valid(tok) {
		t.Fatalf("generated token %q does not validate", tok)
	}
}

func TestGenerateIsDeterministicPerSourceAndDistinctAcrossSources(t *testing.T) {
	a1, _ := Generate(fixedReader(9))
	a2, _ := Generate(fixedReader(9))
	if a1 != a2 {
		t.Fatalf("same randomness produced different tokens: %q vs %q", a1, a2)
	}
	b, _ := Generate(fixedReader(2))
	if a1 == b {
		t.Fatalf("different randomness produced identical tokens: %q", a1)
	}
}

func TestTokenShapePrefixLengthAlphabet(t *testing.T) {
	// Every generated token: fixed prefix, fixed length, Crockford
	// alphabet only — which by construction excludes ambiguous I, L, O, U.
	for seed := byte(0); seed < 20; seed++ {
		tok, _ := Generate(fixedReader(seed))
		if !strings.HasPrefix(tok, Prefix) {
			t.Errorf("token %q missing prefix %q", tok, Prefix)
		}
		if len(tok) != Length {
			t.Errorf("token %q has length %d, want %d", tok, len(tok), Length)
		}
		for _, c := range tok[len(Prefix):] {
			if !strings.ContainsRune(Alphabet, c) {
				t.Errorf("token %q contains %q outside the Crockford alphabet", tok, c)
			}
		}
		if strings.ContainsAny(tok, "ILOU") {
			t.Errorf("token %q contains an ambiguous character", tok)
		}
	}
}

func TestValidAcceptsKnownGoodToken(t *testing.T) {
	// Pinned example used throughout docs and the smoke test.
	if !Valid("CM7Q3KXN4TP2A9ZR6WB0") {
		t.Fatal("documented example token must validate")
	}
}

func TestValidRejectsMalformedTokens(t *testing.T) {
	tok, _ := Generate(fixedReader(3))
	cases := map[string]string{
		"wrong prefix":     "XX" + tok[2:],
		"truncated":        tok[:Length-1],
		"overlong":         tok + "0",
		"empty":            "",
		"prefix only":      Prefix,
		"ambiguous I":      tok[:5] + "I" + tok[6:],
		"ambiguous L":      tok[:5] + "L" + tok[6:],
		"ambiguous O":      tok[:5] + "O" + tok[6:],
		"lowercase body":   strings.ToLower(tok),
		"punctuation body": tok[:5] + "!" + tok[6:],
	}
	for name, bad := range cases {
		if Valid(bad) {
			t.Errorf("%s: %q validated", name, bad)
		}
	}
}

func TestChecksumDetectsEverySingleCharSubstitution(t *testing.T) {
	// Substitute every payload position with every other alphabet char:
	// the checksum must catch all of them, or a typo in --token would
	// silently plant an unscannable canary.
	tok, _ := Generate(fixedReader(7))
	body := tok[len(Prefix) : len(tok)-checkChars]
	for i := 0; i < len(body); i++ {
		for _, c := range Alphabet {
			if byte(c) == body[i] {
				continue
			}
			mutated := tok[:len(Prefix)+i] + string(c) + tok[len(Prefix)+i+1:]
			if Valid(mutated) {
				t.Fatalf("substitution at payload position %d (%q) not detected", i, mutated)
			}
		}
	}
}

func TestChecksumDetectsAdjacentTranspositions(t *testing.T) {
	tok, _ := Generate(fixedReader(11))
	start := len(Prefix)
	for i := start; i < Length-checkChars-1; i++ {
		if tok[i] == tok[i+1] {
			continue // swapping equal chars is a no-op
		}
		b := []byte(tok)
		b[i], b[i+1] = b[i+1], b[i]
		if Valid(string(b)) {
			t.Fatalf("transposition at %d (%q) not detected", i, string(b))
		}
	}
}

func TestGenerateErrorsOnExhaustedRandomness(t *testing.T) {
	if _, err := Generate(bytes.NewReader([]byte{1, 2, 3})); err == nil {
		t.Fatal("Generate with a 3-byte source should fail")
	}
}
