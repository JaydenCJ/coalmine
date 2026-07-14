// Package token generates and validates coalmine canary tokens.
//
// A token looks like CM7Q3KXN4TP2A9ZR6WJD: the fixed prefix "CM", an
// 80-bit random payload in Crockford base32 (16 characters), and a
// 2-character checksum over the payload. The Crockford alphabet excludes
// I, L, O and U, so tokens survive human transcription, and 80 bits of
// entropy makes an accidental collision with natural text or code
// effectively impossible — which is what keeps scan false positives at
// zero.
package token

import (
	"fmt"
	"io"
	"strings"
)

// Alphabet is Crockford base32: digits and uppercase letters minus the
// ambiguous I, L, O, U.
const Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Prefix marks every coalmine token; combined with the payload entropy it
// makes greppable, unmistakable needles.
const Prefix = "CM"

const (
	payloadBytes = 10 // 80 bits of entropy
	payloadChars = payloadBytes * 8 / 5
	checkChars   = 2
)

// Length is the total character length of a well-formed token.
const Length = len(Prefix) + payloadChars + checkChars

// Generate reads payloadBytes of randomness from r (crypto/rand.Reader in
// production, a fixed reader in tests) and returns a well-formed token.
func Generate(r io.Reader) (string, error) {
	raw := make([]byte, payloadBytes)
	if _, err := io.ReadFull(r, raw); err != nil {
		return "", fmt.Errorf("token: reading randomness: %w", err)
	}
	payload := encodeBase32(raw)
	return Prefix + payload + checksum(payload), nil
}

// Valid reports whether s is a well-formed coalmine token: correct prefix,
// length, alphabet, and checksum. It intentionally rejects lowercase input;
// canonical tokens are uppercase and the scanner handles case folding.
func Valid(s string) bool {
	if len(s) != Length || !strings.HasPrefix(s, Prefix) {
		return false
	}
	body := s[len(Prefix):]
	for _, c := range body {
		if !strings.ContainsRune(Alphabet, c) {
			return false
		}
	}
	payload := body[:payloadChars]
	return checksum(payload) == body[payloadChars:]
}

// encodeBase32 packs b into Crockford base32. Callers only pass lengths
// whose bit count is divisible by 5, so there is never a partial tail.
func encodeBase32(b []byte) string {
	var out strings.Builder
	var acc, bits uint
	for _, x := range b {
		acc = acc<<8 | uint(x)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out.WriteByte(Alphabet[(acc>>bits)&31])
		}
	}
	return out.String()
}

// checksum folds the payload into two alphabet characters. The polynomial
// accumulator over a 1024-value space detects any single-character
// substitution and most transpositions, so a mistyped --token is rejected
// instead of silently planting an unscannable canary.
func checksum(payload string) string {
	acc := 0
	for _, c := range payload {
		acc = (acc*37 + strings.IndexRune(Alphabet, c)) % 1024
	}
	return string([]byte{Alphabet[acc>>5], Alphabet[acc&31]})
}
