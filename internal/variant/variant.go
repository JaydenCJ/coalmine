// Package variant turns one canary token into the full set of literal
// needles the scanner searches for: the token itself plus every encoding a
// model is routinely asked to smuggle a prompt out through — base64 at all
// three byte offsets, hex, ROT13, reversal, and percent-encoding. Needles
// are precomputed once per canary, so scanning stays a plain substring
// search no matter how many channels are covered.
package variant

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/JaydenCJ/coalmine/internal/normalize"
)

// Confidence levels attached to findings.
const (
	High   = "high"   // the transformation is unambiguous for a full token
	Medium = "medium" // aggressive normalization or a partial match
)

// Needle is one literal to search for, bound to the haystack view it must
// be searched in.
type Needle struct {
	// Name identifies the obfuscation channel: exact, base64, hex, rot13,
	// reversed, percent.
	Name string
	// Text is the literal substring to look for. For folded/condensed
	// views it has already been passed through normalize.FoldString.
	Text string
	// View names the haystack view to search: raw, folded or condensed.
	View string
	// Confidence is High or Medium.
	Confidence string
}

// Needles expands a token into every precomputed needle. The token is
// assumed to be a canonical uppercase coalmine token.
func Needles(tok string) []Needle {
	up := strings.ToUpper(tok)
	var out []Needle
	seen := map[string]bool{}
	add := func(name, text, view, conf string) {
		if text == "" {
			return
		}
		key := view + "\x00" + text
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, Needle{Name: name, Text: text, View: view, Confidence: conf})
	}

	// The plain token, tolerant of case mangling, zero-width padding and
	// homoglyphs (folded view), and additionally of separator stuffing
	// (condensed view — Medium, because the normalization is aggressive).
	add("exact", normalize.FoldString(up), "folded", High)
	add("exact", normalize.FoldString(up), "condensed", Medium)

	// base64: a token embedded anywhere inside a larger base64 stream
	// lands at byte offset 0, 1 or 2 modulo 3. For each offset we encode
	// with that many leading pad bytes and slice out the characters fully
	// determined by the token alone, giving three ~26-char needles that
	// match regardless of what surrounds the token. Because token bytes
	// are alphanumeric ASCII, the needles never contain '+' or '/', so the
	// same three literals also match URL-safe base64 streams.
	for shift := 0; shift < 3; shift++ {
		add("base64", base64Core(up, shift), "raw", High)
	}

	// hex: 40 stable characters; the folded view uppercases the haystack
	// so lowercase and uppercase hex both hit this one needle.
	add("hex", normalize.FoldString(strings.ToUpper(hex.EncodeToString([]byte(up)))), "folded", High)

	// rot13: letters rotate, digits stay. Folding both sides keeps the
	// needle consistent even though ROT13 output can contain I/L/O.
	add("rot13", normalize.FoldString(rot13(up)), "folded", High)

	// reversed: the classic "spell it backwards" exfiltration.
	add("reversed", normalize.FoldString(reverse(up)), "folded", High)

	// percent: full URL-encoding of every byte (%43%4D…); hex digits fold
	// to uppercase so %4d and %4D both match.
	add("percent", normalize.FoldString(percentEncode(up)), "folded", High)

	return out
}

// base64Core returns the substring of base64(prefix+tok) whose characters
// are fully determined by tok when tok starts at byte offset shift (mod 3)
// inside the encoded stream.
func base64Core(tok string, shift int) string {
	padded := strings.Repeat("\x00", shift) + tok
	enc := base64.RawStdEncoding.EncodeToString([]byte(padded))
	startBit := shift * 8
	first := (startBit + 5) / 6         // ceil: first char inside tok bits
	last := (startBit + len(tok)*8) / 6 // floor: exclusive end
	if first >= last || last > len(enc) {
		return ""
	}
	return enc[first:last]
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

func reverse(s string) string {
	b := []byte(s) // tokens are ASCII
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func percentEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "%%%02X", s[i])
	}
	return b.String()
}
