// Package normalize builds transformed views of a haystack that undo the
// obfuscation channels attackers actually use when exfiltrating a system
// prompt — zero-width padding, homoglyph substitution, case mangling, and
// separator stuffing — while preserving a byte-accurate mapping from every
// position in the view back to the original text, so findings report real
// line:col locations.
package normalize

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// View is a transformed copy of a haystack plus the offset map back to it.
type View struct {
	// Name identifies the transformation: "raw", "folded" or "condensed".
	Name string
	// Text is the transformed haystack that needles are searched in.
	Text string

	off     []int // off[i] = original byte offset of Text[i]; nil = identity
	origLen int
}

// OrigOffset maps a byte position in the view back to the original text.
// Positions at or past the end of the view map to the original length, so
// [start, end) needle spans convert cleanly.
func (v *View) OrigOffset(i int) int {
	if v.off == nil {
		if i > v.origLen {
			return v.origLen
		}
		return i
	}
	if i >= len(v.off) {
		return v.origLen
	}
	return v.off[i]
}

// Raw wraps s in an identity view. Case-sensitive needles (the base64
// family) are searched here, untouched.
func Raw(s string) View {
	return View{Name: "raw", Text: s, origLen: len(s)}
}

// Fold produces the case-and-glyph-normalized view: zero-width characters
// are removed, Latin-lookalike homoglyphs and fullwidth forms are mapped to
// ASCII, letters are uppercased, and the Crockford-ambiguous I/L/O are
// folded to 1/1/0. Needles destined for this view must be folded with
// FoldString so both sides agree.
func Fold(s string) View {
	var b strings.Builder
	b.Grow(len(s))
	off := make([]int, 0, len(s))
	for i, r := range s {
		if isZeroWidth(r) {
			continue
		}
		r = foldRune(r)
		var buf [utf8.UTFMax]byte
		n := utf8.EncodeRune(buf[:], r)
		b.Write(buf[:n])
		for j := 0; j < n; j++ {
			off = append(off, i)
		}
	}
	return View{Name: "folded", Text: b.String(), off: off, origLen: len(s)}
}

// Condense strips whitespace and separator punctuation from a folded view,
// composing the offset maps. This is what catches a token leaked as
// "C M 7 Q …" or "CM7-Q3K-XN4…"; only full-token needles are searched here
// to keep the aggressive normalization from inventing false positives.
func Condense(v View) View {
	var b strings.Builder
	b.Grow(len(v.Text))
	off := make([]int, 0, len(v.Text))
	for i, r := range v.Text {
		if isSeparator(r) {
			continue
		}
		var buf [utf8.UTFMax]byte
		n := utf8.EncodeRune(buf[:], r)
		b.Write(buf[:n])
		orig := v.OrigOffset(i)
		for j := 0; j < n; j++ {
			off = append(off, orig)
		}
	}
	return View{Name: "condensed", Text: b.String(), off: off, origLen: v.origLen}
}

// FoldString applies the folded-view transformation to a needle so it can
// be searched inside a Fold (or Condense) view.
func FoldString(s string) string {
	return Fold(s).Text
}

// isZeroWidth reports characters that render as nothing and exist in leaks
// purely to defeat exact-match scanners.
func isZeroWidth(r rune) bool {
	switch {
	case r == 0x00AD: // soft hyphen
		return true
	case r == 0x180E: // Mongolian vowel separator
		return true
	case r >= 0x200B && r <= 0x200F: // ZWSP, ZWNJ, ZWJ, LRM, RLM
		return true
	case r >= 0x202A && r <= 0x202E: // bidi embedding controls
		return true
	case r >= 0x2060 && r <= 0x2064: // word joiner, invisible operators
		return true
	case r == 0xFEFF: // BOM / zero-width no-break space
		return true
	}
	return false
}

// homoglyphs maps Cyrillic and Greek characters that render identically to
// Latin token characters. Values are the ASCII the attacker wants a human
// to read.
var homoglyphs = map[rune]rune{
	// Cyrillic
	'А': 'A', 'В': 'B', 'Е': 'E', 'З': '3', 'К': 'K', 'М': 'M', 'Н': 'H',
	'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'У': 'Y', 'Х': 'X',
	'а': 'A', 'в': 'B', 'е': 'E', 'з': '3', 'к': 'K', 'м': 'M', 'н': 'H',
	'о': 'O', 'р': 'P', 'с': 'C', 'т': 'T', 'у': 'Y', 'х': 'X',
	// Greek
	'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Κ': 'K', 'Μ': 'M',
	'Ν': 'N', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X', 'ο': 'O',
}

// foldRune normalizes one rune for the folded view.
func foldRune(r rune) rune {
	if m, ok := homoglyphs[r]; ok {
		r = m
	}
	// Fullwidth forms (！ Ａ ９ …) map straight onto printable ASCII.
	if r >= 0xFF01 && r <= 0xFF5E {
		r = r - 0xFF01 + 0x21
	}
	r = unicode.ToUpper(r)
	// Crockford base32 decodes I and L as 1 and O as 0; fold the haystack
	// the same way so CM0… rewritten as CMO… still matches. Needles pass
	// through the identical fold, keeping both sides consistent.
	switch r {
	case 'I', 'L':
		return '1'
	case 'O':
		return '0'
	}
	return r
}

// isSeparator reports runes stripped by Condense: anything an attacker can
// interleave into a token without changing how a human reads it.
func isSeparator(r rune) bool {
	if unicode.IsSpace(r) {
		return true
	}
	return strings.ContainsRune("-_.,:;|/\\+*='\"`()[]{}<>~^&%$#@!?", r)
}
