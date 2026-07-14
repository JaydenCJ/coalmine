// Package scan is the detection engine: it searches text for every planted
// canary across all obfuscation channels (see internal/variant and
// internal/normalize), plus partial-token fragments, and reports findings
// with exact line:col locations and excerpts from the original text.
package scan

import (
	"sort"
	"strings"

	"github.com/JaydenCJ/coalmine/internal/normalize"
	"github.com/JaydenCJ/coalmine/internal/store"
	"github.com/JaydenCJ/coalmine/internal/variant"
)

// DefaultMinFragment is the default minimum length (in token characters)
// for partial-leak detection. Twelve characters of an 80-bit-entropy token
// keeps accidental matches out of real logs.
const DefaultMinFragment = 12

// MinFragmentFloor is the smallest --min-fragment the CLI accepts; below
// this the fragment channel would start matching coincidences.
const MinFragmentFloor = 8

// FragmentVariant names the partial-match channel in findings.
const FragmentVariant = "fragment"

// Finding is one detected leak.
type Finding struct {
	CanaryID   string `json:"canary_id"`
	Label      string `json:"label"`
	Variant    string `json:"variant"`
	Confidence string `json:"confidence"`
	File       string `json:"file"`
	Line       int    `json:"line"` // 1-based
	Col        int    `json:"col"`  // 1-based, byte column
	// MatchedChars counts token characters recovered: full token length
	// for whole-token variants, fewer for fragments.
	MatchedChars int    `json:"matched_chars"`
	TokenChars   int    `json:"token_chars"`
	Excerpt      string `json:"excerpt"`

	start, end int // original byte span, for dedup and sorting
}

// variantPriority orders candidates for overlap dedup: when the same bytes
// trip several channels, the most specific interpretation wins.
var variantPriority = map[string]int{
	"exact": 0, "base64": 1, "hex": 2, "percent": 3,
	"rot13": 4, "reversed": 5, FragmentVariant: 9,
}

type compiledNeedle struct {
	canary store.Canary
	needle variant.Needle
}

type compiledToken struct {
	canary  store.Canary
	folded  string          // folded token text
	windows map[string]bool // all minFrag-length substrings of folded
}

// Engine scans text for a fixed set of canaries. Building one Engine and
// reusing it across files amortizes needle generation.
type Engine struct {
	needles []compiledNeedle
	tokens  []compiledToken
	minFrag int
}

// New compiles canaries into an Engine. minFragment <= 0 disables the
// fragment channel entirely.
func New(canaries []store.Canary, minFragment int) *Engine {
	e := &Engine{minFrag: minFragment}
	for _, c := range canaries {
		for _, n := range variant.Needles(c.Token) {
			e.needles = append(e.needles, compiledNeedle{canary: c, needle: n})
		}
		if minFragment > 0 {
			folded := normalize.FoldString(strings.ToUpper(c.Token))
			windows := map[string]bool{}
			for i := 0; i+minFragment <= len(folded); i++ {
				windows[folded[i:i+minFragment]] = true
			}
			e.tokens = append(e.tokens, compiledToken{canary: c, folded: folded, windows: windows})
		}
	}
	return e
}

// ScanText scans one document and returns its findings, sorted by position.
// name is used only to fill Finding.File.
func (e *Engine) ScanText(name, content string) []Finding {
	raw := normalize.Raw(content)
	folded := normalize.Fold(content)
	condensed := normalize.Condense(folded)
	views := map[string]*normalize.View{"raw": &raw, "folded": &folded, "condensed": &condensed}

	var cands []Finding
	for _, cn := range e.needles {
		view := views[cn.needle.View]
		for _, span := range findAll(view.Text, cn.needle.Text) {
			cands = append(cands, Finding{
				CanaryID:     cn.canary.ID,
				Label:        cn.canary.Label,
				Variant:      cn.needle.Name,
				Confidence:   cn.needle.Confidence,
				File:         name,
				MatchedChars: len(normalize.FoldString(strings.ToUpper(cn.canary.Token))),
				TokenChars:   len(cn.canary.Token),
				start:        view.OrigOffset(span[0]),
				end:          view.OrigOffset(span[1]),
			})
		}
	}
	for _, ct := range e.tokens {
		for _, fr := range fragments(ct, folded.Text, e.minFrag) {
			cands = append(cands, Finding{
				CanaryID:     ct.canary.ID,
				Label:        ct.canary.Label,
				Variant:      FragmentVariant,
				Confidence:   variant.Medium,
				File:         name,
				MatchedChars: fr[1] - fr[0],
				TokenChars:   len(ct.canary.Token),
				start:        folded.OrigOffset(fr[0]),
				end:          folded.OrigOffset(fr[1]),
			})
		}
	}

	accepted := dedup(cands)
	lines := lineIndex(content)
	for i := range accepted {
		accepted[i].Line, accepted[i].Col = locate(lines, accepted[i].start)
		accepted[i].Excerpt = excerpt(content, lines, accepted[i].start, accepted[i].end)
	}
	sort.Slice(accepted, func(i, j int) bool {
		a, b := accepted[i], accepted[j]
		if a.start != b.start {
			return a.start < b.start
		}
		if a.Label != b.Label {
			return a.Label < b.Label
		}
		return a.Variant < b.Variant
	})
	return accepted
}

// findAll returns every [start,end) occurrence of needle in hay.
// Occurrences may overlap needles of other variants but not themselves;
// advancing by one byte would only re-report the same leak.
func findAll(hay, needle string) [][2]int {
	var out [][2]int
	for from := 0; ; {
		i := strings.Index(hay[from:], needle)
		if i < 0 {
			return out
		}
		start := from + i
		out = append(out, [2]int{start, start + len(needle)})
		from = start + len(needle)
	}
}

// fragments finds maximal runs of the folded haystack that are substrings
// of the folded token, at least minFrag long. The window map makes the
// common (non-matching) path a single hash lookup per position.
func fragments(ct compiledToken, hay string, minFrag int) [][2]int {
	var out [][2]int
	for i := 0; i+minFrag <= len(hay); {
		if !ct.windows[hay[i:i+minFrag]] {
			i++
			continue
		}
		j := i + minFrag
		for j < len(hay) && strings.Contains(ct.folded, hay[i:j+1]) {
			j++
		}
		out = append(out, [2]int{i, j})
		i = j
	}
	return out
}

// dedup keeps, per canary, the best non-overlapping interpretation of each
// byte span: an exact hit is not additionally reported as a fragment, and
// a condensed match never shadows a folded one.
func dedup(cands []Finding) []Finding {
	sort.Slice(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if pa, pb := variantPriority[a.Variant], variantPriority[b.Variant]; pa != pb {
			return pa < pb
		}
		// Within a variant, prefer High confidence (folded) over Medium
		// (condensed), then longer, then earlier matches.
		if a.Confidence != b.Confidence {
			return a.Confidence == variant.High
		}
		if la, lb := a.end-a.start, b.end-b.start; la != lb {
			return la > lb
		}
		return a.start < b.start
	})
	taken := map[string][][2]int{}
	var out []Finding
	for _, c := range cands {
		overlaps := false
		for _, iv := range taken[c.CanaryID] {
			if c.start < iv[1] && iv[0] < c.end {
				overlaps = true
				break
			}
		}
		if overlaps {
			continue
		}
		taken[c.CanaryID] = append(taken[c.CanaryID], [2]int{c.start, c.end})
		out = append(out, c)
	}
	return out
}

// lineIndex returns the byte offset of the start of every line.
func lineIndex(content string) []int {
	starts := []int{0}
	for i := 0; i < len(content); i++ {
		if content[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

// locate converts a byte offset to 1-based line and column.
func locate(lines []int, off int) (line, col int) {
	i := sort.Search(len(lines), func(i int) bool { return lines[i] > off }) - 1
	return i + 1, off - lines[i] + 1
}

// excerptContext is how many bytes of surrounding line are kept on each
// side of a match in the excerpt.
const excerptContext = 40

// excerpt cuts a single-line window around the matched span out of the
// original text, marking truncation with ellipses and flattening control
// characters so reports stay one-finding-per-line.
func excerpt(content string, lines []int, start, end int) string {
	li, _ := locate(lines, start)
	lineStart := lines[li-1]
	lineEnd := len(content)
	if li < len(lines) {
		lineEnd = lines[li] - 1
	}
	if end > lineEnd {
		end = lineEnd // multi-line match: excerpt the first line only
	}
	ws, we := start-excerptContext, end+excerptContext
	if ws < lineStart {
		ws = lineStart
	}
	if we > lineEnd {
		we = lineEnd
	}
	s := content[ws:we]
	s = strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7F {
			return -1
		}
		return r
	}, s)
	if ws > lineStart {
		s = "…" + s
	}
	if we < lineEnd {
		s += "…"
	}
	return s
}
