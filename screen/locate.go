// Copyright 2026 Matthew Hunter
// SPDX-License-Identifier: Apache-2.0

package screen

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/matthewjhunter/airlock/normalize"
)

// Span is where a verdict's evidence actually occurs in the content it was screened
// from. Byte offsets into the string passed to [Verdict.Locate].
type Span struct {
	Start int
	End   int

	// Exact is true when the model's quote is a byte-for-byte substring of the
	// content. False means it only matched after folding case, whitespace, and
	// Unicode confusables -- the quote is real but the model tidied it up, which
	// models routinely do. A false here is not a problem; it is information.
	Exact bool
}

// Text returns the span of the original content, which is the trustworthy version of
// the evidence: it comes from the source text rather than from the model.
func (s Span) Text(content string) string {
	if s.Start < 0 || s.End > len(content) || s.Start >= s.End {
		return ""
	}
	return content[s.Start:s.End]
}

// Locate finds the verdict's evidence in the content it was screened from, and is the
// reason a caller who still holds the original text is in a much stronger position
// than one who does not.
//
// # Why this matters more than the quote itself
//
// The prompt requires the model to quote the span it says is addressing an AI. That
// requirement does real work -- it is hard to quote an instruction that is not there
// -- but on its own it is only a request. A model that has decided an article feels
// dangerous can still produce a quote-shaped string to justify itself, and nothing in
// the reply distinguishes a real citation from an invented one.
//
// The content does. If the quoted span does not occur in the text, the model did not
// find it there; it made it up. That is not a weak verdict, it is a void one, and
// [Verdict.VerifyEvidence] treats it as such. This upgrades the evidence requirement
// from "did you cite something" to "does your citation exist", which is the check that
// actually catches a model rationalizing a hunch.
//
// # And it answers where to put the quote
//
// Once the span is located, the quote is redundant: the caller can recover it from the
// source with [Span.Text] whenever it is needed. So store the offsets, not the text.
// Two ints, bounded and harmless, instead of an attacker-authored string of
// attacker-chosen length in a log line, an error message, and a database column.
//
// # Matching
//
// Exact substring first. Failing that, both sides are folded -- case, whitespace runs,
// invisible characters, and Unicode confusables -- and matched again, because models
// habitually normalize what they quote (straightening quotes, collapsing newlines,
// fixing a homoglyph). A fold match still yields offsets into the ORIGINAL text, so
// [Span.Text] returns what the source really says, not the model's tidied version.
func (v Verdict) Locate(content string) (Span, bool) {
	ev := strings.TrimSpace(v.Evidence)
	if ev == "" || content == "" {
		return Span{}, false
	}

	// Exact.
	if i := strings.Index(content, ev); i >= 0 {
		return Span{Start: i, End: i + len(ev), Exact: true}, true
	}

	// Folded. Build a view of the content that is rune-aligned back to the original.
	view, at := foldView(content)
	needle, _ := foldView(ev)
	if needle == "" {
		return Span{}, false
	}

	j := strings.Index(view, needle)
	if j < 0 {
		return Span{}, false
	}

	// Byte offset in the view -> rune index in the view -> rune index in the original.
	loRune := len([]rune(view[:j]))
	hiRune := loRune + len([]rune(needle))
	if loRune >= len(at) || hiRune > len(at) || hiRune == 0 {
		return Span{}, false
	}

	origRunes := []rune(content)
	startRune := at[loRune]
	endRune := at[hiRune-1] + 1
	if startRune < 0 || endRune > len(origRunes) || startRune >= endRune {
		return Span{}, false
	}

	start := len(string(origRunes[:startRune]))
	end := len(string(origRunes[:endRune]))
	return Span{Start: start, End: end, Exact: false}, true
}

// VerifyEvidence checks a verdict against the content it was produced from.
//
// A threat whose quoted evidence does not occur in the content is a fabrication: the
// model reported an instruction it cannot show you. Reject it. This is the strongest
// form of the anti-false-positive check in this package, and it is available to any
// caller that still holds the original text -- which, in practice, is every caller,
// since it had to have the text to screen it.
//
// A clean verdict (threat 0) needs no evidence and verifies trivially.
func (v Verdict) VerifyEvidence(content string) (Span, error) {
	if v.Threat <= 0 {
		return Span{}, nil
	}
	if strings.TrimSpace(v.Evidence) == "" {
		return Span{}, fmt.Errorf("screen: verdict reports threat %d but quotes no evidence", v.Threat)
	}

	span, ok := v.Locate(content)
	if !ok {
		return Span{}, fmt.Errorf("screen: verdict reports threat %d citing %q, but that text does not "+
			"occur in the content -- the model fabricated its evidence, so the finding is void (reason: %q)",
			v.Threat, truncate(v.Evidence, 80), truncate(v.Reason, 80))
	}
	return span, nil
}

// foldView returns a folded view of s, plus a mapping from each rune of the view back
// to the rune index in s it came from.
//
// The fold drops invisible characters, folds Unicode confusables and fullwidth forms,
// lowercases, and collapses each run of whitespace to a single space. That is the set
// of differences a model introduces when it quotes: it tidies. The mapping is what
// lets a match in the folded view be reported as offsets in the untouched original.
func foldView(s string) (string, []int) {
	runes := []rune(s)
	out := make([]rune, 0, len(runes))
	at := make([]int, 0, len(runes))

	prevSpace := false
	for i, r := range runes {
		if isInvisible(r) {
			continue
		}
		if unicode.IsSpace(r) {
			if prevSpace {
				continue // collapse the run
			}
			prevSpace = true
			out = append(out, ' ')
			at = append(at, i)
			continue
		}
		prevSpace = false
		out = append(out, unicode.ToLower(foldWidth(r)))
		at = append(at, i)
	}

	// ConfusableToASCII maps rune-for-rune, so the alignment above survives it.
	folded := []rune(normalize.ConfusableToASCII(string(out)))
	if len(folded) != len(at) {
		// Defensive: if the fold ever stops being 1:1, refuse to guess at offsets.
		return "", nil
	}

	// Trim leading/trailing space without losing the mapping.
	lo, hi := 0, len(folded)
	for lo < hi && folded[lo] == ' ' {
		lo++
	}
	for hi > lo && folded[hi-1] == ' ' {
		hi--
	}
	return string(folded[lo:hi]), at[lo:hi]
}

// isInvisible and foldWidth mirror wrap's, deliberately duplicated rather than
// exported from there: wrap's copies exist to defend a fence delimiter, these exist to
// align a quote with its source, and the two should be free to diverge.
func isInvisible(r rune) bool {
	switch {
	case r <= 0x1F && r != '\t' && r != '\n' && r != '\r':
		return true
	case r == 0x7F:
		return true
	case r >= 0x80 && r <= 0x9F:
		return true
	default:
		return unicode.Is(normalize.InvisibleRanges, r)
	}
}

func foldWidth(r rune) rune {
	if r >= 0xFF01 && r <= 0xFF5E {
		return r - 0xFEE0
	}
	return r
}
