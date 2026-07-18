// Copyright 2026 Matthew Hunter
// SPDX-License-Identifier: Apache-2.0

package screen

import (
	"strings"
	"unicode"

	"github.com/matthewjhunter/airlock/normalize"
)

// Span is where a verdict's evidence occurs in the content it was screened from.
//
// # Ephemeral. Do not persist these offsets.
//
// They are byte offsets into the exact string handed to [Verdict.Locate], and that
// string is a derived, short-lived artifact: content gets sanitized, truncated to a
// prompt limit, and neutralized (which changes its length) before a model ever sees it,
// and the article behind it gets re-fetched, re-extracted, and edited upstream.
//
// Stored offsets rot. The failure is silent and therefore nasty: they keep RESOLVING,
// against text that has since shifted underneath them, and hand back a confident,
// plausible, wrong span. A security record that misattributes quietly is worse than one
// that admits it does not know.
//
// So call Locate when you need the span -- at screen time to verify the citation, at
// display time to highlight it -- and throw the result away. The durable record is
// [Finding], which holds no offsets and no payload.
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
// [Verdict.Finding] refuses to produce a record from it. This upgrades the evidence
// requirement from "did you cite something" to "does your citation exist", which is the
// check that actually catches a model rationalizing a hunch.
//
// # Call it, use it, throw it away
//
// The span is ephemeral -- see [Span]. Do not store the offsets, and do not store the
// quote either: attacker-authored bytes belong in the fenced prompt and in the article
// the caller already keeps, not in a log line, an error string, or a new column. The
// durable record is [Finding], which carries neither.
//
// Locate is for the two moments the span is actually needed: verifying the citation at
// screen time, and highlighting it at display time, against whatever content the caller
// holds right now. If the article has changed since and the span no longer matches, that
// is a true answer and worth surfacing.
//
// # Matching
//
// Exact substring first. Failing that, both sides are folded -- case, whitespace runs,
// invisible characters, and Unicode confusables -- and matched again, because models
// habitually normalize what they quote (straightening quotes, collapsing newlines,
// fixing a homoglyph). A fold match still yields offsets into the ORIGINAL text, so
// [Span.Text] returns what the source really says, not the model's tidied version.
//
// # Truncated evidence
//
// [ParseVerdict] and [Verdict.Validate] bound Evidence to [EvidenceMaxRunes], marking
// a cut with a trailing "...". That marker is never in the source -- it is a display
// convention Locate adds, not a quote the model made -- so matching it verbatim would
// make every truncated evidence unverifiable regardless of whether it was genuine. If
// the full string does not match, Locate retries with the marker stripped, matching
// only the guaranteed-verbatim prefix. That verifies less text, never different text:
// a match still has to be a real span of content, so a model that fabricates evidence
// still fails here.
func (v Verdict) Locate(content string) (Span, bool) {
	ev := strings.TrimSpace(v.Evidence)
	if ev == "" || content == "" {
		return Span{}, false
	}

	if span, ok := locateExact(content, ev); ok {
		return span, true
	}
	if prefix, ok := strings.CutSuffix(ev, "..."); ok {
		prefix = strings.TrimRight(prefix, " ")
		if prefix != "" {
			if span, ok := locateExact(content, prefix); ok {
				return span, true
			}
		}
	}
	return Span{}, false
}

// locateExact tries an exact substring match, then a folded one, for a needle that is
// assumed to be a verbatim (possibly case/whitespace/confusable-tidied) span of content.
func locateExact(content, ev string) (Span, bool) {
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

	before, _, found := strings.Cut(view, needle)
	if !found {
		return Span{}, false
	}

	// Byte offset in the view -> rune index in the view -> rune index in the original.
	loRune := len([]rune(before))
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
