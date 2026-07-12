// Copyright 2026 Matthew Hunter
// SPDX-License-Identifier: Apache-2.0

// This file holds airlock's own additions to the normalize package. The vendored
// Apache-2.0 code from pipelock lives in pipelock.go; keep the two apart so the
// licensing boundary stays legible. See doc.go for the package documentation.

package normalize

import "golang.org/x/text/unicode/norm"

// StripCombiningMarks removes Unicode combining marks (category Mn) and returns the
// result in composed (NFC) form.
//
// It wraps the vendored implementation, which decomposes with NFD and strips the
// marks but stops there. The trailing recomposition is airlock's fix for a real bug
// in that implementation, and it is live upstream.
//
// NFD does not only split accents off their base characters -- it also decomposes
// precomposed Hangul syllables into conjoining jamo. Those jamo are category Lo,
// not Mn, so the mark strip leaves them alone, and the text stays decomposed: a
// 2-rune Korean word comes back as 4 runes that render identically but do not
// compare equal.
//
// The consequence is that any pattern written in ordinary precomposed Hangul --
// which is how Korean is actually written, and how every Korean rule in the detect
// corpus is written -- can never match normalized text. pipelock's own "CJK
// Instruction Override KR" pattern matches a raw Korean phrase and then fails
// against the output of its own ForMatching. The rule is dead code upstream, and it
// fails open: no match, no error, no signal.
//
// Recomposing with NFC restores the precomposed forms. It cannot resurrect the
// marks that were just stripped, because they are gone from the string by then --
// TestStripCombiningMarks_RecompositionKeepsMarksOff asserts exactly that, since it
// is the obvious way this fix could go wrong.
func StripCombiningMarks(s string) string {
	return norm.NFC.String(stripCombiningMarksUpstream(s))
}
