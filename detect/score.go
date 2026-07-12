// Copyright 2026 Matthew Hunter
// SPDX-License-Identifier: Apache-2.0

package detect

import "math"

// Evidence weights, one per severity tier. These are airlock's judgment, the same
// judgment recorded per rule in rules_seed.go, expressed as a number so that hits
// can be combined.
//
// They are NOT probabilities and NOT calibrated against any corpus of real attacks.
// Nobody has measured how often text containing "from now on you will" is actually
// hostile. Read them as an ordering: a High hit is worth a lot, a Medium hit is
// worth something, a Low hit is worth almost nothing.
const (
	weightLow    = 0.05
	weightMedium = 0.30
	weightHigh   = 0.80

	// weightObfuscated is the weight given to deliberate obfuscation of the raw
	// input (see Result.Obfuscated). Stacking three or more combining marks on a
	// character has no benign purpose in text being fed to a model, so it is real
	// evidence of intent even when no rule matched -- but it is evidence of intent
	// only, never of a specific attack, so it sits at the Medium weight and not
	// higher.
	weightObfuscated = weightMedium
)

// weight returns the evidence weight of a severity tier.
func (s Severity) weight() float64 {
	switch s {
	case SeverityLow:
		return weightLow
	case SeverityMedium:
		return weightMedium
	case SeverityHigh:
		return weightHigh
	default:
		return 0
	}
}

// Score aggregates every hit into a single number from 0 to 100, so that results
// with different mixes of rules can be ranked and thresholded.
//
// # What it is
//
// Evidence is combined the way independent evidence combines: the score is the
// complement of the product of the complements of the weights, scaled to 100. A
// result scores high when it is hard to explain away ALL of its evidence at once.
//
//	score = 100 * (1 - product over categories of (1 - weight(strongest hit in category)))
//
// The per-category grouping is the important part, and it is not a detail. Rules
// within a category are frequently near-duplicates of each other: "ignore all
// previous instructions" trips both prompt-injection and
// cross-lingual-instruction-override, because the cross-lingual pattern lists the
// English verbs too. Those are one piece of evidence wearing two hats, not two
// independent findings, and counting them twice would inflate a single canonical
// override to a near-certainty. So each category contributes only its strongest hit,
// and corroboration has to come from genuinely different kinds of evidence -- an
// override AND concealment AND a credential demand -- which is what corroboration
// should mean.
//
// That yields the two properties you want from an aggregate and cannot get from a
// plain maximum or a plain sum:
//
//   - Corroboration across categories. An override alone scores 80; an override plus
//     concealment plus a covert-action directive scores 99. A result that is hostile
//     in several independent ways is more convincing than one that is hostile in a
//     single way, and the score says so.
//   - Diminishing returns, with the tiers preserved. Each additional category adds
//     less than the last, and weak evidence stays weak no matter how much of it there
//     is. Every Low rule in the corpus firing at once still only reaches 14, far below
//     a single Medium hit. Low hits cannot pile up into a false alarm.
//
// Result.Obfuscated contributes as its own category at the Medium weight, so that
// text somebody went to the trouble of mangling does not score zero merely because
// the mangling defeated every rule.
//
// # What it is not
//
// It is not a probability, not a confidence, and not calibrated. A score of 73 does
// not mean the text is 73% likely to be an attack; nothing here has been measured
// against real-world base rates, and the input weights are an editorial judgment
// rather than an estimate. Do not present it to a user as a likelihood, and do not
// build a threshold on it without looking at what actually fires in your own traffic.
//
// It also inherits every limitation of the detector underneath it. A paraphrased
// injection that trips no rule scores 0, and 0 means "none of 28 regexes fired" --
// never "this text is safe". [Result.Highest] remains the more conservative reading,
// and the two are meant to be used together: Highest tells you the strongest single
// claim, Score tells you how much there is of it.
func (r Result) Score() int {
	// Strongest hit per category. Rules inside a category overlap heavily, so
	// counting each one separately would double-count a single piece of evidence.
	strongest := make(map[string]Severity, len(r.Matches))
	for _, m := range r.Matches {
		if m.Severity > strongest[m.Category] {
			strongest[m.Category] = m.Severity
		}
	}

	remaining := 1.0
	for _, sev := range strongest {
		remaining *= 1 - sev.weight()
	}
	if r.Obfuscated {
		remaining *= 1 - weightObfuscated
	}

	score := math.Round((1 - remaining) * 100)

	// The arithmetic cannot leave [0,100] -- every weight is in [0,1), so remaining
	// is too -- but clamp anyway. A scoring function that can hand back a number
	// outside its documented range is the kind of thing a caller builds a threshold
	// on and gets surprised by later.
	return int(math.Min(100, math.Max(0, score)))
}
