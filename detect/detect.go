// Copyright 2026 Matthew Hunter
// SPDX-License-Identifier: Apache-2.0

// Package detect is a deliberately weak, advisory tripwire for hostile text.
//
// # Read this before you use it
//
// This detector is keyword-anchored regex run over normalized text. That is all it
// is. It catches an attacker who writes "ignore all previous instructions",
// including one who spells it with a Cyrillic o, a zero-width space, or a boxed
// emoji, because [normalize] folds those away first. It does not catch an attacker
// who writes the same idea in different words. Paraphrase defeats it completely,
// and there is no version of this approach that fixes that.
//
// So a clean scan means nothing. It is not evidence that text is safe; it is
// evidence that the text did not happen to contain one of 28 known phrasings. If
// you find yourself treating a clean Detect result as a safety property, stop --
// this package has failed you, and the failure was predictable.
//
// airlock's actual guarantee is structural: [github.com/matthewjhunter/airlock/wrap]
// marks untrusted content so the model knows not to obey it, and that marking holds
// whether or not anything in this package fires. Detection rides behind that fence
// as a second, weaker line -- it can notice a hostile span that a model might still
// act on even when the marking held. Suspenders, never the belt.
//
// # Advisory means advisory
//
// [Detect] returns a signal and mutates nothing. It does not block, strip, rewrite,
// sanitize, or refuse. There is no action field and no enforcement posture, by
// design: this package has no idea what a hit should mean in your application, and
// pretending otherwise would put a security decision in the wrong place. You decide.
//
// # Severity
//
// Rule severities are airlock's editorial judgment, not data inherited from the
// upstream corpus -- see [Severity] and rules_seed.go, which records the reasoning
// for each rule. In particular a [SeverityLow] hit is close to worthless on its
// own; those rules match text that is just as likely to be ordinary prose.
package detect

import (
	"github.com/matthewjhunter/airlock/normalize"
)

// Match is a single rule that fired. It reports what matched and how much that is
// worth, and nothing about what to do next -- that is the caller's call.
type Match struct {
	// Rule is the stable rule ID, e.g. "prompt-injection".
	Rule string

	// Title is the human-readable rule name, e.g. "Prompt Injection".
	Title string

	// Category groups related rules: injection, jailbreak, concealment,
	// credential, escalation, execution, tooling, memory, disclosure,
	// control-token.
	Category string

	// Severity is how much weight to give this hit. airlock's judgment; see the
	// Severity doc.
	Severity Severity

	// Field is the structured field the rule matched in, or "" for freetext. The
	// current corpus is entirely freetext, so this is always "" today.
	Field string
}

// Result is what a scan found.
//
// There is deliberately no confidence score. A float would imply a calibration this
// detector does not have and cannot have -- there is no principled way to say a
// given text is 0.73 hostile. The honest aggregate is [Result.Highest]: the
// strongest rule that fired, on a three-tier scale whose tiers are written down.
type Result struct {
	// Matches holds every rule that fired, in corpus order. Each rule appears at
	// most once no matter how many times its pattern occurs in the text.
	Matches []Match

	// Obfuscated reports that the raw input carried enough stacked combining marks
	// to look like deliberate obfuscation rather than natural language.
	//
	// This is independent of Matches. Normalization strips the marks before
	// matching, so an obfuscated payload can normalize into text that trips no rule
	// at all -- and that combination (someone went to the trouble of obfuscating,
	// and we still found nothing) is worth surfacing on its own.
	Obfuscated bool

	// ObfuscationDensity is the longest run of combining marks on a single base
	// character in the raw input. See [normalize.ZalgoDensity].
	ObfuscationDensity int
}

// Found reports whether any rule fired.
//
// A false here is not a safety property. See the package doc.
func (r Result) Found() bool { return len(r.Matches) > 0 }

// Highest returns the severity of the most serious rule that fired, or SeverityNone
// if none did. This is the honest aggregate; there is no numeric score.
func (r Result) Highest() Severity {
	var high Severity
	for _, m := range r.Matches {
		if m.Severity > high {
			high = m.Severity
		}
	}
	return high
}

// Detect scans text for known hostile phrasings and reports what it found.
//
// It mutates nothing and returns no opinion about what should happen next.
//
// The text is normalized with [normalize.ForMatching] before matching, so the usual
// encoding evasions -- zero-width characters, homoglyphs, fullwidth forms,
// combining marks, exotic whitespace -- do not get a free pass. The obfuscation
// signal is measured on the raw input first, because normalization is what destroys
// the evidence for it.
//
// Each rule reports at most once, however many times it matches. Matches come back
// in corpus order, so the result is deterministic across calls and builds.
//
// Remember what this is: 28 regexes. A clean result means those 28 did not fire, and
// nothing more.
func Detect(text string) Result {
	// Measured before normalization, which strips the marks it counts.
	density := normalize.ZalgoDensity(text)

	normalized := normalize.ForMatching(text)

	var matches []Match
	for _, r := range compiled() {
		// The seed corpus is entirely freetext. A field-scoped rule has no
		// business matching a freetext scan, so skip it rather than let it fire
		// against the wrong input.
		if r.Field != "" {
			continue
		}
		if r.re.MatchString(normalized) {
			matches = append(matches, Match{
				Rule:     r.ID,
				Title:    r.Title,
				Category: r.Category,
				Severity: r.Severity,
				Field:    r.Field,
			})
		}
	}

	return Result{
		Matches:            matches,
		Obfuscated:         density >= normalize.ZalgoSuspiciousThreshold,
		ObfuscationDensity: density,
	}
}
