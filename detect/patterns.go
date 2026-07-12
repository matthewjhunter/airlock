// Copyright 2026 Matthew Hunter
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"fmt"
	"regexp"
	"sync"
)

// Severity is how much a hit on a rule actually tells you.
//
// It is airlock's editorial judgment, not data carried from any upstream corpus.
// pipelock's response-scan patterns have no severity field; every value here was
// assigned in rules_seed.go, with a written reason per rule.
//
// The tiers describe evidentiary weight, not damage:
//
//   - SeverityHigh: the text is hostile or it is nothing. There is no honest
//     reading of a match.
//   - SeverityMedium: hostile in context, but the phrasing has legitimate uses,
//     so a match needs a look before it means anything.
//   - SeverityLow: might be injection, and is just as likely to be ordinary
//     prose. A Low hit on its own is close to worthless -- treat it as a prior,
//     not a finding.
type Severity int

const (
	// SeverityNone is the zero value: no rule fired. Result.Highest returns it for
	// an empty result. It is not a tier a rule can be assigned.
	SeverityNone Severity = iota

	// SeverityLow is the weakest tier. See the Severity doc: a Low hit alone is
	// not evidence of much.
	SeverityLow
	SeverityMedium
	SeverityHigh
)

// String returns the lowercase name of the severity. The zero value is "none";
// anything out of range is "invalid".
func (s Severity) String() string {
	switch s {
	case SeverityNone:
		return "none"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	default:
		return "invalid"
	}
}

// Rule is one detection rule: a regex plus the metadata a caller needs to decide
// what a hit means.
//
// This is airlock's own representation, deliberately not pipelock's YAML bundle
// schema. There is no format_version, no required_features, no monotonic_version,
// no signing. The vendored corpus in rules_seed.go was converted into this shape
// once, at port time; nothing at runtime tracks pipelock's schema.
type Rule struct {
	// ID is the stable kebab-case identifier, e.g. "prompt-injection". Callers
	// key off this; Title is for humans.
	ID string

	// Title is the human-readable name, carried from the upstream corpus.
	Title string

	// Category groups related rules: injection, jailbreak, concealment,
	// credential, escalation, execution, tooling, memory, disclosure,
	// control-token.
	Category string

	// Severity is how much weight to give a hit. See the Severity doc -- this is
	// airlock's judgment, and rules_seed.go records the reasoning per rule.
	Severity Severity

	// Pattern is the RE2 source. It is matched against normalized text (see
	// Detect), never against the raw input.
	Pattern string

	// Field scopes the rule to a structured field rather than freetext. Empty
	// means freetext. "name" and "description" scope a rule to MCP tool metadata.
	// The seed corpus is entirely freetext; this exists for the tool-poison rules
	// if airlock ever grows a tool-registration inspection path.
	Field string
}

// compiledRule pairs a Rule with its compiled regex.
type compiledRule struct {
	Rule
	re *regexp.Regexp
}

// compiled returns the seed corpus, compiled once.
//
// A regex in the seed that does not compile is a bug in airlock's own vendored
// data, not bad user input, so this panics rather than degrading quietly to a
// detector with a silent hole in it. TestSeedRulesCompile catches it long before
// any caller does.
var compiled = sync.OnceValue(func() []compiledRule {
	out := make([]compiledRule, 0, len(seedRules))
	for _, r := range seedRules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			panic(fmt.Sprintf("detect: seed rule %q has an uncompilable pattern: %v", r.ID, err))
		}
		out = append(out, compiledRule{Rule: r, re: re})
	}
	return out
})

// Rules returns a copy of the built-in rule corpus, in its stable order.
//
// Exposed so a caller can see exactly what airlock scans for, and on what
// evidentiary footing. The returned slice is a copy; mutating it changes nothing.
func Rules() []Rule {
	out := make([]Rule, len(seedRules))
	copy(out, seedRules)
	return out
}
