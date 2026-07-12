// Copyright 2026 Matthew Hunter
// SPDX-License-Identifier: Apache-2.0

package screen

import (
	"fmt"
	"log/slog"
	"slices"
)

// Categories is the fixed vocabulary a verdict's category must belong to.
//
// It is a closed set on purpose. Category is a field a model fills in from
// attacker-influenced text, and it is a field callers persist, index, log, and build
// dashboards on. A free-text category is an attacker-authored string with a
// respectable-looking name on it. Anything outside this set becomes
// [CategoryUnclassified].
var Categories = []string{
	"override",    // disregard/replace/downgrade the AI's instructions
	"persona",     // "you are now an unrestricted assistant"
	"concealment", // hide this from the user, act silently
	"extraction",  // reveal the system prompt, tool definitions, credentials
	"tool-hijack", // call a tool, send a request, run code
	"fake-turn",   // forged turn boundaries or control tokens
	"encoded",     // decode this and then execute it
}

// CategoryUnclassified is the category assigned when a model returns one that is not
// in [Categories], or returns none while reporting a threat.
const CategoryUnclassified = "unclassified"

// CategoryNone is the category of a clean verdict.
const CategoryNone = "none"

// canonicalCategory constrains a model-supplied category to the known vocabulary.
func canonicalCategory(c string, threat int) string {
	if threat <= 0 {
		return CategoryNone
	}
	if slices.Contains(Categories, c) {
		return c
	}
	return CategoryUnclassified
}

// Finding is the part of a screening result that is safe to keep.
//
// It holds no attacker-authored bytes. Not the quoted evidence, not the model's prose
// about it, not a byte offset into a string that will not exist tomorrow. Three fields,
// all bounded, all drawn from closed vocabularies. This is the thing to put in a
// database column, an audit log, a metric, an alert, and an error message.
//
// # Why the payload is not in here
//
// Everything airlock does rests on untrusted text reaching a model only inside a
// nonce fence. A log line is not fenced. Neither is an error string, a dashboard, or
// a database column that some tool renders later. Evidence quoted out of a hostile
// article and parked in any of those has been handed a second delivery path -- to a
// human, to a log-scraping agent, to whatever model eventually summarizes the ops
// dashboard. Fencing the article and then copying its payload into the logs is not a
// defense.
//
// So the payload does not get stored. It gets RE-DERIVED when it is actually needed:
// the caller already has the article, and [Verdict.Locate] will find the span again at
// display time, inside whatever untrusted-content boundary already exists for showing
// article text. If the article has since changed and the span no longer matches, the
// caller learns that honestly, rather than being shown a stale offset resolving
// confidently against the wrong words.
type Finding struct {
	// Threat runs 0 to 10, 0 = clean. Zero is the expected answer for almost all text.
	Threat int `json:"threat"`

	// Category is one of [Categories], [CategoryNone], or [CategoryUnclassified].
	// Never free text.
	Category string `json:"category"`

	// Verified reports that the model's cited evidence was located in the content.
	//
	// For a clean verdict (Threat 0) there is nothing to cite and this is false. For a
	// threat, a Finding only exists if the evidence verified -- [Verdict.Finding]
	// refuses to produce one otherwise -- so on a stored threat this is always true.
	// It is recorded anyway, because a schema that cannot express "unverified" quietly
	// assumes every row was checked.
	Verified bool `json:"verified"`
}

// Clean reports whether the screen found nothing.
func (f Finding) Clean() bool { return f.Threat <= 0 }

// Finding verifies the verdict against the content it was screened from and reduces it
// to the payload-free record worth keeping.
//
// It fails when the model reports a threat it cannot show you: either it quoted nothing,
// or it quoted text that does not occur in the content. The second case is the important
// one. A model that has decided an article feels dangerous can still produce a
// quote-shaped string to justify itself; only the source text can tell that apart from a
// real citation. Evidence that is not in the article was not found in the article, and a
// finding built on it is void rather than merely weak.
//
// The returned error names the threat, the category, and the size of the citation -- and
// quotes none of it. See [Finding] for why an error message is the last place attacker
// text should end up.
func (v Verdict) Finding(content string) (Finding, error) {
	v, err := v.Validate()
	if err != nil {
		return Finding{}, err
	}

	cat := canonicalCategory(v.Category, v.Threat)

	if v.Threat <= 0 {
		return Finding{Threat: 0, Category: CategoryNone}, nil
	}

	if _, ok := v.Locate(content); !ok {
		return Finding{}, fmt.Errorf("screen: verdict reports threat %d (category=%s) citing a "+
			"%d-rune span that does not occur in the content: the model fabricated its evidence, "+
			"so the finding is void", v.Threat, cat, len([]rune(v.Evidence)))
	}

	return Finding{Threat: v.Threat, Category: cat, Verified: true}, nil
}

// String redacts the attacker-derived fields.
//
// This is not cosmetic. Verdict carries a verbatim quote of hostile content, and Go
// will cheerfully render a struct into a log line the moment anyone writes %v. The
// default rendering of this type therefore has to be the safe one, so that leaking the
// payload takes a deliberate act rather than an idle one. [Verdict.DebugString] is that
// deliberate act, and it is named so the intent is legible at the call site.
func (v Verdict) String() string {
	return fmt.Sprintf("screen.Verdict{Threat:%d Category:%s Evidence:<%d runes redacted> Reason:<%d runes redacted>}",
		v.Threat, canonicalCategory(v.Category, v.Threat), len([]rune(v.Evidence)), len([]rune(v.Reason)))
}

// LogValue redacts the attacker-derived fields for structured logging, for the same
// reason [Verdict.String] does. slog will otherwise reflect over the struct and emit
// the quote.
func (v Verdict) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int("threat", v.Threat),
		slog.String("category", canonicalCategory(v.Category, v.Threat)),
		slog.Int("evidence_runes", len([]rune(v.Evidence))),
		slog.Int("reason_runes", len([]rune(v.Reason))),
	)
}

// DebugString renders the verdict INCLUDING the model's quoted evidence and its prose.
//
// Both are attacker-derived. This exists because tuning a screening prompt without
// seeing what the model quoted is guesswork, and that is a real need -- but it is a
// need with a blast radius, so it is spelled out at the call site rather than being
// what you get for free from %v.
//
// Gate it behind a debug setting, keep it out of anything an agent or an LLM reads
// downstream, and do not persist what it returns.
func (v Verdict) DebugString() string {
	return fmt.Sprintf("screen.Verdict{Threat:%d Category:%s Evidence:%q Reason:%q}",
		v.Threat, canonicalCategory(v.Category, v.Threat), v.Evidence, v.Reason)
}
