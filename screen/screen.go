// Copyright 2026 Matthew Hunter
// SPDX-License-Identifier: Apache-2.0

// Package screen is the model-backed half of airlock's injection detection: a
// canonical screening prompt, the schema of the verdict it asks for, and the
// conversion of that verdict into airlock's [detect] vocabulary.
//
// # It does not call a model
//
// screen makes no network calls and has no model client, no HTTP client, no
// timeouts, no retries, and no configuration for any provider. It hands you a
// prompt string and parses a reply string. What runs in between is the caller's
// business.
//
// That is deliberate, and it is what keeps airlock auditable. The value of [wrap]
// is that the whole guarantee fits in your head; the moment this library opens a
// socket it becomes a service client and stops being something you can reason
// about. Callers already own their model plumbing -- concurrency ceilings, model
// selection, temperature, prompt overrides -- and they should keep owning it.
//
// # Why the prompt reads the way it does
//
// Safety-trained models are the ones you want for this job and are also the ones
// most likely to get it wrong, in a specific and predictable direction: asked
// whether text is "unsafe", they answer the question they were trained on, which is
// whether the text is offensive. They flag politics. They flag cruelty. They flag
// articles about scams. None of that is prompt injection.
//
// So the prompt never uses the word "safe". It replaces the question entirely:
// not "is this text bad" but "is this text giving orders to an AI". It supplies a
// decisive test (who is the sentence addressed to -- a human reader, or a model?),
// an explicit and long list of things that are NOT injections, and an evidence
// requirement: to report a threat the model must quote the exact span aimed at an
// AI, verbatim. No quotable span means no injection, and the score is 0.
//
// The evidence requirement is the load-carrying part. A model can always feel that
// something is off; it cannot always quote an instruction, and being forced to try
// is what separates "this article disturbs me" from "this article is talking to me".
//
// # Extending it
//
// The built-in exclusion list is generic -- politics, cruelty, misinformation,
// quoted attack code, imperatives aimed at humans. Domains have their own recurring
// false positives, and those go in [Options.Exclusions], which are appended to the
// prompt as additional "not an injection" rules. A feed reader might exclude
// clickbait and affiliate links; a code-review bot might exclude commit messages
// that say "ignore the previous commit".
package screen

import (
	_ "embed"
	"fmt"
	"strings"
	"text/template"

	"github.com/matthewjhunter/airlock/detect"
	"github.com/matthewjhunter/airlock/unwrap"
	"github.com/matthewjhunter/airlock/wrap"
)

//go:embed prompt.txt
var promptText string

var promptTmpl = template.Must(template.New("screen").Parse(promptText))

// Options tunes the screening prompt.
type Options struct {
	// Exclusions are additional "this is NOT an injection" rules, appended to the
	// generic list already in the prompt. Use them for the false positives specific
	// to your domain -- the things your model keeps flagging that you keep having to
	// explain are fine.
	//
	// Each entry should be a short phrase, not a sentence of prose: "Clickbait
	// headlines and affiliate links", not "Please do not flag clickbait because we
	// have found that it is usually harmless."
	Exclusions []string
}

// Prompt is a rendered screening prompt and the nonce that fences its content.
type Prompt struct {
	// Text is the prompt to send to the model.
	Text string

	// Nonce is the fence delimiter used in Text. Retained so a caller can assert
	// the model did not echo the fence back, or log which fence was used.
	Nonce string
}

// Render builds a screening prompt for content.
//
// The content is neutralized and fenced by [wrap]: it is enclosed in a per-call
// nonce delimiter that the prompt names in its trusted region, and any fence-shaped
// tag inside it -- including one disguised with homoglyphs or zero-width characters
// -- is removed first. The content cannot close the fence it sits in.
func Render(content string, opts Options) (Prompt, error) {
	nonce, err := wrap.Nonce()
	if err != nil {
		return Prompt{}, fmt.Errorf("screen: %w", err)
	}

	var sb strings.Builder
	err = promptTmpl.Execute(&sb, struct {
		Nonce      string
		Content    string
		Exclusions []string
	}{
		Nonce:   nonce,
		Content: wrap.Neutralize(content),
		// Exclusions are operator-authored, not attacker-authored, but they are
		// still interpolated into the trusted region of a prompt. Neutralize them
		// too: a fence tag pasted into a config file by accident should not be able
		// to split the prompt.
		Exclusions: neutralizeAll(opts.Exclusions),
	})
	if err != nil {
		return Prompt{}, fmt.Errorf("screen: render prompt: %w", err)
	}

	return Prompt{Text: sb.String(), Nonce: nonce}, nil
}

func neutralizeAll(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = wrap.Neutralize(s)
	}
	return out
}

// Bounds on the free-text fields a model returns. The prompt asks for short values;
// these enforce it, because a prompt is a request and a model is not obliged to
// honor it -- and because the text in question is derived from attacker-authored
// content, so its length is attacker-chosen.
//
// EvidenceMaxRunes is deliberately tight. The evidence field exists to prove the
// model found a specific instruction rather than a general unease, and the shortest
// span that does that is the most convincing one. It also has to fit somewhere real:
// a log line, an error message, a database column.
const (
	EvidenceMaxRunes = 120
	ReasonMaxRunes   = 300
)

// Verdict is the model's answer, as the prompt asks for it.
//
// # Evidence and Reason are attacker-derived. Treat them as untrusted.
//
// Evidence is a verbatim quote of hostile content, and Reason is a sentence the model
// wrote about it. Both are downstream of text an attacker wrote, and both have just
// been carried back out through the fence into your data model. Consequences:
//
//   - Evidence can itself contain a fence delimiter -- the model is quoting attacker
//     text, and that text may well have contained one. [ParseVerdict] runs both
//     fields through [wrap.Neutralize] for exactly this reason, so a quoted tag
//     cannot ride back into a later prompt.
//   - Never interpolate either field into another prompt unfenced. If you want the
//     model to explain a verdict, fence the evidence like any other untrusted span.
//   - Escape both before rendering them in a UI, and expect them in your logs.
type Verdict struct {
	// Threat runs 0 to 10. 0 means no instruction addressed to an AI was found,
	// and is the expected answer for almost all text.
	//
	// The polarity matches the rest of airlock: zero is clean, and evidence adds.
	// A safety score, where a high number means "fine", cannot be combined with
	// other evidence without subtracting from a ceiling.
	Threat int `json:"threat"`

	// Category is the model's classification: override, persona, concealment,
	// extraction, tool-hijack, fake-turn, encoded, or none.
	Category string `json:"category"`

	// Evidence is the verbatim span the model says is addressed to an AI. The
	// prompt requires it: no quotable span means no injection. An empty Evidence
	// with a non-zero Threat is a malformed verdict -- see [Verdict.Validate].
	Evidence string `json:"evidence"`

	// Reason is one sentence naming who the quoted text addresses and what it
	// orders.
	Reason string `json:"reason"`
}

// ParseVerdict recovers a Verdict from a model's reply, tolerating the usual wrappers
// models add (markdown fences, leading commentary) via [unwrap].
//
// It neutralizes and bounds Evidence and Reason as it parses. Both are attacker-derived
// -- Evidence is a verbatim quote of hostile text -- so this is the boundary at which
// they stop being a prompt response and become data your program handles. A quoted
// fence delimiter is stripped here, and an over-long field is truncated here, rather
// than in whatever log line or database column happens to receive it later.
func ParseVerdict(reply string) (Verdict, error) {
	v, err := unwrap.Into[Verdict](reply)
	if err != nil {
		return Verdict{}, fmt.Errorf("screen: parse verdict: %w", err)
	}

	v.Evidence = truncate(wrap.Neutralize(v.Evidence), EvidenceMaxRunes)
	v.Reason = truncate(wrap.Neutralize(v.Reason), ReasonMaxRunes)
	v.Category = truncate(v.Category, 32)

	return v, nil
}

// truncate cuts s to at most n runes, marking that it did so. Runes, not bytes: a
// byte-wise cut would split a multi-byte character and produce invalid UTF-8, and the
// text being cut here is frequently not ASCII.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return strings.TrimRight(string(r[:n]), " ") + "..."
}

// Validate reports whether the verdict is internally coherent, and clamps Threat
// into range.
//
// The check that matters is the evidence requirement. A model that reports a threat
// without quoting the instruction it found has not detected an injection -- it has
// had a feeling, which is the exact failure this prompt is built to suppress. The
// caller decides what to do about it; Validate only names it.
func (v Verdict) Validate() (Verdict, error) {
	out := v
	if out.Threat < 0 {
		out.Threat = 0
	}
	if out.Threat > 10 {
		out.Threat = 10
	}

	// Belt and braces: ParseVerdict already bounds these, but a Verdict can also be
	// constructed directly, and an unbounded attacker-derived string must not reach an
	// error message or a log line.
	out.Evidence = truncate(out.Evidence, EvidenceMaxRunes)
	out.Reason = truncate(out.Reason, ReasonMaxRunes)

	if out.Threat > 0 && strings.TrimSpace(out.Evidence) == "" {
		// Metadata only. The reason field is model prose about attacker text and can
		// quote it; an error string is not a fenced channel. See [Finding].
		return out, fmt.Errorf("screen: verdict reports threat %d (category=%s) but quotes no "+
			"evidence; the prompt requires a verbatim span addressed to an AI, so this is a "+
			"content judgment rather than an injection finding",
			out.Threat, canonicalCategory(out.Category, out.Threat))
	}
	return out, nil
}

// Severity maps the model's 0-10 threat onto airlock's evidentiary tiers.
func (v Verdict) Severity() detect.Severity {
	switch {
	case v.Threat <= 0:
		return detect.SeverityNone
	case v.Threat <= 3:
		return detect.SeverityLow
	case v.Threat <= 6:
		return detect.SeverityMedium
	default:
		return detect.SeverityHigh
	}
}

// Matches expresses the verdict as [detect.Match] values, so a model screen and the
// regex corpus combine through the same [detect.Result.Score].
//
// The match is filed under the category "llm-screen" rather than under the model's
// own classification, and that is on purpose. Score collapses hits within a category
// because rules in a category are usually near-duplicates of one another -- the same
// evidence counted twice. A model verdict is not a duplicate of a regex hit: it is an
// independent method reaching the same conclusion, which is what corroboration
// actually means. Keeping it in its own category lets it corroborate rather than
// collapse.
func (v Verdict) Matches() []detect.Match {
	sev := v.Severity()
	if sev == detect.SeverityNone {
		return nil
	}

	cat := v.Category
	if cat == "" || cat == "none" {
		cat = "unclassified"
	}

	return []detect.Match{{
		Rule:     "llm-screen",
		Title:    "Model injection screen: " + cat,
		Category: "llm-screen",
		Severity: sev,
	}}
}

// Prompt returns the raw screening prompt template, for callers who want to inspect,
// diff, or fork it. It is the embedded prompt.txt, unrendered.
func PromptTemplate() string { return promptText }
