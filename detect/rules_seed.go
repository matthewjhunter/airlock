// Copyright 2026 Matthew Hunter
// SPDX-License-Identifier: Apache-2.0

// This file is airlock's JUDGMENT about the vendored pattern corpus in
// rules_pipelock.go. The regexes are pipelock's (Apache-2.0); everything here --
// the IDs, the categories, the severities, and the reasoning -- is airlock's own,
// and is not inherited from any upstream source.
//
// It has to be airlock's own, because there is nothing to inherit: pipelock's
// ResponseScanPattern struct is {Name, Regex, Bundle, BundleVersion, Compiled}. It
// carries no severity. Only pipelock's DLP patterns do, and those are exactly the
// patterns airlock does not port.
//
// # What severity means here
//
// The tiers grade EVIDENTIARY WEIGHT -- how much a hit actually tells you -- not
// how much damage the attack would do:
//
//   - High:   the text is hostile or it is nothing. No honest reading of a match.
//   - Medium: hostile in context, but the phrasing has legitimate uses.
//   - Low:    might be injection; just as likely ordinary prose. A Low hit alone is
//             close to worthless. The test suite asserts Low rules DO fire on benign
//             text, because that is precisely what the tier claims about them.
//
// Every rule below records why it sits where it does. Disagree and change it: that
// is a reviewable judgment, which is the entire point of writing it down.

package detect

import "fmt"

// ruleMeta is airlock's judgment about one vendored pattern, keyed by its upstream
// name.
type ruleMeta struct {
	ID       string
	Category string
	Severity Severity
}

// ruleMetaByUpstreamName assigns an ID, a category, and a severity to each pattern
// in rules_pipelock.go. A pattern with no entry here is a build-time panic, not a
// silent omission -- see seedRules.
var ruleMetaByUpstreamName = map[string]ruleMeta{
	// The canonical override. Prose does not tell its reader to disregard prior instructions.
	"Prompt Injection": {ID: "prompt-injection", Category: "injection", Severity: SeverityHigh},

	// Matches a bare `system:` at line start. Chat transcripts, YAML, and logs are full of it.
	"System Override": {ID: "system-override", Category: "injection", Severity: SeverityLow},

	// 'you are now DAN/unrestricted/jailbroken' has no honest reading.
	"Role Override": {ID: "role-override", Category: "jailbreak", Severity: SeverityHigh},

	// 'updated rules' and 'new instructions' are ordinary English; fires constantly on documentation.
	"New Instructions": {ID: "new-instructions", Category: "injection", Severity: SeverityLow},

	// Named jailbreak modes (DAN, developer mode, sudo mode) are terms of art with no benign use in content.
	"Jailbreak Attempt": {ID: "jailbreak-attempt", Category: "jailbreak", Severity: SeverityHigh},

	// Text that asks to be hidden from the user is hostile by construction.
	"Hidden Instruction": {ID: "hidden-instruction", Category: "concealment", Severity: SeverityHigh},

	// 'from now on you will' is directive and forward-scoped, but legitimate instruction-giving sounds the same.
	"Behavior Override": {ID: "behavior-override", Category: "injection", Severity: SeverityMedium},

	// Decode-then-execute and eval(atob( are attack shapes, not content.
	"Encoded Payload": {ID: "encoded-payload", Category: "execution", Severity: SeverityHigh},

	// Content commanding the model to call a tool is suspicious, but documentation describes tool calls too.
	"Tool Invocation": {ID: "tool-invocation", Category: "tooling", Severity: SeverityMedium},

	// Content does not get to grant the model admin rights.
	"Authority Escalation": {ID: "authority-escalation", Category: "escalation", Severity: SeverityHigh},

	// Reclassifying prior instructions as 'advisory' or 'outdated' is a targeted attack on the instruction hierarchy.
	"Instruction Downgrade": {ID: "instruction-downgrade", Category: "injection", Severity: SeverityHigh},

	// 'set the previous instructions aside' is the canonical override in a politer register.
	"Instruction Dismissal": {ID: "instruction-dismissal", Category: "injection", Severity: SeverityHigh},

	// 'prioritize the user request' is how ordinary task descriptions are phrased.
	"Priority Override": {ID: "priority-override", Category: "injection", Severity: SeverityLow},

	// Content demanding credentials from the model in order to 'continue' is a phishing shape. Acted on, it is the worst case.
	"Auth Material Requirement": {ID: "auth-material-requirement", Category: "credential", Severity: SeverityHigh},

	// Persisting attacker text across sessions is serious, but 'remember this for later' is also a normal user request.
	"Memory Persistence Directive": {ID: "memory-persistence-directive", Category: "memory", Severity: SeverityMedium},

	// Steering future tool choice is a real attack, but the phrasing overlaps legitimate preference-setting.
	"Preference Poisoning": {ID: "preference-poisoning", Category: "memory", Severity: SeverityMedium},

	// Concealment plus credentials. Both halves are damning; together there is no honest reading.
	"Silent Credential Handling": {ID: "silent-credential-handling", Category: "credential", Severity: SeverityHigh},

	// 'secretly exfiltrate/send/run' states hostile intent outright.
	"Covert Action Directive": {ID: "covert-action-directive", Category: "concealment", Severity: SeverityHigh},

	// Raw ChatML/Llama/Mistral control tokens in content are an attempt to forge a turn boundary.
	"Instruction Boundary": {ID: "instruction-boundary", Category: "control-token", Severity: SeverityHigh},

	// The canonical override, in Spanish.
	"Spanish Instruction Override": {ID: "spanish-instruction-override", Category: "injection", Severity: SeverityHigh},

	// Prompt extraction, Spanish. Damaging, but not directly actuating -- see system-prompt-disclosure.
	"Spanish System Prompt Disclosure": {ID: "spanish-system-prompt-disclosure", Category: "disclosure", Severity: SeverityMedium},

	// The canonical override with mixed-language verb/noun pairing.
	"Cross-Lingual Instruction Override": {ID: "cross-lingual-instruction-override", Category: "injection", Severity: SeverityHigh},

	// Prompt extraction, mixed-language.
	"Cross-Lingual System Prompt Disclosure": {ID: "cross-lingual-system-prompt-disclosure", Category: "disclosure", Severity: SeverityMedium},

	// The canonical override, in Chinese.
	"CJK Instruction Override ZH": {ID: "cjk-instruction-override-zh", Category: "injection", Severity: SeverityHigh},

	// The canonical override, in Japanese.
	"CJK Instruction Override JP": {ID: "cjk-instruction-override-jp", Category: "injection", Severity: SeverityHigh},

	// The canonical override, in Korean. Note this rule cannot fire at all without the NFC fix in normalize -- see normalize.StripCombiningMarks.
	"CJK Instruction Override KR": {ID: "cjk-instruction-override-kr", Category: "injection", Severity: SeverityHigh},

	// Named jailbreak modes, CJK.
	"CJK Jailbreak Mode": {ID: "cjk-jailbreak-mode", Category: "jailbreak", Severity: SeverityHigh},

	// Dumping the system prompt or tool definitions leaks configuration, but does not by itself make the model act. Strictly less serious than content that solicits credentials or actuates a tool, so it does not get High.
	"System Prompt Disclosure": {ID: "system-prompt-disclosure", Category: "disclosure", Severity: SeverityMedium},
}

// seedRules is the built-in corpus: the vendored regexes joined to airlock's
// judgment, in upstream order.
//
// A vendored pattern with no metadata entry panics at init rather than being
// dropped. A corpus that quietly shrank when someone re-vendored upstream would
// look complete and not be, which is the failure mode this package can least afford.
var seedRules = func() []Rule {
	out := make([]Rule, 0, len(pipelockPatterns))
	for _, p := range pipelockPatterns {
		meta, ok := ruleMetaByUpstreamName[p.Name]
		if !ok {
			panic(fmt.Sprintf("detect: vendored pattern %q has no severity/category "+
				"assigned in ruleMetaByUpstreamName; assign one rather than dropping it", p.Name))
		}
		out = append(out, Rule{
			ID:       meta.ID,
			Title:    p.Name,
			Category: meta.Category,
			Severity: meta.Severity,
			Pattern:  p.Regex,
		})
	}
	return out
}()
