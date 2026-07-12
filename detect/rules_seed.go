// Copyright 2026 Josh Waldrep
// Copyright 2026 Matthew Hunter
// SPDX-License-Identifier: Apache-2.0

// Code in this file is DATA, converted once at port time -- do not hand-edit the
// regexes. They were extracted mechanically from pipelock's
// internal/config/defaults.go and internal/scanner/core.go at commit
// 41e5c57051866d43c5d87cb4e7d5a927cfe3f95f (Apache-2.0), so they are character-
// for-character upstream. See NOTICE and docs/pipelock-port.md.
//
// # What was dropped, and why (no silent caps)
//
// defaults.go holds 30 response-scan patterns. Three are NOT ported:
//
//   - Credential Solicitation
//   - Markdown Link Credential Exfiltration
//   - Credential Path Directive
//
// All three inspect where data is going rather than what the model was told, which
// makes them egress/DLP concerns and puts them outside airlock's scope. They are
// also the only three whose regex lives in a Go constant rather than inline, so
// the extraction confirms the boundary independently.
//
// The remaining 27, plus System Prompt Disclosure (the one injection pattern
// core.go has that defaults.go lacks), give the 28 rules below.
//
// # Severity is airlock's judgment, NOT upstream data
//
// pipelock's ResponseScanPattern carries no severity field -- only its DLP
// patterns do, and those are the ones we dropped. Every Severity below is an
// editorial call made here, about how much a hit actually tells you:
//
//   - High:   the text is hostile or it is nothing. Overrides, jailbreaks,
//             concealment, credential solicitation, control tokens.
//   - Medium: hostile in context, but the phrasing has honest uses.
//   - Low:    might be injection; just as likely to be ordinary prose. A Low hit
//             on its own is close to worthless. Treat it as a prior, not a finding.
//
// Each rule records why it sits where it does. Disagree and change it -- that is a
// reviewable judgment, which is the point of writing it down.

package detect

// seedRules is the vendored built-in corpus: 28 rules, in a stable order.
var seedRules = []Rule{
	{
		// The canonical override. Prose does not tell a reader to disregard its prior instructions.
		ID:       "prompt-injection",
		Title:    "Prompt Injection",
		Category: "injection",
		Severity: SeverityHigh,
		Pattern:  `(?i)(ignore|disregard|forget|abandon)[-,;:.\s]+\s*(?:all\s+\w+\s+|\w+\s+all\s+|all\s+|\w+\s+)?(previous|prior|above|earlier)\s+(\w+\s+)?(instructions|prompts|rules|context|directives|constraints|policies|guardrails)`,
	},
	{
		// Matches a bare `system:` at line start. Chat transcripts, YAML, and logs are full of it.
		ID:       "system-override",
		Title:    "System Override",
		Category: "injection",
		Severity: SeverityLow,
		Pattern:  `(?im)^\s*system\s*:`,
	},
	{
		// 'you are now DAN/unrestricted/jailbroken' has no honest reading.
		ID:       "role-override",
		Title:    "Role Override",
		Category: "jailbreak",
		Severity: SeverityHigh,
		Pattern:  `(?i)you\s+are\s+(now\s+)?(a\s+)?((?-i:\bDAN\b)|evil|unrestricted|jailbroken|unfiltered)`,
	},
	{
		// 'updated rules' and 'new instructions' are ordinary English. Fires constantly on documentation.
		ID:       "new-instructions",
		Title:    "New Instructions",
		Category: "injection",
		Severity: SeverityLow,
		Pattern:  `(?i)(new|updated|revised)\s+(instructions|directives|rules|prompt)`,
	},
	{
		// Named jailbreak modes (DAN, developer mode, sudo mode) are terms of art with no benign use in content.
		ID:       "jailbreak-attempt",
		Title:    "Jailbreak Attempt",
		Category: "jailbreak",
		Severity: SeverityHigh,
		Pattern:  `(?i)((?-i:\bDAN\b)|developer\s+mode|sudo\s+mode|unrestricted\s+mode)`,
	},
	{
		// Text that asks to be hidden from the user is hostile by construction.
		ID:       "hidden-instruction",
		Title:    "Hidden Instruction",
		Category: "concealment",
		Severity: SeverityHigh,
		Pattern:  `(?i)(do\s+not\s+(reveal|tell|show|display|mention)\s+this\s+to\s+the\s+user|hidden\s+instructions?\s*[:=]|invisible\s+to\s+(the\s+)?user|the\s+user\s+(cannot|must\s+not|should\s+not)\s+see\s+this)`,
	},
	{
		// 'from now on you will' is directive and forward-scoped, but appears in legitimate instruction-giving too.
		ID:       "behavior-override",
		Title:    "Behavior Override",
		Category: "injection",
		Severity: SeverityMedium,
		Pattern:  `(?i)from\s+now\s+on\s+(you\s+)?(will|must|should|shall)\s+`,
	},
	{
		// Decode-then-execute and eval(atob( are attack shapes, not content.
		ID:       "encoded-payload",
		Title:    "Encoded Payload",
		Category: "execution",
		Severity: SeverityHigh,
		Pattern:  `(?i)(decode\s+(this|the\s+following)\s+(from\s+)?base64\s+and\s+(execute|run|follow)|eval\s*\(\s*atob\s*\()`,
	},
	{
		// Content that commands the model to call a tool is suspicious, but documentation describes tool calls too.
		ID:       "tool-invocation",
		Title:    "Tool Invocation",
		Category: "tooling",
		Severity: SeverityMedium,
		Pattern:  `(?i)you\s+must\s+(\w+\s+)?(call|execute|run|invoke)\s+(the|this|a)\s+(\w+\s+)?(function|tool|command|api|endpoint)`,
	},
	{
		// Content does not get to grant the model admin rights.
		ID:       "authority-escalation",
		Title:    "Authority Escalation",
		Category: "escalation",
		Severity: SeverityHigh,
		Pattern:  `(?i)you\s+(now\s+)?have\s+(full\s+)?(admin|root|system|superuser|elevated)\s+(access|privileges|permissions|rights)`,
	},
	{
		// Reclassifying prior instructions as 'advisory' or 'outdated' is a targeted attack on the instruction hierarchy.
		ID:       "instruction-downgrade",
		Title:    "Instruction Downgrade",
		Category: "injection",
		Severity: SeverityHigh,
		Pattern:  `(?i)(treat|consider|regard|reinterpret|downgrade)\s+((?:the|all)\s+)?(previous|prior|above|earlier|system|policy|original|existing)\s+(\w+\s+)?(text|instructions?|rules|directives|guidelines|safeguards|constraints|controls|checks|context|prompt|policies|guardrails|parameters)\s+((as|to)\s+)?(historical|outdated|deprecated|optional|background|secondary|non-binding|non-authoritative|informational|advisory)`,
	},
	{
		// 'set the previous instructions aside' is the canonical override in a politer register.
		ID:       "instruction-dismissal",
		Title:    "Instruction Dismissal",
		Category: "injection",
		Severity: SeverityHigh,
		Pattern:  `(?i)(set|put)\s+(the\s+)?(previous|prior|above|earlier|system|original)\s+(\w+\s+)?(instructions?|directives|rules|constraints|context|prompt|safeguards|guidelines|policies|guardrails)\s+(aside|away|to\s+(one|the)\s+side)`,
	},
	{
		// 'prioritize the user request' is how ordinary task descriptions are phrased.
		ID:       "priority-override",
		Title:    "Priority Override",
		Category: "injection",
		Severity: SeverityLow,
		Pattern:  `(?i)\bprioritize\s+(the\s+)?(task|user|current|new|latest)\s+(request|message|input|instructions?|prompt)`,
	},
	{
		// Content demanding credentials from the model to 'continue' is a phishing shape. Credential solicitation is the worst case if acted on.
		ID:       "auth-material-requirement",
		Title:    "Auth Material Requirement",
		Category: "credential",
		Severity: SeverityHigh,
		Pattern:  `(?is)\bto\s+(complete|continue|finish|proceed|verify)\b.{0,80}\b(authentication|credential|token|api[_ -]?key|private[_ -]?key|ssh[_ -]?key)\b.{0,40}\b(required|needed|necessary|must be)\b`,
	},
	{
		// Persisting attacker text across sessions is serious, but 'remember this for later' is also a normal user request.
		ID:       "memory-persistence-directive",
		Title:    "Memory Persistence Directive",
		Category: "memory",
		Severity: SeverityMedium,
		Pattern:  `(?is)\b(save|store|remember|retain|persist|record|cache)\b.{0,40}\b(this|these|that|it|the)\b.{0,60}\b(for future|for later|across sessions?|next session|next time|future tasks?|future sessions?|for all future|subsequent|permanently|from now on|going forward|in all future)\b`,
	},
	{
		// Steering future tool choice is a real attack, but the phrasing overlaps with legitimate preference-setting.
		ID:       "preference-poisoning",
		Title:    "Preference Poisoning",
		Category: "memory",
		Severity: SeverityMedium,
		Pattern:  `(?is)\b(from now on|always|going forward|in future)\b.{0,80}\b(prefer|prioritize|trust|choose|use|default to)\b.{0,60}\b(this tool|that tool|my tool|the external|the remote)\b`,
	},
	{
		// Concealment plus credentials. Both halves are damning; together there is no honest reading.
		ID:       "silent-credential-handling",
		Title:    "Silent Credential Handling",
		Category: "credential",
		Severity: SeverityHigh,
		Pattern:  `(?is)\b(do not|don'?t|never)\s+(mention|display|show|tell|reveal|log|report)\b.{0,100}\b(password|token|secret|credential|private[_ -]?key|api[_ -]?key)\b`,
	},
	{
		// 'secretly exfiltrate/send/run' states hostile intent outright.
		ID:       "covert-action-directive",
		Title:    "Covert Action Directive",
		Category: "concealment",
		Severity: SeverityHigh,
		Pattern:  `(?is)(secretly|silently|covertly|quietly|without\s+(?:the\s+user\s+)?(?:knowing|noticing|seeing))[,;:]?\s+.{0,40}\b(execut\w*|run|call|invoke|send|fetch|curl|wget|download|upload|post|exfiltrat\w*|leak|stream|transmit|relay|forward|smuggle)\b`,
	},
	{
		// Raw ChatML/Llama/Mistral control tokens in content are an attempt to forge a turn boundary.
		ID:       "instruction-boundary",
		Title:    "Instruction Boundary",
		Category: "control-token",
		Severity: SeverityHigh,
		Pattern:  `(<\|(?:endoftext|im_start|im_end|system|end_header_id|begin_of_text)\|>|\[/?INST\]|<\|(?:user|assistant)\|>|<<SYS>>)`,
	},
	{
		// Same canonical override, Spanish.
		ID:       "spanish-instruction-override",
		Title:    "Spanish Instruction Override",
		Category: "injection",
		Severity: SeverityHigh,
		Pattern:  `(?i)\b(ignora|omite|olvida|desobedece|descarta)\b.{0,30}\b(las\s+)?(instrucciones|indicaciones|directivas|reglas)\b.{0,30}\b(anteriores|previas|precedentes|de\s+arriba)\b`,
	},
	{
		// Prompt extraction, Spanish. Damaging but not directly actuating -- see system-prompt-disclosure.
		ID:       "spanish-system-prompt-disclosure",
		Title:    "Spanish System Prompt Disclosure",
		Category: "disclosure",
		Severity: SeverityMedium,
		Pattern:  `(?i)\b(muestra|revela|imprime|expone|dime)\b.{0,40}\b(prompt|mensaje)\s+(del\s+)?sistema\b`,
	},
	{
		// Canonical override with mixed-language verb/noun pairing.
		ID:       "cross-lingual-instruction-override",
		Title:    "Cross-Lingual Instruction Override",
		Category: "injection",
		Severity: SeverityHigh,
		Pattern:  `(?i)\b(ignore|disregard|forget|abandon|ignora|omite|olvida|desobedece|descarta)\b.{0,40}\b(previous|prior|above|earlier|anteriores|previas|precedentes|de\s+arriba)\b.{0,40}\b(instructions?|instrucciones|indicaciones|directivas|reglas|prompts?|context|constraints?|policies|guardrails)\b`,
	},
	{
		// Prompt extraction, mixed-language.
		ID:       "cross-lingual-system-prompt-disclosure",
		Title:    "Cross-Lingual System Prompt Disclosure",
		Category: "disclosure",
		Severity: SeverityMedium,
		Pattern:  `(?i)\b(show|reveal|print|display|dump|muestra|revela|imprime|expone|dime)\b.{0,40}\b(system\s+prompt|prompt\s+(del\s+)?sistema|mensaje\s+(del\s+)?sistema)\b`,
	},
	{
		// Canonical override, Chinese.
		ID:       "cjk-instruction-override-zh",
		Title:    "CJK Instruction Override ZH",
		Category: "injection",
		Severity: SeverityHigh,
		Pattern:  `(忽略|无视|忽视|不理|不要遵[循守]|放弃|跳过).{0,10}(之前|以上|上述|以前|上面|先前|前面).{0,8}(所有|全部|一切)?.{0,6}(指令|指示|说明|规则|命令|提示|约束|限制)`,
	},
	{
		// Canonical override, Japanese.
		ID:       "cjk-instruction-override-jp",
		Title:    "CJK Instruction Override JP",
		Category: "injection",
		Severity: SeverityHigh,
		Pattern:  `(以前|前|上記|これまで|今まで).{0,6}(指示|命令|ルール|規則|指令).{0,6}(すべて|全て|全部)?.{0,4}(無視|忘れ|従わな|捨て)`,
	},
	{
		// Canonical override, Korean.
		ID:       "cjk-instruction-override-kr",
		Title:    "CJK Instruction Override KR",
		Category: "injection",
		Severity: SeverityHigh,
		Pattern:  `(이전|위|앞|기존).{0,6}(모든\s*)?(지시|지침|명령|규칙|지령).{0,6}(무시|잊어|따르지|어기|무효)`,
	},
	{
		// Named jailbreak modes, CJK.
		ID:       "cjk-jailbreak-mode",
		Title:    "CJK Jailbreak Mode",
		Category: "jailbreak",
		Severity: SeverityHigh,
		Pattern:  `(开发者模式|无限制模式|開発者モード|制限なしモード|개발자\s*모드|제한\s*없는\s*모드|没有任何?限制|制限.{0,4}(解除|無視)|제한.{0,4}(해제|무시))`,
	},
	{
		// Asking the model to dump its system prompt or tool definitions leaks configuration, but does not by itself make the model act. Strictly less serious than content that solicits credentials or actuates a tool -- so it does not get High.
		ID:       "system-prompt-disclosure",
		Title:    "System Prompt Disclosure",
		Category: "disclosure",
		Severity: SeverityMedium,
		Pattern:  `(?is)\b(output|print|reveal|show|display|dump|return|exfiltrate)\b.{0,80}\b(system\s+prompt|tool\s+definitions?|developer\s+instructions?)\b`,
	},
}
