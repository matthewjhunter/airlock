// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0
//
// VENDORED APACHE-2.0 DATA -- NOT airlock's own work.
//
// The regexes below were extracted mechanically (not retyped) from
// github.com/luckyPipewrench/pipelock at commit
// 41e5c57051866d43c5d87cb4e7d5a927cfe3f95f, and are character-for-character
// upstream. See NOTICE at the repository root.
//
//   - 27 of the 30 ResponseScanPattern entries in internal/config/defaults.go.
//   - System Prompt Disclosure, from internal/scanner/core.go -- the one injection
//     pattern core.go carries that defaults.go lacks.
//
// # What was NOT taken, and why (no silent caps)
//
// Three of defaults.go's 30 patterns are deliberately absent:
//
//   - Credential Solicitation
//   - Markdown Link Credential Exfiltration
//   - Credential Path Directive
//
// All three inspect where data is going rather than what the model was told, which
// makes them egress/DLP and puts them outside airlock's scope. They are also the
// only three whose regex lives in a Go constant rather than inline, so the
// extraction confirms the boundary independently. TestDroppedCredentialRulesAreAbsent
// fails if they reappear.
//
// This file is DATA. It carries no severity, no category, and no opinion -- pipelock's
// ResponseScanPattern has no severity field, so there is nothing of the sort to
// inherit. airlock's judgment about what these patterns are worth lives in
// rules_seed.go, and is airlock's alone.

package detect

// pipelockPattern is one upstream pattern, exactly as it appears in pipelock.
type pipelockPattern struct {
	Name  string
	Regex string
}

// pipelockPatterns is the vendored corpus, in upstream order.
var pipelockPatterns = []pipelockPattern{
	{Name: "Prompt Injection", Regex: `(?i)(ignore|disregard|forget|abandon)[-,;:.\s]+\s*(?:all\s+\w+\s+|\w+\s+all\s+|all\s+|\w+\s+)?(previous|prior|above|earlier)\s+(\w+\s+)?(instructions|prompts|rules|context|directives|constraints|policies|guardrails)`},
	{Name: "System Override", Regex: `(?im)^\s*system\s*:`},
	{Name: "Role Override", Regex: `(?i)you\s+are\s+(now\s+)?(a\s+)?((?-i:\bDAN\b)|evil|unrestricted|jailbroken|unfiltered)`},
	{Name: "New Instructions", Regex: `(?i)(new|updated|revised)\s+(instructions|directives|rules|prompt)`},
	{Name: "Jailbreak Attempt", Regex: `(?i)((?-i:\bDAN\b)|developer\s+mode|sudo\s+mode|unrestricted\s+mode)`},
	{Name: "Hidden Instruction", Regex: `(?i)(do\s+not\s+(reveal|tell|show|display|mention)\s+this\s+to\s+the\s+user|hidden\s+instructions?\s*[:=]|invisible\s+to\s+(the\s+)?user|the\s+user\s+(cannot|must\s+not|should\s+not)\s+see\s+this)`},
	{Name: "Behavior Override", Regex: `(?i)from\s+now\s+on\s+(you\s+)?(will|must|should|shall)\s+`},
	{Name: "Encoded Payload", Regex: `(?i)(decode\s+(this|the\s+following)\s+(from\s+)?base64\s+and\s+(execute|run|follow)|eval\s*\(\s*atob\s*\()`},
	{Name: "Tool Invocation", Regex: `(?i)you\s+must\s+(\w+\s+)?(call|execute|run|invoke)\s+(the|this|a)\s+(\w+\s+)?(function|tool|command|api|endpoint)`},
	{Name: "Authority Escalation", Regex: `(?i)you\s+(now\s+)?have\s+(full\s+)?(admin|root|system|superuser|elevated)\s+(access|privileges|permissions|rights)`},
	{Name: "Instruction Downgrade", Regex: `(?i)(treat|consider|regard|reinterpret|downgrade)\s+((?:the|all)\s+)?(previous|prior|above|earlier|system|policy|original|existing)\s+(\w+\s+)?(text|instructions?|rules|directives|guidelines|safeguards|constraints|controls|checks|context|prompt|policies|guardrails|parameters)\s+((as|to)\s+)?(historical|outdated|deprecated|optional|background|secondary|non-binding|non-authoritative|informational|advisory)`},
	{Name: "Instruction Dismissal", Regex: `(?i)(set|put)\s+(the\s+)?(previous|prior|above|earlier|system|original)\s+(\w+\s+)?(instructions?|directives|rules|constraints|context|prompt|safeguards|guidelines|policies|guardrails)\s+(aside|away|to\s+(one|the)\s+side)`},
	{Name: "Priority Override", Regex: `(?i)\bprioritize\s+(the\s+)?(task|user|current|new|latest)\s+(request|message|input|instructions?|prompt)`},
	{Name: "Auth Material Requirement", Regex: `(?is)\bto\s+(complete|continue|finish|proceed|verify)\b.{0,80}\b(authentication|credential|token|api[_ -]?key|private[_ -]?key|ssh[_ -]?key)\b.{0,40}\b(required|needed|necessary|must be)\b`},
	{Name: "Memory Persistence Directive", Regex: `(?is)\b(save|store|remember|retain|persist|record|cache)\b.{0,40}\b(this|these|that|it|the)\b.{0,60}\b(for future|for later|across sessions?|next session|next time|future tasks?|future sessions?|for all future|subsequent|permanently|from now on|going forward|in all future)\b`},
	{Name: "Preference Poisoning", Regex: `(?is)\b(from now on|always|going forward|in future)\b.{0,80}\b(prefer|prioritize|trust|choose|use|default to)\b.{0,60}\b(this tool|that tool|my tool|the external|the remote)\b`},
	{Name: "Silent Credential Handling", Regex: `(?is)\b(do not|don'?t|never)\s+(mention|display|show|tell|reveal|log|report)\b.{0,100}\b(password|token|secret|credential|private[_ -]?key|api[_ -]?key)\b`},
	{Name: "Covert Action Directive", Regex: `(?is)(secretly|silently|covertly|quietly|without\s+(?:the\s+user\s+)?(?:knowing|noticing|seeing))[,;:]?\s+.{0,40}\b(execut\w*|run|call|invoke|send|fetch|curl|wget|download|upload|post|exfiltrat\w*|leak|stream|transmit|relay|forward|smuggle)\b`},
	{Name: "Instruction Boundary", Regex: `(<\|(?:endoftext|im_start|im_end|system|end_header_id|begin_of_text)\|>|\[/?INST\]|<\|(?:user|assistant)\|>|<<SYS>>)`},
	{Name: "Spanish Instruction Override", Regex: `(?i)\b(ignora|omite|olvida|desobedece|descarta)\b.{0,30}\b(las\s+)?(instrucciones|indicaciones|directivas|reglas)\b.{0,30}\b(anteriores|previas|precedentes|de\s+arriba)\b`},
	{Name: "Spanish System Prompt Disclosure", Regex: `(?i)\b(muestra|revela|imprime|expone|dime)\b.{0,40}\b(prompt|mensaje)\s+(del\s+)?sistema\b`},
	{Name: "Cross-Lingual Instruction Override", Regex: `(?i)\b(ignore|disregard|forget|abandon|ignora|omite|olvida|desobedece|descarta)\b.{0,40}\b(previous|prior|above|earlier|anteriores|previas|precedentes|de\s+arriba)\b.{0,40}\b(instructions?|instrucciones|indicaciones|directivas|reglas|prompts?|context|constraints?|policies|guardrails)\b`},
	{Name: "Cross-Lingual System Prompt Disclosure", Regex: `(?i)\b(show|reveal|print|display|dump|muestra|revela|imprime|expone|dime)\b.{0,40}\b(system\s+prompt|prompt\s+(del\s+)?sistema|mensaje\s+(del\s+)?sistema)\b`},
	{Name: "CJK Instruction Override ZH", Regex: `(忽略|无视|忽视|不理|不要遵[循守]|放弃|跳过).{0,10}(之前|以上|上述|以前|上面|先前|前面).{0,8}(所有|全部|一切)?.{0,6}(指令|指示|说明|规则|命令|提示|约束|限制)`},
	{Name: "CJK Instruction Override JP", Regex: `(以前|前|上記|これまで|今まで).{0,6}(指示|命令|ルール|規則|指令).{0,6}(すべて|全て|全部)?.{0,4}(無視|忘れ|従わな|捨て)`},
	{Name: "CJK Instruction Override KR", Regex: `(이전|위|앞|기존).{0,6}(모든\s*)?(지시|지침|명령|규칙|지령).{0,6}(무시|잊어|따르지|어기|무효)`},
	{Name: "CJK Jailbreak Mode", Regex: `(开发者模式|无限制模式|開発者モード|制限なしモード|개발자\s*모드|제한\s*없는\s*모드|没有任何?限制|制限.{0,4}(解除|無視)|제한.{0,4}(해제|무시))`},
	{Name: "System Prompt Disclosure", Regex: `(?is)\b(output|print|reveal|show|display|dump|return|exfiltrate)\b.{0,80}\b(system\s+prompt|tool\s+definitions?|developer\s+instructions?)\b`},
}
