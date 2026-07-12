# Porting note: extracting the pipelock normalizer + injection patterns

Working note for a future session. Goal: seed airlock's advisory detector
(`detect`) and its supporting `normalize` package from pipelock's Apache-2.0
code, without dragging in pipelock's egress/DLP/SSRF machinery or its
block/strip enforcement posture.

This is a **vendor-and-adapt** job, not a dependency. Everything we want lives
under pipelock's `internal/`, so Go will not let us import it -- we copy the
source, re-license-header it, and attribute. Read this whole file before
touching code.

## Why we're doing this at all

airlock's thesis (see the repo README and the blog article
`nobody-marks-the-web-as-untrusted`) is that **structural marking beats
detection**. `wrap` is the guarantee. This detector is a deliberately weak,
best-effort tripwire that rides behind the fence -- it catches a hostile span
that a model might still act on even when the marking held. Keep that framing in
the package doc. Detection here is the suspenders, never the belt. If a future
reader starts trusting a clean scan as safety, the package doc failed.

## Source coordinates

Two upstream repos, both Apache-2.0, both by Josh Waldrep ("Joshua Waldrep" in
copyright lines).

**Pinned 2026-07-11 (re-scout done).** These are the SHAs to vendor from and to
name in the NOTICE:

| Repo | Pinned commit | Date |
|---|---|---|
| `luckyPipewrench/pipelock` | `41e5c57051866d43c5d87cb4e7d5a927cfe3f95f` | 2026-07-11 |
| `luckyPipewrench/pipelock-rules` | `5990349b9d654ad6dd0ed46edd8f3b3062d18c91` | 2026-07-08 |

The churn this note worried about did not touch us. All five extraction targets
are **byte-identical** between the original survey SHAs
(`446ed52`/`68eb7c9`) and the pinned pipelock HEAD; the five intervening commits
hit dashboard, conductor, receipt, and anchor. pipelock-rules has not moved at
all -- its HEAD *is* the survey SHA.

### pipelock core (github.com/luckyPipewrench/pipelock)

License boundary is drawn two ways that agree: top-level `LICENSE` is Apache-2.0,
`enterprise/LICENSE` is Elastic License 2.0, and **every file** carries an SPDX
header. Re-verified at the pin: every file we want carries
`// SPDX-License-Identifier: Apache-2.0`, and no `.go` file outside `enterprise/`
carries anything else. Nothing we want is under `enterprise/`. Re-verify the SPDX
header on each file at copy time anyway -- it is the authoritative per-file signal.

Take these:

| File | What it is | Action |
|---|---|---|
| `internal/normalize/normalize.go` | 529 lines: ~13 normalization primitives (NFKC via x/text, zero-width / invisible-range strip incl. the Tags block / Pliny steganography, homoglyph-confusable fold, combining-mark strip, exotic-whitespace strip, leetspeak digit->letter fold, vowel fold, Zalgo density) plus four named pipelines that compose them: `ForDLP`, `ForMatching`, `ForPolicy`, `ForToolText`. Self-described "single source of truth for normalization." | **Port the primitives in full** (they are cohesive, and the file's own tests cover them). The pipeline we want is **`ForMatching`** (StripZeroWidth -> NFKC -> ConfusableToASCII -> StripCombiningMarks -> Whitespace), plus `Leetspeak` and `FoldVowels` as separate passes. **Do not export `ForDLP`** -- it is the DLP pipeline and is out of scope by our own filter below. Becomes airlock package `normalize`. |
| `internal/config/defaults.go` | The built-in `ResponseScanPattern` regexes -- **30 of them**, not the 29 that pipelock's own `docs/bypass-resistance.md` claims. All inside the `Patterns: []ResponseScanPattern{...}` block that starts at line 223. | **Port the injection/override/concealment/tooling/memory/multilingual/control-token patterns. DROP only the three unambiguous credential-exfil ones** (see scope below). This is the primary pattern corpus. |
| `internal/scanner/core.go` | `coreResponsePattern` -- 10 immutable-tier patterns. Diffed against defaults.go at the pin: 7 are byte-identical dupes, 3 are credential. | **Take exactly one: `System Prompt Disclosure`** (English) -- `(?is)\b(output\|print\|reveal\|show\|display\|dump\|return\|exfiltrate)\b.{0,80}\b(system\s+prompt\|tool\s+definitions?\|developer\s+instructions?)\b`. That is the only pattern here defaults.go lacks. Contrary to an earlier draft of this note, `Instruction Boundary` is *not* a variant -- it is character-for-character identical to defaults.go's. And core's `Covert Action Directive` is a strict **subset** of defaults' (defaults adds `exfiltrat\|leak\|stream\|transmit\|relay\|forward\|smuggle`), so take defaults' version. |
| `internal/scanner/response_prefilter.go` | Keyword pre-filter: extract literal anchors from each regex, skip regex eval when no anchor is present in the text. Pure optimization, content-based (no blind spots). | **Optional.** Port only if detector latency matters on large inputs. Correctness does not depend on it. |

Do **not** take (out of airlock's scope -- these are egress/network/DLP, a
different module living in a proxy, not text-into/out-of-prompt hygiene):
`internal/scanner/scanner.go` (SSRF, blocklist, entropy, rate limit, data
budget), `text_dlp.go`, `sigv4.go`, `dnsresolver.go`, `dns_error.go`,
`databudget.go`, `address_similarity.go`, `canary.go`, and the whole
`enterprise/` tree.

#### Which "credential" patterns actually get dropped

An earlier draft said "drop the credential/DLP ones" as if that were one bucket.
It is not. Run each against the scope filter below -- *does it inspect what the
model was told?* -- and the seven split three ways:

**Drop (3).** These inspect where data is going; they are the constants
`CredentialSolicitationRegex`, `MarkdownLinkCredentialExfilRegex`, and
`CredentialPathDirectiveRegex`, defined in `internal/config`. Since we are
dropping them we never need to chase the constants. If a later decision reverses
this, grep `internal/config`.

- Credential Solicitation
- Markdown Link Credential Exfiltration
- Credential Path Directive

**Keep (2) -- these are injection, not DLP.** They match hostile text aimed *at
the model*, which is squarely our scope:

- **Silent Credential Handling** -- `(do not|don't|never) (mention|show|reveal|log)
  ... (password|token|secret|api key)`. This is an injected instruction telling
  the model to conceal. Concealment is a category we already keep.
- **Auth Material Requirement** -- `to (complete|continue|verify) ...
  (authentication|credential|token|api key) ... (required|needed|must be)`. This is
  hostile text demanding credentials *from* the model.

**Keep (2) -- never actually in dispute.** Memory Persistence Directive and
Preference Poisoning read as "credential-adjacent" but are memory/tooling
injection, which the table above already lists as keeps.

### pipelock-rules (github.com/luckyPipewrench/pipelock-rules)

Read at commit `5990349b9d654ad6dd0ed46edd8f3b3062d18c91`. Whole repo is
Apache-2.0 with an explicit CLA ("contributions are licensed under the Apache
License 2.0"). Rule content is signed YAML.

Take, filtered to our scope:

- `rules/pipelock-community/injection/*.yaml` -- 10 files.
- `rules/pipelock-community/tool-poison/*.yaml` -- 7 files (only if airlock ever
  touches the MCP tool-registration path; see below).

Do **not** take: `rules/pipelock-community/dlp/*` and
`rules/healthcare-phi-pii/*` (DLP / PHI-PII -- out of scope).

The injection YAMLs mostly duplicate the built-ins. Cherry-pick the genuinely
new ones and skip the language dupes:

- **Keep** (new coverage the built-ins lack): `delimiter-breakout`
  (`--- END OF SYSTEM ---`), `system-tag-override` (fake `<system_instructions>`
  / `<override>` XML tags), `hidden-html-override` and `html-comment-override`
  (override text in `display:none` / `<!-- -->`), `tool-call-imperative`
  (literal `tools/call` MCP method), `explicit-http-exfil`.
- **Keep** (new languages): `french-override`, `german-override`.
- **Skip** (already covered by built-in Spanish + CJK patterns):
  `spanish-override`, `chinese-override`.

## Scope filter (the one rule that governs every include/exclude above)

airlock is **text into a prompt / out of a reply**. Injection detection and
tool-poison detection qualify. Outbound-request policy -- DLP secret patterns,
URL/SSRF scanning, PHI/PII, pre-DNS blocking, egress budgets -- does NOT. That
belongs to a proxy or harness, a separate module. When in doubt about a pattern:
if it inspects *what the model was told*, keep it; if it inspects *where a
request is going or what data is leaving*, drop it.

## Dependency decision: airlock stops being zero-dep

Settled 2026-07-11. The original note missed this entirely.

airlock today has **no `go.sum`** -- zero dependencies, `go 1.22` library floor
(set deliberately in `673fcf9`). The normalizer needs NFKC, and there is no
stdlib NFKC, so **this port ends airlock's zero-dep status**. That is accepted.
`golang.org/x/text/unicode/norm` is the only thing `normalize.go` imports beyond
`strings` and `unicode`, so the blast radius is one package of one module.

**Pin `golang.org/x/text v0.21.0`. Keep the `go 1.22` floor. Do not bump.**

pipelock pins x/text `v0.37.0`, whose go directive is `1.25.0` -- adopting that
version would force airlock's floor to 1.25 and break the 1.22 promise to library
consumers. v0.21.0 is the last release carrying a `go 1.18` directive, so it sits
comfortably under our floor.

The obvious worry is that an older x/text ships older Unicode tables and therefore
misses newer confusables -- a real evasion surface for a normalization-based
control. It was measured, not assumed:

- v0.21.0 tops out at Unicode **15.0.0** tables; v0.37.0 ships Unicode **17.0.0**.
- Brute-forced NFKC over every valid codepoint under both versions: each folds
  **exactly 4928 codepoints**, with **zero** differences in either direction.
  Unicode 16 and 17 added scripts and emoji but no new NFKC compatibility
  decompositions, which is what the Unicode normalization stability policy would
  predict.
- `govulncheck` reports **no advisories against x/text at any version**, and
  symbol-level results are clean for our import path. (CI already builds
  govulncheck on a modern Go while holding the library floor at 1.22 -- see
  `673fcf9` -- so this stays consistent.)

So bumping the Go floor buys a newer x/text that normalizes identically. There is
no requirement, and therefore no bump. Revisit only if a future Unicode release
actually adds compatibility decompositions -- re-run the brute-force codepoint
diff before assuming it has.

Note also that `ConfusableToASCII` is pipelock's own hand-rolled table inside
`normalize.go`, **not** x/text's confusables data. Homoglyph coverage does not
track the x/text version at all; it tracks whatever that table contains. Read it
when porting, and treat gaps there as a real finding.

One portability fix at copy time: three benchmarks in `normalize_test.go` use
`testing.Loop` (Go 1.24+). Rewrite them as `for i := 0; i < b.N; i++` or the
package will not vet at the 1.22 floor. The functional tests all pass green as-is
on Go 1.22 + x/text v0.21.0 (verified).

## Target layout in airlock

```
normalize/
  doc.go              # airlock: package doc
  pipelock.go         # VENDORED Apache-2.0 (Waldrep) -- upstream primitives
  pipelock_test.go    # VENDORED Apache-2.0 (Waldrep) -- upstream tests
  normalize.go        # airlock: StripCombiningMarks (the NFC/Hangul fix)
  normalize_test.go   # airlock: tests for the above
detect/
  doc is in detect.go # airlock: Detect, Match, Result -- advisory, mutates nothing
  patterns.go         # airlock: Rule, Severity -- airlock's own representation
  rules_pipelock.go   # VENDORED Apache-2.0 (Waldrep) -- the 28 regexes, DATA ONLY
  rules_seed.go       # airlock: ID/category/severity + reasoning per rule
  score.go            # airlock: Result.Score() corroboration aggregate
  detect_test.go
  score_test.go
docs/pipelock-port.md # this file
NOTICE                # Apache attribution
```

**Licensing boundary is a file boundary.** Vendored Apache-2.0 code lives only in
files named `pipelock*`. Everything else is airlock's own. This is deliberate: it
means the answer to "is this file someone else's work?" is legible from the
filename, and the NOTICE can enumerate the vendored set exactly.

`normalize` should also be reachable from `wrap` -- neutralizing on normalized
text closes the zero-width / homoglyph breakout of the fence delimiter. Wire that
after both land (small follow-up, not part of the initial port).

## Adaptation rules (do not skip these -- they are the point)

1. **Advisory, never enforcing.** `Detect` returns a signal and mutates nothing.
   No `action` field, no `block`/`strip`/`warn`/`ask`. Drop pipelock's action
   machinery entirely. The caller decides what a hit means.

   ```go
   type Match struct {
       Rule     string // e.g. "prompt-injection"
       Severity string // carried from source, informational only
       Field    string // "" for freetext; "name"/"description" for tool metadata
   }
   func Detect(text string) (score float64, matches []Match)
   ```

2. **Own format, not pipelock's YAML schema.** Convert `defaults.go`'s Go slice
   and the cherry-picked community YAMLs into airlock's `patterns.go`
   representation **at port time, once**. The runtime reads only airlock's
   format. Do not make airlock track pipelock's bundle schema
   (`format_version`, `required_features`, `monotonic_version`, signing). That
   coupling is exactly what we're avoiding.

3. **User rules on disk are the primary extension path.** Load `*.yaml` (airlock
   format) from a `rules_dir` the user owns. The vendored pipelock corpus is a
   seed, not a subscription. If we later add an `airlock rules update` that
   re-vendors from pipelock-rules, it bumps a pinned commit and re-runs the
   converter -- deliberate, reviewable, offline by default. No runtime network
   fetch; if one is ever added, it MUST verify the Ed25519 signature (pipelock's
   signing pubkey is in its Apache source), never trust unsigned YAML.

4. **Tool-poison rules carry `scan_field: name|description`.** They scan MCP tool
   metadata, not response body. Only port them if airlock grows a tool-registration
   inspection path. If ported, `Match.Field` records which field hit. If airlock
   stays pure prompt-in/prompt-out, skip the tool-poison set for now and note it.

5. **No silent caps.** If the converter drops a rule (unknown construct, a
   `required_features` we don't implement, a category we skip), log/emit what was
   dropped. A pruned corpus that looks complete is a lie.

6. **Keep it labeled weak.** The `detect` package doc states plainly: keyword-
   anchored regex over normalized text, defeated by paraphrase, advisory only,
   the fence (`wrap`) is the actual guarantee. This is not editorializing -- it's
   the honest bound, and it's the thesis of the whole project.

## Port status (updated 2026-07-11)

Both packages have landed. What follows is what actually got built, where it
diverged from the plan above, and what is still outstanding.

### Done

- **`normalize`** -- all primitives ported. Every non-comment line is byte-identical
  to upstream except the deleted `ForDLP` (out of scope) and the Hangul fix below.
  All 183 ported upstream subtests pass.
- **`detect`** -- 28 rules: the 27 in-scope patterns from `defaults.go` plus
  `System Prompt Disclosure` from `core.go`. Regexes were extracted mechanically,
  not retyped, and are verified byte-identical to upstream. `Detect` is advisory
  and mutates nothing.

### The Hangul bug (a real upstream defect, fixed here)

pipelock's `StripCombiningMarks` runs NFD and never recomposes. NFD does not only
split accents off their bases -- it decomposes precomposed Hangul syllables into
conjoining jamo, which are category Lo, not Mn, and so survive the mark strip. The
text stays decomposed.

The consequence: any rule written in ordinary precomposed Hangul cannot match
normalized text. **pipelock's own `CJK Instruction Override KR` pattern matches the
raw string and fails against the output of its own `ForMatching`** -- it is dead code
upstream. Verified directly against pipelock at the pinned commit: `ForMatching`
turns a 9-rune Korean phrase into 18 runes.

airlock's `StripCombiningMarks` finishes with NFC. The marks are already gone by
then, so there is nothing for NFC to put back, and precomposed forms are restored.
Pinned by `TestStripCombiningMarks_RecomposesHangul` and a companion test asserting
NFC does not resurrect the stripped marks.

Worth reporting upstream.

### Severity is airlock's judgment, not ported data

The plan above specified `Match.Severity // carried from source`. **There is nothing
to carry**: `ResponseScanPattern` is `{Name, Regex, Bundle, BundleVersion, Compiled}`
-- no severity field. Only pipelock's DLP patterns have severities, and those are the
patterns we dropped.

So severity here is an editorial call, made in airlock and labeled as such, on how
much a hit is actually worth as evidence:

- **High** (18 rules) -- the text is hostile or it is nothing. Overrides, jailbreaks,
  concealment, credential solicitation, control tokens, authority escalation.
- **Medium** (7) -- hostile in context, but the phrasing has honest uses. System
  prompt disclosure, tool-invocation imperatives, memory and preference poisoning.
- **Low** (3) -- might be injection; just as likely ordinary prose. `^system:`,
  "new instructions", "prioritize the task request". A Low hit alone is close to
  worthless, and the test suite asserts these DO fire on benign text -- that is what
  the tier means.

`rules_seed.go` records a one-line reason per rule. The plan's `score float64` was
dropped: a float implies a calibration this detector does not have. `Result.Highest()`
returns the strongest tier that fired, which is the honest aggregate.

### Not done (deliberately, and not silently)

- **pipelock-rules community YAMLs.** None ported yet. The cherry-pick list above
  (`delimiter-breakout`, `system-tag-override`, `hidden-html-override`,
  `html-comment-override`, `tool-call-imperative`, `explicit-http-exfil`,
  `french-override`, `german-override`) still stands. NOTICE credits only pipelock
  until they land.
- **Tool-poison rules.** Not ported. airlock has no tool-registration inspection
  path yet. `Rule.Field` and `Match.Field` exist and are honored by `Detect` (a
  field-scoped rule is skipped on a freetext scan), so the hook is in place.
- **User rules on disk (`rules_dir`).** Not implemented. The seed corpus is
  currently the whole corpus.
- **Vowel-fold matching pass.** `normalize.FoldVowels` is ported and tested, but
  `Detect` does not use it. Doing so needs a parallel corpus of vowel-folded
  patterns, and the precision loss is severe -- "ignore" and "ignara" fold alike.
  Deferred rather than half-built.
- **`response_prefilter.go`.** Not ported. Pure latency optimization; correctness
  does not depend on it.
- **Wiring `normalize` into `wrap`.** Still the follow-up it always was.

## Attribution (Apache-2.0 section 4 -- required)

- Add a top-level `NOTICE` crediting `luckyPipewrench/pipelock` and
  `luckyPipewrench/pipelock-rules`, Copyright 2026 Joshua Waldrep, Apache-2.0,
  with the pinned commit SHAs.
- On each ported `.go` file, retain the original
  `// Copyright 2026 Josh Waldrep` line and add ours, keeping
  `// SPDX-License-Identifier: Apache-2.0`.
- airlock is already Apache-2.0, so licenses are compatible -- this is
  attribution, not relicensing.

## Verify at extract time

Done during the 2026-07-11 re-scout, at the pinned SHAs:

- [x] SPDX header confirmed Apache-2.0 on every file we take; no non-Apache SPDX
      on any `.go` outside `enterprise/`.
- [x] `internal/normalize` and `internal/scanner` still hold the code -- nothing
      moved. All five targets byte-identical to the survey SHAs.
- [x] Recounted defaults.go: **30** patterns, not the 29 that
      `docs/bypass-resistance.md` asserts. Port what is there.
- [x] pipelock's `normalize_test.go` runs green against the normalizer on
      Go 1.22 + x/text v0.21.0 (three `testing.Loop` benchmarks excepted -- see
      the dependency section).

Still to do when code actually gets written:

- [ ] Re-run the SPDX check at copy time anyway. It is cheap and it is the
      authoritative per-file signal.
- [ ] Read `ConfusableToASCII`'s table and judge its coverage on its own merits;
      it is hand-rolled, not x/text data.
- [ ] Get the ported `normalize_test.go` green in airlock before building `detect`
      on top of it.
