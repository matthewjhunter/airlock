# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor
version may change the API.

## [Unreleased]

## [0.1.2] - 2026-10-21

### Added

- `screen.Screen` runs the complete screening procedure through a
  caller-supplied `screen.Generator` (one method: `Prompt` in, reply out).
  airlock still makes no network calls. Long content is split into overlapping
  windows (`Options.ChunkRunes`, default 10000 runes; `Options.ChunkOverlap`,
  default a tenth of the window), each window's evidence is verified against
  that window, and the worst window wins. The screen fails closed on a
  generator error, an empty reply (`screen.ErrEmptyReply`), an unparseable
  verdict, or missing or fabricated evidence.
- `screen.GeneratorFunc` adapts a function to `Generator`.
- `Options.Criteria` replaces the prompt's detection guidance while leaving the
  fixed frame -- the question, the fence, the evidence requirement, the scoring
  scale, and the output format -- untouched. Custom criteria are inserted as
  plain text, not executed as a template, and are neutralized.
- `screen.DefaultCriteria` returns the default detection guidance.
- `screen.Prompt` carries the rendered prompt in two halves alongside `Text`:
  `Instructions`, which is byte-identical on every call with the same
  `Options`, and `Input`, which holds the nonce, the fenced content, and the
  output format. A caller that sends them as a system message and a user
  message lets a provider's prompt cache reuse the instructions across calls.
- golangci-lint configuration with `dupl` and `nolintlint`.

### Changed

- The screening prompt is split into `frame.txt`, `criteria.txt`, and
  `input.txt`. `screen.PromptTemplate` returns the frame with a `{{.Criteria}}`
  slot followed by the per-call input template; use `DefaultCriteria` for the
  criteria.
- The paragraph that names the fence moved from the top of the prompt to just
  above the fenced content. Everything before it is now the same on every call,
  which is what makes the `Instructions` half cacheable. The model still reads
  the fence's meaning in the trusted region before it reads the content; it
  just does so four paragraphs later. Rendered text with default criteria is no
  longer byte-identical to 0.1.1 for that reason.

### Security

- `golang.org/x/text` bumped to v0.39.0. GO-2026-5970 was reachable through
  `norm.Form.String` in `normalize.ForToolText`.

## [0.1.1] - 2026-07-18

### Fixed

- `screen`: evidence that `ParseVerdict` truncated (and marked with `...`) is
  now located in the source text, rather than failing verification as if it
  were fabricated.

### Changed

- CI pins `infodancer/workflows` to `@v0`.
- Test fixtures escape invisible characters, fixing staticcheck findings.

## [0.1.0] - 2026-07-11

### Added

- `normalize`: Unicode normalization ported from pipelock -- confusable
  folding, zero-width and control stripping, combining-mark removal with NFC
  recomposition, leetspeak folding -- composed into `ForMatching`,
  `ForPolicy`, and `ForToolText`.
- `detect`: advisory injection detector seeded from pipelock's corpus, with
  airlock's own severities and a `Score` that aggregates hits across
  categories.
- `screen`: model-backed injection screening -- the prompt, the verdict
  schema, `Verdict.Locate` to verify quoted evidence against the source, and a
  payload-free `Finding` for storage.
- `docs/pipelock-port.md` recording what was ported and why.

### Fixed

- `wrap.Neutralize` now removes fence tags disguised with homoglyphs or
  zero-width characters.

## [0.0.1] - 2026-07-11

### Added

- `wrap`: per-call nonce fencing and delimiter neutralization for untrusted
  text going into a prompt.
- `unwrap`: recovery of the first balanced JSON value from a model reply.
- SECURITY.md with private reporting instructions and the threat model.

[Unreleased]: https://github.com/matthewjhunter/airlock/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/matthewjhunter/airlock/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/matthewjhunter/airlock/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/matthewjhunter/airlock/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/matthewjhunter/airlock/releases/tag/v0.0.1
