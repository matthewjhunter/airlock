// Copyright 2026 Matthew Hunter
// SPDX-License-Identifier: Apache-2.0

// Package normalize collapses Unicode evasion tricks so text can be matched as a
// human would read it, rather than as an attacker encoded it.
//
// The problem it solves: "ignore all previous instructions" can be written with a
// Cyrillic o, a zero-width space wedged between the letters, a combining mark
// stacked on the i, a fullwidth i, a boxed-emoji I, or a digit 1 standing in for
// the i. A model reads every one of those as the same English sentence. A plain
// regex reads none of them. Normalizing first closes that gap.
//
// The package is pure: every function takes a string and returns a string or a
// count, does no I/O, and has no configuration.
//
// # What this is, and what it is not
//
// Normalization is input hygiene, not a security boundary. It makes airlock's
// advisory detector harder to slip past with encoding tricks. It does not make the
// detector sound: an attacker who paraphrases instead of obfuscating walks past a
// perfectly normalized scan. The structural marking done by wrap is airlock's
// actual guarantee. This package stops the cheap evasion; it is never the thing
// that makes detection trustworthy.
//
// # Choosing a pipeline
//
// Three pipelines compose the primitives. Pick by what the text is:
//
//   - [ForMatching]: freetext going into a prompt, or a model reply coming back.
//     Drops invisible characters. This is the default.
//   - [ForPolicy]: same as ForMatching, but turns invisibles into spaces rather
//     than dropping them. Use it where dropping one would fuse two tokens into one,
//     so that "rm<ZWSP>-rf" stays "rm -rf" instead of becoming "rm-rf".
//   - [ForToolText]: MCP tool names and descriptions. Strips every control
//     character (tool metadata has no legitimate use for one) and folds leetspeak.
//
// [FoldVowels] is not a pipeline but an extra pass applied on top of one, for the
// narrow case documented on the function itself.
//
// # Provenance
//
// Most of this package is vendored Apache-2.0 code from pipelock, and it is kept in
// files named for where it came from:
//
//   - pipelock.go, pipelock_test.go -- upstream code and tests. Not airlock's work.
//     Changes from upstream are enumerated in those files' headers.
//   - doc.go, normalize.go, normalize_test.go -- airlock's own additions.
//
// The non-ASCII runes in pipelock.go are written as \u escapes, as upstream wrote
// them. That is deliberate and worth preserving: the characters this package
// defends against are invisible or visually identical to ASCII, so spelling them
// literally would make the tables impossible to review.
//
// See NOTICE at the repository root, and docs/pipelock-port.md.
package normalize
