// Copyright 2026 Matthew Hunter
// SPDX-License-Identifier: Apache-2.0

package screen

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Generator sends one prompt to a model and returns its reply. It is the only thing
// [Screen] needs from the caller, and the only place a model is reached.
//
// Implement it over whatever transport you already have. Timeouts, retries,
// concurrency limits, circuit breakers, model selection, and temperature all belong
// in the implementation, not here: airlock never opens a socket. Return an error for
// any failure to get a reply; [Screen] wraps it with %w, so a caller can still test
// for its own transport errors with [errors.Is].
type Generator interface {
	Generate(ctx context.Context, prompt string) (string, error)
}

// GeneratorFunc adapts an ordinary function to [Generator].
type GeneratorFunc func(ctx context.Context, prompt string) (string, error)

// Generate calls f.
func (f GeneratorFunc) Generate(ctx context.Context, prompt string) (string, error) {
	return f(ctx, prompt)
}

// DefaultChunkRunes is the window size [Screen] uses when [Options.ChunkRunes] is
// zero. It suits a model with an 8k-token context: roughly 2.5k tokens of content
// plus the frame and the reply, with headroom for text that tokenizes badly.
const DefaultChunkRunes = 10000

// ErrEmptyReply is returned when the model's reply is empty or whitespace. The usual
// cause is a reasoning model spending its whole output budget before writing the
// verdict. It is a failed screen, never a clean one.
var ErrEmptyReply = errors.New("screen: model returned an empty reply")

// Screen runs the complete screening procedure over content, calling the model
// through gen, and returns the payload-free [Finding].
//
// Content longer than [Options.ChunkRunes] is split into overlapping windows, and
// each window is rendered, screened, parsed, and verified on its own. The worst
// window decides the result: a long article's threat is the highest threat in any
// part of it, so an injection padded behind benign text is still seen. Each verdict's
// evidence is checked against the window the model actually saw, because a citation
// has to be in the text that produced it.
//
// Screen fails closed. If any window cannot be screened -- the generator errors, the
// reply is empty, the verdict does not parse, or it reports a threat whose evidence
// is missing or does not occur in the window -- Screen returns an error and no
// Finding. An unscreened span cannot be assumed clean, so treat the error as
// "not yet screened" and retry, never as a pass.
//
// Empty content is clean without a model call: there is nothing to screen.
//
// Errors carry metadata only -- which window, the threat, the category -- never
// quoted content. See [Finding] for why.
func Screen(ctx context.Context, gen Generator, content string, opts Options) (Finding, error) {
	size, overlap, err := chunkParams(opts)
	if err != nil {
		return Finding{}, err
	}
	if content == "" {
		return Finding{Threat: 0, Category: CategoryNone}, nil
	}

	windows := chunk(content, size, overlap)
	worst := Finding{Threat: -1}
	for i, w := range windows {
		if err := ctx.Err(); err != nil {
			return Finding{}, fmt.Errorf("screen: window %d of %d: %w", i+1, len(windows), err)
		}
		f, err := screenWindow(ctx, gen, w, opts)
		if err != nil {
			return Finding{}, fmt.Errorf("screen: window %d of %d: %w", i+1, len(windows), err)
		}
		// Strictly greater: on a tie the earliest window keeps the verdict.
		if f.Threat > worst.Threat {
			worst = f
		}
	}
	return worst, nil
}

// screenWindow screens one span in one model call and reduces the verdict to a
// Finding verified against that span.
func screenWindow(ctx context.Context, gen Generator, span string, opts Options) (Finding, error) {
	p, err := Render(span, opts)
	if err != nil {
		return Finding{}, err
	}

	reply, err := gen.Generate(ctx, p.Text)
	if err != nil {
		return Finding{}, fmt.Errorf("generate: %w", err)
	}
	if strings.TrimSpace(reply) == "" {
		return Finding{}, ErrEmptyReply
	}

	v, err := ParseVerdict(reply)
	if err != nil {
		return Finding{}, err
	}
	return v.Finding(span)
}

// chunkParams resolves and validates the window size and overlap. A bad value is an
// error rather than a silent correction: a screen configured to leave gaps between
// windows should not quietly run as something else.
func chunkParams(opts Options) (size, overlap int, err error) {
	size = opts.ChunkRunes
	if size < 0 {
		return 0, 0, fmt.Errorf("screen: ChunkRunes is %d; it must be positive, or 0 for the default", size)
	}
	if size == 0 {
		size = DefaultChunkRunes
	}

	overlap = opts.ChunkOverlap
	if overlap == 0 {
		overlap = size / 10
	}
	if overlap < 0 || overlap >= size {
		return 0, 0, fmt.Errorf("screen: ChunkOverlap is %d; it must be at least 0 and less than the %d-rune window",
			overlap, size)
	}
	return size, overlap, nil
}

// chunk splits s into windows of at most size runes, each starting overlap runes
// before the previous one ended. Runes, not bytes, so no window splits a character.
// The caller guarantees 0 <= overlap < size.
func chunk(s string, size, overlap int) []string {
	r := []rune(s)
	if len(r) <= size {
		return []string{s}
	}
	step := size - overlap
	var windows []string
	for start := 0; ; start += step {
		end := start + size
		if end >= len(r) {
			windows = append(windows, string(r[start:]))
			return windows
		}
		windows = append(windows, string(r[start:end]))
	}
}
