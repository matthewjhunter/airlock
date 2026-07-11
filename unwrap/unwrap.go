// Package unwrap recovers a JSON value from language-model output that may be
// wrapped in markdown code fences or surrounded by prose. Models routinely
// answer "return only JSON" prompts with ```json ... ``` blocks or a sentence
// of preamble; unwrap tolerates that and hands back just the JSON value the
// caller asked for.
//
// unwrap is the output side of airlock. Its input-side companion is package
// wrap, which fences untrusted text on the way into a prompt. Both apply one
// principle at a model trust boundary -- narrow what the untrusted side can
// express down to the thing the caller actually consumes. The model's reply is
// not trusted to be well-formed, so unwrap extracts the first balanced JSON
// value with a string-aware scanner rather than trusting the whole response.
package unwrap

import (
	"encoding/json"
	"errors"
)

// ErrNoJSON is returned when no balanced, valid JSON value can be recovered
// from the input.
var ErrNoJSON = errors.New("unwrap: no JSON value found in model output")

// JSON returns the first balanced JSON value -- object or array -- found in s,
// tolerating markdown code fences and surrounding prose. The returned bytes are
// guaranteed to be valid JSON (json.Valid passes). If no such value is present,
// it returns ErrNoJSON.
//
// "First balanced value" means: scan to the first '{' or '[', then return the
// span up to its matching close, counting nesting and ignoring delimiters that
// appear inside JSON string literals. This is more robust than a first-'{' /
// last-'}' slice, which is fooled by a brace inside a string value or by a
// second JSON object later in the text.
func JSON(s string) (json.RawMessage, error) {
	raw, ok := firstValue(s)
	if !ok {
		return nil, ErrNoJSON
	}
	return json.RawMessage(raw), nil
}

// Into recovers the first balanced JSON value from s (see JSON) and unmarshals
// it into a value of type T. It returns ErrNoJSON if no value is found, or the
// json.Unmarshal error if the recovered value does not fit T.
func Into[T any](s string) (T, error) {
	var v T
	raw, err := JSON(s)
	if err != nil {
		return v, err
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, err
	}
	return v, nil
}

// firstValue returns the first balanced {…} or […] span in s that is itself
// valid JSON, scanning with awareness of string literals and escapes so that a
// delimiter inside a string does not throw off the nesting count.
func firstValue(s string) (string, bool) {
	start := -1
	var openB, closeB byte
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			start, openB, closeB = i, '{', '}'
		case '[':
			start, openB, closeB = i, '[', ']'
		}
		if start >= 0 {
			break
		}
	}
	if start < 0 {
		return "", false
	}

	depth := 0
	inStr := false
	esc := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case openB:
			depth++
		case closeB:
			depth--
			if depth == 0 {
				candidate := s[start : i+1]
				if json.Valid([]byte(candidate)) {
					return candidate, true
				}
				return "", false
			}
		}
	}
	return "", false
}
