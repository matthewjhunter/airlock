package unwrap

import (
	"errors"
	"testing"
)

func TestJSON(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string // expected raw JSON, or "" if ErrNoJSON expected
	}{
		{"bare object", `{"a":1}`, `{"a":1}`},
		{"bare array", `[1,2,3]`, `[1,2,3]`},
		{"leading whitespace", "  \n\t{\"a\":1}\n", `{"a":1}`},
		{
			"markdown fenced",
			"```json\n{\"selected_ids\":[1,2],\"rationale\":\"ok\"}\n```",
			`{"selected_ids":[1,2],"rationale":"ok"}`,
		},
		{
			"prose preamble and trailer",
			"Sure, here you go:\n{\"outcome\":\"stored\"}\nHope that helps!",
			`{"outcome":"stored"}`,
		},
		{"nested object", `{"a":{"b":[1,2]},"c":3}`, `{"a":{"b":[1,2]},"c":3}`},
		{
			"brace inside string value is not a delimiter",
			`{"note":"a } that would fool lastIndex","ok":true}`,
			`{"note":"a } that would fool lastIndex","ok":true}`,
		},
		{
			"escaped quote inside string",
			`{"q":"she said \"hi\" }","n":1}`,
			`{"q":"she said \"hi\" }","n":1}`,
		},
		{
			"stops at first balanced value, ignores trailing object",
			`{"first":1} and then {"second":2}`,
			`{"first":1}`,
		},
		{"no json at all", "just some prose, no braces", ""},
		{"unbalanced open", `{"a":1`, ""},
		{"empty input", "", ""},
		{
			"array of objects",
			"prefix [ {\"id\":1}, {\"id\":2} ] suffix",
			`[ {"id":1}, {"id":2} ]`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := JSON(tt.in)
			if tt.want == "" {
				if !errors.Is(err, ErrNoJSON) {
					t.Fatalf("JSON(%q) err = %v, want ErrNoJSON", tt.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("JSON(%q) unexpected error: %v", tt.in, err)
			}
			if string(got) != tt.want {
				t.Errorf("JSON(%q) = %q, want %q", tt.in, string(got), tt.want)
			}
		})
	}
}

func TestInto(t *testing.T) {
	type resp struct {
		SelectedIDs []int64 `json:"selected_ids"`
		Rationale   string  `json:"rationale"`
	}

	t.Run("fenced object into struct", func(t *testing.T) {
		got, err := Into[resp]("```json\n{\"selected_ids\":[3,7],\"rationale\":\"most relevant\"}\n```")
		if err != nil {
			t.Fatalf("Into: %v", err)
		}
		if len(got.SelectedIDs) != 2 || got.SelectedIDs[0] != 3 || got.SelectedIDs[1] != 7 {
			t.Errorf("SelectedIDs = %v, want [3 7]", got.SelectedIDs)
		}
		if got.Rationale != "most relevant" {
			t.Errorf("Rationale = %q, want %q", got.Rationale, "most relevant")
		}
	})

	t.Run("no json returns ErrNoJSON", func(t *testing.T) {
		_, err := Into[resp]("the model refused to answer")
		if !errors.Is(err, ErrNoJSON) {
			t.Fatalf("err = %v, want ErrNoJSON", err)
		}
	})

	t.Run("recovered value does not fit T", func(t *testing.T) {
		// A JSON array cannot unmarshal into a struct: recovery succeeds, the
		// unmarshal fails, and that error is surfaced (not ErrNoJSON).
		_, err := Into[resp]("[1,2,3]")
		if err == nil {
			t.Fatal("expected unmarshal error, got nil")
		}
		if errors.Is(err, ErrNoJSON) {
			t.Fatalf("err = %v, want an unmarshal error, not ErrNoJSON", err)
		}
	})
}
