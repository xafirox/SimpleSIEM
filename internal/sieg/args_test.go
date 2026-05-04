package sieg

import (
	"reflect"
	"testing"
)

func TestPermuteArgs(t *testing.T) {
	val := map[string]bool{"config": true, "years": true}
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "already in order",
			in:   []string{"--config", "/path", "hostname"},
			want: []string{"--config", "/path", "hostname"},
		},
		{
			name: "flag after positional",
			in:   []string{"hostname", "--config", "/path"},
			want: []string{"--config", "/path", "hostname"},
		},
		{
			name: "two positionals plus trailing flag",
			in:   []string{"hostname", "10.0.0.1", "--config", "/path"},
			want: []string{"--config", "/path", "hostname", "10.0.0.1"},
		},
		{
			name: "bundled flag=value form",
			in:   []string{"hostname", "--config=/path", "--years=10"},
			want: []string{"--config=/path", "--years=10", "hostname"},
		},
		{
			name: "boolean flag (not in value-set)",
			in:   []string{"hostname", "--verbose", "--config", "/path"},
			want: []string{"--verbose", "--config", "/path", "hostname"},
		},
		{
			name: "no positionals",
			in:   []string{"--config", "/path", "--years", "5"},
			want: []string{"--config", "/path", "--years", "5"},
		},
		{
			name: "no flags",
			in:   []string{"hostname", "10.0.0.1"},
			want: []string{"hostname", "10.0.0.1"},
		},
		{
			name: "empty",
			in:   []string{},
			want: []string{},
		},
	}
	for _, tc := range cases {
		got := permuteArgs(tc.in, val)
		if !slicesEq(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func slicesEq(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}
