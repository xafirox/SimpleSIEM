package sieg

import (
	"strings"
	"testing"
)

// TestBuildMenu_CoversAllFeatures locks in that the interactive menu
// exposes every operator-facing capability documented in the README,
// regardless of installed/running state. If a future refactor drops one
// of these labels, this test names it explicitly so the regression
// can't slip through unnoticed.
func TestBuildMenu_CoversAllFeatures(t *testing.T) {
	// Substrings of labels that must always be present, mapped to the
	// README capability they expose.
	required := []string{
		"Triage events",                          // triage
		"Live tail",                              // tail
		"Recent alerts",                          // alerts
		"Verify log integrity",                   // verify
		"Raw query",                              // query
		"Show status",                            // status
		"Rules:",                                 // rules check / test
		"Certificates",                           // certs init / sign / server
	}
	// Convert appears only when the install is set up (we need a config
	// to know what to convert from). Service options vary by state.

	scenarios := []struct {
		name      string
		installed bool
		running   bool
		also      []string // additional labels expected in this state
		notExpect []string // labels that MUST NOT appear in this state
	}{
		{"not installed", false, false,
			[]string{"Install"},
			[]string{"Stop", "Start", "Uninstall", "Convert mode"}},
		{"installed running", true, true,
			[]string{"Stop", "Fix", "Uninstall", "Convert mode"},
			[]string{"Install", "Start"}},
		{"installed stopped", true, false,
			[]string{"Start", "Fix", "Uninstall", "Convert mode"},
			[]string{"Install", "Stop"}},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			opts := buildMenu(sc.installed, sc.running)
			labels := make([]string, 0, len(opts))
			for _, o := range opts {
				labels = append(labels, o.label)
			}
			joined := strings.Join(labels, "\n")

			for _, want := range required {
				if !strings.Contains(joined, want) {
					t.Errorf("missing %q in %s menu — README feature unexposed", want, sc.name)
				}
			}
			for _, want := range sc.also {
				if !strings.Contains(joined, want) {
					t.Errorf("expected state-specific %q in %s menu", want, sc.name)
				}
			}
			for _, no := range sc.notExpect {
				if strings.Contains(joined, no) {
					t.Errorf("unexpected %q in %s menu (should be hidden in this state)", no, sc.name)
				}
			}
			if !strings.Contains(joined, "Quit") {
				t.Error("Quit option missing — user can't escape the menu")
			}
		})
	}
}

// TestNthAction_SkipsHeaders locks in the dispatcher behaviour. Before
// this fix, picking "1" on the menu hit the first slice element — which
// is the "-- Service --" header (action == nil) — and the binary
// nil-dereferenced. nthAction must walk past headers so the on-screen
// numbering matches the slice traversal.
func TestNthAction_SkipsHeaders(t *testing.T) {
	called := ""
	opts := []menuOption{
		{label: "-- A --", action: nil},
		{label: "first", action: func() { called = "first" }},
		{label: "second", action: func() { called = "second" }},
		{label: "-- B --", action: nil},
		{label: "third", action: func() { called = "third" }},
	}
	cases := []struct {
		n    int
		want string
	}{
		{1, "first"},
		{2, "second"},
		{3, "third"},
	}
	for _, tc := range cases {
		called = ""
		fn := nthAction(opts, tc.n)
		if fn == nil {
			t.Errorf("nthAction(opts, %d) returned nil", tc.n)
			continue
		}
		fn()
		if called != tc.want {
			t.Errorf("n=%d called=%q want=%q", tc.n, called, tc.want)
		}
	}
	// Out-of-range indices must return nil, not panic.
	if nthAction(opts, 0) != nil {
		t.Error("n=0 should return nil")
	}
	if nthAction(opts, 99) != nil {
		t.Error("n=99 should return nil")
	}
	if nthAction(opts, -1) != nil {
		t.Error("n=-1 should return nil")
	}
}

// TestBuildMenu_VisibleNumberingMatchesActions exercises the same path
// the user reported: render the menu the way printMenu does, then call
// nthAction with each visible number and confirm none of them returns
// nil. This would have caught the panic at install time.
func TestBuildMenu_VisibleNumberingMatchesActions(t *testing.T) {
	for _, sc := range []struct {
		name      string
		installed bool
		running   bool
	}{
		{"not installed", false, false},
		{"installed running", true, true},
		{"installed stopped", true, false},
	} {
		t.Run(sc.name, func(t *testing.T) {
			opts := buildMenu(sc.installed, sc.running)
			visible := 0
			for _, o := range opts {
				if o.action != nil {
					visible++
				}
			}
			for n := 1; n <= visible; n++ {
				if nthAction(opts, n) == nil {
					t.Errorf("%s: visible choice %d resolved to a nil action", sc.name, n)
				}
			}
		})
	}
}

func TestBuildMenu_HasSectionHeaders(t *testing.T) {
	opts := buildMenu(true, true)
	gotHeaders := []string{}
	for _, o := range opts {
		if o.action == nil {
			gotHeaders = append(gotHeaders, o.label)
		}
	}
	want := []string{"-- Service --", "-- View --", "-- Manage --"}
	for _, w := range want {
		found := false
		for _, g := range gotHeaders {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing section header %q in menu (got %v)", w, gotHeaders)
		}
	}
}
