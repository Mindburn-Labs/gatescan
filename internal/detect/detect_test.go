package detect

import (
	"strings"
	"testing"

	"github.com/Mindburn-Labs/gatescan/internal/workflow"
)

func scan(t *testing.T, src string, opts Options) *Result {
	t.Helper()
	wf, err := workflow.Parse("t.yml", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return Run(wf, opts)
}

func rules(res *Result) map[string]int {
	out := map[string]int{}
	for _, f := range res.Findings {
		out[f.Rule]++
	}
	return out
}

// The headline case: a check reading only what an earlier step in the same job
// wrote has nothing outside itself that could make it fail.
func TestSelfReferentialEvidence(t *testing.T) {
	res := scan(t, `
name: t
on: [push]
jobs:
  g:
    env:
      OUT: build/evidence/result.json
    steps:
      - name: write it
        run: |
          mkdir -p build/evidence
          echo '{"ok":true}' > "$OUT"
      - name: validate it
        run: |
          grep -q '"ok":true' "$OUT" || exit 1
`, Options{})

	if n := rules(res)[RuleSelfReferential]; n != 1 {
		t.Fatalf("self_referential findings = %d, want 1: %+v", n, res.Findings)
	}
	if got := res.Jobs[0].Verdict; got != VerdictNothing {
		t.Errorf("verdict = %s, want %s", got, VerdictNothing)
	}
}

// The anti-false-positive test. A scanner that flags every workflow is noise,
// so a check reading committed repository content must come back clean.
func TestCheckReadingRepositoryContentIsClean(t *testing.T) {
	res := scan(t, `
name: t
on: [push]
jobs:
  g:
    steps:
      - uses: actions/checkout@v4
      - name: compare against committed baseline
        run: |
          diff -u contracts/baseline/v1.json contracts/current.json || exit 1
`, Options{})

	if len(res.Findings) != 0 {
		t.Fatalf("clean workflow produced findings: %+v", res.Findings)
	}
	if got := res.Jobs[0].Verdict; got != VerdictEstablishes {
		t.Errorf("verdict = %s, want %s", got, VerdictEstablishes)
	}
}

func TestFabricatedFallbackAndSuppressedEvidence(t *testing.T) {
	res := scan(t, `
name: t
on: [push]
jobs:
  g:
    env:
      OUT: build/evidence/result.json
    steps:
      - name: detect
        id: detect
        run: echo "present=false" >> "$GITHUB_OUTPUT"
      - name: synthesise
        if: steps.detect.outputs.present != 'true'
        continue-on-error: true
        run: |
          mkdir -p build/evidence
          echo '{"ok":true}' > "$OUT"
      - name: validate
        run: test -s "$OUT" || exit 1
`, Options{})

	got := rules(res)
	for _, want := range []string{RuleFabricated, RuleSuppressed, RuleSelfReferential} {
		if got[want] == 0 {
			t.Errorf("missing %s finding; got %+v", want, got)
		}
	}
}

// Absence of evidence must not read as evidence of compliance.
func TestAbsenceReadsAsPassOnlyWhenUnguarded(t *testing.T) {
	unguarded := `
name: t
on: [push]
jobs:
  g:
    steps:
      - uses: actions/checkout@v4
      - name: verify
        run: |
          for f in build/att/*.json; do
            grep -q verified "$f" || exit 1
          done
`
	guarded := `
name: t
on: [push]
jobs:
  g:
    steps:
      - uses: actions/checkout@v4
      - name: verify
        run: |
          if [ -z "$(ls -A build/att)" ]; then
            echo "no attestations"
            exit 1
          fi
          for f in build/att/*.json; do
            grep -q verified "$f" || exit 1
          done
`
	if n := rules(scan(t, unguarded, Options{}))[RuleAbsencePass]; n != 1 {
		t.Errorf("unguarded loop: got %d findings, want 1", n)
	}
	if n := rules(scan(t, guarded, Options{}))[RuleAbsencePass]; n != 0 {
		t.Errorf("guarded loop: got %d findings, want 0", n)
	}
}

func TestSyntheticAnchorDetectsReservedHostsAndDeadSchemes(t *testing.T) {
	res := scan(t, `
name: t
on: [push]
jobs:
  g:
    steps:
      - name: write anchors
        run: |
          mkdir -p out
          echo '{"job":"https://ci.finance.example/jobs/1","shot":"ci://finance/1/x.png","real":"https://github.com/a/b"}' > out/a.json
`, Options{})

	found := map[string]bool{}
	for _, f := range res.Findings {
		if f.Rule == RuleSyntheticAnchor {
			found[f.Detail] = true
		}
	}
	if len(found) != 2 {
		t.Fatalf("synthetic_anchor findings = %d, want 2: %+v", len(found), found)
	}
	for d := range found {
		if strings.Contains(d, "github.com") {
			t.Errorf("flagged a real host: %s", d)
		}
	}
}

// A path filter naming something the repository excludes can never match, so
// the gate never runs against the subject it claims to guard.
func TestUnreachableSubject(t *testing.T) {
	src := `
name: t
on:
  pull_request:
    paths:
      - "projects/ghost/**"
jobs:
  g:
    steps:
      - run: echo hi
`
	res := scan(t, src, Options{
		GitIgnored: func(p string) bool { return p == "projects/ghost" },
		PathExists: func(string) bool { return false },
	})
	if n := rules(res)[RuleUnreachable]; n != 1 {
		t.Fatalf("unreachable findings = %d, want 1: %+v", n, res.Findings)
	}

	// Present on disk: the filter is reachable, so no finding.
	res = scan(t, src, Options{
		GitIgnored: func(string) bool { return true },
		PathExists: func(string) bool { return true },
	})
	if n := rules(res)[RuleUnreachable]; n != 0 {
		t.Errorf("path that exists still flagged: %+v", res.Findings)
	}
}

// Without repository context the rule must announce that it did not run,
// rather than contributing a silent pass.
func TestUnreachableSubjectSkipsLoudly(t *testing.T) {
	res := scan(t, `
name: t
on:
  pull_request:
    paths: ["x/**"]
jobs:
  g:
    steps:
      - run: echo hi
`, Options{})
	if len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0], RuleUnreachable) {
		t.Fatalf("skipped = %v, want a note naming %s", res.Skipped, RuleUnreachable)
	}
}

func TestVerdictLadder(t *testing.T) {
	cases := []struct {
		name string
		as   []Assertion
		want string
	}{
		{"no checks", nil, VerdictNoAssertion},
		{"all internal", []Assertion{{Internal: []string{"a"}}}, VerdictNothing},
		{"mixed", []Assertion{{Internal: []string{"a"}}, {External: []string{"b"}}}, VerdictPartial},
		{"all external", []Assertion{{External: []string{"b"}}}, VerdictEstablishes},
	}
	for _, c := range cases {
		if got := verdict(c.as); got != c.want {
			t.Errorf("%s: verdict = %s, want %s", c.name, got, c.want)
		}
	}
}

// Findings carry a line number so a reader can go look.
func TestFindingsCiteALine(t *testing.T) {
	res := scan(t, `
name: t
on: [push]
jobs:
  g:
    env:
      OUT: build/o.json
    steps:
      - name: write
        run: |
          mkdir -p build
          echo x > "$OUT"
      - name: check
        run: test -s "$OUT" || exit 1
`, Options{})
	if len(res.Findings) == 0 {
		t.Fatal("expected findings")
	}
	for _, f := range res.Findings {
		if f.Line == 0 {
			t.Errorf("%s has no line number", f.Rule)
		}
		if f.Referent == "" {
			t.Errorf("%s has no referent statement", f.Rule)
		}
	}
}
