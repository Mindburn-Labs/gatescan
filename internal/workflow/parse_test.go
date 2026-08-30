package workflow

import "testing"

const sample = `
name: demo
on:
  pull_request:
    paths:
      - "services/x/**"
  push:
    branches: [main]
env:
  ROOT: ${{ github.workspace }}/services/x
jobs:
  gate:
    name: Gate
    env:
      OUT: $ROOT/.ci/out
      RESULT: $ROOT/.ci/out/result.json
    steps:
      - uses: actions/checkout@v4
      - name: make it
        continue-on-error: true
        run: echo hi > "$RESULT"
      - name: check it
        if: steps.detect.outputs.present != 'true'
        run: test -s "$RESULT" || exit 1
`

func parse(t *testing.T) *Workflow {
	t.Helper()
	wf, err := Parse("demo.yml", []byte(sample))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return wf
}

// `on` resolves to a boolean under YAML 1.1, which is why the parser walks key
// nodes by source text rather than decoding into a struct.
func TestParseFindsOnKeyDespiteBooleanResolution(t *testing.T) {
	wf := parse(t)
	if len(wf.Triggers) != 2 {
		t.Fatalf("triggers = %d, want 2 (%+v)", len(wf.Triggers), wf.Triggers)
	}
	if wf.Triggers[0].Event != "pull_request" {
		t.Errorf("first trigger = %q, want pull_request", wf.Triggers[0].Event)
	}
	if got := wf.Triggers[0].Paths; len(got) != 1 || got[0] != "services/x/**" {
		t.Errorf("paths = %v", got)
	}
}

func TestParseCapturesStepFields(t *testing.T) {
	wf := parse(t)
	if len(wf.Jobs) != 1 || len(wf.Jobs[0].Steps) != 3 {
		t.Fatalf("jobs/steps = %d/%d", len(wf.Jobs), len(wf.Jobs[0].Steps))
	}
	steps := wf.Jobs[0].Steps
	if !steps[1].ContinueOnError {
		t.Error("continue-on-error not captured")
	}
	if steps[2].If == "" {
		t.Error("if not captured")
	}
	if steps[0].Label() != "uses: actions/checkout@v4" {
		t.Errorf("label = %q", steps[0].Label())
	}
	for i, s := range steps {
		if s.Line == 0 {
			t.Errorf("step %d has no line number", i)
		}
	}
}

// Findings cite file:line, so line numbers have to be real.
func TestLineNumbersPointAtTheRightSource(t *testing.T) {
	wf := parse(t)
	want := "name: check it"
	got := wf.Jobs[0].Steps[2].Line
	if got == 0 || !contains(wf.Lines[got-1], want) {
		t.Errorf("step 2 line %d = %q, want a line containing %q", got, wf.Lines[got-1], want)
	}
}

func contains(hay, needle string) bool { return len(hay) >= len(needle) && index(hay, needle) >= 0 }

func index(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// Env entries defined in terms of each other must come out fully resolved,
// and the workspace root must vanish so paths stay repository-relative.
func TestJobEnvResolvesChainsAndStripsWorkspace(t *testing.T) {
	wf := parse(t)
	env := wf.JobEnv(wf.Jobs[0])
	if got, want := env["RESULT"], "services/x/.ci/out/result.json"; got != want {
		t.Errorf("RESULT = %q, want %q", got, want)
	}
	if got, want := env["ROOT"], "services/x"; got != want {
		t.Errorf("ROOT = %q, want %q", got, want)
	}
}

// Two references to the same run id must compare equal; different expressions
// must stay distinct. Dropping expressions entirely would conflate them.
func TestExpandKeepsExpressionsDistinct(t *testing.T) {
	env := map[string]string{}
	a := Expand("dir/${{ github.run_id }}/x", env)
	b := Expand("dir/${{ github.run_id }}/x", env)
	c := Expand("dir/${{ github.run_attempt }}/x", env)
	if a != b {
		t.Errorf("same expression expanded differently: %q vs %q", a, b)
	}
	if a == c {
		t.Errorf("different expressions collapsed to %q", a)
	}
}

// URLs must survive expansion: collapsing "//" would destroy the host.
func TestExpandRawPreservesURLAuthority(t *testing.T) {
	got := ExpandRaw("https://ci.finance.example/jobs/$ID", map[string]string{"ID": "7"})
	if want := "https://ci.finance.example/jobs/7"; got != want {
		t.Errorf("ExpandRaw = %q, want %q", got, want)
	}
	if p := Expand("a//b/", nil); p != "a/b" {
		t.Errorf("Expand path = %q, want a/b", p)
	}
}
