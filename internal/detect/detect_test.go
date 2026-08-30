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

// Two anchor rules, because the two claims are not equally provable: a
// reserved documentation host is fake by standard, an unfamiliar scheme merely
// needs a human. Reporting both at the same weight would over-claim.
func TestAnchorRulesSeparateProvableFromReviewable(t *testing.T) {
	res := scan(t, `
name: t
on: [push]
jobs:
  g:
    steps:
      - name: write anchors
        run: |
          mkdir -p out
          echo '{"job":"https://ci.finance.example/jobs/1","shot":"ci://finance/1/x.png","real":"https://github.com/a/b","chart":"oci://ghcr.io/x/y"}' > out/a.json
`, Options{})

	byRule := map[string][]Finding{}
	for _, f := range res.Findings {
		byRule[f.Rule] = append(byRule[f.Rule], f)
	}
	if n := len(byRule[RuleSyntheticAnchor]); n != 1 {
		t.Errorf("synthetic_anchor = %d, want 1 (the reserved host): %+v", n, byRule[RuleSyntheticAnchor])
	}
	if n := len(byRule[RuleUnresolvable]); n != 1 {
		t.Errorf("unresolvable_anchor = %d, want 1 (the ci:// scheme): %+v", n, byRule[RuleUnresolvable])
	}
	if len(byRule[RuleUnresolvable]) == 1 && byRule[RuleUnresolvable][0].Severity != SeverityMedium {
		t.Error("unresolvable_anchor must stay below the default failure threshold")
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Detail, "github.com") || strings.Contains(f.Detail, "ghcr.io") {
			t.Errorf("flagged a resolvable reference: %s", f.Detail)
		}
	}
}

// A scheme is readable even when the rest of the reference still holds an
// unexpanded variable; letting url.Parse fail there would skip the check
// silently, which is the behaviour this tool exists to object to.
func TestSchemeCheckSurvivesUnexpandedVariables(t *testing.T) {
	rule, _, reason := anchorProblem("madeup://${SOME_VAR}/x.json")
	if rule != RuleUnresolvable || reason == "" {
		t.Errorf("anchorProblem = %q/%q, want an unresolvable_anchor reason", rule, reason)
	}
}

// Contacting a registry or a remote is a referent that path analysis alone
// cannot see. Publishing steps were being reported as vacuous checks.
func TestEgressIsAnExternalReferent(t *testing.T) {
	res := scan(t, `
name: t
on: [push]
jobs:
  g:
    steps:
      - name: package
        run: |
          mkdir -p dist
          tar czf dist/chart.tgz chart/
      - name: push chart
        run: |
          helm push dist/chart.tgz oci://ghcr.io/org/charts || exit 1
`, Options{})
	if n := rules(res)[RuleSelfReferential]; n != 0 {
		t.Errorf("publishing step reported as a vacuous check: %+v", res.Findings)
	}
}

// An artifact a toolchain built from repository source answers to that source,
// one hop beyond what static shell reading can follow.
func TestToolchainOutputCountsAsDerived(t *testing.T) {
	res := scan(t, `
name: t
on: [push]
jobs:
  g:
    steps:
      - uses: actions/checkout@v4
      - name: generate report
        run: |
          mkdir -p reports
          go test ./... -json > reports/out.json
      - name: require coverage
        run: grep -q PASS reports/out.json || exit 1
`, Options{})
	if n := rules(res)[RuleSelfReferential]; n != 0 {
		t.Errorf("toolchain-derived artifact treated as self-referential: %+v", res.Findings)
	}
}

// Regression: a toolchain step that happens to mkdir the artifact tree must not
// launder the provenance of literals other steps write into it. Attributing
// directories the same way as files made a fabricated evidence chain look sound.
func TestMkdirDoesNotLaunderProvenance(t *testing.T) {
	res := scan(t, `
name: t
on: [push]
jobs:
  g:
    steps:
      - name: build
        run: |
          mkdir -p out/evidence
          go build ./... 2>&1 | tee out/build.log
      - name: fabricate
        run: |
          echo '{"ok":true}' > out/evidence/result.json
      - name: validate
        run: grep -q '"ok":true' out/evidence/result.json || exit 1
`, Options{})
	if n := rules(res)[RuleSelfReferential]; n != 1 {
		t.Fatalf("self_referential findings = %d, want 1 — a mkdir must not confer toolchain provenance: %+v", n, res.Findings)
	}
	if got := res.Jobs[0].Verdict; got != VerdictNothing {
		t.Errorf("verdict = %s, want %s", got, VerdictNothing)
	}
}

// Building twice and comparing is a real check: the two runs are independent
// trials and disagreement is the signal. Reporting it at the same weight as a
// tautology would burn the reader's trust on a correct pipeline.
func TestReplicationCheckIsDowngradedNotSuppressed(t *testing.T) {
	res := scan(t, `
name: t
on: [push]
jobs:
  g:
    steps:
      - name: first build
        run: |
          mkdir -p out
          sha256sum bin/app > out/first.sha256
      - name: second build
        run: |
          sha256sum bin/app > out/second.sha256
      - name: diff hashes
        run: diff out/first.sha256 out/second.sha256 || exit 1
`, Options{})
	var found *Finding
	for i, f := range res.Findings {
		if f.Rule == RuleSelfReferential {
			found = &res.Findings[i]
		}
	}
	if found == nil {
		t.Fatalf("replication check should still be reported: %+v", res.Findings)
	}
	if found.Severity != SeverityHigh {
		t.Errorf("severity = %s, want %s for a two-producer comparison", found.Severity, SeverityHigh)
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

// Zero identified inputs means the shell was opaque, not that the gate
// establishes nothing. Reporting a verdict there would be this tool committing
// the very defect it looks for: a conclusion drawn from having seen nothing.
func TestOpaqueChecksAreNotJudged(t *testing.T) {
	res := scan(t, `
name: t
on: [push]
jobs:
  g:
    steps:
      - uses: actions/checkout@v4
      - name: gofmt
        run: |
          out="$(gofmt -l .)"
          if [ -n "$out" ]; then
            exit 1
          fi
`, Options{})
	if got := res.Jobs[0].Verdict; got != VerdictUnanalysed {
		t.Errorf("verdict = %s, want %s", got, VerdictUnanalysed)
	}
	if len(res.Findings) != 0 {
		t.Errorf("opaque job produced findings: %+v", res.Findings)
	}
}

func TestVerdictLadder(t *testing.T) {
	cases := []struct {
		name string
		as   []Assertion
		want string
	}{
		{"no checks", nil, VerdictNoAssertion},
		{"all opaque", []Assertion{{Step: "x"}}, VerdictUnanalysed},
		{"one opaque, one external", []Assertion{{Step: "x"}, {External: []string{"b"}}}, VerdictEstablishes},
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
